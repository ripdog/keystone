//! LAN device inventory (`GET /clients`) and the neighbour discovery it shares
//! with the simple port-forward device picker.
//!
//! The neighbour table is read with `ip -j neigh show` (argument vector, never a
//! shell) and treated as untrusted text: every MAC and address is re-parsed
//! before it is used. The four sources (neighbours, DHCP leases, static
//! reservations, firewall zones and forwards) are merged by `merge_clients`,
//! a pure function so it can be tested without `ip` or a database.

use crate::AppError;
use crate::db::Database;
use anyhow::{Result, anyhow};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use keystone_core::{
    Client, ClientTraffic, ClientTrafficResponse, ClientsResponse, DhcpLease, DnsmasqStaticLease,
    FirewallZone, InterfaceRole, SimplePortForward,
};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::IpAddr,
    path::Path,
    sync::{Arc, OnceLock},
};
use tokio::process::Command;
use tracing::{debug, warn};

/// Kernel NUD states meaning the neighbour answered recently enough to count as
/// present on the network.
const ONLINE_STATES: [&str; 5] = ["REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"];

/// Kernel NUD states meaning the neighbour could not be resolved. Entries in
/// these states are dropped entirely.
const DEAD_STATES: [&str; 2] = ["FAILED", "INCOMPLETE"];

/// Vendor label for locally administered (randomized) MAC addresses.
const RANDOMIZED_VENDOR: &str = "Private (randomized)";

/// IEEE OUI registry from Arch's `hwdata` package. It is world-readable system
/// data, so it stays readable under the daemon's `ProtectSystem=strict` sandbox.
const OUI_PATH: &str = "/usr/share/hwdata/oui.txt";

/// OUI prefix (first three MAC octets) to manufacturer name.
pub type OuiTable = HashMap<[u8; 3], String>;

/// One validated neighbour-table entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neighbour {
    /// Canonical lowercase MAC address.
    pub mac: String,
    pub interface: String,
    pub address: IpAddr,
    /// NUD states reported by iproute2, upper-cased (e.g. REACHABLE, STALE).
    pub states: Vec<String>,
}

/// Parse `aa:bb:cc:dd:ee:ff` (any case) into its six octets.
pub fn parse_mac(input: &str) -> Option<[u8; 6]> {
    let mut octets = [0u8; 6];
    let mut parts = input.split(':');
    for octet in &mut octets {
        *octet = parse_hex_byte(parts.next()?)?;
    }
    parts.next().is_none().then_some(octets)
}

/// Canonical lowercase colon-separated form of a MAC address.
pub fn format_mac(octets: &[u8; 6]) -> String {
    octets
        .iter()
        .map(|o| format!("{o:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Exactly two hex digits. Rejects signs and other characters that
/// `u8::from_str_radix` would otherwise accept.
pub(crate) fn parse_hex_byte(part: &str) -> Option<u8> {
    if part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u8::from_str_radix(part, 16).ok()
}

/// Parse `ip -j neigh show` output into validated entries. Entries with an
/// unparseable MAC or address, a zero MAC, or a dead state are skipped.
pub fn parse_neighbours(json: &[u8]) -> Result<Vec<Neighbour>> {
    let entries: Vec<serde_json::Value> =
        serde_json::from_slice(json).map_err(|e| anyhow!("Cannot parse neighbour table: {e}"))?;
    Ok(entries.iter().filter_map(parse_neighbour).collect())
}

fn parse_neighbour(entry: &serde_json::Value) -> Option<Neighbour> {
    let octets = parse_mac(entry.get("lladdr")?.as_str()?)?;
    if octets == [0; 6] {
        return None;
    }
    let interface = entry.get("dev")?.as_str()?;
    if interface.is_empty() {
        return None;
    }
    let address: IpAddr = entry.get("dst")?.as_str()?.parse().ok()?;
    let states: Vec<String> = entry
        .get("state")
        .and_then(|s| s.as_array())
        .map(|list| {
            list.iter()
                .filter_map(|s| s.as_str())
                .map(str::to_ascii_uppercase)
                .collect()
        })
        .unwrap_or_default();
    if states.iter().any(|s| DEAD_STATES.contains(&s.as_str())) {
        return None;
    }
    Some(Neighbour {
        mac: format_mac(&octets),
        interface: interface.to_string(),
        address,
        states,
    })
}

/// Interfaces that count as LAN: members of non-WAN firewall zones, plus
/// enabled interfaces with the LAN role (which covers systems without explicit
/// zone assignments). WAN-zone interfaces are always excluded.
pub async fn lan_interfaces(db: &Database) -> Result<HashSet<String>> {
    let zones = db.get_firewall_zones().await?;
    let wan_interfaces: HashSet<_> = zones
        .iter()
        .filter(|z| z.is_wan)
        .flat_map(|z| z.interfaces.iter().cloned())
        .collect();
    let mut interfaces: HashSet<_> = zones
        .iter()
        .filter(|z| !z.is_wan)
        .flat_map(|z| z.interfaces.iter().cloned())
        .collect();
    for iface in db.get_interface_configs().await? {
        if iface.enabled && iface.role == InterfaceRole::LAN {
            interfaces.insert(iface.name);
        }
    }
    interfaces.retain(|name| !wan_interfaces.contains(name));
    Ok(interfaces)
}

/// Neighbour entries on LAN interfaces, sorted by interface then address so
/// callers see a deterministic order.
pub async fn lan_neighbours(db: &Database) -> Result<Vec<Neighbour>, AppError> {
    let interfaces = lan_interfaces(db).await?;
    let output = Command::new("ip")
        .args(["-j", "neigh", "show"])
        .output()
        .await
        .map_err(|e| anyhow!("Cannot inspect neighbour table: {e}"))?;
    if !output.status.success() {
        return Err(anyhow!("Failed to inspect LAN neighbours").into());
    }
    let mut neighbours = parse_neighbours(&output.stdout)?;
    neighbours.retain(|n| interfaces.contains(&n.interface));
    neighbours.sort_by(|a, b| (&a.interface, a.address).cmp(&(&b.interface, b.address)));
    Ok(neighbours)
}

/// The OUI registry, loaded on first use. A missing file disables vendor
/// lookup (logged once at debug level); randomized MACs are still labelled.
pub fn oui_table() -> &'static OuiTable {
    static TABLE: OnceLock<OuiTable> = OnceLock::new();
    TABLE.get_or_init(|| load_oui_file(Path::new(OUI_PATH)))
}

fn load_oui_file(path: &Path) -> OuiTable {
    match std::fs::read(path) {
        Ok(bytes) => parse_oui(&String::from_utf8_lossy(&bytes)),
        Err(e) => {
            debug!(
                "Vendor lookup disabled, cannot read {}: {e}",
                path.display()
            );
            OuiTable::new()
        }
    }
}

/// Parse `hwdata` OUI content. Only `(hex)` lines carry a three-octet prefix
/// and a name; headers and `(base 16)` ranges are ignored.
pub fn parse_oui(content: &str) -> OuiTable {
    content.lines().filter_map(parse_oui_line).collect()
}

/// Parse one line such as `00-00-0C   (hex)\t\tCisco Systems, Inc`.
fn parse_oui_line(line: &str) -> Option<([u8; 3], String)> {
    let (prefix, vendor) = line.split_once("(hex)")?;
    let vendor = vendor.trim();
    if vendor.is_empty() {
        return None;
    }
    let mut octets = [0u8; 3];
    let mut parts = prefix.trim().split('-');
    for octet in &mut octets {
        *octet = parse_hex_byte(parts.next()?)?;
    }
    parts.next().is_none().then(|| (octets, vendor.to_string()))
}

/// Locally administered MACs (second-lowest bit of the first octet) are
/// randomized by the host and carry no manufacturer information.
fn is_locally_administered(octets: &[u8; 6]) -> bool {
    octets[0] & 0x02 != 0
}

fn vendor_for(octets: &[u8; 6], oui: &OuiTable) -> Option<String> {
    if is_locally_administered(octets) {
        return Some(RANDOMIZED_VENDOR.to_string());
    }
    oui.get(&[octets[0], octets[1], octets[2]]).cloned()
}

/// Everything the merge reads. Plain slices keep the merge independent of `ip`
/// and the database.
pub struct ClientSources<'a> {
    pub neighbours: &'a [Neighbour],
    pub leases: &'a [DhcpLease],
    pub static_leases: &'a [DnsmasqStaticLease],
    pub zones: &'a [FirewallZone],
    pub forwards: &'a [SimplePortForward],
    pub oui: &'a OuiTable,
}

/// Preference order when a device has several neighbour entries; lower wins.
fn state_rank(state: &str) -> u8 {
    match state {
        "REACHABLE" => 0,
        "PERMANENT" => 1,
        "DELAY" => 2,
        "PROBE" => 3,
        "STALE" => 4,
        _ => 5,
    }
}

fn blank_client(mac: String) -> Client {
    Client {
        mac,
        hostname: None,
        vendor: None,
        interface: None,
        zone: None,
        ipv4: Vec::new(),
        ipv6: Vec::new(),
        online: false,
        neighbour_state: None,
        lease_expires_at: None,
        static_lease_id: None,
        static_ip: None,
        port_forward_count: 0,
    }
}

/// Record an address once. Link-local IPv6 is never a useful client address.
fn add_address(client: &mut Client, ip: IpAddr) {
    let text = ip.to_string();
    match ip {
        IpAddr::V4(_) => {
            if !client.ipv4.contains(&text) {
                client.ipv4.push(text);
            }
        }
        IpAddr::V6(v6) if v6.is_unicast_link_local() => {}
        IpAddr::V6(_) => {
            if !client.ipv6.contains(&text) {
                client.ipv6.push(text);
            }
        }
    }
}

fn forward_targets(forward: &SimplePortForward) -> impl Iterator<Item = IpAddr> + '_ {
    [forward.ipv4.as_deref(), forward.ipv6.as_deref()]
        .into_iter()
        .flatten()
        .filter_map(|address| address.parse().ok())
}

fn sort_name(client: &Client) -> String {
    client
        .hostname
        .as_deref()
        .unwrap_or(&client.mac)
        .to_ascii_lowercase()
}

/// Merge every source into one `Client` per MAC address, sorted online first
/// and then by name.
pub fn merge_clients(src: &ClientSources<'_>) -> Vec<Client> {
    let zone_of: HashMap<&str, &str> = src
        .zones
        .iter()
        .flat_map(|zone| {
            zone.interfaces
                .iter()
                .map(move |iface| (iface.as_str(), zone.name.as_str()))
        })
        .collect();
    let mut by_mac: BTreeMap<String, Client> = BTreeMap::new();

    // Neighbour table: presence, addresses, and the interface of the best entry.
    for neighbour in src.neighbours {
        let client = by_mac
            .entry(neighbour.mac.clone())
            .or_insert_with(|| blank_client(neighbour.mac.clone()));
        let best = neighbour
            .states
            .iter()
            .min_by_key(|state| state_rank(state))
            .cloned();
        let better = match (&client.neighbour_state, &best) {
            (None, _) => true,
            (Some(current), Some(new)) => state_rank(new) < state_rank(current),
            (Some(_), None) => false,
        };
        if better {
            client.interface = Some(neighbour.interface.clone());
            client.neighbour_state = best;
        }
        if neighbour
            .states
            .iter()
            .any(|state| ONLINE_STATES.contains(&state.as_str()))
        {
            client.online = true;
        }
        add_address(client, neighbour.address);
    }

    // Active DHCP leases: hostname, expiry and addresses. Infinite leases
    // (expires_at 0) report no expiry.
    for lease in src.leases {
        let Some(octets) = parse_mac(&lease.mac_address) else {
            continue;
        };
        let client = by_mac
            .entry(format_mac(&octets))
            .or_insert_with(|| blank_client(format_mac(&octets)));
        if client.hostname.is_none() {
            client.hostname = lease.hostname.clone().filter(|h| !h.is_empty());
        }
        if lease.expires_at != 0 {
            client.lease_expires_at = Some(
                client
                    .lease_expires_at
                    .map_or(lease.expires_at, |current| current.max(lease.expires_at)),
            );
        }
        if let Ok(ip) = lease.ip_address.parse::<IpAddr>() {
            add_address(client, ip);
        }
    }

    // Enabled static reservations with an exact MAC. Wildcard and client-ID
    // reservations have no single MAC and are ignored here. Runs after the
    // leases so a lease hostname takes precedence over the reservation's.
    for reservation in src.static_leases.iter().filter(|l| l.enabled) {
        let (Some(octets), Ok(ip), Some(id)) = (
            parse_mac(&reservation.mac_address),
            reservation.ip_address.parse::<IpAddr>(),
            reservation.id,
        ) else {
            continue;
        };
        let mac = format_mac(&octets);
        let client = by_mac
            .entry(mac.clone())
            .or_insert_with(|| blank_client(mac));
        if client.static_lease_id.is_some() {
            continue;
        }
        client.static_lease_id = Some(id);
        client.static_ip = Some(ip.to_string());
        add_address(client, ip);
        if client.hostname.is_none() {
            client.hostname = reservation.hostname.clone().filter(|h| !h.is_empty());
        }
    }

    let mut clients: Vec<Client> = by_mac.into_values().collect();
    for client in &mut clients {
        if let Some(octets) = parse_mac(&client.mac) {
            client.vendor = vendor_for(&octets, src.oui);
        }
        client.zone = client
            .interface
            .as_deref()
            .and_then(|iface| zone_of.get(iface))
            .map(|zone| zone.to_string());
        client.ipv4.sort_by_key(|a| a.parse::<IpAddr>().ok());
        client.ipv6.sort_by_key(|a| a.parse::<IpAddr>().ok());
        let addresses: Vec<IpAddr> = client
            .ipv4
            .iter()
            .chain(&client.ipv6)
            .filter_map(|a| a.parse().ok())
            .collect();
        client.port_forward_count = src
            .forwards
            .iter()
            .filter(|forward| forward_targets(forward).any(|ip| addresses.contains(&ip)))
            .count();
    }
    clients.sort_by(|a, b| {
        b.online
            .cmp(&a.online)
            .then_with(|| sort_name(a).cmp(&sort_name(b)))
            .then_with(|| a.mac.cmp(&b.mac))
    });
    clients
}

/// Routes for the unified client inventory.
pub fn clients_routes(db: Database) -> Router<Arc<crate::AppState>> {
    Router::new()
        .route("/clients", get(get_clients))
        .with_state(db)
        .merge(Router::new().route("/clients/traffic", get(get_client_traffic)))
}

/// Most devices whose history one request may ask for.
const MAX_TRAFFIC_MACS: usize = 64;

/// Every source merged into the client list.
async fn load_clients(db: &Database) -> Result<Vec<Client>, AppError> {
    let neighbours = lan_neighbours(db).await?;
    let leases = match crate::dnsmasq::get_active_leases() {
        Ok(leases) => leases,
        Err(e) => {
            warn!("Cannot read DHCP leases for the clients list: {e}");
            Vec::new()
        }
    };
    let static_leases = crate::dnsmasq::load_static_leases(db.pool()).await?;
    let zones = db.get_firewall_zones().await?;
    let (_, forwards) = crate::firewall::simple::load_forwards(db).await?;
    Ok(merge_clients(&ClientSources {
        neighbours: &neighbours,
        leases: &leases,
        static_leases: &static_leases,
        zones: &zones,
        forwards: &forwards,
        oui: oui_table(),
    }))
}

/// GET /clients - every device seen on the LAN, one record per MAC address.
async fn get_clients(State(db): State<Database>) -> Result<Json<ClientsResponse>, AppError> {
    Ok(Json(ClientsResponse {
        clients: load_clients(&db).await?,
    }))
}

#[derive(Deserialize)]
struct TrafficQuery {
    /// Comma-separated MAC addresses. Malformed entries are ignored.
    macs: Option<String>,
}

/// MACs named in a `macs` query value, canonicalised, deduplicated and capped.
fn requested_macs(value: Option<&str>) -> Vec<String> {
    let mut macs: Vec<String> = Vec::new();
    for mac in value
        .unwrap_or_default()
        .split(',')
        .filter_map(|text| parse_mac(text.trim()))
        .map(|octets| format_mac(&octets))
    {
        if !macs.contains(&mac) {
            macs.push(mac);
        }
        if macs.len() == MAX_TRAFFIC_MACS {
            break;
        }
    }
    macs
}

/// Every address a device is known by, as parsed IPs.
fn client_addresses(client: &Client) -> Vec<IpAddr> {
    client
        .ipv4
        .iter()
        .chain(&client.ipv6)
        .filter_map(|address| address.parse().ok())
        .collect()
}

/// GET /clients/traffic?macs=... - one minute of WAN throughput for each
/// requested device that is in the client list.
async fn get_client_traffic(
    State(state): State<Arc<crate::AppState>>,
    Query(query): Query<TrafficQuery>,
) -> Result<Json<ClientTrafficResponse>, AppError> {
    let wanted = requested_macs(query.macs.as_deref());
    if wanted.is_empty() {
        return Ok(Json(ClientTrafficResponse::default()));
    }
    let clients = load_clients(&state.db).await?;
    let sampler = state.client_traffic.read().await;
    let clients = clients
        .iter()
        .filter(|client| wanted.contains(&client.mac))
        .map(|client| ClientTraffic {
            mac: client.mac.clone(),
            samples: sampler.series_for(&client_addresses(client)),
        })
        .collect();
    Ok(Json(ClientTrafficResponse { clients }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use keystone_core::RuleProtocol;

    fn neighbour(mac: &str, iface: &str, addr: &str, states: &[&str]) -> Neighbour {
        Neighbour {
            mac: mac.into(),
            interface: iface.into(),
            address: addr.parse().unwrap(),
            states: states.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn lease(mac: &str, ip: &str, hostname: Option<&str>, expires_at: u64) -> DhcpLease {
        DhcpLease {
            mac_address: mac.into(),
            ip_address: ip.into(),
            hostname: hostname.map(Into::into),
            expires_at,
            client_id: None,
        }
    }

    fn reservation(
        id: i64,
        mac: &str,
        ip: &str,
        hostname: Option<&str>,
        enabled: bool,
    ) -> DnsmasqStaticLease {
        DnsmasqStaticLease {
            id: Some(id),
            mac_address: mac.into(),
            ip_address: ip.into(),
            hostname: hostname.map(Into::into),
            enabled,
            ..Default::default()
        }
    }

    fn lan_zone() -> FirewallZone {
        FirewallZone {
            name: "lan".into(),
            interfaces: vec!["br0".into()],
            ..Default::default()
        }
    }

    fn forward(ipv4: Option<&str>, ipv6: Option<&str>) -> SimplePortForward {
        SimplePortForward {
            rule_id: 1,
            ipv4_rule_id: None,
            ipv6_rule_id: None,
            name: "web".into(),
            description: None,
            protocol: RuleProtocol::Tcp,
            external_port: 443,
            destination_port: 443,
            ipv4: ipv4.map(Into::into),
            ipv6: ipv6.map(Into::into),
            source_zone: None,
            source_ip: None,
            enabled: true,
        }
    }

    fn merge_with(
        neighbours: &[Neighbour],
        leases: &[DhcpLease],
        static_leases: &[DnsmasqStaticLease],
        forwards: &[SimplePortForward],
        oui: &OuiTable,
    ) -> Vec<Client> {
        merge_clients(&ClientSources {
            neighbours,
            leases,
            static_leases,
            zones: &[lan_zone()],
            forwards,
            oui,
        })
    }

    fn merge(
        neighbours: &[Neighbour],
        leases: &[DhcpLease],
        static_leases: &[DnsmasqStaticLease],
        forwards: &[SimplePortForward],
    ) -> Vec<Client> {
        merge_with(
            neighbours,
            leases,
            static_leases,
            forwards,
            &OuiTable::new(),
        )
    }

    #[test]
    fn parses_oui_registry_lines() {
        let content = "OUI/MA-L\t\tOrganization\n\
            00-00-0C   (hex)\t\tCisco Systems, Inc\n\
            00-00-0C:24:00   (base 16)\t\tignored range\n\
            00-00-00   (hex)\t\tXEROX CORPORATION\n\
            0G-00-01   (hex)\t\tbad hex\n\
            00-00-01   (hex)\t\t\n\
            00-00-02-03   (hex)\t\ttoo many octets\n";
        let table = parse_oui(content);
        assert_eq!(table.len(), 2);
        assert_eq!(
            table.get(&[0x00, 0x00, 0x0c]).unwrap(),
            "Cisco Systems, Inc"
        );
        assert_eq!(table.get(&[0x00, 0x00, 0x00]).unwrap(), "XEROX CORPORATION");
    }

    #[test]
    fn randomized_macs_are_flagged_instead_of_looked_up() {
        let mut oui = OuiTable::new();
        oui.insert([0x02, 0x00, 0x00], "Would be wrong".into());
        oui.insert([0x00, 0x00, 0x0c], "Cisco Systems, Inc".into());

        assert_eq!(
            vendor_for(&[0x02, 0x00, 0x00, 0, 0, 1], &oui).as_deref(),
            Some(RANDOMIZED_VENDOR)
        );
        assert_eq!(
            vendor_for(&[0x06, 0x00, 0x00, 0, 0, 1], &oui).as_deref(),
            Some(RANDOMIZED_VENDOR)
        );
        assert_eq!(
            vendor_for(&[0x00, 0x00, 0x0c, 0, 0, 1], &oui).as_deref(),
            Some("Cisco Systems, Inc")
        );
        assert_eq!(vendor_for(&[0x00, 0x00, 0x99, 0, 0, 1], &oui), None);
    }

    #[test]
    fn merges_sources_into_one_record_per_mac() {
        let neighbours = [
            neighbour("aa:bb:cc:00:00:01", "br0", "192.168.1.20", &["REACHABLE"]),
            neighbour("aa:bb:cc:00:00:01", "br0", "2001:db8::20", &["REACHABLE"]),
            neighbour("aa:bb:cc:00:00:01", "br0", "fe80::20", &["REACHABLE"]),
        ];
        // Uppercase lease MAC must still merge with the lowercase neighbour.
        let leases = [lease(
            "AA:BB:CC:00:00:01",
            "192.168.1.20",
            Some("laptop"),
            2000,
        )];
        let statics = [reservation(
            7,
            "aa:bb:cc:00:00:01",
            "192.168.1.20",
            Some("reserved-name"),
            true,
        )];
        let forwards = [
            forward(Some("192.168.1.20"), None),
            forward(Some("192.168.1.99"), None),
        ];

        let clients = merge(&neighbours, &leases, &statics, &forwards);
        assert_eq!(clients.len(), 1);
        let client = &clients[0];
        assert_eq!(client.mac, "aa:bb:cc:00:00:01");
        assert_eq!(client.hostname.as_deref(), Some("laptop"));
        assert!(client.online);
        assert_eq!(client.neighbour_state.as_deref(), Some("REACHABLE"));
        assert_eq!(client.interface.as_deref(), Some("br0"));
        assert_eq!(client.zone.as_deref(), Some("lan"));
        assert_eq!(client.ipv4, vec!["192.168.1.20"]);
        assert_eq!(client.ipv6, vec!["2001:db8::20"]);
        assert_eq!(client.lease_expires_at, Some(2000));
        assert_eq!(client.static_lease_id, Some(7));
        assert_eq!(client.static_ip.as_deref(), Some("192.168.1.20"));
        assert_eq!(client.port_forward_count, 1);
    }

    #[test]
    fn leases_and_reservations_without_neighbours_are_offline() {
        let leases = [
            lease("bb:00:00:00:00:02", "192.168.1.30", Some("phone"), 0),
            lease("bb:00:00:00:00:02", "192.168.1.31", None, 0),
        ];
        let statics = [
            reservation(
                9,
                "cc:00:00:00:00:03",
                "192.168.1.40",
                Some("printer"),
                true,
            ),
            // Disabled and wildcard reservations do not describe a present device.
            reservation(10, "dd:00:00:00:00:04", "192.168.1.41", None, false),
            reservation(11, "00:11:22:*:*:*", "192.168.1.42", None, true),
        ];

        let clients = merge(&[], &leases, &statics, &[]);
        let macs: Vec<&str> = clients.iter().map(|c| c.mac.as_str()).collect();
        assert_eq!(macs, vec!["bb:00:00:00:00:02", "cc:00:00:00:00:03"]);

        let phone = &clients[0];
        assert!(!phone.online);
        assert_eq!(phone.interface, None);
        assert_eq!(phone.zone, None);
        assert_eq!(phone.neighbour_state, None);
        assert_eq!(
            phone.lease_expires_at, None,
            "infinite leases report no expiry"
        );
        assert_eq!(phone.ipv4, vec!["192.168.1.30", "192.168.1.31"]);
        assert_eq!(phone.static_lease_id, None);

        let printer = &clients[1];
        assert!(!printer.online);
        assert_eq!(printer.hostname.as_deref(), Some("printer"));
        assert_eq!(printer.static_lease_id, Some(9));
        assert_eq!(printer.ipv4, vec!["192.168.1.40"]);
    }

    #[test]
    fn stale_and_permanent_count_as_online_and_best_state_wins() {
        let neighbours = [
            neighbour("aa:00:00:00:00:01", "br0", "192.168.1.5", &["STALE"]),
            neighbour("aa:00:00:00:00:01", "br1", "192.168.1.6", &["REACHABLE"]),
            neighbour("aa:00:00:00:00:02", "br0", "192.168.1.7", &["DELAY"]),
            neighbour("aa:00:00:00:00:03", "br0", "192.168.1.8", &["NOARP"]),
        ];
        let clients = merge(&neighbours, &[], &[], &[]);
        let by_mac = |mac: &str| clients.iter().find(|c| c.mac == mac).unwrap();

        let both = by_mac("aa:00:00:00:00:01");
        assert!(both.online);
        assert_eq!(both.neighbour_state.as_deref(), Some("REACHABLE"));
        assert_eq!(both.interface.as_deref(), Some("br1"));
        assert_eq!(both.zone, None, "br1 is not in any firewall zone");

        assert!(by_mac("aa:00:00:00:00:02").online);
        assert!(!by_mac("aa:00:00:00:00:03").online);
        assert_eq!(
            by_mac("aa:00:00:00:00:03").neighbour_state.as_deref(),
            Some("NOARP")
        );
    }

    #[test]
    fn sorts_online_first_then_by_name() {
        let neighbours = [neighbour(
            "ee:00:00:00:00:01",
            "br0",
            "192.168.1.9",
            &["REACHABLE"],
        )];
        let leases = [
            lease("aa:00:00:00:00:01", "192.168.1.50", Some("alpha"), 2000),
            lease("bb:00:00:00:00:01", "192.168.1.51", Some("Zeta"), 2000),
        ];
        let neighbours_named = [neighbour(
            "cc:00:00:00:00:01",
            "br0",
            "192.168.1.60",
            &["REACHABLE"],
        )];
        let leases_named = [lease(
            "cc:00:00:00:00:01",
            "192.168.1.60",
            Some("mid"),
            2000,
        )];
        let mut all_leases = leases.to_vec();
        all_leases.extend(leases_named);
        let mut all_neighbours = neighbours.to_vec();
        all_neighbours.extend(neighbours_named);

        let clients = merge(&all_neighbours, &all_leases, &[], &[]);
        let order: Vec<Option<&str>> = clients.iter().map(|c| c.hostname.as_deref()).collect();
        // Online devices first. An unnamed device sorts by MAC ("ee:..." before
        // "mid"). Offline devices follow, compared case-insensitively.
        assert_eq!(order, vec![None, Some("mid"), Some("alpha"), Some("Zeta")]);
        assert!(clients[0].online && clients[1].online);
        assert!(!clients[2].online && !clients[3].online);
    }

    #[test]
    fn ipv4_addresses_sort_numerically_and_dedupe() {
        let neighbours = [
            neighbour("aa:00:00:00:00:01", "br0", "192.168.1.10", &["REACHABLE"]),
            neighbour("aa:00:00:00:00:01", "br0", "192.168.1.9", &["REACHABLE"]),
            neighbour("aa:00:00:00:00:01", "br0", "192.168.1.9", &["STALE"]),
        ];
        let clients = merge(&neighbours, &[], &[], &[]);
        assert_eq!(clients[0].ipv4, vec!["192.168.1.9", "192.168.1.10"]);
    }

    #[test]
    fn counts_forwards_to_any_address_of_the_client_once() {
        let neighbours = [
            neighbour("aa:00:00:00:00:01", "br0", "192.168.1.10", &["REACHABLE"]),
            neighbour("aa:00:00:00:00:01", "br0", "2001:db8::10", &["REACHABLE"]),
        ];
        let leases = [lease("aa:00:00:00:00:01", "192.168.1.10", None, 2000)];
        let statics = [reservation(
            1,
            "aa:00:00:00:00:02",
            "2001:db8::77",
            None,
            true,
        )];
        let forwards = [
            // Dual-stack pair to the same device counts once per forward.
            forward(Some("192.168.1.10"), Some("2001:db8::10")),
            forward(None, Some("2001:db8::77")),
            forward(Some("192.168.1.200"), None),
        ];
        let clients = merge(&neighbours, &leases, &statics, &forwards);
        let by_mac = |mac: &str| clients.iter().find(|c| c.mac == mac).unwrap();
        assert_eq!(by_mac("aa:00:00:00:00:01").port_forward_count, 1);
        assert_eq!(by_mac("aa:00:00:00:00:02").port_forward_count, 1);
    }

    #[test]
    fn labels_vendors_in_merged_output() {
        let mut oui = OuiTable::new();
        oui.insert([0x00, 0x00, 0x0c], "Cisco Systems, Inc".into());
        let neighbours = [
            neighbour("00:00:0c:00:00:01", "br0", "192.168.1.2", &["REACHABLE"]),
            neighbour("02:00:00:00:00:02", "br0", "192.168.1.3", &["REACHABLE"]),
        ];
        let clients = merge_with(&neighbours, &[], &[], &[], &oui);
        let vendor_of = |mac: &str| {
            clients
                .iter()
                .find(|c| c.mac == mac)
                .and_then(|c| c.vendor.clone())
        };
        assert_eq!(
            vendor_of("00:00:0c:00:00:01").as_deref(),
            Some("Cisco Systems, Inc")
        );
        assert_eq!(
            vendor_of("02:00:00:00:00:02").as_deref(),
            Some(RANDOMIZED_VENDOR)
        );
    }

    #[test]
    fn traffic_query_keeps_valid_unique_macs_only() {
        assert!(requested_macs(None).is_empty());
        assert_eq!(
            requested_macs(Some(
                "AA:BB:CC:00:00:01, aa:bb:cc:00:00:01,nope,aa:bb:cc:00:00:02,;rm"
            )),
            vec!["aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"]
        );
        let many: Vec<String> = (0..200)
            .map(|i| format!("aa:bb:cc:00:{:02x}:01", i))
            .collect();
        assert_eq!(
            requested_macs(Some(&many.join(","))).len(),
            MAX_TRAFFIC_MACS
        );
    }

    #[test]
    fn client_addresses_skip_unparseable_entries() {
        let mut client = blank_client("aa:bb:cc:00:00:01".into());
        client.ipv4 = vec!["192.168.1.2".into(), "junk".into()];
        client.ipv6 = vec!["2001:db8::2".into()];
        assert_eq!(client_addresses(&client).len(), 2);
    }

    #[test]
    fn parses_mac_addresses_strictly() {
        assert_eq!(
            parse_mac("AA:bb:0C:dd:ee:ff"),
            Some([0xaa, 0xbb, 0x0c, 0xdd, 0xee, 0xff])
        );
        assert_eq!(
            format_mac(&[0xaa, 0xbb, 0x0c, 0, 1, 2]),
            "aa:bb:0c:00:01:02"
        );
        // Wildcards, short forms, extra groups and signs are not MAC addresses.
        assert_eq!(parse_mac("00:11:22:*:*:*"), None);
        assert_eq!(parse_mac("00:11:22:33:44"), None);
        assert_eq!(parse_mac("00:11:22:33:44:55:66"), None);
        assert_eq!(parse_mac("+0:11:22:33:44:55"), None);
        assert_eq!(parse_mac("-"), None);
        assert_eq!(parse_mac(""), None);
    }

    #[test]
    fn neighbour_table_is_validated_and_filtered() {
        let json = br#"[
            {"dst":"192.168.1.20","dev":"br0","lladdr":"AA:BB:CC:00:00:01","state":["REACHABLE"]},
            {"dst":"192.168.1.21","dev":"br0","lladdr":"aa:bb:cc:00:00:02","state":["FAILED"]},
            {"dst":"192.168.1.22","dev":"br0","lladdr":"aa:bb:cc:00:00:03","state":["INCOMPLETE"]},
            {"dst":"192.168.1.23","dev":"br0","lladdr":"00:00:00:00:00:00","state":["STALE"]},
            {"dst":"192.168.1.24","dev":"br0","lladdr":"not-a-mac","state":["STALE"]},
            {"dst":"not-an-ip","dev":"br0","lladdr":"aa:bb:cc:00:00:04","state":["STALE"]},
            {"dst":"192.168.1.25","lladdr":"aa:bb:cc:00:00:05","state":["STALE"]},
            {"dst":"fe80::1","dev":"br0","lladdr":"aa:bb:cc:00:00:06","state":["REACHABLE"]},
            {"dst":"192.168.1.26","dev":"eth9","lladdr":"aa:bb:cc:00:00:07"}
        ]"#;
        let parsed = parse_neighbours(json).unwrap();
        let macs: Vec<&str> = parsed.iter().map(|n| n.mac.as_str()).collect();
        assert_eq!(
            macs,
            vec![
                "aa:bb:cc:00:00:01",
                "aa:bb:cc:00:00:06",
                "aa:bb:cc:00:00:07"
            ]
        );
        assert_eq!(parsed[0].states, vec!["REACHABLE".to_string()]);
        assert!(parsed[2].states.is_empty());
    }

    #[test]
    fn rejects_malformed_neighbour_json() {
        assert!(parse_neighbours(b"{not json").is_err());
        assert!(parse_neighbours(b"[]").unwrap().is_empty());
    }
}
