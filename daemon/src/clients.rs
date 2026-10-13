//! LAN neighbour discovery shared by the clients inventory and the simple
//! port-forward device picker.
//!
//! The neighbour table is read with `ip -j neigh show` (argument vector, never a
//! shell) and treated as untrusted text: every MAC and address is re-parsed
//! before it is used.

use crate::AppError;
use crate::db::Database;
use anyhow::{Result, anyhow};
use keystone_core::InterfaceRole;
use std::{collections::HashSet, net::IpAddr};
use tokio::process::Command;

/// Kernel NUD states meaning the neighbour could not be resolved. Entries in
/// these states are dropped entirely.
const DEAD_STATES: [&str; 2] = ["FAILED", "INCOMPLETE"];

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

#[cfg(test)]
mod tests {
    use super::*;

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
