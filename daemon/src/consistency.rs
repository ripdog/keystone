//! Soft consistency checks for the status page. Unlike `config_validation`
//! (hard errors rejected at save time), these report configurations that are
//! accepted but probably do not do what the operator intends: overlapping
//! subnets, firewall zones that contradict interface roles, DHCP servers on
//! the wrong side, and so on.
//!
//! `config_checks` gathers a snapshot from the database and the running
//! system; `analyze` is pure so it can be tested with synthetic snapshots.

use crate::config_validation::static_ipv4;
use crate::db::Database;
use ipnet::{IpNet, Ipv4Net};
use keystone_core::{
    BridgeConfig, CaddyConfig, CheckCategory, CheckSeverity, DhcpMode, DnsmasqStateResponse,
    DnsmasqUpstreamMode, FirewallConfig, InterfaceConfig, InterfaceRole, IpForwardMode,
    SystemCheck, VlanConfig,
};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// Everything `analyze` looks at.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub configs: Vec<InterfaceConfig>,
    pub vlans: Vec<VlanConfig>,
    pub bridges: Vec<BridgeConfig>,
    pub firewall: FirewallConfig,
    pub dnsmasq: DnsmasqStateResponse,
    pub caddy: CaddyConfig,
    /// Interface names present in /sys/class/net
    pub system_interfaces: HashSet<String>,
    /// Live addresses per interface (from `ip addr`)
    pub live_addresses: HashMap<String, Vec<IpNet>>,
    /// Nameservers listed in /etc/resolv.conf
    pub resolv_nameservers: Vec<IpAddr>,
}

fn finding(
    id: String,
    name: &str,
    category: CheckCategory,
    severity: CheckSeverity,
    message: String,
    fix: &str,
) -> SystemCheck {
    SystemCheck {
        id,
        name: name.to_string(),
        category,
        severity,
        message,
        fix_advice: Some(fix.to_string()),
    }
}

fn warn(id: String, name: &str, message: String, fix: &str) -> SystemCheck {
    finding(
        id,
        name,
        CheckCategory::Configuration,
        CheckSeverity::Warning,
        message,
        fix,
    )
}

fn net_overlap(a: &Ipv4Net, b: &Ipv4Net) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

/// Gather the snapshot and run all consistency checks. Returns only findings,
/// or a single Pass row when there are none.
pub async fn config_checks(db: &Database) -> Vec<SystemCheck> {
    let snapshot = match gather(db).await {
        Ok(s) => s,
        Err(e) => {
            return vec![warn(
                "consistency_unavailable".into(),
                "Configuration consistency",
                format!("Could not load configuration for consistency checks: {e:#}"),
                "Check the daemon log and /var/lib/keystone permissions",
            )];
        }
    };
    let mut checks = analyze(&snapshot);
    if checks.is_empty() {
        checks.push(SystemCheck {
            id: "consistency".into(),
            name: "Configuration consistency".into(),
            category: CheckCategory::Configuration,
            severity: CheckSeverity::Pass,
            message: "No contradictory or suspicious settings found".into(),
            fix_advice: None,
        });
    }
    checks
}

async fn gather(db: &Database) -> anyhow::Result<Snapshot> {
    let pool = db.pool();
    let (live_addresses, system_interfaces, resolv) = tokio::task::spawn_blocking(|| {
        (
            read_live_addresses(),
            read_system_interfaces(),
            std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default(),
        )
    })
    .await?;
    Ok(Snapshot {
        configs: db.get_interface_configs().await?,
        vlans: db.get_all_vlans().await?,
        bridges: db.get_all_bridges().await?,
        firewall: db.get_firewall_config().await?,
        dnsmasq: crate::dnsmasq::load_dnsmasq_state(pool).await?,
        caddy: crate::caddy::load_caddy_config(pool).await?,
        system_interfaces,
        live_addresses,
        resolv_nameservers: parse_resolv_nameservers(&resolv),
    })
}

fn read_system_interfaces() -> HashSet<String> {
    std::fs::read_dir("/sys/class/net")
        .map(|d| {
            d.flatten()
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn read_live_addresses() -> HashMap<String, Vec<IpNet>> {
    std::process::Command::new("ip")
        .args(["-j", "addr", "show"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| parse_ip_addr_json(&o.stdout))
        .unwrap_or_default()
}

/// Parse `ip -j addr show` output.
pub fn parse_ip_addr_json(json: &[u8]) -> HashMap<String, Vec<IpNet>> {
    let mut map = HashMap::new();
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(json) else {
        return map;
    };
    for entry in value.as_array().into_iter().flatten() {
        let Some(name) = entry.get("ifname").and_then(|v| v.as_str()) else {
            continue;
        };
        let nets: Vec<IpNet> = entry
            .get("addr_info")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .filter_map(|a| {
                let local = a.get("local")?.as_str()?;
                let prefix = a.get("prefixlen")?.as_u64()?;
                format!("{local}/{prefix}").parse().ok()
            })
            .collect();
        map.insert(name.to_string(), nets);
    }
    map
}

/// Nameserver addresses from resolv.conf content.
pub fn parse_resolv_nameservers(content: &str) -> Vec<IpAddr> {
    content
        .lines()
        .filter_map(|l| {
            let mut parts = l.split_whitespace();
            (parts.next()? == "nameserver").then_some(())?;
            // Strip an IPv6 zone id such as fe80::1%eth0
            parts.next()?.split('%').next()?.parse().ok()
        })
        .collect()
}

/// Run all checks on a snapshot. Pure.
pub fn analyze(s: &Snapshot) -> Vec<SystemCheck> {
    let mut out = Vec::new();
    let enabled: Vec<&InterfaceConfig> = s.configs.iter().filter(|c| c.enabled).collect();
    let enabled_by_name: HashMap<&str, &InterfaceConfig> =
        enabled.iter().map(|c| (c.name.as_str(), *c)).collect();
    let virtual_names: HashSet<&str> = s
        .vlans
        .iter()
        .map(|v| v.name.as_str())
        .chain(s.bridges.iter().map(|b| b.name.as_str()))
        .collect();

    check_subnets(s, &enabled, &mut out);
    check_missing_nics(s, &enabled, &virtual_names, &mut out);
    check_gateways(&enabled, &mut out);
    check_firewall(s, &enabled, &enabled_by_name, &mut out);
    check_ipv6(s, &enabled, &enabled_by_name, &mut out);
    check_dnsmasq(s, &enabled_by_name, &mut out);
    check_virtual_devices(s, &enabled_by_name, &mut out);
    check_dangling(s, &enabled_by_name, &mut out);
    out
}

fn check_subnets(s: &Snapshot, enabled: &[&InterfaceConfig], out: &mut Vec<SystemCheck>) {
    for wan in enabled.iter().filter(|c| c.role == InterfaceRole::WAN) {
        let mut wan_ips: Vec<std::net::Ipv4Addr> = s
            .live_addresses
            .get(&wan.name)
            .into_iter()
            .flatten()
            .filter_map(|n| match n {
                IpNet::V4(n) if !n.addr().is_link_local() => Some(n.addr()),
                _ => None,
            })
            .collect();
        wan_ips.extend(static_ipv4(wan).iter().map(|n| n.addr()));
        wan_ips.sort();
        wan_ips.dedup();
        for lan in enabled
            .iter()
            .filter(|c| c.role == InterfaceRole::LAN && c.name != wan.name)
        {
            for net in static_ipv4(lan) {
                if let Some(ip) = wan_ips.iter().find(|ip| net.contains(*ip)) {
                    out.push(finding(
                        format!("consistency_wan_lan_overlap_{}_{}", wan.name, lan.name),
                        "WAN and LAN subnets overlap",
                        CheckCategory::Network,
                        CheckSeverity::Error,
                        format!(
                            "WAN {} has address {ip}, which is inside the subnet {} of LAN {}. This is typical double NAT behind an ISP modem and breaks routing between the two.",
                            wan.name,
                            net.trunc(),
                            lan.name
                        ),
                        &format!(
                            "Renumber the LAN on the Interfaces page (edit {}), e.g. use 192.168.50.1/24, then update DHCP ranges to match.",
                            lan.name
                        ),
                    ));
                }
            }
        }
    }

    // LAN/LAN overlap and duplicate addresses across interfaces
    for (i, a) in enabled.iter().enumerate() {
        for b in &enabled[i + 1..] {
            if a.role != InterfaceRole::LAN || b.role != InterfaceRole::LAN {
                continue;
            }
            for na in static_ipv4(a) {
                for nb in static_ipv4(b) {
                    if net_overlap(&na, &nb) {
                        out.push(finding(
                            format!("consistency_lan_overlap_{}_{}", a.name, b.name),
                            "LAN subnets overlap",
                            CheckCategory::Network,
                            CheckSeverity::Error,
                            format!(
                                "{} ({}) and {} ({}) have overlapping subnets; the router cannot tell which interface to use for the shared range.",
                                a.name,
                                na.trunc(),
                                b.name,
                                nb.trunc()
                            ),
                            &format!(
                                "Give {} and {} different subnets on the Interfaces page.",
                                a.name, b.name
                            ),
                        ));
                    }
                }
            }
        }
    }
    let mut seen: HashMap<IpAddr, &str> = HashMap::new();
    for c in enabled {
        for ip in c
            .addresses
            .iter()
            .filter_map(|a| a.address.parse::<IpNet>().ok())
            .map(|n| n.addr())
        {
            if let Some(other) = seen.insert(ip, c.name.as_str())
                && other != c.name
            {
                out.push(finding(
                    format!("consistency_duplicate_address_{}_{}", other, c.name),
                    "Duplicate interface address",
                    CheckCategory::Network,
                    CheckSeverity::Error,
                    format!("{ip} is configured on both {other} and {}.", c.name),
                    &format!(
                        "Change the static address of {} on the Interfaces page.",
                        c.name
                    ),
                ));
            }
        }
    }
}

fn check_missing_nics(
    s: &Snapshot,
    enabled: &[&InterfaceConfig],
    virtual_names: &HashSet<&str>,
    out: &mut Vec<SystemCheck>,
) {
    // An empty listing means /sys was unreadable; do not flag everything.
    if s.system_interfaces.is_empty() {
        return;
    }
    for c in enabled {
        if !s.system_interfaces.contains(&c.name) && !virtual_names.contains(c.name.as_str()) {
            out.push(warn(
                format!("consistency_missing_nic_{}", c.name),
                "Configured interface not found",
                format!(
                    "Interface configuration '{}' is enabled but no such network device exists. The NIC may have been renamed or removed.",
                    c.name
                ),
                &format!(
                    "On the Interfaces page, delete or disable the '{}' configuration and configure the device's current name.",
                    c.name
                ),
            ));
        }
    }
}

fn check_gateways(enabled: &[&InterfaceConfig], out: &mut Vec<SystemCheck>) {
    for c in enabled {
        let Some(gw) = c.gateway.as_deref().and_then(|g| g.parse::<IpAddr>().ok()) else {
            continue;
        };
        let dhcp4 = matches!(c.dhcp_mode, DhcpMode::Yes | DhcpMode::Ipv4);
        if gw.is_ipv4() && dhcp4 {
            out.push(warn(
                format!("consistency_gateway_with_dhcp_{}", c.name),
                "Static gateway with DHCP",
                format!(
                    "{} has a static gateway ({gw}) but DHCPv4 is enabled, so there will be two competing default routes.",
                    c.name
                ),
                &format!(
                    "On the Interfaces page edit {}: clear the gateway, or turn DHCP off.",
                    c.name
                ),
            ));
            continue;
        }
        let reachable = c
            .addresses
            .iter()
            .filter_map(|a| a.address.parse::<IpNet>().ok())
            .any(|n| n.trunc().contains(&gw));
        let link_local_v6 = matches!(gw, IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80);
        if !reachable && !link_local_v6 {
            out.push(warn(
                format!("consistency_gateway_unreachable_{}", c.name),
                "Gateway outside interface subnet",
                format!(
                    "The gateway {gw} of {} is not inside any of its static subnets, so it cannot be reached directly.",
                    c.name
                ),
                &format!(
                    "On the Interfaces page edit {}: fix the gateway or the interface address/prefix.",
                    c.name
                ),
            ));
        }
    }
}

fn check_firewall(
    s: &Snapshot,
    enabled: &[&InterfaceConfig],
    enabled_by_name: &HashMap<&str, &InterfaceConfig>,
    out: &mut Vec<SystemCheck>,
) {
    let fw = &s.firewall;
    let has_policy = !fw.zones.is_empty() || !fw.forward_rules.is_empty();
    let zoned: HashSet<&str> = fw
        .zones
        .iter()
        .flat_map(|z| z.interfaces.iter().map(String::as_str))
        .collect();

    if !fw.zones.is_empty() {
        for c in enabled {
            if !zoned.contains(c.name.as_str()) {
                out.push(warn(
                    format!("consistency_no_zone_{}", c.name),
                    "Interface not in a firewall zone",
                    format!(
                        "{} is enabled but belongs to no firewall zone, so its traffic is dropped.",
                        c.name
                    ),
                    &format!("On the Firewall page, add {} to a zone.", c.name),
                ));
            }
        }
    }

    for zone in &fw.zones {
        for iface in &zone.interfaces {
            let Some(cfg) = enabled_by_name.get(iface.as_str()) else {
                // Missing/disabled interfaces are reported by check_dangling
                continue;
            };
            if cfg.role == InterfaceRole::WAN && !zone.is_wan {
                out.push(warn(
                    format!("consistency_role_zone_{}_{}", iface, zone.name),
                    "WAN interface in a non-WAN zone",
                    format!(
                        "{iface} has the WAN role but is in zone '{}', which is not marked as a WAN zone; WAN protections and NAT will not apply to it.",
                        zone.name
                    ),
                    &format!(
                        "On the Firewall page, move {iface} to the WAN zone (or mark zone '{}' as WAN).",
                        zone.name
                    ),
                ));
            }
            if cfg.role == InterfaceRole::LAN && zone.is_wan {
                out.push(warn(
                    format!("consistency_role_zone_{}_{}", iface, zone.name),
                    "LAN interface in a WAN zone",
                    format!(
                        "{iface} has the LAN role but is in WAN zone '{}'; LAN clients would be treated as untrusted.",
                        zone.name
                    ),
                    &format!(
                        "On the Firewall page, move {iface} to a LAN zone, or change its role on the Interfaces page."
                    ),
                ));
            }
        }
        if zone.masquerade_ipv4 && !zone.is_wan {
            out.push(warn(
                format!("consistency_masq_non_wan_{}", zone.name),
                "Masquerade on a non-WAN zone",
                format!(
                    "Zone '{}' masquerades IPv4 but is not a WAN zone; traffic leaving through it will have its source address rewritten.",
                    zone.name
                ),
                &format!(
                    "On the Firewall page edit zone '{}': turn off masquerade, or mark it as WAN.",
                    zone.name
                ),
            ));
        }
    }
    let wan_zones: Vec<_> = fw.zones.iter().filter(|z| z.is_wan).collect();
    if !wan_zones.is_empty() && !wan_zones.iter().any(|z| z.masquerade_ipv4) {
        out.push(warn(
            "consistency_no_masquerade".into(),
            "No NAT on the WAN zone",
            "A WAN zone exists but no zone masquerades IPv4, so private LAN addresses will leave unchanged and the ISP will drop them.".into(),
            "On the Firewall page edit the WAN zone and enable IPv4 masquerade (unless your ISP routes a public subnet to you).",
        ));
    }
    if has_policy
        && !enabled
            .iter()
            .any(|c| matches!(c.ip_forward, IpForwardMode::Yes | IpForwardMode::Ipv4))
    {
        out.push(warn(
            "consistency_no_ipv4_forwarding".into(),
            "IPv4 forwarding is off",
            "The firewall has zones or forward rules, but no enabled interface has IPv4 forwarding on, so the router will not forward LAN traffic.".into(),
            "On the Interfaces page edit your LAN and WAN interfaces and set IP forwarding to Yes or IPv4.",
        ));
    }
}

fn check_ipv6(
    s: &Snapshot,
    enabled: &[&InterfaceConfig],
    enabled_by_name: &HashMap<&str, &InterfaceConfig>,
    out: &mut Vec<SystemCheck>,
) {
    let dnsmasq_ra_ifaces: HashSet<&str> = if s.dnsmasq.config.enabled {
        s.dnsmasq
            .dhcp_ranges
            .iter()
            .filter(|r| r.enabled && r.ipv6_mode.is_some())
            .map(|r| r.interface.as_str())
            .collect()
    } else {
        HashSet::new()
    };
    for c in enabled {
        let dhcp6 = matches!(c.dhcp_mode, DhcpMode::Yes | DhcpMode::Ipv6);
        let without_ra = c
            .dhcpv6_client
            .as_ref()
            .map(|d| d.without_ra.as_str())
            .unwrap_or("no");
        if dhcp6 && !c.ipv6_accept_ra && without_ra == "no" {
            out.push(warn(
                format!("consistency_dhcpv6_no_ra_{}", c.name),
                "DHCPv6 will never start",
                format!(
                    "{} uses DHCPv6 but does not accept router advertisements, and DHCPv6 'without RA' is 'no'. networkd only starts DHCPv6 after seeing an RA.",
                    c.name
                ),
                &format!(
                    "On the Interfaces page edit {}: enable 'Accept router advertisements', or set DHCPv6 'without RA' to 'solicit'.",
                    c.name
                ),
            ));
        }
        if c.role == InterfaceRole::WAN && c.ipv6_send_ra {
            out.push(warn(
                format!("consistency_wan_send_ra_{}", c.name),
                "Router advertisements on WAN",
                format!(
                    "WAN interface {} is set to send IPv6 router advertisements to the upstream network.",
                    c.name
                ),
                &format!("On the Interfaces page edit {}: turn off 'Send router advertisements'.", c.name),
            ));
        }
        if c.role == InterfaceRole::WAN && c.dhcp_prefix_delegation.is_some() {
            out.push(warn(
                format!("consistency_wan_pd_{}", c.name),
                "Prefix delegation on WAN",
                format!(
                    "WAN interface {} has DHCP prefix delegation configured; prefixes are delegated onto LAN interfaces, not the WAN.",
                    c.name
                ),
                &format!("On the Interfaces page edit {}: remove its prefix delegation settings and configure them on the LAN interface.", c.name),
            ));
        }
        if let Some(uplink) = c
            .dhcp_prefix_delegation
            .as_ref()
            .and_then(|pd| pd.uplink_interface.as_deref())
            && let Some(up) = enabled_by_name.get(uplink)
        {
            if up.role != InterfaceRole::WAN {
                out.push(warn(
                    format!("consistency_pd_uplink_not_wan_{}", c.name),
                    "Prefix delegation uplink is not a WAN",
                    format!(
                        "{} takes its delegated prefix from {uplink}, which does not have the WAN role.",
                        c.name
                    ),
                    &format!("On the Interfaces page edit {}: choose the WAN interface as the PD uplink.", c.name),
                ));
            } else if !up
                .dhcpv6_client
                .as_ref()
                .map(|d| d.use_delegated_prefix)
                .unwrap_or(true)
            {
                out.push(warn(
                    format!("consistency_pd_uplink_unused_{}", c.name),
                    "Uplink ignores delegated prefix",
                    format!(
                        "{} takes its prefix from {uplink}, but {uplink} has 'use delegated prefix' turned off, so no prefix will arrive.",
                        c.name
                    ),
                    &format!("On the Interfaces page edit {uplink}: enable DHCPv6 'use delegated prefix'."),
                ));
            }
        }
        if c.ipv6_send_ra && dnsmasq_ra_ifaces.contains(c.name.as_str()) {
            out.push(warn(
                format!("consistency_double_ra_{}", c.name),
                "Two router advertisement senders",
                format!(
                    "{} sends router advertisements from both networkd and dnsmasq, which will fight over prefix and flags.",
                    c.name
                ),
                &format!("Turn off 'Send router advertisements' on the {} interface, or remove the IPv6 mode from its DHCP range on the DHCP page.", c.name),
            ));
        }
    }
}

fn check_dnsmasq(
    s: &Snapshot,
    enabled_by_name: &HashMap<&str, &InterfaceConfig>,
    out: &mut Vec<SystemCheck>,
) {
    let d = &s.dnsmasq;
    if !d.config.enabled {
        return;
    }
    let ranges: Vec<_> = d.dhcp_ranges.iter().filter(|r| r.enabled).collect();

    for iface in &d.config.listen_interfaces {
        if enabled_by_name
            .get(iface.as_str())
            .is_some_and(|c| c.role == InterfaceRole::WAN)
        {
            out.push(warn(
                format!("consistency_dnsmasq_listens_wan_{iface}"),
                "DNS/DHCP listening on WAN",
                format!("dnsmasq is configured to listen on WAN interface {iface}, exposing DNS/DHCP to the upstream network."),
                "On the DNS/DHCP page remove the WAN interface from 'Listen interfaces'.",
            ));
        }
    }
    if d.config.listen_interfaces.is_empty() && ranges.is_empty() && d.config.dns_port != 0 {
        out.push(warn(
            "consistency_dnsmasq_listens_everywhere".into(),
            "DNS listening on all interfaces",
            "dnsmasq has no listen interfaces and no DHCP ranges, so it answers DNS on every interface including the WAN.".into(),
            "On the DNS/DHCP page set 'Listen interfaces' to your LAN interfaces.",
        ));
    }
    if d.config.dns_port == 0 && ranges.is_empty() {
        out.push(warn(
            "consistency_dnsmasq_idle".into(),
            "dnsmasq does nothing",
            "dnsmasq is enabled but DNS is off (port 0) and there are no enabled DHCP ranges."
                .into(),
            "On the DNS/DHCP page add a DHCP range or set a DNS port, or disable dnsmasq.",
        ));
    }
    match d.config.upstream_mode {
        DnsmasqUpstreamMode::System => {
            let loopback = |ip: &IpAddr| {
                *ip == IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                    || *ip == IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
            };
            if !s.resolv_nameservers.is_empty() && s.resolv_nameservers.iter().all(loopback) {
                out.push(warn(
                    "consistency_dnsmasq_loop".into(),
                    "DNS forwarding loop",
                    "dnsmasq uses the system resolver, but /etc/resolv.conf only lists 127.0.0.1/::1, which is dnsmasq itself. Queries will loop.".into(),
                    "On the DNS/DHCP page set the upstream mode to Custom with explicit upstream servers.",
                ));
            }
        }
        DnsmasqUpstreamMode::LocalAdGuard => out.push(warn(
            "consistency_dnsmasq_adguard".into(),
            "AdGuard upstream on port 5353",
            "The local AdGuard upstream uses port 5353, which is normally mDNS. Verify that AdGuard Home really listens on 127.0.0.1:5353.".into(),
            "Check AdGuard Home's DNS listen port, or use Custom upstream servers on the DNS/DHCP page.",
        )),
        DnsmasqUpstreamMode::Custom | DnsmasqUpstreamMode::Blocky => {}
    }
    for r in &ranges {
        match enabled_by_name.get(r.interface.as_str()) {
            Some(c) if static_ipv4(c).is_empty() => out.push(warn(
                format!("consistency_range_no_ip_{}", r.name),
                "DHCP range on interface without IPv4",
                format!(
                    "DHCP range '{}' is on {}, which has no static IPv4 address, so dnsmasq cannot serve it.",
                    r.name, r.interface
                ),
                &format!("Give {} a static IPv4 address on the Interfaces page.", r.interface),
            )),
            _ => {}
        }
    }

    let known_tags: HashSet<&str> = ranges
        .iter()
        .map(|r| r.interface.as_str())
        .chain(
            d.static_leases
                .iter()
                .filter(|l| l.enabled)
                .flat_map(|l| l.set_tags.iter().map(String::as_str)),
        )
        .collect();
    for opt in d.dhcp_options.iter().filter(|o| o.enabled) {
        for tag in &opt.match_tags {
            if !known_tags.contains(tag.as_str()) {
                out.push(warn(
                    format!("consistency_option_tag_{}_{}", opt.option, tag),
                    "DHCP option tag matches nothing",
                    format!(
                        "DHCP option '{}' only applies to tag '{tag}', but no enabled range uses an interface of that name and no static lease sets that tag, so it is never sent.",
                        opt.option
                    ),
                    "On the DNS/DHCP page edit the option and use an interface name or a tag set by a static lease.",
                ));
            }
        }
    }
}

fn check_virtual_devices(
    s: &Snapshot,
    enabled_by_name: &HashMap<&str, &InterfaceConfig>,
    out: &mut Vec<SystemCheck>,
) {
    for v in &s.vlans {
        if !enabled_by_name.contains_key(v.name.as_str()) {
            out.push(warn(
                format!("consistency_vlan_no_config_{}", v.name),
                "VLAN without interface configuration",
                format!(
                    "VLAN {} has no enabled interface configuration, so it has no IP address. That is only correct for a pure layer-2 device.",
                    v.name
                ),
                &format!("On the Interfaces page add an enabled configuration for {} (role, address, zone), or delete the VLAN.", v.name),
            ));
        }
    }
    for b in &s.bridges {
        if !enabled_by_name.contains_key(b.name.as_str()) {
            out.push(warn(
                format!("consistency_bridge_no_config_{}", b.name),
                "Bridge without interface configuration",
                format!(
                    "Bridge {} has no enabled interface configuration, so the router has no IP address on it. That is only correct for a pure layer-2 bridge.",
                    b.name
                ),
                &format!("On the Interfaces page add an enabled configuration for {} (role, address, zone), or delete the bridge.", b.name),
            ));
        }
    }
}

fn check_dangling(
    s: &Snapshot,
    enabled_by_name: &HashMap<&str, &InterfaceConfig>,
    out: &mut Vec<SystemCheck>,
) {
    let known = |name: &str| {
        enabled_by_name.contains_key(name)
            || s.vlans.iter().any(|v| v.name == name)
            || s.bridges.iter().any(|b| b.name == name)
    };
    for zone in &s.firewall.zones {
        for iface in zone.interfaces.iter().filter(|i| !known(i)) {
            out.push(warn(
                format!("consistency_dangling_zone_{}_{}", zone.name, iface),
                "Firewall zone references unknown interface",
                format!("Firewall zone '{}' lists interface {iface}, which is not an enabled interface, VLAN or bridge.", zone.name),
                &format!("On the Firewall page remove {iface} from zone '{}' or fix the name.", zone.name),
            ));
        }
    }
    if s.dnsmasq.config.enabled {
        for r in s.dnsmasq.dhcp_ranges.iter().filter(|r| r.enabled) {
            if !enabled_by_name.contains_key(r.interface.as_str()) {
                out.push(warn(
                    format!("consistency_dangling_range_{}", r.name),
                    "DHCP range on unknown interface",
                    format!(
                        "DHCP range '{}' is on {}, which has no enabled interface configuration.",
                        r.name, r.interface
                    ),
                    &format!("On the DNS/DHCP page change or delete range '{}'.", r.name),
                ));
            }
        }
    }
    if s.caddy.enabled
        && !s.caddy.bind_interface.is_empty()
        && !enabled_by_name.contains_key(s.caddy.bind_interface.as_str())
    {
        out.push(warn(
            "consistency_dangling_caddy".into(),
            "Caddy binds to unknown interface",
            format!(
                "Caddy is set to bind to {}, which has no enabled interface configuration.",
                s.caddy.bind_interface
            ),
            "On the Caddy page choose an existing LAN interface as the bind interface.",
        ));
    }
    for c in enabled_by_name.values() {
        if let Some(up) = c
            .dhcp_prefix_delegation
            .as_ref()
            .and_then(|pd| pd.uplink_interface.as_deref())
            && !enabled_by_name.contains_key(up)
        {
            out.push(warn(
                format!("consistency_dangling_pd_{}", c.name),
                "Prefix delegation uplink missing",
                format!("{} takes its delegated prefix from {up}, which has no enabled interface configuration.", c.name),
                &format!("On the Interfaces page edit {}: choose an existing WAN interface as the PD uplink.", c.name),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keystone_core::{
        DhcpPrefixDelegationConfig, Dhcpv6ClientConfig, DnsmasqConfig, DnsmasqDhcpOption,
        DnsmasqDhcpRange, DnsmasqIpv6Mode, DnsmasqStaticLease, FirewallZone, StaticAddress,
    };

    fn cfg(name: &str, role: InterfaceRole, addrs: &[&str]) -> InterfaceConfig {
        InterfaceConfig {
            name: name.into(),
            role,
            ip_forward: IpForwardMode::Ipv4,
            addresses: addrs
                .iter()
                .map(|a| StaticAddress {
                    address: a.to_string(),
                    label: None,
                    scope: Default::default(),
                })
                .collect(),
            ..Default::default()
        }
    }

    fn zone(name: &str, wan: bool, masq: bool, ifaces: &[&str]) -> FirewallZone {
        FirewallZone {
            name: name.into(),
            is_wan: wan,
            masquerade_ipv4: masq,
            interfaces: ifaces.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    fn range(name: &str, iface: &str) -> DnsmasqDhcpRange {
        DnsmasqDhcpRange {
            name: name.into(),
            interface: iface.into(),
            start_address: "192.168.1.100".into(),
            end_address: "192.168.1.200".into(),
            ..Default::default()
        }
    }

    /// A healthy router: eth0 WAN (DHCP), eth1 LAN with DHCP.
    fn healthy() -> Snapshot {
        let mut wan = cfg("eth0", InterfaceRole::WAN, &[]);
        wan.dhcp_mode = DhcpMode::Ipv4;
        let mut s = Snapshot {
            configs: vec![wan, cfg("eth1", InterfaceRole::LAN, &["192.168.1.1/24"])],
            ..Default::default()
        };
        s.firewall.zones = vec![
            zone("wan", true, true, &["eth0"]),
            zone("lan", false, false, &["eth1"]),
        ];
        s.dnsmasq.config = DnsmasqConfig {
            upstream_mode: DnsmasqUpstreamMode::Custom,
            ..Default::default()
        };
        s.dnsmasq.dhcp_ranges = vec![range("lan", "eth1")];
        s.system_interfaces = ["eth0", "eth1", "lo"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        s.live_addresses
            .insert("eth0".into(), vec!["203.0.113.5/24".parse().unwrap()]);
        s.resolv_nameservers = vec!["1.1.1.1".parse().unwrap()];
        s
    }

    fn ids(s: &Snapshot) -> Vec<String> {
        analyze(s).into_iter().map(|c| c.id).collect()
    }

    fn has(s: &Snapshot, prefix: &str) -> bool {
        ids(s).iter().any(|i| i.starts_with(prefix))
    }

    #[test]
    fn healthy_config_has_no_findings() {
        assert_eq!(ids(&healthy()), Vec::<String>::new());
    }

    #[test]
    fn every_finding_has_fix_advice_and_unique_id() {
        let mut s = healthy();
        s.live_addresses
            .insert("eth0".into(), vec!["192.168.1.2/24".parse().unwrap()]);
        s.configs[1].gateway = Some("10.9.9.9".into());
        let checks = analyze(&s);
        assert!(checks.len() >= 2);
        let unique: HashSet<_> = checks.iter().map(|c| &c.id).collect();
        assert_eq!(unique.len(), checks.len());
        assert!(checks.iter().all(|c| c.fix_advice.is_some()));
        assert!(checks.iter().all(|c| c.severity != CheckSeverity::Pass));
    }

    #[test]
    fn wan_lan_overlap_is_error() {
        let mut s = healthy();
        s.live_addresses
            .insert("eth0".into(), vec!["192.168.1.2/24".parse().unwrap()]);
        let checks = analyze(&s);
        let c = checks
            .iter()
            .find(|c| c.id.starts_with("consistency_wan_lan_overlap"))
            .unwrap();
        assert_eq!(c.severity, CheckSeverity::Error);
        assert!(c.fix_advice.as_ref().unwrap().contains("192.168.50.1/24"));
        // link-local on the WAN is ignored
        let mut s = healthy();
        s.live_addresses
            .insert("eth0".into(), vec!["169.254.1.1/16".parse().unwrap()]);
        assert!(!has(&s, "consistency_wan_lan_overlap"));
    }

    #[test]
    fn lan_overlap_and_duplicates() {
        let mut s = healthy();
        s.configs
            .push(cfg("eth2", InterfaceRole::LAN, &["192.168.1.0/25"]));
        assert!(has(&s, "consistency_lan_overlap"));
        s.configs[2].addresses[0].address = "192.168.1.1/24".into();
        assert!(has(&s, "consistency_duplicate_address"));
        s.configs[2].addresses[0].address = "192.168.2.1/24".into();
        s.firewall.zones[1].interfaces.push("eth2".into());
        s.system_interfaces.insert("eth2".into());
        assert_eq!(ids(&s), Vec::<String>::new());
    }

    #[test]
    fn missing_nic() {
        let mut s = healthy();
        s.system_interfaces.remove("eth1");
        assert!(has(&s, "consistency_missing_nic_eth1"));
        // virtual devices are created by networkd, so they are fine
        s.bridges.push(BridgeConfig {
            name: "eth1".into(),
            ..Default::default()
        });
        assert!(!has(&s, "consistency_missing_nic"));
        // a disabled config is not flagged
        let mut s = healthy();
        s.system_interfaces.remove("eth1");
        s.configs[1].enabled = false;
        assert!(!has(&s, "consistency_missing_nic"));
    }

    #[test]
    fn gateway_checks() {
        let mut s = healthy();
        s.configs[1].gateway = Some("10.0.0.1".into());
        assert!(has(&s, "consistency_gateway_unreachable_eth1"));
        s.configs[1].gateway = Some("192.168.1.254".into());
        assert!(!has(&s, "consistency_gateway"));
        s.configs[1].gateway = Some("fe80::1".into());
        assert!(!has(&s, "consistency_gateway"));
        s.configs[0].gateway = Some("203.0.113.1".into());
        assert!(has(&s, "consistency_gateway_with_dhcp_eth0"));
    }

    #[test]
    fn firewall_checks() {
        let mut s = healthy();
        s.configs
            .push(cfg("eth2", InterfaceRole::LAN, &["10.0.0.1/24"]));
        assert!(has(&s, "consistency_no_zone_eth2"));

        let mut s = healthy();
        s.firewall.zones[0].interfaces = vec![];
        s.firewall.zones[1].interfaces = vec!["eth1".into(), "eth0".into()];
        assert!(has(&s, "consistency_role_zone_eth0_lan"));
        s.firewall.zones[1].is_wan = true;
        assert!(has(&s, "consistency_role_zone_eth1_lan"));

        let mut s = healthy();
        s.firewall.zones[1].masquerade_ipv4 = true;
        assert!(has(&s, "consistency_masq_non_wan_lan"));

        let mut s = healthy();
        s.firewall.zones[0].masquerade_ipv4 = false;
        assert!(has(&s, "consistency_no_masquerade"));

        let mut s = healthy();
        for c in &mut s.configs {
            c.ip_forward = IpForwardMode::Ipv6;
        }
        assert!(has(&s, "consistency_no_ipv4_forwarding"));
        // no firewall policy at all: nothing to say
        s.firewall = FirewallConfig::default();
        assert!(!has(&s, "consistency_no_ipv4_forwarding"));
        assert!(!has(&s, "consistency_no_zone"));
    }

    #[test]
    fn dangling_zone_interface() {
        let mut s = healthy();
        s.firewall.zones[1].interfaces.push("ghost".into());
        assert!(has(&s, "consistency_dangling_zone_lan_ghost"));
        s.vlans.push(VlanConfig {
            name: "ghost".into(),
            ..Default::default()
        });
        assert!(!has(&s, "consistency_dangling_zone"));
    }

    #[test]
    fn ipv6_checks() {
        let mut s = healthy();
        s.configs[0].dhcp_mode = DhcpMode::Ipv6;
        s.configs[0].ipv6_accept_ra = false;
        assert!(has(&s, "consistency_dhcpv6_no_ra_eth0"));
        s.configs[0].dhcpv6_client = Some(Dhcpv6ClientConfig {
            without_ra: "solicit".into(),
            ..Default::default()
        });
        assert!(!has(&s, "consistency_dhcpv6_no_ra"));

        let mut s = healthy();
        s.configs[0].ipv6_send_ra = true;
        s.configs[0].dhcp_prefix_delegation = Some(DhcpPrefixDelegationConfig::default());
        assert!(has(&s, "consistency_wan_send_ra_eth0"));
        assert!(has(&s, "consistency_wan_pd_eth0"));

        let mut s = healthy();
        s.configs[1].dhcp_prefix_delegation = Some(DhcpPrefixDelegationConfig {
            uplink_interface: Some("eth0".into()),
            ..Default::default()
        });
        assert!(!has(&s, "consistency_pd"));
        s.configs[0].dhcpv6_client = Some(Dhcpv6ClientConfig {
            use_delegated_prefix: false,
            ..Default::default()
        });
        assert!(has(&s, "consistency_pd_uplink_unused_eth1"));
        s.configs[1]
            .dhcp_prefix_delegation
            .as_mut()
            .unwrap()
            .uplink_interface = Some("eth1".into());
        assert!(has(&s, "consistency_pd_uplink_not_wan_eth1"));
        s.configs[1]
            .dhcp_prefix_delegation
            .as_mut()
            .unwrap()
            .uplink_interface = Some("nope".into());
        assert!(has(&s, "consistency_dangling_pd_eth1"));

        let mut s = healthy();
        s.configs[1].ipv6_send_ra = true;
        s.dnsmasq.dhcp_ranges[0].ipv6_mode = Some(DnsmasqIpv6Mode::Slaac);
        assert!(has(&s, "consistency_double_ra_eth1"));
        s.dnsmasq.config.enabled = false;
        assert!(!has(&s, "consistency_double_ra"));
    }

    #[test]
    fn dnsmasq_checks() {
        let mut s = healthy();
        s.dnsmasq.config.listen_interfaces = vec!["eth0".into()];
        assert!(has(&s, "consistency_dnsmasq_listens_wan_eth0"));

        let mut s = healthy();
        s.dnsmasq.dhcp_ranges.clear();
        assert!(has(&s, "consistency_dnsmasq_listens_everywhere"));
        s.dnsmasq.config.dns_port = 0;
        assert!(has(&s, "consistency_dnsmasq_idle"));
        assert!(!has(&s, "consistency_dnsmasq_listens_everywhere"));

        let mut s = healthy();
        s.dnsmasq.config.upstream_mode = DnsmasqUpstreamMode::System;
        s.resolv_nameservers = vec!["127.0.0.1".parse().unwrap()];
        assert!(has(&s, "consistency_dnsmasq_loop"));
        s.resolv_nameservers.push("9.9.9.9".parse().unwrap());
        assert!(!has(&s, "consistency_dnsmasq_loop"));

        let mut s = healthy();
        s.dnsmasq.config.upstream_mode = DnsmasqUpstreamMode::LocalAdGuard;
        assert!(has(&s, "consistency_dnsmasq_adguard"));

        let mut s = healthy();
        s.configs[1].addresses.clear();
        assert!(has(&s, "consistency_range_no_ip_lan"));
        s.configs[1].enabled = false;
        assert!(has(&s, "consistency_dangling_range_lan"));

        let mut s = healthy();
        s.dnsmasq.dhcp_options = vec![DnsmasqDhcpOption {
            option: "router".into(),
            value: "1.2.3.4".into(),
            match_tags: vec!["eth1".into(), "voip".into()],
            enabled: true,
            ..Default::default()
        }];
        assert!(has(&s, "consistency_option_tag_router_voip"));
        assert!(!has(&s, "consistency_option_tag_router_eth1"));
        s.dnsmasq.static_leases = vec![DnsmasqStaticLease {
            set_tags: vec!["voip".into()],
            ..Default::default()
        }];
        assert!(!has(&s, "consistency_option_tag"));

        // disabled dnsmasq: no dnsmasq findings
        let mut s = healthy();
        s.dnsmasq.config.enabled = false;
        s.dnsmasq.config.listen_interfaces = vec!["eth0".into()];
        assert!(ids(&s).is_empty());
    }

    #[test]
    fn vlan_and_bridge_without_config() {
        let mut s = healthy();
        s.vlans.push(VlanConfig {
            name: "eth1.10".into(),
            ..Default::default()
        });
        s.bridges.push(BridgeConfig {
            name: "br0".into(),
            members: vec!["eth2".into()],
            ..Default::default()
        });
        assert!(has(&s, "consistency_vlan_no_config_eth1.10"));
        assert!(has(&s, "consistency_bridge_no_config_br0"));
    }

    #[test]
    fn caddy_bind_dangling() {
        let mut s = healthy();
        s.caddy.enabled = true;
        s.caddy.bind_interface = "br-lan".into();
        assert!(has(&s, "consistency_dangling_caddy"));
        s.caddy.bind_interface = "eth1".into();
        assert!(!has(&s, "consistency_dangling_caddy"));
        s.caddy.enabled = false;
        s.caddy.bind_interface = "gone".into();
        assert!(!has(&s, "consistency_dangling_caddy"));
    }

    #[test]
    fn parsers() {
        let json = br#"[{"ifname":"eth0","addr_info":[{"family":"inet","local":"10.0.0.2","prefixlen":24},{"family":"inet6","local":"fe80::1","prefixlen":64}]},{"ifname":"lo","addr_info":[]}]"#;
        let map = parse_ip_addr_json(json);
        assert_eq!(map["eth0"].len(), 2);
        assert!(map["lo"].is_empty());
        assert!(parse_ip_addr_json(b"garbage").is_empty());
        let ns = parse_resolv_nameservers(
            "# c\nnameserver 127.0.0.1\nnameserver fe80::1%eth0\nsearch lan\n",
        );
        assert_eq!(ns.len(), 2);
    }
}
