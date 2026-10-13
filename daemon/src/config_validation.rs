//! Hard validation of configurations that make no sense. These checks run when
//! a setting is saved and again before the corresponding apply, so rows that
//! predate the checks can never reach the system. Softer findings are reported
//! by `consistency` on the status page instead.

use ipnet::{IpNet, Ipv4Net};
use keystone_core::{
    BridgeConfig, CaddyConfig, DhcpMode, DnsmasqAddressAction, DnsmasqAddressOverride,
    DnsmasqCnameRecord, DnsmasqConfig, DnsmasqDhcpOption, DnsmasqDhcpRange, DnsmasqHostRecord,
    DnsmasqStaticLease, FirewallZone, InterfaceConfig, InterfaceRole, VlanConfig,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Static IPv4 networks (with host address) configured on an interface.
pub fn static_ipv4(config: &InterfaceConfig) -> Vec<Ipv4Net> {
    config
        .addresses
        .iter()
        .filter_map(|a| match a.address.parse::<IpNet>() {
            Ok(IpNet::V4(net)) => Some(net),
            _ => None,
        })
        .collect()
}

/// Validate the addresses, routes, DNS servers, MTU and PD uplink of a single
/// interface configuration. Returns human-readable errors.
pub fn validate_interface_config(config: &InterfaceConfig) -> Vec<String> {
    let mut errors = Vec::new();
    let name = &config.name;
    let mut has_ipv6 = matches!(config.dhcp_mode, DhcpMode::Yes | DhcpMode::Ipv6);

    for addr in &config.addresses {
        match addr.address.parse::<IpNet>() {
            Err(_) => errors.push(format!(
                "{name}: address '{}' is not a valid CIDR address (e.g. 192.168.1.1/24)",
                addr.address
            )),
            Ok(IpNet::V4(net)) => {
                if net.prefix_len() < 31 {
                    if net.addr() == net.network() {
                        errors.push(format!(
                            "{name}: {} is the network address of {}, not a usable host address",
                            net.addr(),
                            net.trunc()
                        ));
                    } else if net.addr() == net.broadcast() {
                        errors.push(format!(
                            "{name}: {} is the broadcast address of {}, not a usable host address",
                            net.addr(),
                            net.trunc()
                        ));
                    }
                }
            }
            Ok(IpNet::V6(_)) => has_ipv6 = true,
        }
    }

    if let Some(gateway) = &config.gateway
        && gateway.parse::<IpAddr>().is_err()
    {
        errors.push(format!(
            "{name}: gateway '{gateway}' is not a valid IP address"
        ));
    }
    for route in &config.routes {
        if route.gateway.parse::<IpAddr>().is_err() {
            errors.push(format!(
                "{name}: route gateway '{}' is not a valid IP address",
                route.gateway
            ));
        }
        if let Some(dest) = &route.destination
            && dest.parse::<IpNet>().is_err()
        {
            errors.push(format!(
                "{name}: route destination '{dest}' is not a valid network (e.g. 10.0.0.0/8)"
            ));
        }
    }
    for dns in &config.dns_servers {
        if dns.parse::<IpAddr>().is_err() {
            errors.push(format!(
                "{name}: DNS server '{dns}' is not a valid IP address"
            ));
        }
    }

    if let Some(mtu) = config.mtu {
        if !(68..=65535).contains(&mtu) {
            errors.push(format!(
                "{name}: MTU {mtu} is outside the valid range 68-65535"
            ));
        } else if mtu < 1280 && (has_ipv6 || config.ipv6_accept_ra) {
            errors.push(format!(
                "{name}: MTU {mtu} is below 1280, the minimum for IPv6; raise the MTU or disable IPv6 (addresses, DHCPv6 and router advertisements) on this interface"
            ));
        }
    }

    if let Some(pd) = &config.dhcp_prefix_delegation
        && pd.uplink_interface.as_deref() == Some(name.as_str())
    {
        errors.push(format!(
            "{name}: the prefix delegation uplink cannot be the interface itself"
        ));
    }
    errors
}

/// Validate every enabled interface configuration (used before apply).
pub fn validate_interface_configs(configs: &[InterfaceConfig]) -> Vec<String> {
    configs
        .iter()
        .filter(|c| c.enabled)
        .flat_map(validate_interface_config)
        .collect()
}

/// Validate a DHCP range against the interface configurations.
pub fn validate_dhcp_range(range: &DnsmasqDhcpRange, configs: &[InterfaceConfig]) -> Vec<String> {
    let mut errors = Vec::new();
    if range.name.is_empty() {
        errors.push("Range name is required".to_owned());
    }
    if range.interface.is_empty() {
        errors.push("Interface is required".to_owned());
    }
    if range.start_address.is_empty() || range.end_address.is_empty() {
        errors.push("Start and end addresses are required".to_owned());
        return errors;
    }
    let name = &range.name;
    let start = range.start_address.parse::<IpAddr>();
    let end = range.end_address.parse::<IpAddr>();
    let (start, end) = match (start, end) {
        (Ok(s), Ok(e)) => (s, e),
        (s, e) => {
            if s.is_err() {
                errors.push(format!(
                    "DHCP range '{name}': start address '{}' is not a valid IP address",
                    range.start_address
                ));
            }
            if e.is_err() {
                errors.push(format!(
                    "DHCP range '{name}': end address '{}' is not a valid IP address",
                    range.end_address
                ));
            }
            return errors;
        }
    };
    if start.is_ipv4() != end.is_ipv4() {
        errors.push(format!(
            "DHCP range '{name}': start and end must be the same address family"
        ));
        return errors;
    }
    if start > end {
        errors.push(format!(
            "DHCP range '{name}': start address {start} is after end address {end}"
        ));
        return errors;
    }

    let Some(iface) = configs
        .iter()
        .find(|c| c.enabled && c.name == range.interface)
    else {
        return errors;
    };
    if iface.role == InterfaceRole::WAN {
        errors.push(format!(
            "DHCP range '{name}': {} has the WAN role; a DHCP server must not run on the WAN side",
            range.interface
        ));
    }
    if let (IpAddr::V4(s), IpAddr::V4(e)) = (start, end) {
        let nets = static_ipv4(iface);
        if !nets.is_empty() {
            if !nets.iter().any(|n| n.contains(&s) && n.contains(&e)) {
                let subnets: Vec<_> = nets.iter().map(|n| n.trunc().to_string()).collect();
                errors.push(format!(
                    "DHCP range '{name}': {s} - {e} is not inside the subnet of {} ({})",
                    range.interface,
                    subnets.join(", ")
                ));
            }
            for n in &nets {
                if n.addr() >= s && n.addr() <= e {
                    errors.push(format!(
                        "DHCP range '{name}': the range contains the router's own address {} on {}",
                        n.addr(),
                        range.interface
                    ));
                }
            }
        }
    }
    errors
}

/// A DNS name as dnsmasq takes it in host records, CNAMEs and overrides:
/// dot-separated labels of letters, digits, hyphens and underscores, with no
/// label starting or ending in a hyphen. One trailing dot is allowed.
pub fn valid_dns_name(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// A MAC address as written in a dhcp-host line: six colon-separated octets,
/// each two hex digits or `*` as a wildcard.
pub fn valid_mac_pattern(mac: &str) -> bool {
    let octets: Vec<&str> = mac.split(':').collect();
    octets.len() == 6
        && octets.iter().all(|octet| {
            *octet == "*" || (octet.len() == 2 && octet.bytes().all(|b| b.is_ascii_hexdigit()))
        })
}

/// Validate the global dnsmasq settings that are written as directives: the
/// local domain, and each upstream server's address, port and domain.
pub fn validate_dnsmasq_config(config: &DnsmasqConfig) -> Vec<String> {
    let mut errors = Vec::new();
    if let Some(domain) = &config.local_domain
        && !valid_dns_name(domain)
    {
        errors.push(format!(
            "Local domain {domain:?} is not a valid domain name"
        ));
    }
    for server in &config.upstream_servers {
        if server.address.parse::<IpAddr>().is_err() && !valid_dns_name(&server.address) {
            errors.push(format!(
                "Upstream server {:?} is not an IP address or hostname",
                server.address
            ));
        }
        if server.port == Some(0) {
            errors.push(format!("Upstream server {:?} uses port 0", server.address));
        }
        if let Some(domain) = &server.domain
            && !valid_dns_name(domain)
        {
            errors.push(format!(
                "Upstream server {:?} is limited to {domain:?}, which is not a valid domain name",
                server.address
            ));
        }
    }
    errors
}

/// Validate a DNS host record: at least one name and address, and their syntax.
pub fn validate_host_record(record: &DnsmasqHostRecord) -> Vec<String> {
    let mut errors = Vec::new();
    if record.hostnames.is_empty() {
        errors.push("At least one hostname is required".to_owned());
    }
    if record.ipv4_address.is_none() && record.ipv6_address.is_none() {
        errors.push("At least one IP address (IPv4 or IPv6) is required".to_owned());
    }
    for name in &record.hostnames {
        if !valid_dns_name(name) {
            errors.push(format!("Host record: {name:?} is not a valid hostname"));
        }
    }
    if let Some(ipv4) = &record.ipv4_address
        && ipv4.parse::<Ipv4Addr>().is_err()
    {
        errors.push(format!("Host record: {ipv4:?} is not a valid IPv4 address"));
    }
    if let Some(ipv6) = &record.ipv6_address
        && ipv6.parse::<Ipv6Addr>().is_err()
    {
        errors.push(format!("Host record: {ipv6:?} is not a valid IPv6 address"));
    }
    errors
}

/// Validate the alias and target of a CNAME record.
pub fn validate_cname_record(record: &DnsmasqCnameRecord) -> Vec<String> {
    let mut errors = Vec::new();
    for (role, label, name) in [
        ("alias", "Alias", &record.alias),
        ("target", "Target", &record.target),
    ] {
        if name.is_empty() {
            errors.push(format!("{label} is required"));
        } else if !valid_dns_name(name) {
            errors.push(format!(
                "CNAME record: {role} {name:?} is not a valid hostname"
            ));
        }
    }
    errors
}

/// Validate a custom DHCP option: both the option and its value are required.
pub fn validate_dhcp_option(option: &DnsmasqDhcpOption) -> Vec<String> {
    let mut errors = Vec::new();
    if option.option.is_empty() {
        errors.push("Option name/number is required".to_owned());
    }
    if option.value.is_empty() {
        errors.push("Option value is required".to_owned());
    }
    errors
}

/// Validate an address override's domain pattern and, for redirects, its address.
pub fn validate_address_override(entry: &DnsmasqAddressOverride) -> Vec<String> {
    let mut errors = Vec::new();
    if entry.domain.is_empty() {
        errors.push("Domain is required".to_owned());
        return errors;
    }
    let domain = entry.domain.strip_prefix("*.").unwrap_or(&entry.domain);
    if !valid_dns_name(domain) {
        errors.push(format!(
            "Address override: {:?} is not a valid domain (wildcards are written as *.example.com)",
            entry.domain
        ));
    }
    if entry.action == DnsmasqAddressAction::Redirect
        && entry
            .redirect_address
            .as_deref()
            .is_none_or(|addr| addr.parse::<IpAddr>().is_err())
    {
        errors.push(format!(
            "Address override: redirect target {:?} is not a valid IP address",
            entry.redirect_address.as_deref().unwrap_or_default()
        ));
    }
    errors
}

/// Validate a static lease against existing leases and router addresses.
pub fn validate_static_lease(
    lease: &DnsmasqStaticLease,
    existing: &[DnsmasqStaticLease],
    configs: &[InterfaceConfig],
) -> Vec<String> {
    let mut errors = Vec::new();
    if lease.mac_address.is_empty() && lease.client_id.is_none() {
        errors.push("MAC address or client ID is required".to_owned());
    }
    if lease.ip_address.is_empty() {
        errors.push("IP address is required".to_owned());
        return errors;
    }
    // dhcp-host joins the MAC with commas, so a malformed value would inject fields.
    if !lease.mac_address.is_empty() && !valid_mac_pattern(&lease.mac_address) {
        errors.push(format!(
            "Static lease: {:?} is not a valid MAC address (expected six colon-separated octets such as 00:11:22:33:44:55)",
            lease.mac_address
        ));
    }
    let ip = match lease.ip_address.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            errors.push(format!(
                "Static lease: '{}' is not a valid IP address",
                lease.ip_address
            ));
            return errors;
        }
    };
    if !lease.enabled {
        return errors;
    }
    for other in existing {
        if !other.enabled || (lease.id.is_some() && other.id == lease.id) {
            continue;
        }
        if !lease.mac_address.is_empty()
            && other.mac_address.eq_ignore_ascii_case(&lease.mac_address)
        {
            errors.push(format!(
                "Static lease: MAC address {} already has a lease ({})",
                lease.mac_address, other.ip_address
            ));
        }
        if other.ip_address.parse::<IpAddr>().ok() == Some(ip) {
            errors.push(format!(
                "Static lease: IP address {ip} is already reserved for {}",
                if other.mac_address.is_empty() {
                    "another client"
                } else {
                    other.mac_address.as_str()
                }
            ));
        }
    }
    for config in configs.iter().filter(|c| c.enabled) {
        for addr in config
            .addresses
            .iter()
            .filter_map(|a| a.address.parse::<IpNet>().ok())
        {
            if addr.addr() == ip {
                errors.push(format!(
                    "Static lease: {ip} is the router's own address on {}",
                    config.name
                ));
            }
        }
    }
    errors
}

/// Re-check all persisted DHCP ranges and leases before applying dnsmasq.
pub fn validate_dhcp_state(
    ranges: &[DnsmasqDhcpRange],
    leases: &[DnsmasqStaticLease],
    configs: &[InterfaceConfig],
) -> Vec<String> {
    let mut errors = Vec::new();
    for range in ranges.iter().filter(|r| r.enabled) {
        errors.extend(validate_dhcp_range(range, configs));
    }
    for (i, lease) in leases.iter().enumerate() {
        errors.extend(validate_static_lease(lease, &leases[i + 1..], configs));
    }
    errors
}

/// Names of other zones that already contain any interface of `zone`.
pub fn zone_interface_conflicts(zone: &FirewallZone, all: &[FirewallZone]) -> Vec<String> {
    let mut errors = Vec::new();
    for iface in &zone.interfaces {
        for other in all {
            let same = (zone.id.is_some() && other.id == zone.id) || other.name == zone.name;
            if !same && other.interfaces.contains(iface) {
                errors.push(format!(
                    "Interface {iface} already belongs to zone '{}'; an interface can be in only one zone",
                    other.name
                ));
            }
        }
    }
    errors
}

/// Everything that references an interface name, so deletion can be refused.
#[allow(clippy::too_many_arguments)]
pub fn interface_references(
    name: &str,
    configs: &[InterfaceConfig],
    zones: &[FirewallZone],
    ranges: &[DnsmasqDhcpRange],
    caddy: &CaddyConfig,
    vlans: &[VlanConfig],
    bridges: &[BridgeConfig],
) -> Vec<String> {
    let mut refs = Vec::new();
    for zone in zones
        .iter()
        .filter(|z| z.interfaces.iter().any(|i| i == name))
    {
        refs.push(format!("firewall zone '{}'", zone.name));
    }
    for range in ranges.iter().filter(|r| r.interface == name) {
        refs.push(format!("DHCP range '{}'", range.name));
    }
    if caddy.bind_interface == name {
        refs.push("Caddy bind interface".to_string());
    }
    for config in configs.iter().filter(|c| c.name != name) {
        if config
            .dhcp_prefix_delegation
            .as_ref()
            .and_then(|pd| pd.uplink_interface.as_deref())
            == Some(name)
        {
            refs.push(format!("prefix delegation uplink of {}", config.name));
        }
    }
    for bridge in bridges
        .iter()
        .filter(|b| b.members.iter().any(|m| m == name))
    {
        refs.push(format!("member of bridge {}", bridge.name));
    }
    for vlan in vlans.iter().filter(|v| v.parent_interface == name) {
        refs.push(format!("parent of VLAN {}", vlan.name));
    }
    refs
}

#[cfg(test)]
mod tests {
    use super::*;
    use keystone_core::{
        DhcpPrefixDelegationConfig, DnsmasqUpstreamServer, StaticAddress, StaticRoute,
    };

    fn addr(a: &str) -> StaticAddress {
        StaticAddress {
            address: a.into(),
            label: None,
            scope: Default::default(),
        }
    }

    fn iface(name: &str, role: InterfaceRole, addrs: &[&str]) -> InterfaceConfig {
        InterfaceConfig {
            name: name.into(),
            role,
            addresses: addrs.iter().map(|a| addr(a)).collect(),
            ..Default::default()
        }
    }

    fn range(iface: &str, s: &str, e: &str) -> DnsmasqDhcpRange {
        DnsmasqDhcpRange {
            name: "r".into(),
            interface: iface.into(),
            start_address: s.into(),
            end_address: e.into(),
            ..Default::default()
        }
    }

    fn lease(id: i64, mac: &str, ip: &str) -> DnsmasqStaticLease {
        DnsmasqStaticLease {
            id: Some(id),
            mac_address: mac.into(),
            ip_address: ip.into(),
            ..Default::default()
        }
    }

    fn zone(id: i64, name: &str, ifaces: &[&str]) -> FirewallZone {
        FirewallZone {
            id: Some(id),
            name: name.into(),
            interfaces: ifaces.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn address_must_be_cidr_and_usable_host() {
        assert!(
            validate_interface_config(&iface("lan", InterfaceRole::LAN, &["192.168.1.1/24"]))
                .is_empty()
        );
        assert!(
            !validate_interface_config(&iface("lan", InterfaceRole::LAN, &["192.168.1.1"]))
                .is_empty()
        );
        assert!(
            !validate_interface_config(&iface("lan", InterfaceRole::LAN, &["999.1.1.1/24"]))
                .is_empty()
        );
        let e = validate_interface_config(&iface("lan", InterfaceRole::LAN, &["192.168.1.0/24"]));
        assert!(e[0].contains("network address"));
        let e = validate_interface_config(&iface("lan", InterfaceRole::LAN, &["192.168.1.255/24"]));
        assert!(e[0].contains("broadcast"));
        // /31 and /32 have no network/broadcast addresses
        assert!(
            validate_interface_config(&iface(
                "l",
                InterfaceRole::LAN,
                &["10.0.0.0/31", "10.0.0.1/32"]
            ))
            .is_empty()
        );
        assert!(
            validate_interface_config(&iface("l", InterfaceRole::LAN, &["fd00::1/64"])).is_empty()
        );
    }

    #[test]
    fn gateway_routes_and_dns_must_parse() {
        let mut c = iface("wan", InterfaceRole::WAN, &["10.0.0.2/24"]);
        c.gateway = Some("10.0.0.1".into());
        c.dns_servers = vec!["1.1.1.1".into(), "2606:4700::1111".into()];
        c.routes = vec![StaticRoute {
            destination: Some("10.9.0.0/16".into()),
            gateway: "10.0.0.254".into(),
            metric: None,
            table: None,
            route_type: Default::default(),
        }];
        assert!(validate_interface_config(&c).is_empty());
        c.gateway = Some("gw".into());
        c.dns_servers.push("dns.example".into());
        c.routes[0].destination = Some("10.9.0.0".into());
        c.routes[0].gateway = "x".into();
        assert_eq!(validate_interface_config(&c).len(), 4);
    }

    #[test]
    fn mtu_rules() {
        let mut c = iface("lan", InterfaceRole::LAN, &["192.168.1.1/24"]);
        c.ipv6_accept_ra = false;
        c.mtu = Some(1500);
        assert!(validate_interface_config(&c).is_empty());
        c.mtu = Some(67);
        assert!(!validate_interface_config(&c).is_empty());
        c.mtu = Some(70000);
        assert!(!validate_interface_config(&c).is_empty());
        c.mtu = Some(1000);
        assert!(
            validate_interface_config(&c).is_empty(),
            "IPv4-only may use a small MTU"
        );
        c.ipv6_accept_ra = true;
        assert!(validate_interface_config(&c)[0].contains("1280"));
        c.ipv6_accept_ra = false;
        c.addresses.push(addr("fd00::1/64"));
        assert!(!validate_interface_config(&c).is_empty());
    }

    #[test]
    fn pd_uplink_cannot_be_self() {
        let mut c = iface("lan", InterfaceRole::LAN, &[]);
        c.dhcp_prefix_delegation = Some(DhcpPrefixDelegationConfig {
            uplink_interface: Some("lan".into()),
            ..Default::default()
        });
        assert!(validate_interface_config(&c)[0].contains("itself"));
        c.dhcp_prefix_delegation.as_mut().unwrap().uplink_interface = Some("wan".into());
        assert!(validate_interface_config(&c).is_empty());
    }

    #[test]
    fn dhcp_range_checks() {
        let lan = iface("lan", InterfaceRole::LAN, &["192.168.1.1/24"]);
        let cfgs = [lan];
        assert!(
            validate_dhcp_range(&range("lan", "192.168.1.100", "192.168.1.200"), &cfgs).is_empty()
        );
        assert!(!validate_dhcp_range(&range("lan", "192.168.1.100", "oops"), &cfgs).is_empty());
        assert!(
            validate_dhcp_range(&range("lan", "192.168.1.200", "192.168.1.100"), &cfgs)[0]
                .contains("after end")
        );
        assert!(
            validate_dhcp_range(&range("lan", "192.168.1.100", "fd00::1"), &cfgs)[0]
                .contains("family")
        );
        assert!(
            validate_dhcp_range(&range("lan", "192.168.2.10", "192.168.2.20"), &cfgs)[0]
                .contains("not inside")
        );
        assert!(
            validate_dhcp_range(&range("lan", "192.168.1.1", "192.168.1.50"), &cfgs)[0]
                .contains("own address")
        );
        let wan = iface("wan", InterfaceRole::WAN, &[]);
        assert!(
            validate_dhcp_range(&range("wan", "10.0.0.2", "10.0.0.9"), &[wan])[0].contains("WAN")
        );
        // unknown or dynamic interface: only syntactic checks
        assert!(validate_dhcp_range(&range("x", "10.0.0.2", "10.0.0.9"), &[]).is_empty());
    }

    #[test]
    fn static_lease_checks() {
        let cfgs = [iface("lan", InterfaceRole::LAN, &["192.168.1.1/24"])];
        let existing = [lease(1, "aa:bb:cc:dd:ee:01", "192.168.1.10")];
        assert!(
            validate_static_lease(
                &lease(2, "aa:bb:cc:dd:ee:02", "192.168.1.11"),
                &existing,
                &cfgs
            )
            .is_empty()
        );
        assert!(
            !validate_static_lease(&lease(2, "aa:bb:cc:dd:ee:02", "nope"), &existing, &cfgs)
                .is_empty()
        );
        assert!(
            validate_static_lease(
                &lease(2, "AA:BB:CC:DD:EE:01", "192.168.1.11"),
                &existing,
                &cfgs
            )[0]
            .contains("MAC")
        );
        assert!(
            validate_static_lease(
                &lease(2, "aa:bb:cc:dd:ee:02", "192.168.1.10"),
                &existing,
                &cfgs
            )[0]
            .contains("already reserved")
        );
        assert!(
            validate_static_lease(
                &lease(2, "aa:bb:cc:dd:ee:02", "192.168.1.1"),
                &existing,
                &cfgs
            )[0]
            .contains("router's own")
        );
        // updating itself is fine; a disabled lease is ignored
        assert!(
            validate_static_lease(
                &lease(1, "aa:bb:cc:dd:ee:01", "192.168.1.10"),
                &existing,
                &cfgs
            )
            .is_empty()
        );
        let mut off = lease(1, "aa:bb:cc:dd:ee:01", "192.168.1.10");
        off.enabled = false;
        assert!(
            validate_static_lease(
                &lease(2, "aa:bb:cc:dd:ee:01", "192.168.1.10"),
                &[off],
                &cfgs
            )
            .is_empty()
        );
    }

    #[test]
    fn global_dnsmasq_names_and_upstreams_must_be_well_formed() {
        let mut config = DnsmasqConfig {
            local_domain: Some("lan".into()),
            upstream_servers: vec![
                DnsmasqUpstreamServer {
                    address: "1.1.1.1".into(),
                    port: Some(853),
                    domain: None,
                },
                DnsmasqUpstreamServer {
                    address: "dns.example".into(),
                    port: None,
                    domain: Some("corp.example".into()),
                },
            ],
            ..Default::default()
        };
        assert!(validate_dnsmasq_config(&config).is_empty());

        config.local_domain = Some("lan/x".into());
        assert!(validate_dnsmasq_config(&config)[0].contains("Local domain"));
        config.local_domain = Some(String::new());
        assert!(!validate_dnsmasq_config(&config).is_empty());
        config.local_domain = None;

        config.upstream_servers[0].address = "1.1.1.1, 9.9.9.9".into();
        config.upstream_servers[0].port = Some(0);
        config.upstream_servers[1].domain = Some("corp example".into());
        let errors = validate_dnsmasq_config(&config);
        assert_eq!(errors.len(), 3, "{errors:?}");
    }

    #[test]
    fn required_fields_are_reported_by_their_validators() {
        let host = DnsmasqHostRecord::default();
        let errors = validate_host_record(&host);
        assert!(
            errors
                .iter()
                .any(|e| e == "At least one hostname is required")
        );
        assert!(
            errors
                .iter()
                .any(|e| e.starts_with("At least one IP address"))
        );
        let cname = validate_cname_record(&DnsmasqCnameRecord::default());
        assert_eq!(cname, ["Alias is required", "Target is required"]);
        assert_eq!(
            validate_address_override(&DnsmasqAddressOverride::default()),
            ["Domain is required"]
        );
        assert_eq!(
            validate_dhcp_option(&DnsmasqDhcpOption::default()),
            ["Option name/number is required", "Option value is required"]
        );
        let lease = DnsmasqStaticLease {
            ip_address: "192.168.1.10".into(),
            ..Default::default()
        };
        assert_eq!(
            validate_static_lease(&lease, &[], &[]),
            ["MAC address or client ID is required"]
        );
        let range = DnsmasqDhcpRange::default();
        let errors = validate_dhcp_range(&range, &[]);
        assert!(
            errors.contains(&"Range name is required".to_owned()),
            "{errors:?}"
        );
        assert!(
            errors.contains(&"Start and end addresses are required".to_owned()),
            "{errors:?}"
        );
    }

    #[test]
    fn mac_patterns_are_six_colon_separated_octets() {
        assert!(valid_mac_pattern("00:11:22:33:44:55"));
        assert!(valid_mac_pattern("AA:bb:*:*:*:*"));
        for bad in [
            "00:11:22:33:44",
            "00:11:22:33:44,55",
            "00-11-22-33-44-55",
            "00:11:22:33:44:5g",
            "00:11:22:33:44:555",
            "0:1:2:3:4:5",
            "00:11:22:33:44:55\n",
        ] {
            assert!(!valid_mac_pattern(bad), "{bad:?}");
        }
        let cfgs = [iface("lan", InterfaceRole::LAN, &["192.168.1.1/24"])];
        let errors =
            validate_static_lease(&lease(2, "00:11:22:33:44,55", "192.168.1.11"), &[], &cfgs);
        assert!(
            errors.iter().any(|e| e.contains("MAC address")),
            "{errors:?}"
        );
    }

    #[test]
    fn host_records_cnames_and_overrides_need_names_and_addresses() {
        let record = |names: &[&str], v4: Option<&str>, v6: Option<&str>| DnsmasqHostRecord {
            hostnames: names.iter().map(|n| n.to_string()).collect(),
            ipv4_address: v4.map(str::to_owned),
            ipv6_address: v6.map(str::to_owned),
            enabled: true,
            ..Default::default()
        };
        assert!(
            validate_host_record(&record(
                &["nas.lan.example", "nas"],
                Some("192.168.1.20"),
                None
            ))
            .is_empty()
        );
        assert!(validate_host_record(&record(&["nas"], None, Some("fd00::20"))).is_empty());
        for bad in [
            "nas.example
dhcp-option=3,1.2.3.4",
            "a,b",
            "-bad.example",
            "bad..example",
            "",
            "sp ace.example",
        ] {
            assert!(
                !validate_host_record(&record(&[bad], Some("192.168.1.20"), None)).is_empty(),
                "{bad:?}"
            );
        }
        assert!(!validate_host_record(&record(&["nas"], Some("192.168.1.256"), None)).is_empty());
        assert!(!validate_host_record(&record(&["nas"], Some(""), None)).is_empty());
        assert!(!validate_host_record(&record(&["nas"], None, Some("nope"))).is_empty());

        let cname = |alias: &str, target: &str| DnsmasqCnameRecord {
            alias: alias.into(),
            target: target.into(),
            enabled: true,
            ..Default::default()
        };
        assert!(validate_cname_record(&cname("files.example", "nas.example.")).is_empty());
        assert!(!validate_cname_record(&cname("files.example", "nas example")).is_empty());
        assert!(!validate_cname_record(&cname("files\nexample", "nas.example")).is_empty());

        let entry = |domain: &str, action, redirect: Option<&str>| DnsmasqAddressOverride {
            domain: domain.into(),
            action,
            redirect_address: redirect.map(str::to_owned),
            enabled: true,
            ..Default::default()
        };
        assert!(
            validate_address_override(&entry("*.ads.example", DnsmasqAddressAction::Block, None))
                .is_empty()
        );
        assert!(
            validate_address_override(&entry(
                "ads.example",
                DnsmasqAddressAction::Null,
                Some("junk")
            ))
            .is_empty()
        );
        assert!(
            validate_address_override(&entry(
                "ads.example",
                DnsmasqAddressAction::Redirect,
                Some("10.0.0.1")
            ))
            .is_empty()
        );
        assert!(
            !validate_address_override(&entry("ads.example", DnsmasqAddressAction::Redirect, None))
                .is_empty()
        );
        assert!(
            !validate_address_override(&entry(
                "ads.example",
                DnsmasqAddressAction::Redirect,
                Some("nope")
            ))
            .is_empty()
        );
        assert!(
            !validate_address_override(&entry("ads example", DnsmasqAddressAction::Block, None))
                .is_empty()
        );
    }

    #[test]
    fn dhcp_state_reports_duplicates_once() {
        let leases = [
            lease(1, "aa:bb:cc:dd:ee:01", "10.0.0.5"),
            lease(2, "aa:bb:cc:dd:ee:01", "10.0.0.6"),
        ];
        assert_eq!(validate_dhcp_state(&[], &leases, &[]).len(), 1);
    }

    #[test]
    fn zone_membership_is_exclusive() {
        let zones = [zone(1, "lan", &["eth1"]), zone(2, "wan", &["eth0"])];
        assert!(zone_interface_conflicts(&zone(2, "wan", &["eth0"]), &zones).is_empty());
        let e = zone_interface_conflicts(&zone(3, "dmz", &["eth1"]), &zones);
        assert!(e[0].contains("'lan'"));
        assert!(zone_interface_conflicts(&zone(1, "lan", &["eth1", "eth2"]), &zones).is_empty());
    }

    #[test]
    fn deletion_references_listed() {
        let mut other = iface("eth2", InterfaceRole::LAN, &[]);
        other.dhcp_prefix_delegation = Some(DhcpPrefixDelegationConfig {
            uplink_interface: Some("eth0".into()),
            ..Default::default()
        });
        let caddy = CaddyConfig {
            bind_interface: "eth0".into(),
            ..Default::default()
        };
        let bridge = BridgeConfig {
            name: "br0".into(),
            members: vec!["eth0".into()],
            ..Default::default()
        };
        let vlan = VlanConfig {
            name: "eth0.10".into(),
            parent_interface: "eth0".into(),
            ..Default::default()
        };
        let refs = interface_references(
            "eth0",
            &[other],
            &[zone(1, "wan", &["eth0"])],
            &[range("eth0", "10.0.0.2", "10.0.0.9")],
            &caddy,
            &[vlan],
            &[bridge],
        );
        assert_eq!(refs.len(), 6, "{refs:?}");
        assert!(
            interface_references("eth9", &[], &[], &[], &CaddyConfig::default(), &[], &[])
                .is_empty()
        );
    }
}
