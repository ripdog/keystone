//! Representative firewall configurations shared by the generator and tester
//! tests. They are deliberately varied (groups, port ranges, hairpin NAT on and
//! off, disabled and invalid rules) so behaviour is checked on realistic shapes
//! rather than on one hand-picked rule.

use keystone_core::{
    AddressGroup, FirewallAction, FirewallConfig, FirewallGlobalSettings, FirewallPolicy,
    FirewallZone, ForwardRule, InputRule, PortForward, PortGroup, RuleProtocol, ZoneForwardPolicy,
};

fn zone(
    name: &str,
    interfaces: &[&str],
    is_wan: bool,
    masquerade_ipv4: bool,
    input: FirewallPolicy,
) -> FirewallZone {
    FirewallZone {
        id: None,
        name: name.into(),
        description: None,
        interfaces: interfaces.iter().map(|i| i.to_string()).collect(),
        is_wan,
        masquerade_ipv4,
        default_input_policy: input,
    }
}

fn address_group(name: &str, entries: &[&str]) -> AddressGroup {
    AddressGroup {
        name: name.into(),
        entries: entries.iter().map(|e| e.to_string()).collect(),
        ..Default::default()
    }
}

fn port_group(name: &str, entries: &[&str]) -> PortGroup {
    PortGroup {
        name: name.into(),
        entries: entries.iter().map(|e| e.to_string()).collect(),
        ..Default::default()
    }
}

/// Every sample configuration, named for test diagnostics.
pub(crate) fn sample_configs() -> Vec<(&'static str, FirewallConfig)> {
    vec![
        ("empty", FirewallConfig::default()),
        ("minimal_wan_only", minimal_wan_only()),
        ("rich", rich()),
        ("rich_quiet", rich_quiet()),
        ("rich_upnp", rich_upnp()),
        ("rich_dns", rich_dns()),
        ("rich_ipv6_suffix", rich_ipv6_suffix()),
    ]
}

/// `rich` plus a forward rule and a port forward that target IPv6 hosts by
/// interface-identifier suffix instead of by address.
pub(crate) fn rich_ipv6_suffix() -> FirewallConfig {
    let mut config = rich();
    config.forward_rules.push(ForwardRule {
        id: Some(900),
        name: "NAS over IPv6".into(),
        source_zone: Some("wan".into()),
        protocol: Some(RuleProtocol::Tcp),
        dest_port_start: Some(443),
        dest_ipv6_suffix: Some("::1234".into()),
        ..Default::default()
    });
    config.port_forwards.push(PortForward {
        id: Some(901),
        name: "Game server v6".into(),
        source_zone: Some("wan".into()),
        protocol: RuleProtocol::TcpUdp,
        external_port_start: 27015,
        external_port_end: Some(27020),
        dest_ip: "192.168.1.60".into(),
        dest_ipv6_suffix: Some("::a:b:c:d".into()),
        ..Default::default()
    });
    config
}

/// `rich` with LAN DNS forced to the router and DNS-over-TLS rejected. The
/// exempt group has IPv4 and IPv6 entries, so both families carry exemptions.
pub(crate) fn rich_dns() -> FirewallConfig {
    let mut config = rich();
    config.global_settings.force_local_dns = true;
    config.global_settings.block_dns_over_tls = true;
    config.global_settings.dns_exempt_group = Some("mixed".to_string());
    config
}

/// `rich` with UPnP / NAT-PMP enabled: miniupnpd's mappings are accepted from
/// the WAN to two LAN interfaces.
pub(crate) fn rich_upnp() -> FirewallConfig {
    let mut config = rich();
    config.upnp_forward = Some(keystone_core::upnp::UpnpForwardAccept {
        wan_interface: "eth0".to_string(),
        lan_interfaces: vec!["eth1".to_string(), "eth2".to_string()],
    });
    config
}

/// One WAN zone and one port forward: no LAN, so hairpin NAT has no effect.
pub(crate) fn minimal_wan_only() -> FirewallConfig {
    FirewallConfig {
        zones: vec![zone("wan", &["eth0"], true, true, FirewallPolicy::Drop)],
        port_forwards: vec![PortForward {
            id: Some(1),
            name: "Web".into(),
            enabled: true,
            protocol: RuleProtocol::Tcp,
            source_zone: Some("wan".into()),
            external_port_start: 8080,
            dest_ip: "192.168.1.100".into(),
            dest_port: Some(80),
            ..Default::default()
        }],
        global_settings: FirewallGlobalSettings::default(),
        ..Default::default()
    }
}

/// A WAN, a LAN, a DMZ and an IoT zone with groups, ranges, disabled and
/// invalid entries, and hairpin NAT enabled.
pub(crate) fn rich() -> FirewallConfig {
    FirewallConfig {
        zones: vec![
            zone("wan", &["eth0"], true, true, FirewallPolicy::Drop),
            zone(
                "lan",
                &["eth1", "eth2"],
                false,
                false,
                FirewallPolicy::Accept,
            ),
            zone("dmz", &["eth3"], false, true, FirewallPolicy::Drop),
            zone("iot", &["eth4"], false, false, FirewallPolicy::Drop),
            // Zone with no interfaces: never produces rules.
            zone("spare", &[], false, false, FirewallPolicy::Accept),
        ],
        zone_forwards: vec![
            ZoneForwardPolicy {
                id: Some(1),
                source_zone: "lan".into(),
                dest_zone: "wan".into(),
                policy: FirewallAction::Accept,
                enabled: true,
            },
            ZoneForwardPolicy {
                id: Some(2),
                source_zone: "lan".into(),
                dest_zone: "dmz".into(),
                policy: FirewallAction::Reject,
                enabled: true,
            },
            ZoneForwardPolicy {
                id: Some(3),
                source_zone: "iot".into(),
                dest_zone: "wan".into(),
                policy: FirewallAction::Accept,
                enabled: false,
            },
            ZoneForwardPolicy {
                id: Some(4),
                source_zone: "iot".into(),
                dest_zone: "nowhere".into(),
                policy: FirewallAction::Accept,
                enabled: true,
            },
        ],
        port_forwards: vec![
            PortForward {
                id: Some(1),
                name: "Web".into(),
                enabled: true,
                protocol: RuleProtocol::Tcp,
                source_zone: Some("wan".into()),
                external_port_start: 8080,
                dest_ip: "192.168.1.100".into(),
                dest_port: Some(80),
                ..Default::default()
            },
            PortForward {
                id: Some(2),
                name: "Game".into(),
                enabled: true,
                protocol: RuleProtocol::TcpUdp,
                source_zone: Some("wan".into()),
                external_port_start: 27000,
                external_port_end: Some(27050),
                source_ip: Some("198.51.100.0/24".into()),
                dest_ip: "192.168.1.50".into(),
                ..Default::default()
            },
            PortForward {
                id: Some(3),
                name: "Alt SSH".into(),
                enabled: true,
                protocol: RuleProtocol::Udp,
                source_zone: None,
                external_port_start: 2222,
                source_group: Some("iot_hosts".into()),
                dest_ip: "192.168.1.20".into(),
                dest_port: Some(22),
                ..Default::default()
            },
            // Source group with no IPv4 entries: DNAT cannot match, no rule.
            PortForward {
                id: Some(4),
                name: "v6 only".into(),
                enabled: true,
                protocol: RuleProtocol::Tcp,
                source_group: Some("v6_only".into()),
                external_port_start: 9000,
                dest_ip: "192.168.1.30".into(),
                ..Default::default()
            },
            PortForward {
                id: Some(5),
                name: "Disabled".into(),
                enabled: false,
                protocol: RuleProtocol::Tcp,
                external_port_start: 9100,
                dest_ip: "192.168.1.31".into(),
                ..Default::default()
            },
            PortForward {
                id: Some(6),
                name: "Bad destination".into(),
                enabled: true,
                protocol: RuleProtocol::Tcp,
                external_port_start: 9200,
                dest_ip: "not-an-address".into(),
                ..Default::default()
            },
        ],
        input_rules: vec![
            InputRule {
                id: Some(1),
                name: "Allow SSH from LAN".into(),
                enabled: true,
                position: 1,
                zone: Some("lan".into()),
                protocol: Some(RuleProtocol::Tcp),
                port_start: Some(22),
                ..Default::default()
            },
            InputRule {
                id: Some(2),
                name: "Allow DNS from LAN hosts".into(),
                enabled: true,
                position: 2,
                zone: Some("lan".into()),
                protocol: Some(RuleProtocol::TcpUdp),
                source_group: Some("lan_hosts".into()),
                dest_port_group: Some("dns".into()),
                ..Default::default()
            },
            // Lower position than the others, so it is evaluated first.
            InputRule {
                id: Some(3),
                name: "Drop IoT to router".into(),
                enabled: true,
                position: 0,
                zone: Some("iot".into()),
                action: FirewallAction::Drop,
                log_enabled: true,
                log_prefix: Some("iot-drop: ".into()),
                ..Default::default()
            },
            InputRule {
                id: Some(4),
                name: "Limited SSH from WAN".into(),
                enabled: true,
                position: 5,
                zone: Some("wan".into()),
                protocol: Some(RuleProtocol::Tcp),
                port_start: Some(22),
                rate_limit: Some("5/minute".into()),
                ..Default::default()
            },
            InputRule {
                id: Some(5),
                name: "Drop LAN ping".into(),
                enabled: true,
                position: 3,
                zone: Some("lan".into()),
                protocol: Some(RuleProtocol::Icmp),
                action: FirewallAction::Drop,
                ..Default::default()
            },
            InputRule {
                id: Some(6),
                name: "Reject DMZ admin".into(),
                enabled: true,
                position: 4,
                zone: Some("dmz".into()),
                protocol: Some(RuleProtocol::Tcp),
                port_start: Some(8443),
                source_ip: Some("192.168.50.7".into()),
                action: FirewallAction::Reject,
                ..Default::default()
            },
            InputRule {
                id: Some(7),
                name: "Mixed group NTP".into(),
                enabled: true,
                position: 6,
                protocol: Some(RuleProtocol::Udp),
                port_start: Some(123),
                source_group: Some("mixed".into()),
                ..Default::default()
            },
            InputRule {
                id: Some(8),
                name: "Disabled rule".into(),
                enabled: false,
                position: 7,
                zone: Some("lan".into()),
                ..Default::default()
            },
            InputRule {
                id: Some(9),
                name: "Invalid rate".into(),
                enabled: true,
                position: 8,
                zone: Some("lan".into()),
                rate_limit: Some("bogus".into()),
                ..Default::default()
            },
            InputRule {
                id: Some(10),
                name: "Unknown zone".into(),
                enabled: true,
                position: 9,
                zone: Some("ghost".into()),
                ..Default::default()
            },
        ],
        forward_rules: vec![
            ForwardRule {
                id: Some(1),
                name: "LAN web out".into(),
                enabled: true,
                position: 1,
                source_zone: Some("lan".into()),
                dest_zone: Some("wan".into()),
                protocol: Some(RuleProtocol::TcpUdp),
                source_group: Some("lan_hosts".into()),
                dest_port_group: Some("web".into()),
                ..Default::default()
            },
            ForwardRule {
                id: Some(2),
                name: "IoT to LAN".into(),
                enabled: true,
                position: 2,
                source_zone: Some("iot".into()),
                dest_zone: Some("lan".into()),
                action: FirewallAction::Drop,
                log_enabled: true,
                ..Default::default()
            },
            ForwardRule {
                id: Some(3),
                name: "DMZ to 10 net".into(),
                enabled: true,
                position: 0,
                source_zone: Some("dmz".into()),
                dest_ip: Some("10.9.9.9".into()),
                action: FirewallAction::Drop,
                ..Default::default()
            },
            ForwardRule {
                id: Some(4),
                name: "Ranged UDP".into(),
                enabled: true,
                position: 3,
                source_zone: Some("wan".into()),
                dest_zone: Some("dmz".into()),
                protocol: Some(RuleProtocol::Udp),
                dest_port_start: Some(5000),
                dest_port_end: Some(5010),
                rate_limit: Some("10/second".into()),
                ..Default::default()
            },
            ForwardRule {
                id: Some(5),
                name: "Mixed group out".into(),
                enabled: true,
                position: 4,
                source_group: Some("mixed".into()),
                dest_group: Some("lan_hosts".into()),
                ..Default::default()
            },
            ForwardRule {
                id: Some(6),
                name: "Disabled forward".into(),
                enabled: false,
                position: 5,
                source_zone: Some("lan".into()),
                ..Default::default()
            },
        ],
        address_groups: vec![
            address_group("lan_hosts", &["10.0.0.0/8", "10.1.2.3", "fd00::/64"]),
            address_group("iot_hosts", &["192.168.50.0/24"]),
            address_group("v6_only", &["2001:db8::/32"]),
            address_group("mixed", &["192.0.2.0/24", "2001:db8:1::/48"]),
        ],
        port_groups: vec![
            port_group("web", &["80", "443", "8000-8100"]),
            port_group("dns", &["53", "853"]),
        ],
        global_settings: FirewallGlobalSettings {
            ping_wan_enabled: true,
            ping_lan_enabled: true,
            hairpin_nat_enabled: true,
            ..FirewallGlobalSettings::default()
        },
        upnp_forward: None,
    }
}

/// `rich` with ping and hairpin NAT switched off.
pub(crate) fn rich_quiet() -> FirewallConfig {
    let mut config = rich();
    config.global_settings = FirewallGlobalSettings {
        ping_wan_enabled: false,
        ping_lan_enabled: false,
        hairpin_nat_enabled: false,
        ..FirewallGlobalSettings::default()
    };
    config
}
