//! nftables ruleset generation from Keystone firewall configuration
//!
//! This module converts Keystone's zone-based firewall configuration into
//! nftables JSON format using the `nftables` crate.
//!
//! # Module Structure
//!
//! - `chains/` - Chain generation submodules (input, forward, output, nat)
//! - `statements` - Helper functions for creating nftables statements
//! - `preview` - Human-readable preview generation

mod chains;
mod preview;
pub mod statements;

use chains::{
    generate_forward_chain, generate_input_chain, generate_output_chain,
    generate_postrouting_chain, generate_prerouting_chain,
};
use preview::generate_preview;

use keystone_core::{FirewallConfig, FirewallZone};
use nftables::{
    batch::Batch,
    schema::{NfListObject, Table},
    types::NfFamily,
};
use std::borrow::Cow;
use std::collections::HashMap;

/// Name of the filter table
pub const FILTER_TABLE: &str = "keystone";
/// Name of the NAT table
pub const NAT_TABLE: &str = "keystone_nat";

/// Result of ruleset generation
pub struct GeneratedRuleset<'a> {
    /// The nftables JSON ruleset
    pub nftables: nftables::schema::Nftables<'a>,
    /// Human-readable preview text
    pub preview: String,
}

/// Generate a complete nftables ruleset from the firewall configuration
pub fn generate_ruleset(config: &FirewallConfig) -> GeneratedRuleset<'static> {
    let mut batch = Batch::new();

    // Build zone-to-interfaces mapping for quick lookup
    let zone_interfaces = build_zone_interface_map(&config.zones);

    // Note: Table creation is idempotent - if table exists, add just succeeds.
    // The apply function handles cleanup of existing tables separately.

    // Create filter table
    batch.add(NfListObject::Table(Table {
        family: NfFamily::INet,
        name: Cow::Borrowed(FILTER_TABLE),
        ..Default::default()
    }));

    // Create NAT table
    batch.add(NfListObject::Table(Table {
        family: NfFamily::INet,
        name: Cow::Borrowed(NAT_TABLE),
        ..Default::default()
    }));

    // Generate filter chains
    generate_input_chain(&mut batch, config, &zone_interfaces);
    generate_forward_chain(&mut batch, config, &zone_interfaces);
    generate_output_chain(&mut batch);

    // Generate NAT chains
    generate_prerouting_chain(&mut batch, config, &zone_interfaces);
    generate_postrouting_chain(&mut batch, config, &zone_interfaces);

    let nftables = batch.to_nftables();
    let preview = generate_preview(config, &zone_interfaces);

    GeneratedRuleset { nftables, preview }
}

/// Build a map of zone name -> interface list for quick lookups
pub fn build_zone_interface_map(zones: &[FirewallZone]) -> HashMap<String, Vec<String>> {
    zones
        .iter()
        .map(|z| (z.name.clone(), z.interfaces.clone()))
        .collect()
}

/// Resolve an optional zone reference to its interfaces.
///
/// `Ok(None)` means no zone was referenced (match any interface). A referenced
/// zone that is missing or has no interfaces is `Err(())`: callers must emit no
/// rule, otherwise the interface match would be dropped and the rule would
/// apply to every interface.
pub(crate) fn resolve_zone_interfaces<'a>(
    zone: Option<&str>,
    zone_interfaces: &'a HashMap<String, Vec<String>>,
    rule_name: &str,
) -> Result<Option<&'a [String]>, ()> {
    let Some(name) = zone else { return Ok(None) };
    match zone_interfaces.get(name) {
        Some(interfaces) if !interfaces.is_empty() => Ok(Some(interfaces.as_slice())),
        _ => {
            tracing::warn!(
                "Skipping rule '{rule_name}': zone '{name}' does not exist or has no interfaces"
            );
            Err(())
        }
    }
}

/// Find explicitly Internet-facing zones.
pub fn find_wan_zones(zones: &[FirewallZone]) -> Vec<&FirewallZone> {
    zones.iter().filter(|zone| zone.is_wan).collect()
}

/// Find zones whose egress traffic should receive IPv4 source NAT.
pub fn find_ipv4_masquerade_zones(zones: &[FirewallZone]) -> Vec<&FirewallZone> {
    zones.iter().filter(|zone| zone.masquerade_ipv4).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use keystone_core::{
        FirewallAction, FirewallGlobalSettings, FirewallPolicy, InputRule, PortForward,
        RuleProtocol, ZoneForwardPolicy,
    };

    fn create_test_config() -> FirewallConfig {
        FirewallConfig {
            zones: vec![
                FirewallZone {
                    id: Some(1),
                    name: "wan".to_string(),
                    description: Some("Internet-facing".to_string()),
                    interfaces: vec!["eth0".to_string()],
                    is_wan: true,
                    masquerade_ipv4: true,
                    default_input_policy: FirewallPolicy::Drop,
                    default_forward_policy: FirewallPolicy::Drop,
                },
                FirewallZone {
                    id: Some(2),
                    name: "lan".to_string(),
                    description: Some("Internal network".to_string()),
                    interfaces: vec!["eth1".to_string(), "eth2".to_string()],
                    is_wan: false,
                    masquerade_ipv4: false,
                    default_input_policy: FirewallPolicy::Accept,
                    default_forward_policy: FirewallPolicy::Accept,
                },
            ],
            zone_forwards: vec![ZoneForwardPolicy {
                id: Some(1),
                source_zone: "lan".to_string(),
                dest_zone: "wan".to_string(),
                policy: FirewallAction::Accept,
                enabled: true,
            }],
            port_forwards: vec![PortForward {
                id: Some(1),
                name: "Web Server".to_string(),
                description: None,
                enabled: true,
                protocol: RuleProtocol::Tcp,
                source_zone: Some("wan".to_string()),
                external_port_start: 8080,
                external_port_end: None,
                source_ip: None,
                dest_ip: "192.168.1.100".to_string(),
                dest_port: Some(80),
            }],
            input_rules: vec![InputRule {
                id: Some(1),
                name: "Allow SSH from LAN".to_string(),
                description: None,
                enabled: true,
                position: 1,
                zone: Some("lan".to_string()),
                protocol: Some(RuleProtocol::Tcp),
                port_start: Some(22),
                port_end: None,
                source_ip: None,
                action: FirewallAction::Accept,
                log_enabled: false,
                log_prefix: None,
                rate_limit: None,
            }],
            forward_rules: vec![],
            global_settings: FirewallGlobalSettings::default(),
        }
    }

    #[test]
    fn test_generate_ruleset() {
        let config = create_test_config();
        let result = generate_ruleset(&config);

        // Should produce valid JSON
        let json = serde_json::to_string_pretty(&result.nftables).unwrap();
        assert!(json.contains("keystone"));
        assert!(json.contains("keystone_nat"));
        assert!(json.contains("nfproto"));
        assert!(json.contains("ipv4"));
        assert!(json.contains("ipv6-icmp"));
        // A multicast Solicit can receive a unicast DHCPv6 reply which is
        // not classified as established by conntrack. The router must accept it.
        assert!(json.contains("Allow DHCPv6 server replies on WAN"));
        assert!(json.contains("\"sport\""));
        assert!(json.contains("\"dport\""));
    }

    #[test]
    fn test_generate_preview() {
        let config = create_test_config();
        let zone_interfaces = build_zone_interface_map(&config.zones);
        let preview = generate_preview(&config, &zone_interfaces);

        assert!(preview.contains("table inet keystone"));
        assert!(preview.contains("chain input"));
        assert!(preview.contains("chain forward"));
        assert!(preview.contains("chain output"));
        assert!(preview.contains("chain prerouting"));
        assert!(preview.contains("chain postrouting"));
        assert!(preview.contains("masquerade"));
        assert!(preview.contains("udp sport 547 udp dport 546"));
        let dhcpv6 = preview.find("udp sport 547 udp dport 546").unwrap();
        let drop_invalid = preview.find("ct state invalid drop").unwrap();
        assert!(
            dhcpv6 < drop_invalid,
            "DHCPv6 reply must precede invalid DROP"
        );
    }

    #[test]
    fn test_build_zone_interface_map() {
        let zones = vec![
            FirewallZone {
                id: Some(1),
                name: "wan".to_string(),
                description: None,
                interfaces: vec!["eth0".to_string()],
                is_wan: true,
                masquerade_ipv4: true,
                default_input_policy: FirewallPolicy::Drop,
                default_forward_policy: FirewallPolicy::Drop,
            },
            FirewallZone {
                id: Some(2),
                name: "lan".to_string(),
                description: None,
                interfaces: vec!["eth1".to_string(), "eth2".to_string()],
                is_wan: false,
                masquerade_ipv4: false,
                default_input_policy: FirewallPolicy::Accept,
                default_forward_policy: FirewallPolicy::Accept,
            },
        ];

        let map = build_zone_interface_map(&zones);
        assert_eq!(map.get("wan"), Some(&vec!["eth0".to_string()]));
        assert_eq!(
            map.get("lan"),
            Some(&vec!["eth1".to_string(), "eth2".to_string()])
        );
    }

    #[test]
    fn test_find_wan_zones() {
        let zones = vec![
            FirewallZone {
                id: Some(1),
                name: "wan".to_string(),
                description: None,
                interfaces: vec!["eth0".to_string()],
                is_wan: true,
                masquerade_ipv4: true,
                default_input_policy: FirewallPolicy::Drop,
                default_forward_policy: FirewallPolicy::Drop,
            },
            FirewallZone {
                id: Some(2),
                name: "lan".to_string(),
                description: None,
                interfaces: vec!["eth1".to_string()],
                is_wan: false,
                masquerade_ipv4: false,
                default_input_policy: FirewallPolicy::Accept,
                default_forward_policy: FirewallPolicy::Accept,
            },
            FirewallZone {
                id: Some(3),
                name: "isolated".to_string(),
                description: None,
                interfaces: vec!["eth2".to_string()],
                is_wan: false,
                masquerade_ipv4: false,
                default_input_policy: FirewallPolicy::Drop,
                default_forward_policy: FirewallPolicy::Drop,
            },
        ];

        let wan_zones = find_wan_zones(&zones);
        assert_eq!(wan_zones.len(), 1);
        assert_eq!(wan_zones[0].name, "wan");
    }

    fn json_of(config: &FirewallConfig) -> String {
        serde_json::to_string(&generate_ruleset(config).nftables).unwrap()
    }

    #[test]
    fn rule_with_missing_zone_is_not_emitted() {
        let mut config = create_test_config();
        config.input_rules[0].zone = Some("nope".to_string());
        config.forward_rules.push(keystone_core::ForwardRule {
            name: "Fwd to nowhere".to_string(),
            dest_zone: Some("nope".to_string()),
            ..Default::default()
        });
        let json = json_of(&config);
        assert!(!json.contains("Allow SSH from LAN"));
        assert!(!json.contains("Fwd to nowhere"));
    }

    #[test]
    fn rule_with_empty_zone_is_not_emitted() {
        let mut config = create_test_config();
        config.zones[1].interfaces.clear();
        config.port_forwards[0].source_zone = Some("lan".to_string());
        let json = json_of(&config);
        assert!(!json.contains("Allow SSH from LAN"));
        assert!(!json.contains("Web Server (tcp)\""));
    }

    #[test]
    fn port_on_non_port_protocol_is_not_emitted() {
        let mut config = create_test_config();
        config.input_rules[0].protocol = Some(RuleProtocol::Any);
        config.input_rules[0].port_start = Some(22);
        assert!(!json_of(&config).contains("Allow SSH from LAN"));
        config.input_rules[0].protocol = Some(RuleProtocol::Tcp);
        assert!(json_of(&config).contains("Allow SSH from LAN"));
    }

    #[test]
    fn invalid_rate_limit_rule_is_not_emitted() {
        let mut config = create_test_config();
        config.input_rules[0].rate_limit = Some("bogus".to_string());
        assert!(!json_of(&config).contains("Allow SSH from LAN"));
        config.input_rules[0].rate_limit = Some("10/minute".to_string());
        assert!(json_of(&config).contains("Allow SSH from LAN"));
    }

    #[test]
    fn port_forward_dnat_only_matches_local_destinations() {
        let config = create_test_config();
        let json = serde_json::to_value(&generate_ruleset(&config).nftables).unwrap();
        let rules = json["nftables"].as_array().unwrap();
        let dnat = rules
            .iter()
            .find(|r| r["add"]["rule"]["comment"] == "Web Server (tcp)")
            .expect("dnat rule");
        let text = dnat.to_string();
        assert!(text.contains("\"fib\""), "{text}");
        assert!(text.contains("local"));
    }

    #[test]
    fn port_forward_gets_forward_accept_before_user_rules() {
        let config = create_test_config();
        let json = serde_json::to_value(&generate_ruleset(&config).nftables).unwrap();
        let rules = json["nftables"].as_array().unwrap();
        let accept = rules
            .iter()
            .find(|r| r["add"]["rule"]["comment"] == "Web Server DNAT accept (tcp)")
            .expect("forward accept rule");
        let text = accept.to_string();
        assert!(text.contains("\"status\""), "{text}");
        assert!(text.contains("dnat"));
        assert!(text.contains("192.168.1.100"));
        // Translated port 80, not external 8080.
        assert!(text.contains("80") && !text.contains("8080"));
        assert_eq!(accept["add"]["rule"]["chain"], "forward");
    }

    /// Comments of the input-chain rules, in evaluation order.
    fn input_rule_comments(config: &FirewallConfig) -> Vec<String> {
        let json = serde_json::to_value(&generate_ruleset(config).nftables).unwrap();
        json["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["add"]["rule"]["chain"] == "input")
            .map(|r| {
                r["add"]["rule"]["comment"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn user_input_rules_sit_between_icmp_drops_and_icmp_accepts() {
        let mut config = create_test_config();
        config.input_rules[0].name = "Drop LAN ping".to_string();
        let comments = input_rule_comments(&config);
        let first = |needle: &str| {
            comments
                .iter()
                .position(|c| c.contains(needle))
                .unwrap_or_else(|| panic!("missing rule {needle:?} in {comments:?}"))
        };
        let last = |needle: &str| {
            comments
                .iter()
                .rposition(|c| c.contains(needle))
                .unwrap_or_else(|| panic!("missing rule {needle:?} in {comments:?}"))
        };

        let loopback = first("Accept loopback");
        let last_drop = last("Drop ICMP");
        let user_rule = first("Drop LAN ping");
        let first_ping = first("Allow IPv4 ping");
        let first_essential = first("Accept ICMP destination-unreachable");
        let zone_default = first("zone default: accept input");

        assert!(first("Drop ICMP") > loopback);
        assert!(
            user_rule > last_drop,
            "user rules follow dangerous-ICMP drops"
        );
        assert!(first_ping > user_rule, "ping accepts follow user rules");
        assert!(
            first_essential > user_rule,
            "essential ICMP follows user rules"
        );
        assert!(zone_default > first_ping.max(first_essential));
    }
}
