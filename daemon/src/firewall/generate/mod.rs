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
}
