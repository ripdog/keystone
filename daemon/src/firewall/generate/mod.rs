//! nftables ruleset generation from Keystone firewall configuration
//!
//! This module converts Keystone's zone-based firewall configuration into
//! nftables JSON format using the `nftables` crate.
//!
//! # Module Structure
//!
//! - `chains/` - Chain objects; their rules come from `firewall::rules`
//! - `emit` - Translation of the shared rule model into nftables JSON
//! - `preview` - Human-readable preview generation
//! - `sets` - Named sets for address and port groups

pub(crate) mod chains;
pub(crate) mod emit;
mod preview;
pub mod sets;

use crate::firewall::rules::{self, Ruleset};
use chains::{add_chain, output::generate_output_chain};
use nftables::types::{NfChainType, NfHook};
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

    // Named sets for address and port groups. They must exist before the
    // rules that reference them.
    for table in [FILTER_TABLE, NAT_TABLE] {
        for object in sets::group_set_objects(config, table) {
            batch.add(object);
        }
    }

    // Every chain's rules come from the shared model, so the preview and the
    // packet tester see exactly what is emitted here.
    let Ruleset {
        prerouting,
        input,
        forward,
        postrouting,
    } = rules::build(config);

    add_chain(
        &mut batch,
        FILTER_TABLE,
        &input,
        NfChainType::Filter,
        NfHook::Input,
        0,
    );
    add_chain(
        &mut batch,
        FILTER_TABLE,
        &forward,
        NfChainType::Filter,
        NfHook::Forward,
        0,
    );
    generate_output_chain(&mut batch);
    add_chain(
        &mut batch,
        NAT_TABLE,
        &prerouting,
        NfChainType::NAT,
        NfHook::Prerouting,
        -100,
    );
    add_chain(
        &mut batch,
        NAT_TABLE,
        &postrouting,
        NfChainType::NAT,
        NfHook::Postrouting,
        100,
    );

    let nftables = batch.to_nftables();
    let preview = generate_preview(config);

    GeneratedRuleset { nftables, preview }
}

/// The nftables comment of a user-configured rule: `ks:<kind>:<id>` followed by
/// the rule's name. The counters endpoint reads the prefix back to attribute
/// hits to a rule, so the prefix must never change. nftables caps comments at
/// 128 bytes; the label is shortened to fit, the prefix is never cut.
pub(crate) fn rule_comment(kind: &str, id: Option<i64>, label: &str) -> String {
    let mut comment = format!("ks:{kind}:{}", id.unwrap_or_default());
    if !label.is_empty() {
        comment.push(' ');
        comment.push_str(label);
    }
    while comment.len() > MAX_COMMENT_BYTES {
        comment.pop();
    }
    comment
}

/// Longest comment nftables accepts.
const MAX_COMMENT_BYTES: usize = 127;

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
        AddressGroup, FirewallAction, FirewallGlobalSettings, FirewallPolicy, ForwardRule,
        InputRule, PortForward, PortGroup, RuleProtocol, ZoneForwardPolicy,
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
                },
                FirewallZone {
                    id: Some(2),
                    name: "lan".to_string(),
                    description: Some("Internal network".to_string()),
                    interfaces: vec!["eth1".to_string(), "eth2".to_string()],
                    is_wan: false,
                    masquerade_ipv4: false,
                    default_input_policy: FirewallPolicy::Accept,
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
                source_group: None,
                dest_ip: "192.168.1.100".to_string(),
                dest_port: Some(80),
                dest_ipv6_suffix: None,
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
                source_group: None,
                dest_port_group: None,
                action: FirewallAction::Accept,
                log_enabled: false,
                log_prefix: None,
                rate_limit: None,
            }],
            forward_rules: vec![],
            address_groups: vec![],
            port_groups: vec![],
            global_settings: FirewallGlobalSettings::default(),
            upnp_forward: None,
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
        let preview = generate_preview(&config);

        assert!(preview.contains("table inet keystone"));
        assert!(preview.contains("chain input"));
        assert!(preview.contains("chain forward"));
        assert!(preview.contains("chain output"));
        assert!(preview.contains("chain prerouting"));
        assert!(preview.contains("chain postrouting"));
        assert!(preview.contains("masquerade"));
        assert!(preview.contains("udp sport 547 udp dport 546"));
        let dhcpv6 = preview.find("udp sport 547 udp dport 546").unwrap();
        let drop_invalid = preview.find("ct state invalid counter drop").unwrap();
        assert!(
            dhcpv6 < drop_invalid,
            "DHCPv6 reply must precede invalid DROP"
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
            },
            FirewallZone {
                id: Some(2),
                name: "lan".to_string(),
                description: None,
                interfaces: vec!["eth1".to_string()],
                is_wan: false,
                masquerade_ipv4: false,
                default_input_policy: FirewallPolicy::Accept,
            },
            FirewallZone {
                id: Some(3),
                name: "isolated".to_string(),
                description: None,
                interfaces: vec!["eth2".to_string()],
                is_wan: false,
                masquerade_ipv4: false,
                default_input_policy: FirewallPolicy::Drop,
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
            .find(|r| r["add"]["rule"]["comment"] == "ks:portfwd:1 Web Server (tcp)")
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
            .find(|r| {
                r["add"]["rule"]["comment"] == "ks:portfwd-accept:1 Web Server DNAT accept (tcp)"
            })
            .expect("forward accept rule");
        let text = accept.to_string();
        assert!(text.contains("\"status\""), "{text}");
        assert!(text.contains("dnat"));
        assert!(text.contains("192.168.1.100"));
        // Translated port 80, not external 8080.
        assert!(text.contains("80") && !text.contains("8080"));
        assert_eq!(accept["add"]["rule"]["chain"], "forward");
    }

    /// Comments of the forward-chain rules, in evaluation order.
    fn forward_rule_comments(config: &FirewallConfig) -> Vec<String> {
        let json = serde_json::to_value(&generate_ruleset(config).nftables).unwrap();
        json["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["add"]["rule"]["chain"] == "forward")
            .map(|r| {
                r["add"]["rule"]["comment"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn upnp_accept_exists_only_while_upnp_is_enabled() {
        let mut config = create_test_config();
        assert!(
            !forward_rule_comments(&config)
                .iter()
                .any(|c| c == "ks:upnp")
        );

        config.upnp_forward = Some(keystone_core::upnp::UpnpForwardAccept {
            wan_interface: "eth0".to_string(),
            lan_interfaces: vec!["eth1".to_string(), "eth2".to_string()],
        });
        let comments = forward_rule_comments(&config);
        let upnp = comments
            .iter()
            .position(|c| c == "ks:upnp")
            .expect("upnp accept rule");
        let dnat = comments
            .iter()
            .position(|c| c.contains("Web Server DNAT accept (tcp)"))
            .expect("port forward accept rule");
        assert!(
            dnat < upnp,
            "upnp accept must follow the port forward accepts: {comments:?}"
        );

        let json = serde_json::to_value(&generate_ruleset(&config).nftables).unwrap();
        let rule = json["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["add"]["rule"]["comment"] == "ks:upnp")
            .unwrap()
            .to_string();
        assert!(rule.contains("\"dnat\""), "{rule}");
        assert!(rule.contains("\"status\""), "{rule}");
        assert!(rule.contains("\"accept\""), "{rule}");
        assert!(rule.contains("\"eth0\""), "{rule}");
        assert!(
            rule.contains("\"eth1\"") && rule.contains("\"eth2\""),
            "{rule}"
        );
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

    /// Rules whose comment starts with `prefix`, as nftables JSON objects.
    fn rules_commented(config: &FirewallConfig, prefix: &str) -> Vec<serde_json::Value> {
        let json = serde_json::to_value(&generate_ruleset(config).nftables).unwrap();
        json["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|object| {
                object["add"]["rule"]["comment"]
                    .as_str()
                    .is_some_and(|comment| comment.starts_with(prefix))
            })
            .map(|object| object["add"]["rule"].clone())
            .collect()
    }

    /// Named sets with the given name, as nftables JSON objects.
    fn sets_named(config: &FirewallConfig, name: &str) -> Vec<serde_json::Value> {
        let json = serde_json::to_value(&generate_ruleset(config).nftables).unwrap();
        json["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|object| object["add"]["set"]["name"] == name)
            .map(|object| object["add"]["set"].clone())
            .collect()
    }

    fn group_config(addresses: &[&str]) -> FirewallConfig {
        let mut config = create_test_config();
        config.input_rules.clear();
        config.port_forwards.clear();
        config.address_groups = vec![AddressGroup {
            id: Some(1),
            name: "lan_hosts".into(),
            description: None,
            entries: addresses.iter().map(|a| a.to_string()).collect(),
        }];
        config
    }

    fn group_ssh_rule(id: i64, source_group: &str) -> InputRule {
        InputRule {
            id: Some(id),
            name: "Group SSH".into(),
            source_group: Some(source_group.into()),
            protocol: Some(RuleProtocol::Tcp),
            port_start: Some(22),
            ..Default::default()
        }
    }

    #[test]
    fn v4_group_rule_matches_only_the_v4_set() {
        let mut config = group_config(&["10.0.0.0/8", "10.1.2.3"]);
        config.input_rules.push(group_ssh_rule(4, "lan_hosts"));
        let rules = rules_commented(&config, "ks:input:4 ");
        assert_eq!(rules.len(), 1, "{rules:?}");
        let text = rules[0].to_string();
        assert!(text.contains("\"@lan_hosts_v4\""), "{text}");
        assert!(!text.contains("lan_hosts_v6"), "{text}");
        assert!(text.contains("\"protocol\":\"ip\""), "{text}");

        let set = sets_named(&config, "lan_hosts_v4");
        assert_eq!(set.len(), 2, "one set per filter and NAT table");
        assert_eq!(set[0]["type"], "ipv4_addr");
        assert_eq!(set[0]["flags"], serde_json::json!(["interval"]));
        // 10.1.2.3 lies inside 10.0.0.0/8 and is dropped from the set.
        assert_eq!(set[0]["elem"].as_array().unwrap().len(), 1, "{set:?}");
        assert!(sets_named(&config, "lan_hosts_v6").is_empty());
    }

    #[test]
    fn v6_group_rule_matches_only_the_v6_set() {
        let mut config = group_config(&["fd00::/64"]);
        config.input_rules.push(group_ssh_rule(4, "lan_hosts"));
        let rules = rules_commented(&config, "ks:input:4 ");
        assert_eq!(rules.len(), 1, "{rules:?}");
        let text = rules[0].to_string();
        assert!(text.contains("\"@lan_hosts_v6\""), "{text}");
        assert!(text.contains("\"protocol\":\"ip6\""), "{text}");
        assert!(!text.contains("lan_hosts_v4"), "{text}");
        let set = sets_named(&config, "lan_hosts_v6");
        assert_eq!(set[0]["type"], "ipv6_addr");
    }

    #[test]
    fn mixed_group_rule_is_emitted_once_per_family() {
        let mut config = group_config(&["192.0.2.0/24", "2001:db8::/32"]);
        config.input_rules.push(group_ssh_rule(4, "lan_hosts"));
        let rules = rules_commented(&config, "ks:input:4 ");
        assert_eq!(rules.len(), 2, "{rules:?}");
        let texts: Vec<String> = rules.iter().map(|r| r.to_string()).collect();
        assert!(
            texts
                .iter()
                .any(|t| t.contains("\"@lan_hosts_v4\"") && !t.contains("@lan_hosts_v6"))
        );
        assert!(
            texts
                .iter()
                .any(|t| t.contains("\"@lan_hosts_v6\"") && !t.contains("@lan_hosts_v4"))
        );
        // Both families share the comment, so their counters are summed.
        assert!(rules.iter().all(|r| r["comment"] == "ks:input:4 Group SSH"));
    }

    #[test]
    fn port_group_becomes_a_lookup_for_each_tcp_and_udp_rule() {
        let mut config = group_config(&["10.0.0.0/8"]);
        config.port_groups = vec![PortGroup {
            id: Some(1),
            name: "web".into(),
            description: None,
            entries: vec!["80".into(), "443".into(), "8000-8100".into()],
        }];
        config.forward_rules.push(ForwardRule {
            id: Some(9),
            name: "Web out".into(),
            source_group: Some("lan_hosts".into()),
            protocol: Some(RuleProtocol::TcpUdp),
            dest_port_group: Some("web".into()),
            ..Default::default()
        });
        let rules = rules_commented(&config, "ks:forward:9 ");
        assert_eq!(rules.len(), 2, "tcp and udp: {rules:?}");
        for rule in &rules {
            let text = rule.to_string();
            assert!(text.contains("\"@web_ports\""), "{text}");
            assert!(text.contains("\"@lan_hosts_v4\""), "{text}");
        }
        let set = sets_named(&config, "web_ports");
        assert_eq!(set[0]["type"], "inet_service");
        assert_eq!(set[0]["elem"][0], 80);
        assert_eq!(set[0]["elem"][2]["range"], serde_json::json!([8000, 8100]));
    }

    #[test]
    fn rule_naming_an_unknown_group_is_not_emitted() {
        let mut config = group_config(&["10.0.0.0/8"]);
        config.input_rules.push(group_ssh_rule(5, "nobody"));
        assert!(rules_commented(&config, "ks:input:5 ").is_empty());
    }

    #[test]
    fn literal_and_group_families_must_agree() {
        let mut config = group_config(&["fd00::/64"]);
        config.forward_rules.push(ForwardRule {
            id: Some(6),
            name: "Mismatch".into(),
            source_ip: Some("10.0.0.1".into()),
            dest_group: Some("lan_hosts".into()),
            ..Default::default()
        });
        assert!(rules_commented(&config, "ks:forward:6 ").is_empty());
    }

    #[test]
    fn port_forward_source_group_must_have_ipv4_entries() {
        let mut config = group_config(&["fd00::/64"]);
        config.port_forwards.push(PortForward {
            id: Some(3),
            name: "Web".into(),
            enabled: true,
            protocol: RuleProtocol::Tcp,
            external_port_start: 8080,
            source_group: Some("lan_hosts".into()),
            dest_ip: "192.168.1.100".into(),
            ..Default::default()
        });
        assert!(rules_commented(&config, "ks:portfwd:3 ").is_empty());

        config.address_groups[0].entries = vec!["10.9.0.0/16".into()];
        let rules = rules_commented(&config, "ks:portfwd:3 ");
        assert_eq!(rules.len(), 1);
        assert!(rules[0].to_string().contains("\"@lan_hosts_v4\""));
    }

    #[test]
    fn forward_rule_with_suffix_masks_the_ipv6_destination() {
        let config = crate::firewall::fixtures::rich_ipv6_suffix();
        let rules = rules_commented(&config, "ks:forward:900");
        assert_eq!(rules.len(), 1, "{rules:?}");
        let text = rules[0].to_string();
        // `ip6 daddr & ::ffff:ffff:ffff:ffff == ::1234`, and nothing IPv4.
        assert!(text.contains("\"&\""), "{text}");
        assert!(text.contains("::ffff:ffff:ffff:ffff"), "{text}");
        assert!(text.contains("::1234"), "{text}");
        assert!(text.contains("\"ip6\""), "{text}");
        assert!(!text.contains("\"ip\""), "{text}");
    }

    #[test]
    fn port_forward_suffix_adds_an_untranslated_ipv6_accept() {
        let config = crate::firewall::fixtures::rich_ipv6_suffix();
        let accepts = rules_commented(&config, "ks:portfwd-accept:901");
        let v6: Vec<String> = accepts
            .iter()
            .map(|rule| rule.to_string())
            .filter(|text| text.contains("IPv6 accept"))
            .collect();
        assert_eq!(v6.len(), 2, "one per protocol: {accepts:?}");
        for text in &v6 {
            assert!(text.contains("::a:b:c:d"), "{text}");
            // The external range, not a translated port.
            assert!(text.contains("27015") && text.contains("27020"), "{text}");
        }
        // The IPv4 DNAT is still generated alongside.
        assert!(!rules_commented(&config, "ks:portfwd:901").is_empty());
    }

    #[test]
    fn ipv6_only_port_forward_has_no_dnat() {
        let mut config = crate::firewall::fixtures::rich_ipv6_suffix();
        config.port_forwards.retain(|pf| pf.id == Some(901));
        config.port_forwards[0].dest_ip.clear();
        assert!(rules_commented(&config, "ks:portfwd:901").is_empty());
        assert!(rules_commented(&config, "ks:portfwd-hairpin:901").is_empty());
        assert!(!rules_commented(&config, "ks:portfwd-accept:901").is_empty());
    }

    #[test]
    fn invalid_suffix_is_not_emitted() {
        let mut config = crate::firewall::fixtures::rich_ipv6_suffix();
        config.forward_rules.last_mut().unwrap().dest_ipv6_suffix = Some("2001:db8::1".into());
        assert!(rules_commented(&config, "ks:forward:900").is_empty());
    }

    #[test]
    fn every_user_rule_carries_a_counter_and_a_ks_comment() {
        let mut config = create_test_config();
        config.forward_rules.push(ForwardRule {
            id: Some(2),
            name: "Fwd".into(),
            ..Default::default()
        });
        for prefix in [
            "ks:input:1 ",
            "ks:forward:2 ",
            "ks:portfwd:1 ",
            "ks:portfwd-accept:1 ",
        ] {
            let rules = rules_commented(&config, prefix);
            assert!(!rules.is_empty(), "no rule for {prefix}");
            for rule in rules {
                assert!(rule["expr"].to_string().contains("\"counter\""), "{rule}");
            }
        }
    }

    #[test]
    fn emitted_rules_follow_the_shared_model_in_order() {
        use crate::firewall::fixtures::sample_configs;
        for (name, config) in sample_configs() {
            let model = crate::firewall::rules::build(&config);
            let json = serde_json::to_value(generate_ruleset(&config).nftables).unwrap();
            let objects = json["nftables"].as_array().unwrap();
            for (chain, spec) in [
                ("input", &model.input),
                ("forward", &model.forward),
                ("prerouting", &model.prerouting),
                ("postrouting", &model.postrouting),
            ] {
                let emitted: Vec<&str> = objects
                    .iter()
                    .filter(|object| object["add"]["rule"]["chain"] == chain)
                    .filter_map(|object| object["add"]["rule"]["comment"].as_str())
                    .collect();
                let modelled: Vec<&str> = spec.rules.iter().map(|r| r.comment.as_str()).collect();
                assert_eq!(emitted, modelled, "{name}: chain {chain}");
            }
        }
    }

    #[test]
    fn rule_comments_are_capped_at_nftables_limit() {
        let long = "x".repeat(300);
        let comment = rule_comment("input", Some(12), &long);
        assert_eq!(comment.len(), MAX_COMMENT_BYTES);
        assert!(comment.starts_with("ks:input:12 "));
        assert_eq!(rule_comment("forward", None, ""), "ks:forward:0");
    }

    /// Every sample ruleset loads into a real kernel, in a throwaway user and
    /// network namespace. This catches JSON that nft parses but refuses, which
    /// the preview's syntax check cannot see. Skipped where unprivileged user
    /// namespaces or nft are unavailable.
    #[test]
    fn sample_rulesets_load_into_the_kernel() {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let namespace_works = Command::new("unshare")
            .args(["-rn", "nft", "list", "ruleset"])
            .output()
            .is_ok_and(|output| output.status.success());
        if !namespace_works {
            return;
        }
        for (name, config) in crate::firewall::fixtures::sample_configs() {
            let json = serde_json::to_string(&generate_ruleset(&config).nftables).unwrap();
            let mut child = Command::new("unshare")
                .args(["-rn", "nft", "-j", "-f", "-"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("nft starts");
            child
                .stdin
                .take()
                .expect("stdin")
                .write_all(json.as_bytes())
                .expect("write ruleset");
            let output = child.wait_with_output().expect("nft finishes");
            assert!(
                output.status.success(),
                "{name} ruleset does not load:\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
