//! nftables ruleset generation from Keystone firewall configuration
//!
//! This module converts Keystone's zone-based firewall configuration into
//! nftables JSON format using the `nftables` crate.

use keystone_core::{
    FirewallAction, FirewallConfig, FirewallGlobalSettings, FirewallPolicy, FirewallZone,
    ForwardRule, InputRule, PortForward, RuleProtocol, ZoneForwardPolicy,
};
use nftables::{
    batch::Batch,
    expr::{Expression, Meta, MetaKey, Payload, PayloadField, RTKey},
    schema::{Chain, NfListObject, Rule, Table},
    stmt::{Counter, Log, Limit, Match, Operator, Statement},
    types::{NfChainPolicy, NfChainType, NfFamily, NfHook},
};
use std::borrow::Cow;
use std::collections::HashMap;

/// Name of the filter table
const FILTER_TABLE: &str = "keystone";
/// Name of the NAT table  
const NAT_TABLE: &str = "keystone_nat";

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

    // Flush existing keystone tables (atomic replacement)
    batch.add_cmd(nftables::schema::NfCmd::Flush(
        nftables::schema::FlushObject::Table(Table {
            family: NfFamily::INet,
            name: Cow::Borrowed(FILTER_TABLE),
            ..Default::default()
        }),
    ));
    batch.add_cmd(nftables::schema::NfCmd::Flush(
        nftables::schema::FlushObject::Table(Table {
            family: NfFamily::INet,
            name: Cow::Borrowed(NAT_TABLE),
            ..Default::default()
        }),
    ));

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
fn build_zone_interface_map(zones: &[FirewallZone]) -> HashMap<String, Vec<String>> {
    zones
        .iter()
        .map(|z| (z.name.clone(), z.interfaces.clone()))
        .collect()
}

/// Get the zone for a given interface name
#[allow(dead_code)]
fn get_zone_for_interface<'a>(
    interface: &str,
    zones: &'a [FirewallZone],
) -> Option<&'a FirewallZone> {
    zones.iter().find(|z| z.interfaces.contains(&interface.to_string()))
}

/// Find zones that should be considered "WAN" (for masquerading)
/// A zone is WAN if it has default drop policies for both input and forward
fn find_wan_zones(zones: &[FirewallZone]) -> Vec<&FirewallZone> {
    zones
        .iter()
        .filter(|z| {
            z.default_input_policy == FirewallPolicy::Drop
                && z.default_forward_policy == FirewallPolicy::Drop
        })
        .collect()
}

// =============================================================================
// Input Chain Generation
// =============================================================================

/// Generate the input chain (traffic destined for the router itself)
fn generate_input_chain(
    batch: &mut Batch<'static>,
    config: &FirewallConfig,
    zone_interfaces: &HashMap<String, Vec<String>>,
) {
    // Create input chain with drop policy
    batch.add(NfListObject::Chain(Chain {
        family: NfFamily::INet,
        table: Cow::Borrowed(FILTER_TABLE),
        name: Cow::Borrowed("input"),
        _type: Some(NfChainType::Filter),
        hook: Some(NfHook::Input),
        prio: Some(0),
        policy: Some(NfChainPolicy::Drop),
        ..Default::default()
    }));

    // Priority 1: Accept established/related connections
    batch.add(NfListObject::Rule(create_conntrack_established_rule(
        FILTER_TABLE,
        "input",
    )));

    // Priority 2: Drop invalid packets
    batch.add(NfListObject::Rule(create_conntrack_invalid_rule(
        FILTER_TABLE,
        "input",
    )));

    // Priority 3: Accept loopback
    batch.add(NfListObject::Rule(create_loopback_rule(FILTER_TABLE, "input")));

    // Priority 3.5: ICMP safety rules (hardcoded - always block dangerous types)
    generate_icmp_input_rules(batch, config, zone_interfaces);

    // Priority 4: User input rules (position-ordered)
    let mut sorted_rules: Vec<_> = config
        .input_rules
        .iter()
        .filter(|r| r.enabled)
        .collect();
    sorted_rules.sort_by_key(|r| r.position);

    for rule in sorted_rules {
        if let Some(nf_rule) = create_input_rule(rule, zone_interfaces) {
            batch.add(NfListObject::Rule(nf_rule));
        }
    }

    // Priority 5: Zone default policies
    for zone in &config.zones {
        if !zone.interfaces.is_empty() && zone.default_input_policy == FirewallPolicy::Accept {
            batch.add(NfListObject::Rule(create_zone_input_default_rule(zone)));
        }
    }
}

/// Create a rule for conntrack established/related acceptance
fn create_conntrack_established_rule(table: &'static str, chain: &'static str) -> Rule<'static> {
    Rule {
        family: NfFamily::INet,
        table: Cow::Borrowed(table),
        chain: Cow::Borrowed(chain),
        expr: vec![
            Statement::Match(Match {
                left: Expression::Named(nftables::expr::NamedExpression::CT(
                    nftables::expr::CT {
                        key: Cow::Borrowed("state"),
                        ..Default::default()
                    },
                )),
                right: Expression::List(vec![
                    Expression::String(Cow::Borrowed("established")),
                    Expression::String(Cow::Borrowed("related")),
                ]),
                op: Operator::IN,
            }),
            Statement::Accept(None),
        ].into(),
        comment: Some(Cow::Borrowed("Accept established/related")),
        ..Default::default()
    }
}

/// Create a rule for conntrack invalid dropping
fn create_conntrack_invalid_rule(table: &'static str, chain: &'static str) -> Rule<'static> {
    Rule {
        family: NfFamily::INet,
        table: Cow::Borrowed(table),
        chain: Cow::Borrowed(chain),
        expr: vec![
            Statement::Match(Match {
                left: Expression::Named(nftables::expr::NamedExpression::CT(
                    nftables::expr::CT {
                        key: Cow::Borrowed("state"),
                        ..Default::default()
                    },
                )),
                right: Expression::String(Cow::Borrowed("invalid")),
                op: Operator::EQ,
            }),
            Statement::Drop(None),
        ].into(),
        comment: Some(Cow::Borrowed("Drop invalid packets")),
        ..Default::default()
    }
}

/// Create a rule to accept loopback traffic
fn create_loopback_rule(table: &'static str, chain: &'static str) -> Rule<'static> {
    Rule {
        family: NfFamily::INet,
        table: Cow::Borrowed(table),
        chain: Cow::Borrowed(chain),
        expr: vec![
            Statement::Match(Match {
                left: Expression::Named(nftables::expr::NamedExpression::Meta(Meta {
                    key: MetaKey::Iifname,
                })),
                right: Expression::String(Cow::Borrowed("lo")),
                op: Operator::EQ,
            }),
            Statement::Accept(None),
        ].into(),
        comment: Some(Cow::Borrowed("Accept loopback")),
        ..Default::default()
    }
}

/// Generate hardcoded ICMP safety rules
/// - Always block dangerous ICMP types: timestamp, redirect, address-mask
/// - Allow ping (echo-request) based on global settings per zone type
fn generate_icmp_input_rules(
    batch: &mut Batch<'static>,
    config: &FirewallConfig,
    zone_interfaces: &HashMap<String, Vec<String>>,
) {
    // First: Drop dangerous ICMP types from everywhere (hardcoded security)
    // ICMP types to block:
    // - Timestamp Request (13) / Reply (14) - can leak system info
    // - Redirect (5) - can be used for MITM attacks
    // - Address Mask Request (17) / Reply (18) - can leak network info
    
    // Block ICMP timestamp (type 13)
    batch.add(NfListObject::Rule(create_icmp_type_drop_rule(13, "Drop ICMP timestamp")));
    // Block ICMP timestamp reply (type 14)  
    batch.add(NfListObject::Rule(create_icmp_type_drop_rule(14, "Drop ICMP timestamp-reply")));
    // Block ICMP redirect (type 5)
    batch.add(NfListObject::Rule(create_icmp_type_drop_rule(5, "Drop ICMP redirect")));
    // Block ICMP address mask request (type 17)
    batch.add(NfListObject::Rule(create_icmp_type_drop_rule(17, "Drop ICMP address-mask-request")));
    // Block ICMP address mask reply (type 18)
    batch.add(NfListObject::Rule(create_icmp_type_drop_rule(18, "Drop ICMP address-mask-reply")));

    // Identify WAN vs LAN zones
    let wan_zones = find_wan_zones(&config.zones);
    let wan_zone_names: Vec<&str> = wan_zones.iter().map(|z| z.name.as_str()).collect();

    // Handle ping based on global settings
    let settings = &config.global_settings;

    // Allow ping from LAN zones if enabled
    if settings.ping_lan_enabled {
        for zone in &config.zones {
            if !wan_zone_names.contains(&zone.name.as_str()) {
                // This is a LAN zone - allow ping
                if let Some(interfaces) = zone_interfaces.get(&zone.name) {
                    if !interfaces.is_empty() {
                        batch.add(NfListObject::Rule(create_icmp_ping_accept_rule(
                            interfaces,
                            &format!("Allow ping from {} (LAN)", zone.name),
                        )));
                    }
                }
            }
        }
    }

    // Allow ping from WAN zones if enabled
    if settings.ping_wan_enabled {
        for zone in &wan_zones {
            if let Some(interfaces) = zone_interfaces.get(&zone.name) {
                if !interfaces.is_empty() {
                    batch.add(NfListObject::Rule(create_icmp_ping_accept_rule(
                        interfaces,
                        &format!("Allow ping from {} (WAN)", zone.name),
                    )));
                }
            }
        }
    }

    // Always allow essential ICMP for proper network operation:
    // - Destination Unreachable (type 3) - needed for PMTUD
    // - Time Exceeded (type 11) - needed for traceroute
    // - Parameter Problem (type 12) - needed for proper error reporting
    batch.add(NfListObject::Rule(create_icmp_essential_accept_rule()));
}

/// Create a rule to drop a specific ICMP type
fn create_icmp_type_drop_rule(icmp_type: u8, comment: &str) -> Rule<'static> {
    Rule {
        family: NfFamily::INet,
        table: Cow::Borrowed(FILTER_TABLE),
        chain: Cow::Borrowed("input"),
        expr: vec![
            // Match ICMP protocol
            Statement::Match(Match {
                left: Expression::Named(nftables::expr::NamedExpression::Meta(Meta {
                    key: MetaKey::L4proto,
                })),
                right: Expression::String(Cow::Borrowed("icmp")),
                op: Operator::EQ,
            }),
            // Match specific ICMP type
            Statement::Match(Match {
                left: Expression::Named(nftables::expr::NamedExpression::Payload(
                    Payload::PayloadField(PayloadField {
                        protocol: Cow::Borrowed("icmp"),
                        field: Cow::Borrowed("type"),
                    }),
                )),
                right: Expression::Number(icmp_type as u32),
                op: Operator::EQ,
            }),
            Statement::Counter(Counter::Anonymous(None)),
            Statement::Drop(None),
        ].into(),
        comment: Some(Cow::Owned(comment.to_string())),
        ..Default::default()
    }
}

/// Create a rule to accept ICMP ping (echo-request) from specific interfaces
fn create_icmp_ping_accept_rule(interfaces: &[String], comment: &str) -> Rule<'static> {
    let ifaces: Vec<Cow<'static, str>> = interfaces
        .iter()
        .map(|s| Cow::Owned(s.clone()))
        .collect();

    let exprs = vec![
        // Match input interface
        Statement::Match(Match {
            left: Expression::Named(nftables::expr::NamedExpression::Meta(Meta {
                key: MetaKey::Iifname,
            })),
            right: if ifaces.len() == 1 {
                Expression::String(ifaces.into_iter().next().unwrap())
            } else {
                Expression::List(ifaces.into_iter().map(Expression::String).collect())
            },
            op: if interfaces.len() == 1 {
                Operator::EQ
            } else {
                Operator::IN
            },
        }),
        // Match ICMP protocol
        Statement::Match(Match {
            left: Expression::Named(nftables::expr::NamedExpression::Meta(Meta {
                key: MetaKey::L4proto,
            })),
            right: Expression::String(Cow::Borrowed("icmp")),
            op: Operator::EQ,
        }),
        // Match echo-request (type 8)
        Statement::Match(Match {
            left: Expression::Named(nftables::expr::NamedExpression::Payload(
                Payload::PayloadField(PayloadField {
                    protocol: Cow::Borrowed("icmp"),
                    field: Cow::Borrowed("type"),
                }),
            )),
            right: Expression::Number(8), // echo-request
            op: Operator::EQ,
        }),
        Statement::Counter(Counter::Anonymous(None)),
        Statement::Accept(None),
    ];

    Rule {
        family: NfFamily::INet,
        table: Cow::Borrowed(FILTER_TABLE),
        chain: Cow::Borrowed("input"),
        expr: exprs.into(),
        comment: Some(Cow::Owned(comment.to_string())),
        ..Default::default()
    }
}

/// Create a rule to accept essential ICMP types for proper network operation
fn create_icmp_essential_accept_rule() -> Rule<'static> {
    Rule {
        family: NfFamily::INet,
        table: Cow::Borrowed(FILTER_TABLE),
        chain: Cow::Borrowed("input"),
        expr: vec![
            // Match ICMP protocol
            Statement::Match(Match {
                left: Expression::Named(nftables::expr::NamedExpression::Meta(Meta {
                    key: MetaKey::L4proto,
                })),
                right: Expression::String(Cow::Borrowed("icmp")),
                op: Operator::EQ,
            }),
            // Match essential types: 3 (dest-unreachable), 11 (time-exceeded), 12 (parameter-problem)
            Statement::Match(Match {
                left: Expression::Named(nftables::expr::NamedExpression::Payload(
                    Payload::PayloadField(PayloadField {
                        protocol: Cow::Borrowed("icmp"),
                        field: Cow::Borrowed("type"),
                    }),
                )),
                right: Expression::List(vec![
                    Expression::Number(3),  // destination-unreachable
                    Expression::Number(11), // time-exceeded
                    Expression::Number(12), // parameter-problem
                ]),
                op: Operator::IN,
            }),
            Statement::Counter(Counter::Anonymous(None)),
            Statement::Accept(None),
        ].into(),
        comment: Some(Cow::Borrowed("Accept essential ICMP (dest-unreach, time-exceeded, param-problem)")),
        ..Default::default()
    }
}

/// Create an nftables rule from an InputRule
fn create_input_rule(
    rule: &InputRule,
    zone_interfaces: &HashMap<String, Vec<String>>,
) -> Option<Rule<'static>> {
    let mut exprs: Vec<Statement> = Vec::new();

    // Match source zone (interface)
    if let Some(ref zone_name) = rule.zone {
        if let Some(interfaces) = zone_interfaces.get(zone_name) {
            if !interfaces.is_empty() {
                exprs.push(create_iif_match(interfaces));
            }
        }
    }

    // Match source IP
    if let Some(ref src_ip) = rule.source_ip {
        exprs.push(create_saddr_match(src_ip));
    }

    // Match protocol and ports
    if let Some(protocol) = &rule.protocol {
        match protocol {
            RuleProtocol::Any => {}
            RuleProtocol::Tcp => {
                exprs.push(create_protocol_match("tcp"));
                if let Some(port_start) = rule.port_start {
                    exprs.push(create_dport_match(port_start, rule.port_end));
                }
            }
            RuleProtocol::Udp => {
                exprs.push(create_protocol_match("udp"));
                if let Some(port_start) = rule.port_start {
                    exprs.push(create_dport_match(port_start, rule.port_end));
                }
            }
            RuleProtocol::TcpUdp => {
                // For tcp+udp we need to create meta l4proto match
                exprs.push(Statement::Match(Match {
                    left: Expression::Named(nftables::expr::NamedExpression::Meta(Meta {
                        key: MetaKey::L4proto,
                    })),
                    right: Expression::List(vec![
                        Expression::String(Cow::Borrowed("tcp")),
                        Expression::String(Cow::Borrowed("udp")),
                    ]),
                    op: Operator::IN,
                }));
                if let Some(port_start) = rule.port_start {
                    exprs.push(create_dport_match(port_start, rule.port_end));
                }
            }
            RuleProtocol::Icmp => {
                exprs.push(create_protocol_match("icmp"));
            }
            RuleProtocol::Icmpv6 => {
                exprs.push(create_protocol_match("icmpv6"));
            }
        }
    }

    // Rate limiting
    if let Some(ref rate_limit) = rule.rate_limit {
        if let Some(limit_stmt) = parse_rate_limit(rate_limit) {
            exprs.push(limit_stmt);
        }
    }

    // Logging
    if rule.log_enabled {
        let prefix = rule
            .log_prefix
            .as_ref()
            .map(|s| Cow::Owned(s.clone()))
            .unwrap_or_else(|| Cow::Owned(format!("keystone-input-{}: ", rule.name)));
        exprs.push(Statement::Log(Some(Log {
            prefix: Some(prefix),
            group: None,
            snaplen: None,
            queue_threshold: None,
            level: None,
            flags: None,
        })));
    }

    // Counter
    exprs.push(Statement::Counter(Counter::Anonymous(None)));

    // Action
    exprs.push(match rule.action {
        FirewallAction::Accept => Statement::Accept(None),
        FirewallAction::Drop => Statement::Drop(None),
        FirewallAction::Reject => Statement::Reject(None),
    });

    Some(Rule {
        family: NfFamily::INet,
        table: Cow::Borrowed(FILTER_TABLE),
        chain: Cow::Borrowed("input"),
        expr: exprs.into(),
        comment: Some(Cow::Owned(rule.name.clone())),
        ..Default::default()
    })
}

/// Create a zone default input policy rule
fn create_zone_input_default_rule(zone: &FirewallZone) -> Rule<'static> {
    let interfaces: Vec<Cow<'static, str>> = zone
        .interfaces
        .iter()
        .map(|s| Cow::Owned(s.clone()))
        .collect();

    Rule {
        family: NfFamily::INet,
        table: Cow::Borrowed(FILTER_TABLE),
        chain: Cow::Borrowed("input"),
        expr: vec![
            Statement::Match(Match {
                left: Expression::Named(nftables::expr::NamedExpression::Meta(Meta {
                    key: MetaKey::Iifname,
                })),
                right: if interfaces.len() == 1 {
                    Expression::String(interfaces.into_iter().next().unwrap())
                } else {
                    Expression::List(interfaces.into_iter().map(Expression::String).collect())
                },
                op: if zone.interfaces.len() == 1 {
                    Operator::EQ
                } else {
                    Operator::IN
                },
            }),
            Statement::Counter(Counter::Anonymous(None)),
            Statement::Accept(None),
        ].into(),
        comment: Some(Cow::Owned(format!("{} zone default: accept input", zone.name))),
        ..Default::default()
    }
}

// =============================================================================
// Forward Chain Generation
// =============================================================================

/// Generate the forward chain (traffic passing through the router)
fn generate_forward_chain(
    batch: &mut Batch<'static>,
    config: &FirewallConfig,
    zone_interfaces: &HashMap<String, Vec<String>>,
) {
    // Create forward chain with drop policy
    batch.add(NfListObject::Chain(Chain {
        family: NfFamily::INet,
        table: Cow::Borrowed(FILTER_TABLE),
        name: Cow::Borrowed("forward"),
        _type: Some(NfChainType::Filter),
        hook: Some(NfHook::Forward),
        prio: Some(0),
        policy: Some(NfChainPolicy::Drop),
        ..Default::default()
    }));

    // Priority 1: Accept established/related connections
    batch.add(NfListObject::Rule(create_conntrack_established_rule(
        FILTER_TABLE,
        "forward",
    )));

    // Priority 2: Drop invalid packets
    batch.add(NfListObject::Rule(create_conntrack_invalid_rule(
        FILTER_TABLE,
        "forward",
    )));

    // Priority 3: User forward rules (position-ordered)
    let mut sorted_rules: Vec<_> = config
        .forward_rules
        .iter()
        .filter(|r| r.enabled)
        .collect();
    sorted_rules.sort_by_key(|r| r.position);

    for rule in sorted_rules {
        if let Some(nf_rule) = create_forward_rule(rule, zone_interfaces) {
            batch.add(NfListObject::Rule(nf_rule));
        }
    }

    // Priority 4: Zone-to-zone forwarding policies
    for policy in &config.zone_forwards {
        if policy.enabled {
            if let Some(nf_rule) = create_zone_forward_rule(policy, zone_interfaces) {
                batch.add(NfListObject::Rule(nf_rule));
            }
        }
    }
}

/// Create an nftables rule from a ForwardRule
fn create_forward_rule(
    rule: &ForwardRule,
    zone_interfaces: &HashMap<String, Vec<String>>,
) -> Option<Rule<'static>> {
    let mut exprs: Vec<Statement> = Vec::new();

    // Match source zone
    if let Some(ref zone_name) = rule.source_zone {
        if let Some(interfaces) = zone_interfaces.get(zone_name) {
            if !interfaces.is_empty() {
                exprs.push(create_iif_match(interfaces));
            }
        }
    }

    // Match destination zone
    if let Some(ref zone_name) = rule.dest_zone {
        if let Some(interfaces) = zone_interfaces.get(zone_name) {
            if !interfaces.is_empty() {
                exprs.push(create_oif_match(interfaces));
            }
        }
    }

    // Match source IP
    if let Some(ref src_ip) = rule.source_ip {
        exprs.push(create_saddr_match(src_ip));
    }

    // Match destination IP
    if let Some(ref dst_ip) = rule.dest_ip {
        exprs.push(create_daddr_match(dst_ip));
    }

    // Match protocol and ports
    if let Some(protocol) = &rule.protocol {
        match protocol {
            RuleProtocol::Any => {}
            RuleProtocol::Tcp => {
                exprs.push(create_protocol_match("tcp"));
                if let Some(port_start) = rule.dest_port_start {
                    exprs.push(create_dport_match(port_start, rule.dest_port_end));
                }
            }
            RuleProtocol::Udp => {
                exprs.push(create_protocol_match("udp"));
                if let Some(port_start) = rule.dest_port_start {
                    exprs.push(create_dport_match(port_start, rule.dest_port_end));
                }
            }
            RuleProtocol::TcpUdp => {
                exprs.push(Statement::Match(Match {
                    left: Expression::Named(nftables::expr::NamedExpression::Meta(Meta {
                        key: MetaKey::L4proto,
                    })),
                    right: Expression::List(vec![
                        Expression::String(Cow::Borrowed("tcp")),
                        Expression::String(Cow::Borrowed("udp")),
                    ]),
                    op: Operator::IN,
                }));
                if let Some(port_start) = rule.dest_port_start {
                    exprs.push(create_dport_match(port_start, rule.dest_port_end));
                }
            }
            RuleProtocol::Icmp => {
                exprs.push(create_protocol_match("icmp"));
            }
            RuleProtocol::Icmpv6 => {
                exprs.push(create_protocol_match("icmpv6"));
            }
        }
    }

    // Rate limiting
    if let Some(ref rate_limit) = rule.rate_limit {
        if let Some(limit_stmt) = parse_rate_limit(rate_limit) {
            exprs.push(limit_stmt);
        }
    }

    // Logging
    if rule.log_enabled {
        let prefix = rule
            .log_prefix
            .as_ref()
            .map(|s| Cow::Owned(s.clone()))
            .unwrap_or_else(|| Cow::Owned(format!("keystone-fwd-{}: ", rule.name)));
        exprs.push(Statement::Log(Some(Log {
            prefix: Some(prefix),
            group: None,
            snaplen: None,
            queue_threshold: None,
            level: None,
            flags: None,
        })));
    }

    // Counter
    exprs.push(Statement::Counter(Counter::Anonymous(None)));

    // Action
    exprs.push(match rule.action {
        FirewallAction::Accept => Statement::Accept(None),
        FirewallAction::Drop => Statement::Drop(None),
        FirewallAction::Reject => Statement::Reject(None),
    });

    Some(Rule {
        family: NfFamily::INet,
        table: Cow::Borrowed(FILTER_TABLE),
        chain: Cow::Borrowed("forward"),
        expr: exprs.into(),
        comment: Some(Cow::Owned(rule.name.clone())),
        ..Default::default()
    })
}

/// Create a zone-to-zone forwarding rule
fn create_zone_forward_rule(
    policy: &ZoneForwardPolicy,
    zone_interfaces: &HashMap<String, Vec<String>>,
) -> Option<Rule<'static>> {
    let src_interfaces = zone_interfaces.get(&policy.source_zone)?;
    let dst_interfaces = zone_interfaces.get(&policy.dest_zone)?;

    if src_interfaces.is_empty() || dst_interfaces.is_empty() {
        return None;
    }

    let mut exprs: Vec<Statement> = Vec::new();

    // Match source interfaces
    exprs.push(create_iif_match(src_interfaces));

    // Match destination interfaces
    exprs.push(create_oif_match(dst_interfaces));

    // Counter
    exprs.push(Statement::Counter(Counter::Anonymous(None)));

    // Action
    exprs.push(match policy.policy {
        FirewallAction::Accept => Statement::Accept(None),
        FirewallAction::Drop => Statement::Drop(None),
        FirewallAction::Reject => Statement::Reject(None),
    });

    Some(Rule {
        family: NfFamily::INet,
        table: Cow::Borrowed(FILTER_TABLE),
        chain: Cow::Borrowed("forward"),
        expr: exprs.into(),
        comment: Some(Cow::Owned(format!(
            "{} -> {}: {}",
            policy.source_zone, policy.dest_zone, policy.policy
        ))),
        ..Default::default()
    })
}

// =============================================================================
// Output Chain Generation
// =============================================================================

/// Generate the output chain (traffic from the router - permissive by default)
fn generate_output_chain(batch: &mut Batch<'static>) {
    batch.add(NfListObject::Chain(Chain {
        family: NfFamily::INet,
        table: Cow::Borrowed(FILTER_TABLE),
        name: Cow::Borrowed("output"),
        _type: Some(NfChainType::Filter),
        hook: Some(NfHook::Output),
        prio: Some(0),
        policy: Some(NfChainPolicy::Accept),
        ..Default::default()
    }));
}

// =============================================================================
// NAT Chain Generation
// =============================================================================

/// Generate the prerouting chain for DNAT (port forwards)
fn generate_prerouting_chain(
    batch: &mut Batch<'static>,
    config: &FirewallConfig,
    zone_interfaces: &HashMap<String, Vec<String>>,
) {
    // Create prerouting chain
    batch.add(NfListObject::Chain(Chain {
        family: NfFamily::INet,
        table: Cow::Borrowed(NAT_TABLE),
        name: Cow::Borrowed("prerouting"),
        _type: Some(NfChainType::NAT),
        hook: Some(NfHook::Prerouting),
        prio: Some(-100), // dstnat priority
        ..Default::default()
    }));

    // Collect LAN interfaces for hairpin NAT
    let wan_zones = find_wan_zones(&config.zones);
    let wan_zone_names: Vec<&str> = wan_zones.iter().map(|z| z.name.as_str()).collect();
    let mut lan_interfaces: Vec<String> = Vec::new();
    for zone in &config.zones {
        if !wan_zone_names.contains(&zone.name.as_str()) {
            lan_interfaces.extend(zone.interfaces.clone());
        }
    }

    // Port forwards
    for pf in &config.port_forwards {
        if pf.enabled {
            // For tcp+udp, we need two separate rules
            match pf.protocol {
                RuleProtocol::TcpUdp => {
                    if let Some(rule) = create_port_forward_rule(pf, zone_interfaces, "tcp") {
                        batch.add(NfListObject::Rule(rule));
                    }
                    if let Some(rule) = create_port_forward_rule(pf, zone_interfaces, "udp") {
                        batch.add(NfListObject::Rule(rule));
                    }
                    // Hairpin NAT rules (if enabled)
                    if config.global_settings.hairpin_nat_enabled && !lan_interfaces.is_empty() {
                        if let Some(rule) = create_hairpin_dnat_rule(pf, &lan_interfaces, "tcp") {
                            batch.add(NfListObject::Rule(rule));
                        }
                        if let Some(rule) = create_hairpin_dnat_rule(pf, &lan_interfaces, "udp") {
                            batch.add(NfListObject::Rule(rule));
                        }
                    }
                }
                RuleProtocol::Tcp => {
                    if let Some(rule) = create_port_forward_rule(pf, zone_interfaces, "tcp") {
                        batch.add(NfListObject::Rule(rule));
                    }
                    if config.global_settings.hairpin_nat_enabled && !lan_interfaces.is_empty() {
                        if let Some(rule) = create_hairpin_dnat_rule(pf, &lan_interfaces, "tcp") {
                            batch.add(NfListObject::Rule(rule));
                        }
                    }
                }
                RuleProtocol::Udp => {
                    if let Some(rule) = create_port_forward_rule(pf, zone_interfaces, "udp") {
                        batch.add(NfListObject::Rule(rule));
                    }
                    if config.global_settings.hairpin_nat_enabled && !lan_interfaces.is_empty() {
                        if let Some(rule) = create_hairpin_dnat_rule(pf, &lan_interfaces, "udp") {
                            batch.add(NfListObject::Rule(rule));
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

/// Create a port forward (DNAT) rule
fn create_port_forward_rule(
    pf: &PortForward,
    zone_interfaces: &HashMap<String, Vec<String>>,
    protocol: &'static str,
) -> Option<Rule<'static>> {
    let mut exprs: Vec<Statement> = Vec::new();

    // Match source zone (input interface)
    if let Some(ref zone_name) = pf.source_zone {
        if let Some(interfaces) = zone_interfaces.get(zone_name) {
            if !interfaces.is_empty() {
                exprs.push(create_iif_match(interfaces));
            }
        }
    }

    // Match source IP if specified
    if let Some(ref src_ip) = pf.source_ip {
        exprs.push(create_saddr_match(src_ip));
    }

    // Match protocol
    exprs.push(create_protocol_match(protocol));

    // Match destination port(s)
    exprs.push(create_dport_match(pf.external_port_start, pf.external_port_end));

    // Counter
    exprs.push(Statement::Counter(Counter::Anonymous(None)));

    // DNAT action
    let dest_port = pf.dest_port.unwrap_or(pf.external_port_start);

    exprs.push(Statement::DNAT(Some(nftables::stmt::NAT {
        addr: Some(Expression::String(Cow::Owned(pf.dest_ip.clone()))),
        family: None,
        port: Some(Expression::Number(dest_port as u32)),
        flags: None,
    })));

    Some(Rule {
        family: NfFamily::INet,
        table: Cow::Borrowed(NAT_TABLE),
        chain: Cow::Borrowed("prerouting"),
        expr: exprs.into(),
        comment: Some(Cow::Owned(format!("{} ({})", pf.name, protocol))),
        ..Default::default()
    })
}

/// Create a hairpin NAT DNAT rule for LAN clients accessing port forwards via external IP
///
/// Hairpin NAT allows LAN clients to access port-forwarded services using the router's
/// external (WAN) IP address. This works by matching packets from LAN interfaces that
/// are destined to "local" addresses (using fib daddr type local) on the forwarded port,
/// then DNATing them to the internal server.
fn create_hairpin_dnat_rule(
    pf: &PortForward,
    lan_interfaces: &[String],
    protocol: &'static str,
) -> Option<Rule<'static>> {
    if lan_interfaces.is_empty() {
        return None;
    }

    let mut exprs: Vec<Statement> = Vec::new();

    // Match input from LAN interfaces
    exprs.push(create_iif_match(lan_interfaces));

    // Match protocol
    exprs.push(create_protocol_match(protocol));

    // Match destination port(s)
    exprs.push(create_dport_match(pf.external_port_start, pf.external_port_end));

    // Match packets destined to a local address (router's own IPs)
    // This catches traffic to any of the router's IPs, including WAN IP
    exprs.push(Statement::Match(Match {
        left: Expression::Named(nftables::expr::NamedExpression::Fib(nftables::expr::Fib {
            result: nftables::expr::FibResult::Type,
            flags: [nftables::expr::FibFlag::Daddr].into_iter().collect(),
        })),
        right: Expression::String(Cow::Borrowed("local")),
        op: Operator::EQ,
    }));

    // Counter
    exprs.push(Statement::Counter(Counter::Anonymous(None)));

    // DNAT action
    let dest_port = pf.dest_port.unwrap_or(pf.external_port_start);

    exprs.push(Statement::DNAT(Some(nftables::stmt::NAT {
        addr: Some(Expression::String(Cow::Owned(pf.dest_ip.clone()))),
        family: None,
        port: Some(Expression::Number(dest_port as u32)),
        flags: None,
    })));

    Some(Rule {
        family: NfFamily::INet,
        table: Cow::Borrowed(NAT_TABLE),
        chain: Cow::Borrowed("prerouting"),
        expr: exprs.into(),
        comment: Some(Cow::Owned(format!("{} hairpin ({})", pf.name, protocol))),
        ..Default::default()
    })
}

/// Generate the postrouting chain for SNAT (masquerade)
fn generate_postrouting_chain(
    batch: &mut Batch<'static>,
    config: &FirewallConfig,
    _zone_interfaces: &HashMap<String, Vec<String>>,
) {
    // Create postrouting chain
    batch.add(NfListObject::Chain(Chain {
        family: NfFamily::INet,
        table: Cow::Borrowed(NAT_TABLE),
        name: Cow::Borrowed("postrouting"),
        _type: Some(NfChainType::NAT),
        hook: Some(NfHook::Postrouting),
        prio: Some(100), // srcnat priority
        ..Default::default()
    }));

    // Find WAN zones for masquerading
    let wan_zones = find_wan_zones(&config.zones);
    let wan_zone_names: Vec<&str> = wan_zones.iter().map(|z| z.name.as_str()).collect();

    // Collect LAN interfaces for hairpin NAT
    let mut lan_interfaces: Vec<String> = Vec::new();
    for zone in &config.zones {
        if !wan_zone_names.contains(&zone.name.as_str()) {
            lan_interfaces.extend(zone.interfaces.clone());
        }
    }

    // Hairpin NAT SNAT rules - masquerade traffic from LAN to internal servers
    // This is needed so internal servers see the router as the source, enabling
    // the return path to work (server replies to router, router forwards to client)
    if config.global_settings.hairpin_nat_enabled && !lan_interfaces.is_empty() {
        for pf in &config.port_forwards {
            if pf.enabled {
                match pf.protocol {
                    RuleProtocol::TcpUdp => {
                        if let Some(rule) = create_hairpin_snat_rule(pf, &lan_interfaces, "tcp") {
                            batch.add(NfListObject::Rule(rule));
                        }
                        if let Some(rule) = create_hairpin_snat_rule(pf, &lan_interfaces, "udp") {
                            batch.add(NfListObject::Rule(rule));
                        }
                    }
                    RuleProtocol::Tcp => {
                        if let Some(rule) = create_hairpin_snat_rule(pf, &lan_interfaces, "tcp") {
                            batch.add(NfListObject::Rule(rule));
                        }
                    }
                    RuleProtocol::Udp => {
                        if let Some(rule) = create_hairpin_snat_rule(pf, &lan_interfaces, "udp") {
                            batch.add(NfListObject::Rule(rule));
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // WAN masquerade rules
    for zone in wan_zones {
        for iface in &zone.interfaces {
            // MSS clamping for the interface
            batch.add(NfListObject::Rule(create_mss_clamp_rule(iface)));

            // Masquerade for the interface
            batch.add(NfListObject::Rule(create_masquerade_rule(iface)));
        }
    }
}

/// Create a hairpin NAT SNAT rule (masquerade for hairpin traffic)
///
/// For hairpin NAT to work correctly, we need to masquerade traffic from LAN
/// clients that is destined to internal servers (after DNAT). This ensures the
/// server sees the router as the source, so the reply goes back through the router.
fn create_hairpin_snat_rule(
    pf: &PortForward,
    lan_interfaces: &[String],
    protocol: &'static str,
) -> Option<Rule<'static>> {
    if lan_interfaces.is_empty() {
        return None;
    }

    let mut exprs: Vec<Statement> = Vec::new();

    // Match source from LAN interfaces (original source is LAN client)
    exprs.push(create_iif_match(lan_interfaces));

    // Match protocol
    exprs.push(create_protocol_match(protocol));

    // Match destination IP (the internal server)
    exprs.push(create_daddr_match(&pf.dest_ip));

    // Match destination port (the internal server port)
    let dest_port = pf.dest_port.unwrap_or(pf.external_port_start);
    exprs.push(create_dport_match(dest_port, None));

    // Counter
    exprs.push(Statement::Counter(Counter::Anonymous(None)));

    // Masquerade - router becomes the source so server can reply correctly
    exprs.push(Statement::Masquerade(None));

    Some(Rule {
        family: NfFamily::INet,
        table: Cow::Borrowed(NAT_TABLE),
        chain: Cow::Borrowed("postrouting"),
        expr: exprs.into(),
        comment: Some(Cow::Owned(format!("{} hairpin SNAT ({})", pf.name, protocol))),
        ..Default::default()
    })
}

/// Create an MSS clamping rule for an interface
fn create_mss_clamp_rule(interface: &str) -> Rule<'static> {
    Rule {
        family: NfFamily::INet,
        table: Cow::Borrowed(NAT_TABLE),
        chain: Cow::Borrowed("postrouting"),
        expr: vec![
            Statement::Match(Match {
                left: Expression::Named(nftables::expr::NamedExpression::Meta(Meta {
                    key: MetaKey::Oifname,
                })),
                right: Expression::String(Cow::Owned(interface.to_string())),
                op: Operator::EQ,
            }),
            Statement::Match(Match {
                left: Expression::Named(nftables::expr::NamedExpression::Meta(Meta {
                    key: MetaKey::L4proto,
                })),
                right: Expression::String(Cow::Borrowed("tcp")),
                op: Operator::EQ,
            }),
            // Match SYN flag
            Statement::Match(Match {
                left: Expression::Named(nftables::expr::NamedExpression::Payload(
                    Payload::PayloadField(PayloadField {
                        protocol: Cow::Borrowed("tcp"),
                        field: Cow::Borrowed("flags"),
                    }),
                )),
                right: Expression::String(Cow::Borrowed("syn")),
                op: Operator::IN,
            }),
            // Set MSS to path MTU
            Statement::Mangle(nftables::stmt::Mangle {
                key: Expression::Named(nftables::expr::NamedExpression::Payload(
                    Payload::PayloadField(PayloadField {
                        protocol: Cow::Borrowed("tcp"),
                        field: Cow::Borrowed("option"),
                    }),
                )),
                value: Expression::Named(nftables::expr::NamedExpression::RT(nftables::expr::RT {
                    key: RTKey::MTU,
                    family: None,
                })),
            }),
        ].into(),
        comment: Some(Cow::Owned(format!("MSS clamp for {}", interface))),
        ..Default::default()
    }
}

/// Create a masquerade rule for an interface
fn create_masquerade_rule(interface: &str) -> Rule<'static> {
    Rule {
        family: NfFamily::INet,
        table: Cow::Borrowed(NAT_TABLE),
        chain: Cow::Borrowed("postrouting"),
        expr: vec![
            Statement::Match(Match {
                left: Expression::Named(nftables::expr::NamedExpression::Meta(Meta {
                    key: MetaKey::Oifname,
                })),
                right: Expression::String(Cow::Owned(interface.to_string())),
                op: Operator::EQ,
            }),
            Statement::Counter(Counter::Anonymous(None)),
            Statement::Masquerade(None),
        ].into(),
        comment: Some(Cow::Owned(format!("Masquerade for {}", interface))),
        ..Default::default()
    }
}

// =============================================================================
// Helper Functions for Statement Creation
// =============================================================================

/// Create a match statement for input interface(s)
fn create_iif_match(interfaces: &[String]) -> Statement<'static> {
    let ifaces: Vec<Cow<'static, str>> = interfaces
        .iter()
        .map(|s| Cow::Owned(s.clone()))
        .collect();

    Statement::Match(Match {
        left: Expression::Named(nftables::expr::NamedExpression::Meta(Meta {
            key: MetaKey::Iifname,
        })),
        right: if ifaces.len() == 1 {
            Expression::String(ifaces.into_iter().next().unwrap())
        } else {
            Expression::List(ifaces.into_iter().map(Expression::String).collect())
        },
        op: if interfaces.len() == 1 {
            Operator::EQ
        } else {
            Operator::IN
        },
    })
}

/// Create a match statement for output interface(s)
fn create_oif_match(interfaces: &[String]) -> Statement<'static> {
    let ifaces: Vec<Cow<'static, str>> = interfaces
        .iter()
        .map(|s| Cow::Owned(s.clone()))
        .collect();

    Statement::Match(Match {
        left: Expression::Named(nftables::expr::NamedExpression::Meta(Meta {
            key: MetaKey::Oifname,
        })),
        right: if ifaces.len() == 1 {
            Expression::String(ifaces.into_iter().next().unwrap())
        } else {
            Expression::List(ifaces.into_iter().map(Expression::String).collect())
        },
        op: if interfaces.len() == 1 {
            Operator::EQ
        } else {
            Operator::IN
        },
    })
}

/// Create a match statement for source address
fn create_saddr_match(addr: &str) -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(nftables::expr::NamedExpression::Payload(
            Payload::PayloadField(PayloadField {
                protocol: Cow::Borrowed("ip"),
                field: Cow::Borrowed("saddr"),
            }),
        )),
        right: Expression::String(Cow::Owned(addr.to_string())),
        op: Operator::EQ,
    })
}

/// Create a match statement for destination address
fn create_daddr_match(addr: &str) -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(nftables::expr::NamedExpression::Payload(
            Payload::PayloadField(PayloadField {
                protocol: Cow::Borrowed("ip"),
                field: Cow::Borrowed("daddr"),
            }),
        )),
        right: Expression::String(Cow::Owned(addr.to_string())),
        op: Operator::EQ,
    })
}

/// Create a match statement for protocol
fn create_protocol_match(protocol: &'static str) -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(nftables::expr::NamedExpression::Meta(Meta {
            key: MetaKey::L4proto,
        })),
        right: Expression::String(Cow::Borrowed(protocol)),
        op: Operator::EQ,
    })
}

/// Create a match statement for destination port(s)
fn create_dport_match(port_start: u16, port_end: Option<u16>) -> Statement<'static> {
    let port_expr = if let Some(end) = port_end {
        if end > port_start {
            // Port range
            Expression::Range(Box::new(nftables::expr::Range {
                range: [
                    Expression::Number(port_start as u32),
                    Expression::Number(end as u32),
                ],
            }))
        } else {
            Expression::Number(port_start as u32)
        }
    } else {
        Expression::Number(port_start as u32)
    };

    Statement::Match(Match {
        left: Expression::Named(nftables::expr::NamedExpression::Payload(
            Payload::PayloadField(PayloadField {
                protocol: Cow::Borrowed("th"),
                field: Cow::Borrowed("dport"),
            }),
        )),
        right: port_expr,
        op: if port_end.is_some() && port_end.unwrap() > port_start {
            Operator::IN
        } else {
            Operator::EQ
        },
    })
}

/// Parse a rate limit string (e.g., "10/minute") into a Limit statement
fn parse_rate_limit(rate_str: &str) -> Option<Statement<'static>> {
    // Parse format: "count/unit" where unit is second, minute, hour, day
    let parts: Vec<&str> = rate_str.split('/').collect();
    if parts.len() != 2 {
        return None;
    }

    let rate: u32 = parts[0].parse().ok()?;
    let unit = match parts[1].to_lowercase().as_str() {
        "second" | "sec" | "s" => "second",
        "minute" | "min" | "m" => "minute",
        "hour" | "hr" | "h" => "hour",
        "day" | "d" => "day",
        _ => return None,
    };

    Some(Statement::Limit(Limit {
        rate,
        rate_unit: None,
        per: Some(Cow::Borrowed(unit)),
        burst: None,
        burst_unit: None,
        inv: None,
    }))
}

// =============================================================================
// Preview Generation
// =============================================================================

/// Generate a human-readable preview of the firewall rules
fn generate_preview(
    config: &FirewallConfig,
    zone_interfaces: &HashMap<String, Vec<String>>,
) -> String {
    let mut output = String::new();
    let timestamp = chrono_lite_now();

    output.push_str("#!/usr/sbin/nft -f\n");
    output.push_str("# Keystone Firewall - Auto-generated\n");
    output.push_str(&format!("# Generated: {}\n\n", timestamp));

    // Filter table
    output.push_str(&format!("table inet {} {{\n", FILTER_TABLE));

    // Input chain
    output.push_str("    # ========================================\n");
    output.push_str("    # Input Chain (traffic TO the router)\n");
    output.push_str("    # ========================================\n");
    output.push_str("    chain input {\n");
    output.push_str("        type filter hook input priority filter; policy drop;\n");
    output.push_str("        \n");
    output.push_str("        # Priority 1: Established/Related connections\n");
    output.push_str("        ct state established,related accept\n");
    output.push_str("        \n");
    output.push_str("        # Priority 2: Invalid packets\n");
    output.push_str("        ct state invalid drop\n");
    output.push_str("        \n");
    output.push_str("        # Priority 3: Loopback\n");
    output.push_str("        iif lo accept\n");
    output.push_str("        \n");

    // ICMP Safety Rules
    output.push_str("        # Priority 3.5: ICMP Safety Rules (hardcoded)\n");
    output.push_str("        # Drop dangerous ICMP types\n");
    output.push_str("        icmp type timestamp-request counter drop\n");
    output.push_str("        icmp type timestamp-reply counter drop\n");
    output.push_str("        icmp type redirect counter drop\n");
    output.push_str("        icmp type address-mask-request counter drop\n");
    output.push_str("        icmp type address-mask-reply counter drop\n");
    output.push_str("        \n");

    // Ping settings based on global settings
    let wan_zones_preview = find_wan_zones(&config.zones);
    let wan_zone_names_preview: Vec<&str> = wan_zones_preview.iter().map(|z| z.name.as_str()).collect();

    if config.global_settings.ping_lan_enabled {
        output.push_str("        # Allow ping from LAN zones\n");
        for zone in &config.zones {
            if !wan_zone_names_preview.contains(&zone.name.as_str()) && !zone.interfaces.is_empty() {
                let ifaces = format_interface_set(&zone.interfaces);
                output.push_str(&format!(
                    "        iifname {} icmp type echo-request counter accept  # ping from {}\n",
                    ifaces, zone.name
                ));
            }
        }
    }

    if config.global_settings.ping_wan_enabled {
        output.push_str("        # Allow ping from WAN zones\n");
        for zone in &wan_zones_preview {
            if !zone.interfaces.is_empty() {
                let ifaces = format_interface_set(&zone.interfaces);
                output.push_str(&format!(
                    "        iifname {} icmp type echo-request counter accept  # ping from {}\n",
                    ifaces, zone.name
                ));
            }
        }
    }

    output.push_str("        # Allow essential ICMP types (required for proper network operation)\n");
    output.push_str("        icmp type { destination-unreachable, time-exceeded, parameter-problem } counter accept\n");
    output.push_str("        \n");
    output.push_str("        # Priority 4: User Input Rules\n");

    let mut sorted_input_rules: Vec<_> = config.input_rules.iter().filter(|r| r.enabled).collect();
    sorted_input_rules.sort_by_key(|r| r.position);

    for rule in &sorted_input_rules {
        output.push_str(&format!("        {}\n", format_input_rule(rule, zone_interfaces)));
    }

    output.push_str("        \n");
    output.push_str("        # Priority 5: Zone defaults\n");
    for zone in &config.zones {
        if !zone.interfaces.is_empty() && zone.default_input_policy == FirewallPolicy::Accept {
            let ifaces = zone.interfaces.join("\", \"");
            output.push_str(&format!(
                "        iifname {{ \"{}\" }} accept  # {} zone: default accept\n",
                ifaces, zone.name
            ));
        }
    }

    output.push_str("    }\n\n");

    // Forward chain
    output.push_str("    # ========================================\n");
    output.push_str("    # Forward Chain (traffic THROUGH the router)\n");
    output.push_str("    # ========================================\n");
    output.push_str("    chain forward {\n");
    output.push_str("        type filter hook forward priority filter; policy drop;\n");
    output.push_str("        \n");
    output.push_str("        # Priority 1: Established/Related\n");
    output.push_str("        ct state established,related accept\n");
    output.push_str("        \n");
    output.push_str("        # Priority 2: Invalid\n");
    output.push_str("        ct state invalid drop\n");
    output.push_str("        \n");
    output.push_str("        # Priority 3: User Forward Rules\n");

    let mut sorted_forward_rules: Vec<_> = config.forward_rules.iter().filter(|r| r.enabled).collect();
    sorted_forward_rules.sort_by_key(|r| r.position);

    for rule in &sorted_forward_rules {
        output.push_str(&format!("        {}\n", format_forward_rule(rule, zone_interfaces)));
    }

    output.push_str("        \n");
    output.push_str("        # Priority 4: Zone-to-Zone Policies\n");
    for policy in &config.zone_forwards {
        if policy.enabled {
            if let (Some(src_ifaces), Some(dst_ifaces)) = (
                zone_interfaces.get(&policy.source_zone),
                zone_interfaces.get(&policy.dest_zone),
            ) {
                if !src_ifaces.is_empty() && !dst_ifaces.is_empty() {
                    let src = format_interface_set(src_ifaces);
                    let dst = format_interface_set(dst_ifaces);
                    output.push_str(&format!(
                        "        iifname {} oifname {} {}  # {} -> {}\n",
                        src, dst, policy.policy, policy.source_zone, policy.dest_zone
                    ));
                }
            }
        }
    }

    output.push_str("    }\n\n");

    // Output chain
    output.push_str("    # ========================================\n");
    output.push_str("    # Output Chain (traffic FROM the router)\n");
    output.push_str("    # ========================================\n");
    output.push_str("    chain output {\n");
    output.push_str("        type filter hook output priority filter; policy accept;\n");
    output.push_str("    }\n");
    output.push_str("}\n\n");

    // NAT table
    output.push_str(&format!("table inet {} {{\n", NAT_TABLE));

    // Prerouting chain
    output.push_str("    # ========================================\n");
    output.push_str("    # DNAT (Port Forwards)\n");
    output.push_str("    # ========================================\n");
    output.push_str("    chain prerouting {\n");
    output.push_str("        type nat hook prerouting priority dstnat;\n");
    output.push_str("        \n");
    output.push_str("        # Port forwards\n");

    for pf in &config.port_forwards {
        if pf.enabled {
            output.push_str(&format!("        {}\n", format_port_forward(pf, zone_interfaces)));
        }
    }

    // Hairpin DNAT rules
    if config.global_settings.hairpin_nat_enabled {
        // Collect LAN interfaces for hairpin preview
        let mut lan_interfaces_preview: Vec<String> = Vec::new();
        for zone in &config.zones {
            if !wan_zone_names_preview.contains(&zone.name.as_str()) {
                lan_interfaces_preview.extend(zone.interfaces.clone());
            }
        }

        if !lan_interfaces_preview.is_empty() {
            output.push_str("        \n");
            output.push_str("        # Hairpin NAT (NAT reflection for LAN clients)\n");
            for pf in &config.port_forwards {
                if pf.enabled {
                    let ifaces = format_interface_set(&lan_interfaces_preview);
                    let dest_port = pf.dest_port.unwrap_or(pf.external_port_start);
                    output.push_str(&format!(
                        "        iifname {} {} dport {} fib daddr type local counter dnat to {}:{}  # {} hairpin\n",
                        ifaces, pf.protocol, 
                        format_port_range(pf.external_port_start, pf.external_port_end),
                        pf.dest_ip, dest_port, pf.name
                    ));
                }
            }
        }
    }

    output.push_str("    }\n\n");

    // Postrouting chain
    output.push_str("    # ========================================\n");
    output.push_str("    # SNAT (Masquerade + MSS Clamping)\n");
    output.push_str("    # ========================================\n");
    output.push_str("    chain postrouting {\n");
    output.push_str("        type nat hook postrouting priority srcnat;\n");
    output.push_str("        \n");

    // Hairpin SNAT rules
    if config.global_settings.hairpin_nat_enabled {
        let mut lan_interfaces_preview: Vec<String> = Vec::new();
        for zone in &config.zones {
            if !wan_zone_names_preview.contains(&zone.name.as_str()) {
                lan_interfaces_preview.extend(zone.interfaces.clone());
            }
        }

        if !lan_interfaces_preview.is_empty() {
            output.push_str("        # Hairpin NAT SNAT (masquerade for hairpin traffic)\n");
            for pf in &config.port_forwards {
                if pf.enabled {
                    let ifaces = format_interface_set(&lan_interfaces_preview);
                    let dest_port = pf.dest_port.unwrap_or(pf.external_port_start);
                    output.push_str(&format!(
                        "        iifname {} {} ip daddr {} dport {} counter masquerade  # {} hairpin SNAT\n",
                        ifaces, pf.protocol, pf.dest_ip, dest_port, pf.name
                    ));
                }
            }
            output.push_str("        \n");
        }
    }

    let wan_zones = find_wan_zones(&config.zones);
    for zone in wan_zones {
        for iface in &zone.interfaces {
            output.push_str(&format!(
                "        # MSS clamping for {} ({})\n",
                iface, zone.name
            ));
            output.push_str(&format!(
                "        oifname \"{}\" tcp flags syn tcp option maxseg size set rt mtu\n",
                iface
            ));
            output.push_str(&format!(
                "        # Masquerade for {} ({})\n",
                iface, zone.name
            ));
            output.push_str(&format!("        oifname \"{}\" masquerade\n", iface));
        }
    }

    output.push_str("    }\n");
    output.push_str("}\n");

    output
}

/// Format an input rule for preview
fn format_input_rule(rule: &InputRule, zone_interfaces: &HashMap<String, Vec<String>>) -> String {
    let mut parts = Vec::new();

    if let Some(ref zone_name) = rule.zone {
        if let Some(interfaces) = zone_interfaces.get(zone_name) {
            if !interfaces.is_empty() {
                parts.push(format!("iifname {}", format_interface_set(interfaces)));
            }
        }
    }

    if let Some(ref src_ip) = rule.source_ip {
        parts.push(format!("ip saddr {}", src_ip));
    }

    if let Some(protocol) = &rule.protocol {
        match protocol {
            RuleProtocol::Any => {}
            RuleProtocol::Tcp | RuleProtocol::Udp => {
                parts.push(format!("{}", protocol));
                if let Some(port) = rule.port_start {
                    parts.push(format!("dport {}", format_port_range(port, rule.port_end)));
                }
            }
            RuleProtocol::TcpUdp => {
                parts.push("meta l4proto { tcp, udp }".to_string());
                if let Some(port) = rule.port_start {
                    parts.push(format!("dport {}", format_port_range(port, rule.port_end)));
                }
            }
            RuleProtocol::Icmp => parts.push("icmp".to_string()),
            RuleProtocol::Icmpv6 => parts.push("icmpv6".to_string()),
        }
    }

    if let Some(ref rate) = rule.rate_limit {
        parts.push(format!("limit rate {}", rate));
    }

    if rule.log_enabled {
        let prefix = rule.log_prefix.as_deref().unwrap_or(&rule.name);
        parts.push(format!("log prefix \"{}\"", prefix));
    }

    parts.push(format!("{}", rule.action));
    parts.push(format!("comment \"{}\"", rule.name));

    parts.join(" ")
}

/// Format a forward rule for preview
fn format_forward_rule(rule: &ForwardRule, zone_interfaces: &HashMap<String, Vec<String>>) -> String {
    let mut parts = Vec::new();

    if let Some(ref zone_name) = rule.source_zone {
        if let Some(interfaces) = zone_interfaces.get(zone_name) {
            if !interfaces.is_empty() {
                parts.push(format!("iifname {}", format_interface_set(interfaces)));
            }
        }
    }

    if let Some(ref zone_name) = rule.dest_zone {
        if let Some(interfaces) = zone_interfaces.get(zone_name) {
            if !interfaces.is_empty() {
                parts.push(format!("oifname {}", format_interface_set(interfaces)));
            }
        }
    }

    if let Some(ref src_ip) = rule.source_ip {
        parts.push(format!("ip saddr {}", src_ip));
    }

    if let Some(ref dst_ip) = rule.dest_ip {
        parts.push(format!("ip daddr {}", dst_ip));
    }

    if let Some(protocol) = &rule.protocol {
        match protocol {
            RuleProtocol::Any => {}
            RuleProtocol::Tcp | RuleProtocol::Udp => {
                parts.push(format!("{}", protocol));
                if let Some(port) = rule.dest_port_start {
                    parts.push(format!("dport {}", format_port_range(port, rule.dest_port_end)));
                }
            }
            RuleProtocol::TcpUdp => {
                parts.push("meta l4proto { tcp, udp }".to_string());
                if let Some(port) = rule.dest_port_start {
                    parts.push(format!("dport {}", format_port_range(port, rule.dest_port_end)));
                }
            }
            RuleProtocol::Icmp => parts.push("icmp".to_string()),
            RuleProtocol::Icmpv6 => parts.push("icmpv6".to_string()),
        }
    }

    if let Some(ref rate) = rule.rate_limit {
        parts.push(format!("limit rate {}", rate));
    }

    if rule.log_enabled {
        let prefix = rule.log_prefix.as_deref().unwrap_or(&rule.name);
        parts.push(format!("log prefix \"{}\"", prefix));
    }

    parts.push(format!("{}", rule.action));
    parts.push(format!("comment \"{}\"", rule.name));

    parts.join(" ")
}

/// Format a port forward for preview
fn format_port_forward(pf: &PortForward, zone_interfaces: &HashMap<String, Vec<String>>) -> String {
    let mut parts = Vec::new();

    if let Some(ref zone_name) = pf.source_zone {
        if let Some(interfaces) = zone_interfaces.get(zone_name) {
            if !interfaces.is_empty() {
                parts.push(format!("iifname {}", format_interface_set(interfaces)));
            }
        }
    }

    if let Some(ref src_ip) = pf.source_ip {
        parts.push(format!("ip saddr {}", src_ip));
    }

    parts.push(format!("{}", pf.protocol));
    parts.push(format!(
        "dport {}",
        format_port_range(pf.external_port_start, pf.external_port_end)
    ));

    let dest_port = pf.dest_port.unwrap_or(pf.external_port_start);
    parts.push(format!("dnat to {}:{}", pf.dest_ip, dest_port));
    parts.push(format!("comment \"{}\"", pf.name));

    parts.join(" ")
}

/// Format an interface set for preview
fn format_interface_set(interfaces: &[String]) -> String {
    if interfaces.len() == 1 {
        format!("\"{}\"", interfaces[0])
    } else {
        format!(
            "{{ {} }}",
            interfaces
                .iter()
                .map(|s| format!("\"{}\"", s))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

/// Format a port range for preview
fn format_port_range(start: u16, end: Option<u16>) -> String {
    if let Some(e) = end {
        if e > start {
            return format!("{}-{}", start, e);
        }
    }
    start.to_string()
}

/// Simple timestamp without external dependency
fn chrono_lite_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("Unix timestamp: {}", duration.as_secs())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> FirewallConfig {
        FirewallConfig {
            zones: vec![
                FirewallZone {
                    id: Some(1),
                    name: "wan".to_string(),
                    description: Some("Internet-facing".to_string()),
                    interfaces: vec!["eth0".to_string()],
                    default_input_policy: FirewallPolicy::Drop,
                    default_forward_policy: FirewallPolicy::Drop,
                },
                FirewallZone {
                    id: Some(2),
                    name: "lan".to_string(),
                    description: Some("Internal network".to_string()),
                    interfaces: vec!["eth1".to_string(), "eth2".to_string()],
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
    fn test_parse_rate_limit() {
        assert!(parse_rate_limit("10/minute").is_some());
        assert!(parse_rate_limit("100/second").is_some());
        assert!(parse_rate_limit("5/hour").is_some());
        assert!(parse_rate_limit("invalid").is_none());
    }

    #[test]
    fn test_format_port_range() {
        assert_eq!(format_port_range(80, None), "80");
        assert_eq!(format_port_range(80, Some(80)), "80");
        assert_eq!(format_port_range(80, Some(90)), "80-90");
    }

    #[test]
    fn test_format_interface_set() {
        assert_eq!(
            format_interface_set(&["eth0".to_string()]),
            "\"eth0\""
        );
        assert_eq!(
            format_interface_set(&["eth0".to_string(), "eth1".to_string()]),
            "{ \"eth0\", \"eth1\" }"
        );
    }
}
