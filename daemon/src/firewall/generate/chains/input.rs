//! Input chain generation for nftables
//!
//! This module handles generation of the input chain which controls
//! traffic destined for the router itself.

use crate::firewall::generate::statements::{
    add_protocol_match_concrete, create_iif_match, create_saddr_match, expand_protocol,
    parse_rate_limit,
};
use crate::firewall::generate::{FILTER_TABLE, find_wan_zones};
use keystone_core::{FirewallAction, FirewallConfig, FirewallPolicy, FirewallZone, InputRule};
use nftables::{
    batch::Batch,
    expr::{Expression, Meta, MetaKey, Payload, PayloadField},
    schema::{Chain, NfListObject, Rule},
    stmt::{Counter, Log, Match, Operator, Statement},
    types::{NfChainPolicy, NfChainType, NfFamily, NfHook},
};
use std::borrow::Cow;
use std::collections::HashMap;

/// Generate the input chain (traffic destined for the router itself)
pub fn generate_input_chain(
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
    batch.add(NfListObject::Rule(create_loopback_rule(
        FILTER_TABLE,
        "input",
    )));

    // Priority 3.5: ICMP safety rules (hardcoded - always block dangerous types)
    generate_icmp_input_rules(batch, config, zone_interfaces);

    // Priority 4: User input rules (position-ordered)
    let mut sorted_rules: Vec<_> = config.input_rules.iter().filter(|r| r.enabled).collect();
    sorted_rules.sort_by_key(|r| r.position);

    for rule in sorted_rules {
        for nf_rule in create_input_rules(rule, zone_interfaces) {
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
pub fn create_conntrack_established_rule(
    table: &'static str,
    chain: &'static str,
) -> Rule<'static> {
    Rule {
        family: NfFamily::INet,
        table: Cow::Borrowed(table),
        chain: Cow::Borrowed(chain),
        expr: vec![
            Statement::Match(Match {
                left: Expression::Named(nftables::expr::NamedExpression::CT(nftables::expr::CT {
                    key: Cow::Borrowed("state"),
                    ..Default::default()
                })),
                right: Expression::List(vec![
                    Expression::String(Cow::Borrowed("established")),
                    Expression::String(Cow::Borrowed("related")),
                ]),
                op: Operator::IN,
            }),
            Statement::Accept(None),
        ]
        .into(),
        comment: Some(Cow::Borrowed("Accept established/related")),
        ..Default::default()
    }
}

/// Create a rule for conntrack invalid dropping
pub fn create_conntrack_invalid_rule(table: &'static str, chain: &'static str) -> Rule<'static> {
    Rule {
        family: NfFamily::INet,
        table: Cow::Borrowed(table),
        chain: Cow::Borrowed(chain),
        expr: vec![
            Statement::Match(Match {
                left: Expression::Named(nftables::expr::NamedExpression::CT(nftables::expr::CT {
                    key: Cow::Borrowed("state"),
                    ..Default::default()
                })),
                right: Expression::String(Cow::Borrowed("invalid")),
                op: Operator::EQ,
            }),
            Statement::Drop(None),
        ]
        .into(),
        comment: Some(Cow::Borrowed("Drop invalid packets")),
        ..Default::default()
    }
}

/// Create a rule to accept loopback traffic
pub fn create_loopback_rule(table: &'static str, chain: &'static str) -> Rule<'static> {
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
        ]
        .into(),
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
    batch.add(NfListObject::Rule(create_icmp_type_drop_rule(
        13,
        "Drop ICMP timestamp",
    )));
    // Block ICMP timestamp reply (type 14)
    batch.add(NfListObject::Rule(create_icmp_type_drop_rule(
        14,
        "Drop ICMP timestamp-reply",
    )));
    // Block ICMP redirect (type 5)
    batch.add(NfListObject::Rule(create_icmp_type_drop_rule(
        5,
        "Drop ICMP redirect",
    )));
    // Block ICMP address mask request (type 17)
    batch.add(NfListObject::Rule(create_icmp_type_drop_rule(
        17,
        "Drop ICMP address-mask-request",
    )));
    // Block ICMP address mask reply (type 18)
    batch.add(NfListObject::Rule(create_icmp_type_drop_rule(
        18,
        "Drop ICMP address-mask-reply",
    )));

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
                if let Some(interfaces) = zone_interfaces.get(&zone.name)
                    && !interfaces.is_empty()
                {
                    batch.add(NfListObject::Rule(create_icmp_ping_accept_rule(
                        interfaces,
                        &format!("Allow IPv4 ping from {} (LAN)", zone.name),
                    )));
                    batch.add(NfListObject::Rule(create_icmpv6_ping_accept_rule(
                        interfaces,
                        &format!("Allow IPv6 ping from {} (LAN)", zone.name),
                    )));
                }
            }
        }
    }

    // Allow ping from WAN zones if enabled
    if settings.ping_wan_enabled {
        for zone in &wan_zones {
            if let Some(interfaces) = zone_interfaces.get(&zone.name)
                && !interfaces.is_empty()
            {
                batch.add(NfListObject::Rule(create_icmp_ping_accept_rule(
                    interfaces,
                    &format!("Allow IPv4 ping from {} (WAN)", zone.name),
                )));
                batch.add(NfListObject::Rule(create_icmpv6_ping_accept_rule(
                    interfaces,
                    &format!("Allow IPv6 ping from {} (WAN)", zone.name),
                )));
            }
        }
    }

    // Always allow essential ICMP for proper network operation:
    // - Destination Unreachable (type 3) - needed for PMTUD
    // - Time Exceeded (type 11) - needed for traceroute
    // - Parameter Problem (type 12) - needed for proper error reporting
    for rule in create_icmp_essential_accept_rules() {
        batch.add(NfListObject::Rule(rule));
    }
    for rule in create_icmpv6_essential_accept_rules() {
        batch.add(NfListObject::Rule(rule));
    }
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
        ]
        .into(),
        comment: Some(Cow::Owned(comment.to_string())),
        ..Default::default()
    }
}

/// Create a rule to accept ICMP ping (echo-request) from specific interfaces
fn create_icmp_ping_accept_rule(interfaces: &[String], comment: &str) -> Rule<'static> {
    let ifaces: Vec<Cow<'static, str>> = interfaces.iter().map(|s| Cow::Owned(s.clone())).collect();

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

/// Create a rule to accept ICMPv6 echo requests from specific interfaces.
fn create_icmpv6_ping_accept_rule(interfaces: &[String], comment: &str) -> Rule<'static> {
    Rule {
        family: NfFamily::INet,
        table: Cow::Borrowed(FILTER_TABLE),
        chain: Cow::Borrowed("input"),
        expr: vec![
            create_iif_match(interfaces),
            Statement::Match(Match {
                left: Expression::Named(nftables::expr::NamedExpression::Meta(Meta {
                    key: MetaKey::L4proto,
                })),
                right: Expression::String(Cow::Borrowed("ipv6-icmp")),
                op: Operator::EQ,
            }),
            Statement::Match(Match {
                left: Expression::Named(nftables::expr::NamedExpression::Payload(
                    Payload::PayloadField(PayloadField {
                        protocol: Cow::Borrowed("icmpv6"),
                        field: Cow::Borrowed("type"),
                    }),
                )),
                right: Expression::Number(128),
                op: Operator::EQ,
            }),
            Statement::Counter(Counter::Anonymous(None)),
            Statement::Accept(None),
        ]
        .into(),
        comment: Some(Cow::Owned(comment.to_string())),
        ..Default::default()
    }
}

/// Create rules to accept essential ICMP types for proper network operation
/// Returns 3 separate rules for dest-unreachable, time-exceeded, parameter-problem
fn create_icmp_essential_accept_rules() -> Vec<Rule<'static>> {
    vec![
        create_icmp_type_accept_rule(3, "Accept ICMP destination-unreachable"),
        create_icmp_type_accept_rule(11, "Accept ICMP time-exceeded"),
        create_icmp_type_accept_rule(12, "Accept ICMP parameter-problem"),
    ]
}

/// Create a rule to accept a specific ICMP type
fn create_icmp_type_accept_rule(icmp_type: u8, comment: &str) -> Rule<'static> {
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
            Statement::Accept(None),
        ]
        .into(),
        comment: Some(Cow::Owned(comment.to_string())),
        ..Default::default()
    }
}

/// ICMPv6 messages required for error handling, neighbour discovery, router
/// discovery, and multicast listener discovery. Blocking these breaks IPv6.
fn create_icmpv6_essential_accept_rules() -> Vec<Rule<'static>> {
    [
        (1, "Accept ICMPv6 destination-unreachable"),
        (2, "Accept ICMPv6 packet-too-big"),
        (3, "Accept ICMPv6 time-exceeded"),
        (4, "Accept ICMPv6 parameter-problem"),
        (130, "Accept ICMPv6 MLD query"),
        (131, "Accept ICMPv6 MLD report"),
        (132, "Accept ICMPv6 MLD done"),
        (133, "Accept ICMPv6 router-solicitation"),
        (134, "Accept ICMPv6 router-advertisement"),
        (135, "Accept ICMPv6 neighbour-solicitation"),
        (136, "Accept ICMPv6 neighbour-advertisement"),
        (143, "Accept ICMPv6 MLDv2 report"),
    ]
    .into_iter()
    .map(|(icmp_type, comment)| create_icmpv6_type_accept_rule(icmp_type, comment))
    .collect()
}

fn create_icmpv6_type_accept_rule(icmp_type: u8, comment: &str) -> Rule<'static> {
    Rule {
        family: NfFamily::INet,
        table: Cow::Borrowed(FILTER_TABLE),
        chain: Cow::Borrowed("input"),
        expr: vec![
            Statement::Match(Match {
                left: Expression::Named(nftables::expr::NamedExpression::Meta(Meta {
                    key: MetaKey::L4proto,
                })),
                right: Expression::String(Cow::Borrowed("ipv6-icmp")),
                op: Operator::EQ,
            }),
            Statement::Match(Match {
                left: Expression::Named(nftables::expr::NamedExpression::Payload(
                    Payload::PayloadField(PayloadField {
                        protocol: Cow::Borrowed("icmpv6"),
                        field: Cow::Borrowed("type"),
                    }),
                )),
                right: Expression::Number(icmp_type as u32),
                op: Operator::EQ,
            }),
            Statement::Counter(Counter::Anonymous(None)),
            Statement::Accept(None),
        ]
        .into(),
        comment: Some(Cow::Owned(comment.to_string())),
        ..Default::default()
    }
}

/// Create nftables rules from an InputRule.
///
/// Returns multiple rules for TcpUdp protocol (one for TCP, one for UDP),
/// since nftables doesn't support matching multiple protocols in a single rule.
fn create_input_rules(
    rule: &InputRule,
    zone_interfaces: &HashMap<String, Vec<String>>,
) -> Vec<Rule<'static>> {
    // Determine which protocols to generate rules for
    let protocols = rule
        .protocol
        .as_ref()
        .map(expand_protocol)
        .unwrap_or_else(|| vec![None]);

    protocols
        .into_iter()
        .map(|proto| {
            create_input_rule_for_protocol(
                rule,
                zone_interfaces,
                proto,
                rule.port_start,
                rule.port_end,
            )
        })
        .collect()
}

/// Create a single nftables rule for a specific protocol
fn create_input_rule_for_protocol(
    rule: &InputRule,
    zone_interfaces: &HashMap<String, Vec<String>>,
    protocol: Option<&'static str>,
    port_start: Option<u16>,
    port_end: Option<u16>,
) -> Rule<'static> {
    let mut exprs: Vec<Statement> = Vec::new();

    // Match source zone (interface)
    if let Some(ref zone_name) = rule.zone
        && let Some(interfaces) = zone_interfaces.get(zone_name)
        && !interfaces.is_empty()
    {
        exprs.push(create_iif_match(interfaces));
    }

    // Match source IP
    if let Some(ref src_ip) = rule.source_ip {
        exprs.push(create_saddr_match(src_ip));
    }

    // Match protocol and ports
    add_protocol_match_concrete(&mut exprs, protocol, port_start, port_end);

    // Rate limiting
    if let Some(ref rate_limit) = rule.rate_limit
        && let Some(limit_stmt) = parse_rate_limit(rate_limit)
    {
        exprs.push(limit_stmt);
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

    Rule {
        family: NfFamily::INet,
        table: Cow::Borrowed(FILTER_TABLE),
        chain: Cow::Borrowed("input"),
        expr: exprs.into(),
        comment: Some(Cow::Owned(rule.name.clone())),
        ..Default::default()
    }
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
        ]
        .into(),
        comment: Some(Cow::Owned(format!(
            "{} zone default: accept input",
            zone.name
        ))),
        ..Default::default()
    }
}
