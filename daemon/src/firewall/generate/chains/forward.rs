//! Forward chain generation for nftables
//!
//! This module handles generation of the forward chain which controls
//! traffic passing through the router (between interfaces/zones).

use crate::firewall::generate::FILTER_TABLE;
use crate::firewall::generate::chains::input::{
    create_conntrack_established_rule, create_conntrack_invalid_rule,
};
use crate::firewall::generate::statements::{
    add_protocol_match_concrete, create_daddr_match, create_iif_match, create_oif_match,
    create_saddr_match, expand_protocol, parse_rate_limit,
};
use keystone_core::{FirewallAction, FirewallConfig, ForwardRule, ZoneForwardPolicy};
use nftables::{
    batch::Batch,
    schema::{Chain, NfListObject, Rule},
    stmt::{Counter, Log, Statement},
    types::{NfChainPolicy, NfChainType, NfFamily, NfHook},
};
use std::borrow::Cow;
use std::collections::HashMap;

/// Generate the forward chain (traffic passing through the router)
pub fn generate_forward_chain(
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
    let mut sorted_rules: Vec<_> = config.forward_rules.iter().filter(|r| r.enabled).collect();
    sorted_rules.sort_by_key(|r| r.position);

    for rule in sorted_rules {
        for nf_rule in create_forward_rules(rule, zone_interfaces) {
            batch.add(NfListObject::Rule(nf_rule));
        }
    }

    // Priority 4: Zone-to-zone forwarding policies
    for policy in &config.zone_forwards {
        if policy.enabled
            && let Some(nf_rule) = create_zone_forward_rule(policy, zone_interfaces)
        {
            batch.add(NfListObject::Rule(nf_rule));
        }
    }
}

/// Create nftables rules from a ForwardRule.
///
/// Returns multiple rules for TcpUdp protocol (one for TCP, one for UDP),
/// since nftables doesn't support matching multiple protocols in a single rule.
fn create_forward_rules(
    rule: &ForwardRule,
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
            create_forward_rule_for_protocol(
                rule,
                zone_interfaces,
                proto,
                rule.dest_port_start,
                rule.dest_port_end,
            )
        })
        .collect()
}

/// Create a single nftables rule for a specific protocol
fn create_forward_rule_for_protocol(
    rule: &ForwardRule,
    zone_interfaces: &HashMap<String, Vec<String>>,
    protocol: Option<&'static str>,
    port_start: Option<u16>,
    port_end: Option<u16>,
) -> Rule<'static> {
    let mut exprs: Vec<Statement> = Vec::new();

    // Match source zone
    if let Some(ref zone_name) = rule.source_zone
        && let Some(interfaces) = zone_interfaces.get(zone_name)
        && !interfaces.is_empty()
    {
        exprs.push(create_iif_match(interfaces));
    }

    // Match destination zone
    if let Some(ref zone_name) = rule.dest_zone
        && let Some(interfaces) = zone_interfaces.get(zone_name)
        && !interfaces.is_empty()
    {
        exprs.push(create_oif_match(interfaces));
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

    Rule {
        family: NfFamily::INet,
        table: Cow::Borrowed(FILTER_TABLE),
        chain: Cow::Borrowed("forward"),
        expr: exprs.into(),
        comment: Some(Cow::Owned(rule.name.clone())),
        ..Default::default()
    }
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
