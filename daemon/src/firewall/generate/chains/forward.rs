//! Forward chain generation for nftables
//!
//! This module handles generation of the forward chain which controls
//! traffic passing through the router (between interfaces/zones).

use crate::firewall::generate::chains::input::{
    create_conntrack_established_rule, create_conntrack_invalid_rule,
};
use crate::firewall::generate::statements::{
    Side, address_match, create_daddr_match, create_dport_match, create_iif_match,
    create_ipv4_match, create_oif_match, create_protocol_match, expand_protocol, parse_rate_limit,
    push_port_matches, rule_options_are_safe,
};
use crate::firewall::generate::{FILTER_TABLE, resolve_zone_interfaces, rule_comment};
use crate::firewall::groups::{Family, GroupIndex, family_variants, side_families};
use keystone_core::upnp::UpnpForwardAccept;
use keystone_core::{FirewallAction, FirewallConfig, ForwardRule, PortForward, ZoneForwardPolicy};
use nftables::{
    batch::Batch,
    expr::Expression,
    schema::{Chain, NfListObject, Rule},
    stmt::{Counter, Log, Match, Operator, Statement},
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

    // Priority 3: Accept DNATed traffic for enabled port forwards. Without
    // this, raw port forwards (which have no matching forward rule) would be
    // dropped by the chain's default policy.
    for pf in config.port_forwards.iter().filter(|pf| pf.enabled) {
        for nf_rule in create_port_forward_accept_rules(pf) {
            batch.add(NfListObject::Rule(nf_rule));
        }
    }

    // Priority 3b: DNATed traffic from UPnP / NAT-PMP mappings. miniupnpd's
    // own rules live in a separate table, so this accept is what lets their
    // DNATed packets through. It matches only packets already DNATed, arriving
    // on the UPnP WAN and leaving for a UPnP LAN.
    if let Some(upnp) = &config.upnp_forward
        && let Some(nf_rule) = create_upnp_forward_accept_rule(upnp)
    {
        batch.add(NfListObject::Rule(nf_rule));
    }

    // Priority 4: User forward rules (position-ordered)
    let groups = GroupIndex::new(&config.address_groups, &config.port_groups);
    let mut sorted_rules: Vec<_> = config.forward_rules.iter().filter(|r| r.enabled).collect();
    sorted_rules.sort_by_key(|r| r.position);

    for rule in sorted_rules {
        for nf_rule in create_forward_rules(rule, zone_interfaces, &groups) {
            batch.add(NfListObject::Rule(nf_rule));
        }
    }

    // Priority 5: Zone-to-zone forwarding policies
    for policy in &config.zone_forwards {
        if policy.enabled
            && let Some(nf_rule) = create_zone_forward_rule(policy, zone_interfaces)
        {
            batch.add(NfListObject::Rule(nf_rule));
        }
    }
}

/// Accept rules for traffic that was DNATed to a port forward's destination.
fn create_port_forward_accept_rules(pf: &PortForward) -> Vec<Rule<'static>> {
    if pf.dest_ip.parse::<std::net::Ipv4Addr>().is_err() {
        return Vec::new();
    }
    // Translated destination port(s): the explicit dest port, or the external range.
    let (port_start, port_end) = match pf.dest_port {
        Some(port) => (port, None),
        None => (pf.external_port_start, pf.external_port_end),
    };
    expand_protocol(&pf.protocol)
        .into_iter()
        .flatten()
        .filter(|proto| matches!(*proto, "tcp" | "udp"))
        .map(|proto| Rule {
            family: NfFamily::INet,
            table: Cow::Borrowed(FILTER_TABLE),
            chain: Cow::Borrowed("forward"),
            expr: vec![
                create_ipv4_match(),
                Statement::Match(Match {
                    left: Expression::Named(nftables::expr::NamedExpression::CT(
                        nftables::expr::CT {
                            key: Cow::Borrowed("status"),
                            ..Default::default()
                        },
                    )),
                    right: Expression::String(Cow::Borrowed("dnat")),
                    op: Operator::IN,
                }),
                create_daddr_match(&pf.dest_ip),
                create_protocol_match(proto),
                create_dport_match(port_start, port_end),
                Statement::Counter(Counter::Anonymous(None)),
                Statement::Accept(None),
            ]
            .into(),
            comment: Some(Cow::Owned(rule_comment(
                "portfwd-accept",
                pf.id,
                &format!("{} DNAT accept ({})", pf.name, proto),
            ))),
            ..Default::default()
        })
        .collect()
}

/// Accept packets that a UPnP mapping DNATed, from the WAN to the UPnP LANs.
/// The `ct status dnat` match is what restricts the rule to DNATed traffic.
fn create_upnp_forward_accept_rule(upnp: &UpnpForwardAccept) -> Option<Rule<'static>> {
    if upnp.lan_interfaces.is_empty() {
        return None;
    }
    Some(Rule {
        family: NfFamily::INet,
        table: Cow::Borrowed(FILTER_TABLE),
        chain: Cow::Borrowed("forward"),
        expr: vec![
            create_iif_match(std::slice::from_ref(&upnp.wan_interface)),
            create_oif_match(&upnp.lan_interfaces),
            Statement::Match(Match {
                left: Expression::Named(nftables::expr::NamedExpression::CT(nftables::expr::CT {
                    key: Cow::Borrowed("status"),
                    ..Default::default()
                })),
                right: Expression::String(Cow::Borrowed("dnat")),
                op: Operator::IN,
            }),
            Statement::Counter(Counter::Anonymous(None)),
            Statement::Accept(None),
        ]
        .into(),
        comment: Some(Cow::Borrowed("ks:upnp")),
        ..Default::default()
    })
}

/// Create nftables rules from a ForwardRule.
///
/// Returns one rule per (address family, protocol) pair: nftables cannot match
/// several protocols in one rule, and a group that mixes IPv4 and IPv6 needs a
/// separate rule for each family.
fn create_forward_rules(
    rule: &ForwardRule,
    zone_interfaces: &HashMap<String, Vec<String>>,
    groups: &GroupIndex,
) -> Vec<Rule<'static>> {
    let source = side_families(
        rule.source_ip.as_deref(),
        rule.source_group.as_deref(),
        groups,
    );
    let dest = side_families(rule.dest_ip.as_deref(), rule.dest_group.as_deref(), groups);
    let (source, dest) = match (source, dest) {
        (Ok(source), Ok(dest)) => (source, dest),
        (Err(error), _) | (_, Err(error)) => {
            tracing::warn!("Skipping rule '{}': {error}", rule.name);
            return Vec::new();
        }
    };
    let families = family_variants(&[source, dest]);
    if families.is_empty() {
        tracing::warn!(
            "Skipping rule '{}': its source and destination addresses share no IP family",
            rule.name
        );
        return Vec::new();
    }

    // Determine which protocols to generate rules for
    let protocols = rule
        .protocol
        .as_ref()
        .map(expand_protocol)
        .unwrap_or_else(|| vec![None]);

    families
        .iter()
        .flat_map(|family| protocols.iter().map(move |proto| (*family, *proto)))
        .filter_map(|(family, proto)| {
            create_forward_rule_for_protocol(rule, zone_interfaces, proto, family)
        })
        .collect()
}

/// Create a single nftables rule for a specific protocol and address family
fn create_forward_rule_for_protocol(
    rule: &ForwardRule,
    zone_interfaces: &HashMap<String, Vec<String>>,
    protocol: Option<&'static str>,
    family: Option<Family>,
) -> Option<Rule<'static>> {
    let has_port_match = rule.dest_port_start.is_some() || rule.dest_port_group.is_some();
    if !rule_options_are_safe(
        protocol,
        has_port_match,
        rule.rate_limit.as_deref(),
        &rule.name,
    ) {
        return None;
    }
    let mut exprs: Vec<Statement> = Vec::new();

    // Match source zone. An unresolvable zone fails closed.
    if let Some(interfaces) =
        resolve_zone_interfaces(rule.source_zone.as_deref(), zone_interfaces, &rule.name).ok()?
    {
        exprs.push(create_iif_match(interfaces));
    }

    // Match destination zone
    if let Some(interfaces) =
        resolve_zone_interfaces(rule.dest_zone.as_deref(), zone_interfaces, &rule.name).ok()?
    {
        exprs.push(create_oif_match(interfaces));
    }

    // Match source and destination addresses (literal or group, for this family)
    if let Some(source) = address_match(
        Side::Source,
        rule.source_ip.as_deref(),
        rule.source_group.as_deref(),
        family,
    ) {
        exprs.push(source);
    }
    if let Some(dest) = address_match(
        Side::Destination,
        rule.dest_ip.as_deref(),
        rule.dest_group.as_deref(),
        family,
    ) {
        exprs.push(dest);
    }

    // Match protocol and ports
    push_port_matches(
        &mut exprs,
        protocol,
        rule.dest_port_start,
        rule.dest_port_end,
        rule.dest_port_group.as_deref(),
    );

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

    Some(Rule {
        family: NfFamily::INet,
        table: Cow::Borrowed(FILTER_TABLE),
        chain: Cow::Borrowed("forward"),
        expr: exprs.into(),
        comment: Some(Cow::Owned(rule_comment("forward", rule.id, &rule.name))),
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
