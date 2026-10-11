//! NAT chain generation for nftables
//!
//! This module handles generation of the NAT chains:
//! - Prerouting chain for DNAT (port forwards)
//! - Postrouting chain for SNAT (masquerade)

use crate::firewall::generate::statements::{
    create_daddr_match, create_dport_match, create_iif_match, create_ipv4_match,
    create_protocol_match, create_saddr_match,
};
use crate::firewall::generate::{NAT_TABLE, find_ipv4_masquerade_zones, find_wan_zones};
use keystone_core::{FirewallConfig, PortForward, RuleProtocol};
use nftables::{
    batch::Batch,
    expr::{Expression, Meta, MetaKey},
    schema::{Chain, NfListObject, Rule},
    stmt::{Counter, Match, Operator, Statement},
    types::{NfChainType, NfFamily, NfHook},
};
use std::borrow::Cow;
use std::collections::HashMap;

/// Generate the prerouting chain for DNAT (port forwards)
pub fn generate_prerouting_chain(
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
                    if config.global_settings.hairpin_nat_enabled
                        && !lan_interfaces.is_empty()
                        && let Some(rule) = create_hairpin_dnat_rule(pf, &lan_interfaces, "tcp")
                    {
                        batch.add(NfListObject::Rule(rule));
                    }
                }
                RuleProtocol::Udp => {
                    if let Some(rule) = create_port_forward_rule(pf, zone_interfaces, "udp") {
                        batch.add(NfListObject::Rule(rule));
                    }
                    if config.global_settings.hairpin_nat_enabled
                        && !lan_interfaces.is_empty()
                        && let Some(rule) = create_hairpin_dnat_rule(pf, &lan_interfaces, "udp")
                    {
                        batch.add(NfListObject::Rule(rule));
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
    if pf.dest_ip.parse::<std::net::Ipv4Addr>().is_err() {
        return None;
    }
    let mut exprs: Vec<Statement> = vec![create_ipv4_match()];

    // Match source zone (input interface)
    if let Some(ref zone_name) = pf.source_zone
        && let Some(interfaces) = zone_interfaces.get(zone_name)
        && !interfaces.is_empty()
    {
        exprs.push(create_iif_match(interfaces));
    }

    // Match source IP if specified
    if let Some(ref src_ip) = pf.source_ip {
        exprs.push(create_saddr_match(src_ip));
    }

    // Match protocol
    exprs.push(create_protocol_match(protocol));

    // Match destination port(s)
    exprs.push(create_dport_match(
        pf.external_port_start,
        pf.external_port_end,
    ));

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
    if lan_interfaces.is_empty() || pf.dest_ip.parse::<std::net::Ipv4Addr>().is_err() {
        return None;
    }

    let mut exprs: Vec<Statement> = vec![
        create_ipv4_match(),
        // Match input from LAN interfaces
        create_iif_match(lan_interfaces),
        // Match protocol
        create_protocol_match(protocol),
        // Match destination port(s)
        create_dport_match(pf.external_port_start, pf.external_port_end),
        // Match packets destined to a local address (router's own IPs)
        // This catches traffic to any of the router's IPs, including WAN IP
        Statement::Match(Match {
            left: Expression::Named(nftables::expr::NamedExpression::Fib(nftables::expr::Fib {
                result: nftables::expr::FibResult::Type,
                flags: [nftables::expr::FibFlag::Daddr].into_iter().collect(),
            })),
            right: Expression::String(Cow::Borrowed("local")),
            op: Operator::EQ,
        }),
        // Counter
        Statement::Counter(Counter::Anonymous(None)),
    ];

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
pub fn generate_postrouting_chain(
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

    let wan_zones = find_wan_zones(&config.zones);
    let wan_zone_names: Vec<&str> = wan_zones.iter().map(|z| z.name.as_str()).collect();
    let masquerade_zones = find_ipv4_masquerade_zones(&config.zones);

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

    // Explicit IPv4 egress masquerade rules.
    for zone in masquerade_zones {
        for iface in &zone.interfaces {
            // TODO: MSS clamping is disabled due to nftables JSON generation issues
            // The nftables crate doesn't properly support tcp option maxseg mangling
            // See: https://wiki.nftables.org/wiki-nftables/index.php/Mangling_packet_headers
            // batch.add(NfListObject::Rule(create_mss_clamp_rule(iface)));

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
    if lan_interfaces.is_empty() || pf.dest_ip.parse::<std::net::Ipv4Addr>().is_err() {
        return None;
    }

    let mut exprs: Vec<Statement> = vec![create_ipv4_match()];

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
        comment: Some(Cow::Owned(format!(
            "{} hairpin SNAT ({})",
            pf.name, protocol
        ))),
        ..Default::default()
    })
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
                    key: MetaKey::Nfproto,
                })),
                right: Expression::String(Cow::Borrowed("ipv4")),
                op: Operator::EQ,
            }),
            Statement::Match(Match {
                left: Expression::Named(nftables::expr::NamedExpression::Meta(Meta {
                    key: MetaKey::Oifname,
                })),
                right: Expression::String(Cow::Owned(interface.to_string())),
                op: Operator::EQ,
            }),
            Statement::Counter(Counter::Anonymous(None)),
            Statement::Masquerade(None),
        ]
        .into(),
        comment: Some(Cow::Owned(format!("Masquerade for {}", interface))),
        ..Default::default()
    }
}
