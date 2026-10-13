//! NAT chain generation for nftables
//!
//! This module handles generation of the NAT chains:
//! - Prerouting chain for DNAT (port forwards)
//! - Postrouting chain for SNAT (masquerade)

use crate::firewall::generate::statements::{
    Side, address_match, create_daddr_match, create_dport_match, create_iif_match,
    create_ipv4_match, create_protocol_match,
};
use crate::firewall::generate::{
    NAT_TABLE, find_ipv4_masquerade_zones, find_wan_zones, resolve_zone_interfaces, rule_comment,
};
use crate::firewall::groups::{Family, GroupIndex, side_families};
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
    let groups = GroupIndex::new(&config.address_groups, &config.port_groups);

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
                    if let Some(rule) =
                        create_port_forward_rule(pf, zone_interfaces, "tcp", &groups)
                    {
                        batch.add(NfListObject::Rule(rule));
                    }
                    if let Some(rule) =
                        create_port_forward_rule(pf, zone_interfaces, "udp", &groups)
                    {
                        batch.add(NfListObject::Rule(rule));
                    }
                    // Hairpin NAT rules (if enabled)
                    if config.global_settings.hairpin_nat_enabled && !lan_interfaces.is_empty() {
                        if let Some(rule) =
                            create_hairpin_dnat_rule(pf, &lan_interfaces, "tcp", &groups)
                        {
                            batch.add(NfListObject::Rule(rule));
                        }
                        if let Some(rule) =
                            create_hairpin_dnat_rule(pf, &lan_interfaces, "udp", &groups)
                        {
                            batch.add(NfListObject::Rule(rule));
                        }
                    }
                }
                RuleProtocol::Tcp => {
                    if let Some(rule) =
                        create_port_forward_rule(pf, zone_interfaces, "tcp", &groups)
                    {
                        batch.add(NfListObject::Rule(rule));
                    }
                    if config.global_settings.hairpin_nat_enabled
                        && !lan_interfaces.is_empty()
                        && let Some(rule) =
                            create_hairpin_dnat_rule(pf, &lan_interfaces, "tcp", &groups)
                    {
                        batch.add(NfListObject::Rule(rule));
                    }
                }
                RuleProtocol::Udp => {
                    if let Some(rule) =
                        create_port_forward_rule(pf, zone_interfaces, "udp", &groups)
                    {
                        batch.add(NfListObject::Rule(rule));
                    }
                    if config.global_settings.hairpin_nat_enabled
                        && !lan_interfaces.is_empty()
                        && let Some(rule) =
                            create_hairpin_dnat_rule(pf, &lan_interfaces, "udp", &groups)
                    {
                        batch.add(NfListObject::Rule(rule));
                    }
                }
                _ => {}
            }
        }
    }
}

/// True when the external side of the forward is a port range.
fn is_range(pf: &PortForward) -> bool {
    pf.external_port_end
        .is_some_and(|end| end > pf.external_port_start)
}

/// Port to translate to, or `None` to keep the original port. A range without
/// an explicit destination port keeps each port as-is instead of collapsing
/// the whole range onto its first port.
fn dnat_port(pf: &PortForward) -> Option<u16> {
    match pf.dest_port {
        Some(port) => Some(port),
        None if is_range(pf) => None,
        None => Some(pf.external_port_start),
    }
}

/// Source restriction of a port forward. DNAT only matches IPv4, so a source
/// group must have IPv4 entries; otherwise no packet can match and the caller
/// emits no rule.
pub(crate) fn port_forward_source_match(
    pf: &PortForward,
    groups: &GroupIndex,
) -> Result<Option<Statement<'static>>, String> {
    match side_families(pf.source_ip.as_deref(), pf.source_group.as_deref(), groups)? {
        None => Ok(None),
        Some(families) if families.contains(&Family::V4) => Ok(address_match(
            Side::Source,
            pf.source_ip.as_deref(),
            pf.source_group.as_deref(),
            Some(Family::V4),
        )),
        Some(_) => Err(format!(
            "port forward '{}' has no IPv4 source to match",
            pf.name
        )),
    }
}

/// Create a port forward (DNAT) rule
fn create_port_forward_rule(
    pf: &PortForward,
    zone_interfaces: &HashMap<String, Vec<String>>,
    protocol: &'static str,
    groups: &GroupIndex,
) -> Option<Rule<'static>> {
    if pf.dest_ip.parse::<std::net::Ipv4Addr>().is_err() {
        return None;
    }
    let source = match port_forward_source_match(pf, groups) {
        Ok(source) => source,
        Err(error) => {
            tracing::warn!("Skipping port forward '{}': {error}", pf.name);
            return None;
        }
    };
    let mut exprs: Vec<Statement> = vec![create_ipv4_match()];

    // Match source zone (input interface). An unresolvable zone fails closed.
    if let Some(interfaces) =
        resolve_zone_interfaces(pf.source_zone.as_deref(), zone_interfaces, &pf.name).ok()?
    {
        exprs.push(create_iif_match(interfaces));
    }

    // Only traffic addressed to the router itself may be DNATed; otherwise
    // LAN clients' outbound traffic to the same port would be hijacked.
    exprs.push(create_fib_daddr_local_match());

    // Match source address if specified
    exprs.extend(source);

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
    exprs.push(Statement::DNAT(Some(nftables::stmt::NAT {
        addr: Some(Expression::String(Cow::Owned(pf.dest_ip.clone()))),
        family: None,
        port: dnat_port(pf).map(|port| Expression::Number(port as u32)),
        flags: None,
    })));

    Some(Rule {
        family: NfFamily::INet,
        table: Cow::Borrowed(NAT_TABLE),
        chain: Cow::Borrowed("prerouting"),
        expr: exprs.into(),
        comment: Some(Cow::Owned(rule_comment(
            "portfwd",
            pf.id,
            &format!("{} ({})", pf.name, protocol),
        ))),
        ..Default::default()
    })
}

/// Match packets addressed to one of the router's own IPs (`fib daddr type local`)
fn create_fib_daddr_local_match() -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(nftables::expr::NamedExpression::Fib(nftables::expr::Fib {
            result: nftables::expr::FibResult::Type,
            flags: [nftables::expr::FibFlag::Daddr].into_iter().collect(),
        })),
        right: Expression::String(Cow::Borrowed("local")),
        op: Operator::EQ,
    })
}

/// Match packets whose destination is NOT an address of the ingress interface
/// (`fib daddr . iif type != local`). The kernel only reports `local` for this
/// lookup when the address is assigned to the ingress interface itself.
fn create_fib_daddr_not_on_iif_match() -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(nftables::expr::NamedExpression::Fib(nftables::expr::Fib {
            result: nftables::expr::FibResult::Type,
            flags: [nftables::expr::FibFlag::Daddr, nftables::expr::FibFlag::Iif]
                .into_iter()
                .collect(),
        })),
        right: Expression::String(Cow::Borrowed("local")),
        op: Operator::NEQ,
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
    groups: &GroupIndex,
) -> Option<Rule<'static>> {
    if lan_interfaces.is_empty() || pf.dest_ip.parse::<std::net::Ipv4Addr>().is_err() {
        return None;
    }
    let source = match port_forward_source_match(pf, groups) {
        Ok(source) => source,
        Err(error) => {
            tracing::warn!("Skipping hairpin rule for '{}': {error}", pf.name);
            return None;
        }
    };

    let mut exprs: Vec<Statement> = vec![
        create_ipv4_match(),
        // Match input from LAN interfaces
        create_iif_match(lan_interfaces),
    ];
    // The port forward's source restriction applies to LAN clients too: a
    // client the forward excludes must not be redirected by hairpin.
    exprs.extend(source);
    exprs.extend([
        // Match protocol
        create_protocol_match(protocol),
        // Match destination port(s)
        create_dport_match(pf.external_port_start, pf.external_port_end),
        // Match packets destined to a local address (router's own IPs)
        // This catches traffic to any of the router's IPs, including WAN IP
        create_fib_daddr_local_match(),
        // ...but never the router's own address on the ingress LAN interface:
        // those connections (e.g. Caddy on the LAN IP) must reach the router.
        create_fib_daddr_not_on_iif_match(),
        // Counter
        Statement::Counter(Counter::Anonymous(None)),
    ]);

    // DNAT action
    exprs.push(Statement::DNAT(Some(nftables::stmt::NAT {
        addr: Some(Expression::String(Cow::Owned(pf.dest_ip.clone()))),
        family: None,
        port: dnat_port(pf).map(|port| Expression::Number(port as u32)),
        flags: None,
    })));

    Some(Rule {
        family: NfFamily::INet,
        table: Cow::Borrowed(NAT_TABLE),
        chain: Cow::Borrowed("prerouting"),
        expr: exprs.into(),
        comment: Some(Cow::Owned(rule_comment(
            "portfwd-hairpin",
            pf.id,
            &format!("{} hairpin ({})", pf.name, protocol),
        ))),
        ..Default::default()
    })
}

/// Generate the postrouting chain for SNAT (masquerade)
pub fn generate_postrouting_chain(
    batch: &mut Batch<'static>,
    config: &FirewallConfig,
    _zone_interfaces: &HashMap<String, Vec<String>>,
) {
    let groups = GroupIndex::new(&config.address_groups, &config.port_groups);

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
                        if let Some(rule) =
                            create_hairpin_snat_rule(pf, &lan_interfaces, "tcp", &groups)
                        {
                            batch.add(NfListObject::Rule(rule));
                        }
                        if let Some(rule) =
                            create_hairpin_snat_rule(pf, &lan_interfaces, "udp", &groups)
                        {
                            batch.add(NfListObject::Rule(rule));
                        }
                    }
                    RuleProtocol::Tcp => {
                        if let Some(rule) =
                            create_hairpin_snat_rule(pf, &lan_interfaces, "tcp", &groups)
                        {
                            batch.add(NfListObject::Rule(rule));
                        }
                    }
                    RuleProtocol::Udp => {
                        if let Some(rule) =
                            create_hairpin_snat_rule(pf, &lan_interfaces, "udp", &groups)
                        {
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
    groups: &GroupIndex,
) -> Option<Rule<'static>> {
    if lan_interfaces.is_empty() || pf.dest_ip.parse::<std::net::Ipv4Addr>().is_err() {
        return None;
    }
    // Only the traffic the hairpin DNAT redirects may be masqueraded.
    let source = match port_forward_source_match(pf, groups) {
        Ok(source) => source,
        Err(error) => {
            tracing::warn!("Skipping hairpin SNAT for '{}': {error}", pf.name);
            return None;
        }
    };

    let mut exprs: Vec<Statement> = vec![create_ipv4_match()];

    // Match source from LAN interfaces (original source is LAN client)
    exprs.push(create_iif_match(lan_interfaces));
    exprs.extend(source);

    // Match protocol
    exprs.push(create_protocol_match(protocol));

    // Match destination IP (the internal server)
    exprs.push(create_daddr_match(&pf.dest_ip));

    // Match destination port (the internal server port)
    match dnat_port(pf) {
        Some(port) => exprs.push(create_dport_match(port, None)),
        None => exprs.push(create_dport_match(
            pf.external_port_start,
            pf.external_port_end,
        )),
    }

    // Counter
    exprs.push(Statement::Counter(Counter::Anonymous(None)));

    // Masquerade - router becomes the source so server can reply correctly
    exprs.push(Statement::Masquerade(None));

    Some(Rule {
        family: NfFamily::INet,
        table: Cow::Borrowed(NAT_TABLE),
        chain: Cow::Borrowed("postrouting"),
        expr: exprs.into(),
        comment: Some(Cow::Owned(rule_comment(
            "portfwd-hairpin-snat",
            pf.id,
            &format!("{} hairpin SNAT ({})", pf.name, protocol),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn forward(start: u16, end: Option<u16>, dest_port: Option<u16>) -> PortForward {
        PortForward {
            id: None,
            name: "pf".to_string(),
            enabled: true,
            protocol: RuleProtocol::Tcp,
            external_port_start: start,
            external_port_end: end,
            dest_ip: "192.168.1.10".to_string(),
            dest_port,
            source_zone: None,
            source_ip: None,
            source_group: None,
            description: None,
        }
    }

    fn dnat_port_of(rule: &Rule<'static>) -> Option<Expression<'static>> {
        rule.expr
            .iter()
            .find_map(|stmt| match stmt {
                Statement::DNAT(Some(nat)) => Some(nat.port.clone()),
                _ => None,
            })
            .expect("rule has a DNAT statement")
    }

    #[test]
    fn hairpin_dnat_excludes_router_address_on_ingress_interface() {
        let pf = forward(443, None, None);
        let rule =
            create_hairpin_dnat_rule(&pf, &["lan0".to_string()], "tcp", &GroupIndex::default())
                .unwrap();
        let json = serde_json::to_string(&rule).unwrap();
        assert!(json.contains("\"op\":\"!=\""), "{json}");
        assert!(json.contains("\"iif\""), "{json}");
    }

    #[test]
    fn single_port_defaults_to_same_port() {
        let pf = forward(8080, None, None);
        let zones = HashMap::new();
        let rule = create_port_forward_rule(&pf, &zones, "tcp", &GroupIndex::default()).unwrap();
        assert!(matches!(
            dnat_port_of(&rule),
            Some(Expression::Number(8080))
        ));
    }

    #[test]
    fn explicit_dest_port_is_used() {
        let pf = forward(8080, None, Some(80));
        let zones = HashMap::new();
        let rule = create_port_forward_rule(&pf, &zones, "tcp", &GroupIndex::default()).unwrap();
        assert!(matches!(dnat_port_of(&rule), Some(Expression::Number(80))));
        let hairpin =
            create_hairpin_dnat_rule(&pf, &["eth1".to_string()], "tcp", &GroupIndex::default())
                .unwrap();
        assert!(matches!(
            dnat_port_of(&hairpin),
            Some(Expression::Number(80))
        ));
    }

    #[test]
    fn range_without_dest_port_preserves_original_port() {
        let pf = forward(5000, Some(5010), None);
        let zones = HashMap::new();
        let rule = create_port_forward_rule(&pf, &zones, "tcp", &GroupIndex::default()).unwrap();
        assert!(dnat_port_of(&rule).is_none());
        let hairpin =
            create_hairpin_dnat_rule(&pf, &["eth1".to_string()], "tcp", &GroupIndex::default())
                .unwrap();
        assert!(dnat_port_of(&hairpin).is_none());
    }

    #[test]
    fn hairpin_snat_matches_whole_range_when_port_preserved() {
        let pf = forward(5000, Some(5010), None);
        let rule =
            create_hairpin_snat_rule(&pf, &["eth1".to_string()], "tcp", &GroupIndex::default())
                .unwrap();
        let expected = create_dport_match(5000, Some(5010));
        assert!(rule.expr.iter().any(|stmt| {
            serde_json::to_value(stmt).unwrap() == serde_json::to_value(&expected).unwrap()
        }));
    }

    fn json(rule: &Rule<'static>) -> String {
        serde_json::to_string(rule).unwrap()
    }

    fn restricted(source_ip: Option<&str>, source_group: Option<&str>) -> PortForward {
        let mut pf = forward(27000, Some(27050), None);
        pf.source_ip = source_ip.map(str::to_string);
        pf.source_group = source_group.map(str::to_string);
        pf
    }

    #[test]
    fn hairpin_dnat_and_snat_honour_a_literal_source_restriction() {
        let pf = restricted(Some("198.51.100.0/24"), None);
        let lan = ["eth1".to_string()];
        let groups = GroupIndex::default();
        for text in [
            json(&create_hairpin_dnat_rule(&pf, &lan, "udp", &groups).unwrap()),
            json(&create_hairpin_snat_rule(&pf, &lan, "udp", &groups).unwrap()),
        ] {
            assert!(text.contains("\"field\":\"saddr\""), "{text}");
            assert!(text.contains("198.51.100.0/24"), "{text}");
        }
    }

    #[test]
    fn hairpin_dnat_and_snat_honour_a_group_source_restriction() {
        let pf = restricted(None, Some("trusted"));
        let lan = ["eth1".to_string()];
        let address_groups = vec![keystone_core::AddressGroup {
            name: "trusted".into(),
            entries: vec!["198.51.100.0/24".into()],
            ..Default::default()
        }];
        let groups = GroupIndex::new(&address_groups, &[]);
        for text in [
            json(&create_hairpin_dnat_rule(&pf, &lan, "tcp", &groups).unwrap()),
            json(&create_hairpin_snat_rule(&pf, &lan, "tcp", &groups).unwrap()),
        ] {
            assert!(text.contains("@trusted_v4"), "{text}");
        }
    }

    #[test]
    fn hairpin_rules_are_not_emitted_for_a_source_group_without_ipv4() {
        let pf = restricted(None, Some("v6_only"));
        let lan = ["eth1".to_string()];
        let address_groups = vec![keystone_core::AddressGroup {
            name: "v6_only".into(),
            entries: vec!["2001:db8::/32".into()],
            ..Default::default()
        }];
        let groups = GroupIndex::new(&address_groups, &[]);
        assert!(create_hairpin_dnat_rule(&pf, &lan, "tcp", &groups).is_none());
        assert!(create_hairpin_snat_rule(&pf, &lan, "tcp", &groups).is_none());
    }
}
