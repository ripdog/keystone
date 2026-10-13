//! Validation of firewall configuration.
//!
//! These checks run when rules are saved and again before the ruleset is
//! generated, so that bad rows already in the database can never be applied
//! as a rule that silently matches more traffic than intended.

use crate::firewall::generate::statements::parse_rate_limit;
use keystone_core::{FirewallConfig, ForwardRule, InputRule, PortForward, RuleProtocol};
use std::collections::HashMap;
use std::net::Ipv4Addr;

/// Accepted rate limit format, for error messages.
const RATE_LIMIT_HELP: &str =
    "expected \"<count>/<unit>\" such as \"10/minute\" (units: second, minute, hour, day)";

fn is_port_protocol(protocol: Option<&RuleProtocol>) -> bool {
    matches!(
        protocol,
        Some(RuleProtocol::Tcp | RuleProtocol::Udp | RuleProtocol::TcpUdp)
    )
}

fn check_ports(
    what: &str,
    protocol: Option<&RuleProtocol>,
    start: Option<u16>,
    end: Option<u16>,
    errors: &mut Vec<String>,
) {
    if start.is_none() && end.is_none() {
        return;
    }
    if start.is_none() {
        errors.push(format!("{what}: a port end was set without a port start"));
        return;
    }
    if !is_port_protocol(protocol) {
        errors.push(format!(
            "{what}: ports can only be used with protocol TCP, UDP or TCP+UDP"
        ));
    }
    if start == Some(0) || end == Some(0) {
        errors.push(format!("{what}: port 0 is not valid"));
    }
    if let (Some(s), Some(e)) = (start, end)
        && e < s
    {
        errors.push(format!(
            "{what}: port range end ({e}) is less than start ({s})"
        ));
    }
}

fn check_rate_limit(what: &str, rate_limit: Option<&String>, errors: &mut Vec<String>) {
    if let Some(rate) = rate_limit
        && parse_rate_limit(rate).is_none()
    {
        errors.push(format!(
            "{what}: invalid rate limit \"{rate}\"; {RATE_LIMIT_HELP}"
        ));
    }
}

/// Validate the fields of a single input rule (excluding zone existence).
pub fn validate_input_rule(rule: &InputRule) -> Vec<String> {
    let what = format!("Input rule '{}'", rule.name);
    let mut errors = Vec::new();
    check_ports(
        &what,
        rule.protocol.as_ref(),
        rule.port_start,
        rule.port_end,
        &mut errors,
    );
    check_rate_limit(&what, rule.rate_limit.as_ref(), &mut errors);
    errors
}

/// Validate the fields of a single forward rule (excluding zone existence).
pub fn validate_forward_rule(rule: &ForwardRule) -> Vec<String> {
    let what = format!("Forward rule '{}'", rule.name);
    let mut errors = Vec::new();
    check_ports(
        &what,
        rule.protocol.as_ref(),
        rule.dest_port_start,
        rule.dest_port_end,
        &mut errors,
    );
    check_rate_limit(&what, rule.rate_limit.as_ref(), &mut errors);
    errors
}

/// Validate the fields of a single port forward (excluding zone existence).
pub fn validate_port_forward(pf: &PortForward) -> Vec<String> {
    let what = format!("Port forward '{}'", pf.name);
    let mut errors = Vec::new();
    if pf.dest_ip.parse::<Ipv4Addr>().is_err() {
        errors.push(format!(
            "{what}: destination IP \"{}\" is not a valid IPv4 address (IPv6 DNAT is not supported)",
            pf.dest_ip
        ));
    }
    if !is_port_protocol(Some(&pf.protocol)) {
        errors.push(format!("{what}: protocol must be TCP, UDP or TCP+UDP"));
    }
    if pf.external_port_start == 0 || pf.external_port_end == Some(0) || pf.dest_port == Some(0) {
        errors.push(format!("{what}: port 0 is not valid"));
    }
    if let Some(end) = pf.external_port_end
        && end < pf.external_port_start
    {
        errors.push(format!(
            "{what}: external port end ({end}) is less than start ({})",
            pf.external_port_start
        ));
    }
    if pf.dest_port.is_some()
        && pf
            .external_port_end
            .is_some_and(|e| e > pf.external_port_start)
    {
        errors.push(format!(
            "{what}: a destination port cannot be combined with an external port range (it would collapse the range)"
        ));
    }
    errors
}

fn check_zone(
    what: &str,
    role: &str,
    zone: Option<&String>,
    zones: &HashMap<&str, usize>,
    errors: &mut Vec<String>,
) {
    let Some(name) = zone else { return };
    match zones.get(name.as_str()) {
        None => errors.push(format!("{what}: {role} zone '{name}' does not exist")),
        Some(0) => errors.push(format!(
            "{what}: {role} zone '{name}' has no interfaces, so the rule would match every interface"
        )),
        Some(_) => {}
    }
}

/// Validate the whole configuration. Returns human-readable errors.
pub fn validate_firewall_config(cfg: &FirewallConfig) -> Vec<String> {
    let zones: HashMap<&str, usize> = cfg
        .zones
        .iter()
        .map(|z| (z.name.as_str(), z.interfaces.len()))
        .collect();
    let mut errors = Vec::new();

    for (i, zone) in cfg.zones.iter().enumerate() {
        errors.extend(crate::config_validation::zone_interface_conflicts(
            zone,
            &cfg.zones[i + 1..],
        ));
    }

    for rule in &cfg.input_rules {
        errors.extend(validate_input_rule(rule));
        if rule.enabled {
            let what = format!("Input rule '{}'", rule.name);
            check_zone(&what, "source", rule.zone.as_ref(), &zones, &mut errors);
        }
    }
    for rule in &cfg.forward_rules {
        errors.extend(validate_forward_rule(rule));
        if rule.enabled {
            let what = format!("Forward rule '{}'", rule.name);
            check_zone(
                &what,
                "source",
                rule.source_zone.as_ref(),
                &zones,
                &mut errors,
            );
            check_zone(
                &what,
                "destination",
                rule.dest_zone.as_ref(),
                &zones,
                &mut errors,
            );
        }
    }
    for pf in &cfg.port_forwards {
        errors.extend(validate_port_forward(pf));
        if pf.enabled {
            let what = format!("Port forward '{}'", pf.name);
            check_zone(
                &what,
                "source",
                pf.source_zone.as_ref(),
                &zones,
                &mut errors,
            );
        }
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;
    use keystone_core::FirewallZone;

    fn zone(name: &str, ifaces: &[&str]) -> FirewallZone {
        FirewallZone {
            name: name.into(),
            interfaces: ifaces.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    fn input(protocol: Option<RuleProtocol>, start: Option<u16>, end: Option<u16>) -> InputRule {
        InputRule {
            name: "r".into(),
            protocol,
            port_start: start,
            port_end: end,
            ..Default::default()
        }
    }

    #[test]
    fn port_requires_tcp_or_udp() {
        for p in [
            None,
            Some(RuleProtocol::Any),
            Some(RuleProtocol::Icmp),
            Some(RuleProtocol::Icmpv6),
        ] {
            assert!(!validate_input_rule(&input(p, Some(22), None)).is_empty());
        }
        for p in [RuleProtocol::Tcp, RuleProtocol::Udp, RuleProtocol::TcpUdp] {
            assert!(validate_input_rule(&input(Some(p), Some(22), None)).is_empty());
        }
        assert!(validate_input_rule(&input(None, None, None)).is_empty());
    }

    #[test]
    fn port_range_and_zero_rejected() {
        let t = Some(RuleProtocol::Tcp);
        assert!(!validate_input_rule(&input(t, Some(0), None)).is_empty());
        assert!(!validate_input_rule(&input(t, Some(100), Some(50))).is_empty());
        assert!(!validate_input_rule(&input(t, None, Some(50))).is_empty());
        assert!(validate_input_rule(&input(t, Some(50), Some(100))).is_empty());
    }

    #[test]
    fn forward_rule_ports_and_rate_limit() {
        let rule = ForwardRule {
            name: "f".into(),
            dest_port_start: Some(80),
            rate_limit: Some("fast".into()),
            ..Default::default()
        };
        let errors = validate_forward_rule(&rule);
        assert_eq!(errors.len(), 2, "{errors:?}");
        assert!(errors.iter().any(|e| e.contains("10/minute")));
    }

    #[test]
    fn port_forward_checks() {
        let good = PortForward {
            name: "p".into(),
            external_port_start: 8080,
            dest_ip: "192.168.1.2".into(),
            ..Default::default()
        };
        assert!(validate_port_forward(&good).is_empty());

        let mut v6 = good.clone();
        v6.dest_ip = "fd00::1".into();
        assert!(validate_port_forward(&v6)[0].contains("IPv6"));

        let mut any = good.clone();
        any.protocol = RuleProtocol::Any;
        assert!(!validate_port_forward(&any).is_empty());

        let mut range = good.clone();
        range.external_port_end = Some(8090);
        range.dest_port = Some(80);
        assert!(!validate_port_forward(&range).is_empty());
        range.dest_port = None;
        assert!(validate_port_forward(&range).is_empty());

        let mut backwards = good;
        backwards.external_port_end = Some(8000);
        assert!(!validate_port_forward(&backwards).is_empty());
    }

    #[test]
    fn config_rejects_missing_or_empty_zones() {
        let mut cfg = FirewallConfig {
            zones: vec![zone("lan", &["eth1"]), zone("empty", &[])],
            ..Default::default()
        };
        cfg.input_rules.push(InputRule {
            name: "ssh".into(),
            zone: Some("lan".into()),
            protocol: Some(RuleProtocol::Tcp),
            port_start: Some(22),
            ..Default::default()
        });
        assert!(validate_firewall_config(&cfg).is_empty());

        cfg.input_rules[0].zone = Some("missing".into());
        assert!(validate_firewall_config(&cfg)[0].contains("does not exist"));
        cfg.input_rules[0].zone = Some("empty".into());
        assert!(validate_firewall_config(&cfg)[0].contains("no interfaces"));
        // Disabled rules are not applied, so their zones are not checked.
        cfg.input_rules[0].enabled = false;
        assert!(validate_firewall_config(&cfg).is_empty());

        cfg.forward_rules.push(ForwardRule {
            name: "f".into(),
            dest_zone: Some("missing".into()),
            ..Default::default()
        });
        assert_eq!(validate_firewall_config(&cfg).len(), 1);
        cfg.port_forwards.push(PortForward {
            name: "p".into(),
            external_port_start: 80,
            dest_ip: "10.0.0.2".into(),
            source_zone: Some("empty".into()),
            ..Default::default()
        });
        assert_eq!(validate_firewall_config(&cfg).len(), 2);
    }
}
