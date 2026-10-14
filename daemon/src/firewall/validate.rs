//! Validation of firewall configuration.
//!
//! These checks run when rules are saved and again before the ruleset is
//! generated, so that bad rows already in the database can never be applied
//! as a rule that silently matches more traffic than intended.

use crate::firewall::groups::{
    Family, GroupIndex, family_variants, literal_family, side_families, validate_address_group,
    validate_group_names, validate_port_group,
};
use crate::firewall::rules::parse_rate_limit;
use ipnet::IpNet;
use keystone_core::{
    FirewallConfig, FirewallZone, ForwardRule, InputRule, PortForward, RuleProtocol,
    ZoneForwardPolicy,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

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

/// Names, descriptions and log prefixes are written into generated rules, so
/// they must stay on one line.
fn check_text(what: &str, field: &str, value: &str, errors: &mut Vec<String>) {
    if !keystone_core::validation::is_single_line(value) {
        errors.push(format!("{what}: {field} contains control characters"));
    }
}

fn check_optional_text(what: &str, field: &str, value: Option<&str>, errors: &mut Vec<String>) {
    if let Some(value) = value {
        check_text(what, field, value, errors);
    }
}

/// Source addresses are a single IP address or a CIDR network.
fn check_address(what: &str, field: &str, value: Option<&str>, errors: &mut Vec<String>) {
    if let Some(value) = value
        && value.parse::<IpAddr>().is_err()
        && value.parse::<IpNet>().is_err()
    {
        errors.push(format!(
            "{what}: {field} {value:?} is not an IP address or CIDR network"
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

/// A group reference must name a group of the right kind.
fn check_address_group_ref(
    what: &str,
    role: &str,
    name: Option<&str>,
    groups: &GroupIndex,
    errors: &mut Vec<String>,
) {
    if let Some(name) = name
        && !groups.has_address(name)
    {
        errors.push(format!("{what}: {role} '{name}' does not exist"));
    }
}

fn check_port_group_ref(
    what: &str,
    name: Option<&str>,
    groups: &GroupIndex,
    errors: &mut Vec<String>,
) {
    if let Some(name) = name
        && !groups.has_port(name)
    {
        errors.push(format!("{what}: port group '{name}' does not exist"));
    }
}

/// A literal address and an address group are alternatives for one side.
fn check_one_of(what: &str, first: (&str, bool), second: (&str, bool), errors: &mut Vec<String>) {
    if first.1 && second.1 {
        errors.push(format!(
            "{what}: {} and {} cannot both be set",
            first.0, second.0
        ));
    }
}

/// A port group needs a protocol that has ports.
fn check_port_group_protocol(
    what: &str,
    protocol: Option<&RuleProtocol>,
    group: Option<&String>,
    errors: &mut Vec<String>,
) {
    if group.is_some() && !is_port_protocol(protocol) {
        errors.push(format!(
            "{what}: a port group can only be used with protocol TCP, UDP or TCP+UDP"
        ));
    }
}

/// Validate the fields of a single input rule, including its group references.
pub fn validate_input_rule(rule: &InputRule, groups: &GroupIndex) -> Vec<String> {
    let what = format!("Input rule '{}'", rule.name);
    let mut errors = Vec::new();
    check_text(&what, "name", &rule.name, &mut errors);
    check_optional_text(
        &what,
        "description",
        rule.description.as_deref(),
        &mut errors,
    );
    check_optional_text(&what, "log prefix", rule.log_prefix.as_deref(), &mut errors);
    check_address(&what, "source IP", rule.source_ip.as_deref(), &mut errors);
    check_one_of(
        &what,
        ("source IP", rule.source_ip.is_some()),
        ("source group", rule.source_group.is_some()),
        &mut errors,
    );
    check_address_group_ref(
        &what,
        "source group",
        rule.source_group.as_deref(),
        groups,
        &mut errors,
    );
    check_one_of(
        &what,
        (
            "destination ports",
            rule.port_start.is_some() || rule.port_end.is_some(),
        ),
        ("destination port group", rule.dest_port_group.is_some()),
        &mut errors,
    );
    check_ports(
        &what,
        rule.protocol.as_ref(),
        rule.port_start,
        rule.port_end,
        &mut errors,
    );
    check_port_group_protocol(
        &what,
        rule.protocol.as_ref(),
        rule.dest_port_group.as_ref(),
        &mut errors,
    );
    check_port_group_ref(&what, rule.dest_port_group.as_deref(), groups, &mut errors);
    check_rate_limit(&what, rule.rate_limit.as_ref(), &mut errors);
    errors
}

/// Validate the fields of a single forward rule, including its group references
/// and whether its source and destination address families can meet.
pub fn validate_forward_rule(rule: &ForwardRule, groups: &GroupIndex) -> Vec<String> {
    let what = format!("Forward rule '{}'", rule.name);
    let mut errors = Vec::new();
    check_text(&what, "name", &rule.name, &mut errors);
    check_optional_text(
        &what,
        "description",
        rule.description.as_deref(),
        &mut errors,
    );
    check_optional_text(&what, "log prefix", rule.log_prefix.as_deref(), &mut errors);
    check_address(&what, "source IP", rule.source_ip.as_deref(), &mut errors);
    check_address(
        &what,
        "destination IP",
        rule.dest_ip.as_deref(),
        &mut errors,
    );
    check_one_of(
        &what,
        ("source IP", rule.source_ip.is_some()),
        ("source group", rule.source_group.is_some()),
        &mut errors,
    );
    check_one_of(
        &what,
        ("destination IP", rule.dest_ip.is_some()),
        ("destination group", rule.dest_group.is_some()),
        &mut errors,
    );
    check_one_of(
        &what,
        (
            "destination ports",
            rule.dest_port_start.is_some() || rule.dest_port_end.is_some(),
        ),
        ("destination port group", rule.dest_port_group.is_some()),
        &mut errors,
    );
    check_address_group_ref(
        &what,
        "source group",
        rule.source_group.as_deref(),
        groups,
        &mut errors,
    );
    check_address_group_ref(
        &what,
        "destination group",
        rule.dest_group.as_deref(),
        groups,
        &mut errors,
    );
    check_port_group_ref(&what, rule.dest_port_group.as_deref(), groups, &mut errors);
    check_ports(
        &what,
        rule.protocol.as_ref(),
        rule.dest_port_start,
        rule.dest_port_end,
        &mut errors,
    );
    check_port_group_protocol(
        &what,
        rule.protocol.as_ref(),
        rule.dest_port_group.as_ref(),
        &mut errors,
    );
    check_rate_limit(&what, rule.rate_limit.as_ref(), &mut errors);

    // Only meaningful when both sides resolve; reference errors are reported above.
    let source = side_families(
        rule.source_ip.as_deref(),
        rule.source_group.as_deref(),
        groups,
    );
    let dest = side_families(rule.dest_ip.as_deref(), rule.dest_group.as_deref(), groups);
    if let (Ok(source), Ok(dest)) = (source, dest)
        && family_variants(&[source, dest]).is_empty()
    {
        errors.push(format!(
            "{what}: the source and destination addresses are of different IP families"
        ));
    }
    errors
}

/// Validate the fields of a single port forward, including its source group.
pub fn validate_port_forward(pf: &PortForward, groups: &GroupIndex) -> Vec<String> {
    let what = format!("Port forward '{}'", pf.name);
    let mut errors = Vec::new();
    check_text(&what, "name", &pf.name, &mut errors);
    check_optional_text(&what, "description", pf.description.as_deref(), &mut errors);
    check_address(&what, "source IP", pf.source_ip.as_deref(), &mut errors);
    check_one_of(
        &what,
        ("source IP", pf.source_ip.is_some()),
        ("source group", pf.source_group.is_some()),
        &mut errors,
    );
    // DNAT is IPv4 only, so a source restriction must be able to match IPv4.
    if let Some(source) = pf.source_ip.as_deref()
        && literal_family(source) == Some(Family::V6)
    {
        errors.push(format!(
            "{what}: source IP {source:?} must be IPv4 (port forwards are IPv4 only)"
        ));
    }
    check_address_group_ref(
        &what,
        "source group",
        pf.source_group.as_deref(),
        groups,
        &mut errors,
    );
    if let Some(name) = pf.source_group.as_deref()
        && groups
            .families(name)
            .is_some_and(|families| !families.contains(&Family::V4))
    {
        errors.push(format!(
            "{what}: source group '{name}' has no IPv4 entries, and port forwards are IPv4 only"
        ));
    }
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

/// Validate a zone's own fields: its name, description and interface names.
/// Reserved names and interface membership shared with other zones are checked
/// by the callers that have the other zones.
pub fn validate_zone(zone: &FirewallZone) -> Vec<String> {
    let what = format!("Zone '{}'", zone.name);
    let mut errors = Vec::new();
    if zone.name.is_empty() {
        errors.push("Zone name is required".to_string());
    }
    check_text(&what, "name", &zone.name, &mut errors);
    check_optional_text(
        &what,
        "description",
        zone.description.as_deref(),
        &mut errors,
    );
    for interface in &zone.interfaces {
        if let Err(error) = keystone_core::validation::interface_name(interface) {
            errors.push(format!("{what}: {error}"));
        }
    }
    errors
}

/// Validate a zone-to-zone policy's zone names. Zone existence is enforced by
/// the foreign keys that store the policy.
pub fn validate_zone_forward(policy: &ZoneForwardPolicy) -> Vec<String> {
    let what = format!(
        "Zone forward '{}' -> '{}'",
        policy.source_zone, policy.dest_zone
    );
    let mut errors = Vec::new();
    check_text(&what, "source zone", &policy.source_zone, &mut errors);
    check_text(&what, "destination zone", &policy.dest_zone, &mut errors);
    errors
}

fn check_zone(
    what: &str,
    role: &str,
    zone: Option<&String>,
    zones: &HashMap<&str, usize>,
    require_interfaces: bool,
    errors: &mut Vec<String>,
) {
    let Some(name) = zone else { return };
    match zones.get(name.as_str()) {
        None => errors.push(format!("{what}: {role} zone '{name}' does not exist")),
        Some(0) if require_interfaces => errors.push(format!(
            "{what}: {role} zone '{name}' has no interfaces, so the rule would match every interface"
        )),
        Some(_) => {}
    }
}

/// Validate the whole configuration as apply requires it. Returns
/// human-readable errors.
pub fn validate_firewall_config(cfg: &FirewallConfig) -> Vec<String> {
    check_firewall(cfg, true)
}

/// The checks of [`validate_firewall_config`] for a configuration that is
/// stored or restored rather than applied. A zone with no interfaces is not an
/// error here: the default rules of an unfinished setup refer to such zones,
/// and apply refuses them until interfaces are assigned. Everything else,
/// including references to zones that do not exist, is still checked.
pub fn validate_firewall_definitions(cfg: &FirewallConfig) -> Vec<String> {
    check_firewall(cfg, false)
}

fn check_firewall(cfg: &FirewallConfig, require_interfaces: bool) -> Vec<String> {
    let zones: HashMap<&str, usize> = cfg
        .zones
        .iter()
        .map(|z| (z.name.as_str(), z.interfaces.len()))
        .collect();
    let groups = GroupIndex::new(&cfg.address_groups, &cfg.port_groups);
    let mut errors = Vec::new();

    for zone in &cfg.zones {
        errors.extend(validate_zone(zone));
    }
    for group in &cfg.address_groups {
        errors.extend(validate_address_group(group));
    }
    for group in &cfg.port_groups {
        errors.extend(validate_port_group(group));
    }
    errors.extend(validate_group_names(&cfg.address_groups, &cfg.port_groups));
    for policy in &cfg.zone_forwards {
        errors.extend(validate_zone_forward(policy));
    }
    check_address_group_ref(
        "Firewall settings",
        "DNS exempt group",
        cfg.global_settings.dns_exempt_group.as_deref(),
        &groups,
        &mut errors,
    );
    for (i, zone) in cfg.zones.iter().enumerate() {
        errors.extend(crate::config_validation::zone_interface_conflicts(
            zone,
            &cfg.zones[i + 1..],
        ));
    }

    for rule in &cfg.input_rules {
        errors.extend(validate_input_rule(rule, &groups));
        if rule.enabled {
            let what = format!("Input rule '{}'", rule.name);
            check_zone(
                &what,
                "source",
                rule.zone.as_ref(),
                &zones,
                require_interfaces,
                &mut errors,
            );
        }
    }
    for rule in &cfg.forward_rules {
        errors.extend(validate_forward_rule(rule, &groups));
        if rule.enabled {
            let what = format!("Forward rule '{}'", rule.name);
            check_zone(
                &what,
                "source",
                rule.source_zone.as_ref(),
                &zones,
                require_interfaces,
                &mut errors,
            );
            check_zone(
                &what,
                "destination",
                rule.dest_zone.as_ref(),
                &zones,
                require_interfaces,
                &mut errors,
            );
        }
    }
    for pf in &cfg.port_forwards {
        errors.extend(validate_port_forward(pf, &groups));
        if pf.enabled {
            let what = format!("Port forward '{}'", pf.name);
            check_zone(
                &what,
                "source",
                pf.source_zone.as_ref(),
                &zones,
                require_interfaces,
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
            assert!(
                !validate_input_rule(&input(p, Some(22), None), &GroupIndex::default()).is_empty()
            );
        }
        for p in [RuleProtocol::Tcp, RuleProtocol::Udp, RuleProtocol::TcpUdp] {
            assert!(
                validate_input_rule(&input(Some(p), Some(22), None), &GroupIndex::default())
                    .is_empty()
            );
        }
        assert!(validate_input_rule(&input(None, None, None), &GroupIndex::default()).is_empty());
    }

    #[test]
    fn port_range_and_zero_rejected() {
        let t = Some(RuleProtocol::Tcp);
        assert!(!validate_input_rule(&input(t, Some(0), None), &GroupIndex::default()).is_empty());
        assert!(
            !validate_input_rule(&input(t, Some(100), Some(50)), &GroupIndex::default()).is_empty()
        );
        assert!(!validate_input_rule(&input(t, None, Some(50)), &GroupIndex::default()).is_empty());
        assert!(
            validate_input_rule(&input(t, Some(50), Some(100)), &GroupIndex::default()).is_empty()
        );
    }

    #[test]
    fn forward_rule_ports_and_rate_limit() {
        let rule = ForwardRule {
            name: "f".into(),
            dest_port_start: Some(80),
            rate_limit: Some("fast".into()),
            ..Default::default()
        };
        let errors = validate_forward_rule(&rule, &GroupIndex::default());
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
        assert!(validate_port_forward(&good, &GroupIndex::default()).is_empty());

        let mut v6 = good.clone();
        v6.dest_ip = "fd00::1".into();
        assert!(validate_port_forward(&v6, &GroupIndex::default())[0].contains("IPv6"));

        let mut any = good.clone();
        any.protocol = RuleProtocol::Any;
        assert!(!validate_port_forward(&any, &GroupIndex::default()).is_empty());

        let mut range = good.clone();
        range.external_port_end = Some(8090);
        range.dest_port = Some(80);
        assert!(!validate_port_forward(&range, &GroupIndex::default()).is_empty());
        range.dest_port = None;
        assert!(validate_port_forward(&range, &GroupIndex::default()).is_empty());

        let mut backwards = good;
        backwards.external_port_end = Some(8000);
        assert!(!validate_port_forward(&backwards, &GroupIndex::default()).is_empty());
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

    #[test]
    fn rule_text_must_be_single_line() {
        let mut rule = InputRule {
            name: "ssh\naccept".into(),
            protocol: Some(RuleProtocol::Tcp),
            port_start: Some(22),
            ..Default::default()
        };
        assert!(
            validate_input_rule(&rule, &GroupIndex::default())
                .iter()
                .any(|e| e.contains("name contains control characters"))
        );
        rule.name = "ssh".into();
        rule.description = Some("LAN\u{2028}only".into());
        assert!(
            validate_input_rule(&rule, &GroupIndex::default())
                .iter()
                .any(|e| e.contains("description contains control"))
        );
        rule.description = None;
        rule.log_prefix = Some("ssh\r".into());
        assert!(
            validate_input_rule(&rule, &GroupIndex::default())
                .iter()
                .any(|e| e.contains("log prefix contains control"))
        );
        rule.log_prefix = None;
        assert!(validate_input_rule(&rule, &GroupIndex::default()).is_empty());
    }

    #[test]
    fn source_and_destination_addresses_are_ips_or_networks() {
        let mut rule = ForwardRule {
            name: "f".into(),
            protocol: Some(RuleProtocol::Tcp),
            dest_port_start: Some(80),
            ..Default::default()
        };
        for good in ["10.0.0.0/8", "10.0.0.1", "fd00::/64", "fd00::1"] {
            rule.source_ip = Some(good.into());
            rule.dest_ip = Some(good.into());
            assert!(
                validate_forward_rule(&rule, &GroupIndex::default()).is_empty(),
                "{good}"
            );
        }
        for bad in ["10.0.0.0/33", "10.0.0.1 accept", "example.com"] {
            rule.source_ip = Some(bad.into());
            rule.dest_ip = None;
            assert!(
                validate_forward_rule(&rule, &GroupIndex::default())[0].contains("source IP"),
                "{bad}"
            );
        }
        rule.source_ip = None;
        rule.dest_ip = Some("10.0.0.300".into());
        assert!(validate_forward_rule(&rule, &GroupIndex::default())[0].contains("destination IP"));
    }

    #[test]
    fn port_forward_text_and_source_must_be_well_formed() {
        let mut pf = PortForward {
            name: "web".into(),
            external_port_start: 8080,
            dest_ip: "192.168.1.2".into(),
            ..Default::default()
        };
        assert!(validate_port_forward(&pf, &GroupIndex::default()).is_empty());
        pf.description = Some("web\nserver".into());
        assert!(!validate_port_forward(&pf, &GroupIndex::default()).is_empty());
        pf.description = None;
        pf.source_ip = Some("not an ip".into());
        assert!(!validate_port_forward(&pf, &GroupIndex::default()).is_empty());
    }

    #[test]
    fn zone_fields_and_interface_names_are_checked() {
        let mut z = zone("office", &["eth1", "br-lan.10"]);
        assert!(validate_zone(&z).is_empty());
        z.interfaces.push("eth1\naccept".into());
        assert!(
            validate_zone(&z)
                .iter()
                .any(|e| e.contains("Invalid network interface name"))
        );
        z.interfaces.pop();
        z.name = "office\rx".into();
        assert!(
            validate_zone(&z)
                .iter()
                .any(|e| e.contains("name contains control characters"))
        );
        z.name = String::new();
        assert!(validate_zone(&z)[0].contains("Zone name is required"));
    }

    #[test]
    fn zone_forward_zone_names_must_be_single_line() {
        let policy = ZoneForwardPolicy {
            source_zone: "lan".into(),
            dest_zone: "wan".into(),
            ..Default::default()
        };
        assert!(validate_zone_forward(&policy).is_empty());
        let bad = ZoneForwardPolicy {
            dest_zone: "wan\n".into(),
            ..policy
        };
        assert!(!validate_zone_forward(&bad).is_empty());
        let cfg = FirewallConfig {
            zone_forwards: vec![bad],
            ..Default::default()
        };
        assert!(!validate_firewall_config(&cfg).is_empty());
    }
}

#[cfg(test)]
mod group_validation_tests {
    use super::*;
    use keystone_core::{AddressGroup, PortGroup};

    fn groups() -> (Vec<AddressGroup>, Vec<PortGroup>) {
        (
            vec![
                AddressGroup {
                    name: "v4_only".into(),
                    entries: vec!["10.0.0.0/8".into()],
                    ..Default::default()
                },
                AddressGroup {
                    name: "v6_only".into(),
                    entries: vec!["fd00::/64".into()],
                    ..Default::default()
                },
            ],
            vec![PortGroup {
                name: "web".into(),
                entries: vec!["443".into()],
                ..Default::default()
            }],
        )
    }

    #[test]
    fn source_ip_and_source_group_are_exclusive() {
        let (a, p) = groups();
        let index = GroupIndex::new(&a, &p);
        let rule = InputRule {
            name: "r".into(),
            source_ip: Some("10.1.1.1".into()),
            source_group: Some("v4_only".into()),
            ..Default::default()
        };
        assert!(
            validate_input_rule(&rule, &index)
                .iter()
                .any(|e| e.contains("cannot both be set"))
        );
    }

    #[test]
    fn group_references_must_exist_with_the_right_kind() {
        let (a, p) = groups();
        let index = GroupIndex::new(&a, &p);
        let missing = InputRule {
            name: "r".into(),
            source_group: Some("nope".into()),
            ..Default::default()
        };
        assert!(validate_input_rule(&missing, &index)[0].contains("'nope' does not exist"));

        // A port group is not an address group, and vice versa.
        let wrong_kind = ForwardRule {
            name: "f".into(),
            protocol: Some(RuleProtocol::Tcp),
            dest_group: Some("web".into()),
            dest_port_group: Some("v4_only".into()),
            ..Default::default()
        };
        let errors = validate_forward_rule(&wrong_kind, &index);
        assert!(
            errors.iter().any(|e| e.contains("destination group 'web'")),
            "{errors:?}"
        );
        assert!(
            errors.iter().any(|e| e.contains("port group 'v4_only'")),
            "{errors:?}"
        );
    }

    #[test]
    fn port_group_needs_tcp_or_udp_and_excludes_literal_ports() {
        let (a, p) = groups();
        let index = GroupIndex::new(&a, &p);
        let no_protocol = InputRule {
            name: "r".into(),
            dest_port_group: Some("web".into()),
            ..Default::default()
        };
        assert!(
            validate_input_rule(&no_protocol, &index)
                .iter()
                .any(|e| e.contains("port group can only be used"))
        );

        let both = InputRule {
            name: "r".into(),
            protocol: Some(RuleProtocol::Tcp),
            port_start: Some(22),
            dest_port_group: Some("web".into()),
            ..Default::default()
        };
        assert!(
            validate_input_rule(&both, &index)
                .iter()
                .any(|e| e.contains("cannot both be set"))
        );

        let good = InputRule {
            name: "r".into(),
            protocol: Some(RuleProtocol::TcpUdp),
            dest_port_group: Some("web".into()),
            ..Default::default()
        };
        assert!(validate_input_rule(&good, &index).is_empty());
    }

    #[test]
    fn forward_rule_families_must_meet() {
        let (a, p) = groups();
        let index = GroupIndex::new(&a, &p);
        let mismatch = ForwardRule {
            name: "f".into(),
            source_group: Some("v4_only".into()),
            dest_group: Some("v6_only".into()),
            ..Default::default()
        };
        assert!(
            validate_forward_rule(&mismatch, &index)
                .iter()
                .any(|e| e.contains("different IP families"))
        );

        let literal_mismatch = ForwardRule {
            name: "f".into(),
            source_ip: Some("10.0.0.1".into()),
            dest_ip: Some("fd00::1".into()),
            ..Default::default()
        };
        assert!(!validate_forward_rule(&literal_mismatch, &index).is_empty());

        let same = ForwardRule {
            name: "f".into(),
            source_group: Some("v4_only".into()),
            dest_ip: Some("192.0.2.1".into()),
            ..Default::default()
        };
        assert!(validate_forward_rule(&same, &index).is_empty());
    }

    #[test]
    fn port_forward_source_group_must_be_able_to_match_ipv4() {
        let (a, p) = groups();
        let index = GroupIndex::new(&a, &p);
        let pf = PortForward {
            name: "web".into(),
            external_port_start: 8080,
            dest_ip: "192.168.1.2".into(),
            source_group: Some("v6_only".into()),
            ..Default::default()
        };
        assert!(
            validate_port_forward(&pf, &index)
                .iter()
                .any(|e| e.contains("no IPv4 entries"))
        );

        let v4 = PortForward {
            source_group: Some("v4_only".into()),
            ..pf.clone()
        };
        assert!(validate_port_forward(&v4, &index).is_empty());

        let v6_literal = PortForward {
            source_group: None,
            source_ip: Some("fd00::/64".into()),
            ..pf
        };
        assert!(
            validate_port_forward(&v6_literal, &index)
                .iter()
                .any(|e| e.contains("must be IPv4"))
        );
    }

    #[test]
    fn stored_configuration_checks_group_objects_and_references() {
        let (a, mut p) = groups();
        p[0].name = "v4_only".into(); // duplicate of an address group name
        let cfg = FirewallConfig {
            address_groups: a,
            port_groups: p,
            input_rules: vec![InputRule {
                name: "r".into(),
                source_group: Some("gone".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let errors = validate_firewall_definitions(&cfg);
        assert!(
            errors.iter().any(|e| e.contains("more than one")),
            "{errors:?}"
        );
        assert!(
            errors.iter().any(|e| e.contains("'gone' does not exist")),
            "{errors:?}"
        );
    }
}
