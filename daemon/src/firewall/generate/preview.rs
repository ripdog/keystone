//! Human-readable preview of the nftables ruleset.
//!
//! The preview is rendered from the same rule model as the JSON ruleset, so it
//! lists exactly the rules that are applied, in the same order. Its text is
//! nftables syntax: `nft -c -f` parses it (see the tests).

use crate::firewall::generate::{FILTER_TABLE, NAT_TABLE};
use crate::firewall::groups::{
    Family, address_set_name, normalized_networks, normalized_ports, port_set_name,
};
use crate::firewall::rules::{Addr, ChainSpec, Cond, Ports, RuleSpec, Side, Verdict, build};
use keystone_core::FirewallConfig;
use std::net::IpAddr;

/// Render the complete ruleset as nftables text.
pub fn generate_preview(config: &FirewallConfig) -> String {
    let ruleset = build(config);
    let mut out = String::new();
    out.push_str("#!/usr/sbin/nft -f\n");
    out.push_str("# Keystone Firewall - Auto-generated\n");
    out.push_str(&format!("# Generated: {}\n\n", timestamp()));

    out.push_str(&format!("table inet {FILTER_TABLE} {{\n"));
    out.push_str(&set_definitions(config));
    push_chain(
        &mut out,
        &ruleset.input,
        "type filter hook input priority filter;",
    );
    push_chain(
        &mut out,
        &ruleset.forward,
        "type filter hook forward priority filter;",
    );
    out.push_str("    chain output {\n");
    out.push_str("        type filter hook output priority filter; policy accept;\n");
    out.push_str("    }\n}\n\n");

    out.push_str(&format!("table inet {NAT_TABLE} {{\n"));
    out.push_str(&set_definitions(config));
    push_chain(
        &mut out,
        &ruleset.prerouting,
        "type nat hook prerouting priority dstnat;",
    );
    push_chain(
        &mut out,
        &ruleset.postrouting,
        "type nat hook postrouting priority srcnat;",
    );
    out.push_str("}\n");
    out
}

fn push_chain(out: &mut String, chain: &ChainSpec, declaration: &str) {
    let policy = match chain.policy {
        Some(Verdict::Drop) => " policy drop;",
        Some(Verdict::Accept) => " policy accept;",
        _ => "",
    };
    out.push_str(&format!("    chain {} {{\n", chain.name));
    out.push_str(&format!("        {declaration}{policy}\n"));
    let mut section = None;
    for rule in &chain.rules {
        if section != Some(rule.section) {
            out.push_str(&format!("\n        # {}\n", rule.section));
            section = Some(rule.section);
        }
        out.push_str(&format!("        {}\n", rule_text(rule)));
    }
    out.push_str("    }\n\n");
}

fn rule_text(rule: &RuleSpec) -> String {
    let mut parts: Vec<String> = rule.conds.iter().map(cond_text).collect();
    if let Some(prefix) = &rule.log {
        parts.push(format!("log prefix \"{}\"", quoted(prefix)));
    }
    parts.push("counter".to_string());
    parts.push(verdict_text(rule.verdict));
    parts.push(format!("comment \"{}\"", quoted(&rule.comment)));
    parts.join(" ")
}

fn cond_text(cond: &Cond) -> String {
    match cond {
        Cond::Iif(interfaces) => format!("iifname {}", interface_set(interfaces)),
        Cond::Oif(interfaces) => format!("oifname {}", interface_set(interfaces)),
        Cond::Nfproto(Family::V4) => "meta nfproto ipv4".to_string(),
        Cond::Nfproto(Family::V6) => "meta nfproto ipv6".to_string(),
        Cond::Addr { side, addr } => address_text(*side, addr),
        Cond::L4(protocol) => format!("meta l4proto {protocol}"),
        Cond::Port {
            side,
            payload,
            ports,
        } => port_text(*side, payload, ports),
        Cond::IcmpType { v6, icmp_type } => {
            let protocol = if *v6 { "icmpv6" } else { "icmp" };
            format!("{protocol} type {icmp_type}")
        }
        Cond::CtStateIn(states) => format!("ct state {}", states.join(",")),
        Cond::CtStateIs(state) => format!("ct state {state}"),
        Cond::CtDnat => "ct status dnat".to_string(),
        Cond::FibLocal => "fib daddr type local".to_string(),
        Cond::FibNotOnIngress => "fib daddr . iif type != local".to_string(),
        Cond::RateLimit { rate, per } => format!("limit rate {rate}/{per}"),
    }
}

fn verdict_text(verdict: Verdict) -> String {
    match verdict {
        Verdict::Accept => "accept".to_string(),
        Verdict::Drop => "drop".to_string(),
        Verdict::Reject => "reject".to_string(),
        Verdict::Dnat {
            addr,
            port: Some(port),
        } => format!("dnat to {addr}:{port}"),
        Verdict::Dnat { addr, port: None } => format!("dnat to {addr}"),
        Verdict::Masquerade => "masquerade".to_string(),
    }
}

fn address_text(side: Side, addr: &Addr) -> String {
    let field = side_field(side, "saddr", "daddr");
    match addr {
        Addr::Literal(text) => {
            let family = match text.split('/').next().unwrap_or(text).parse::<IpAddr>() {
                Ok(IpAddr::V6(_)) => "ip6",
                _ => "ip",
            };
            format!("{family} {field} {text}")
        }
        Addr::Group { name, family } => format!(
            "{} {} @{}",
            family.payload(),
            field,
            address_set_name(name, *family)
        ),
    }
}

fn port_text(side: Side, payload: &str, ports: &Ports) -> String {
    let field = side_field(side, "sport", "dport");
    let value = match ports {
        Ports::Single(port) => port.to_string(),
        Ports::Range(start, end) => format!("{start}-{end}"),
        Ports::Group(group) => format!("@{}", port_set_name(group)),
    };
    format!("{payload} {field} {value}")
}

fn side_field(side: Side, source: &'static str, destination: &'static str) -> &'static str {
    match side {
        Side::Source => source,
        Side::Destination => destination,
    }
}

/// `"eth0"`, or `{ "eth1", "eth2" }` for several interfaces.
fn interface_set(interfaces: &[String]) -> String {
    if let [interface] = interfaces {
        format!("\"{}\"", quoted(interface))
    } else {
        let names: Vec<String> = interfaces
            .iter()
            .map(|name| format!("\"{}\"", quoted(name)))
            .collect();
        format!("{{ {} }}", names.join(", "))
    }
}

/// nftables quoted strings have no escapes, so quotes and backslashes are
/// replaced. Only the text shown in the preview is affected.
fn quoted(text: &str) -> String {
    text.chars()
        .map(|c| if c == '"' || c == '\\' { '\'' } else { c })
        .collect()
}

/// Named sets for every group, as they appear in each table.
fn set_definitions(config: &FirewallConfig) -> String {
    let mut out = String::new();
    for group in &config.address_groups {
        for family in [Family::V4, Family::V6] {
            let nets = normalized_networks(&group.entries, family);
            if nets.is_empty() {
                continue;
            }
            let elements: Vec<String> = nets.iter().map(|net| net.to_string()).collect();
            let set_type = match family {
                Family::V4 => "ipv4_addr",
                Family::V6 => "ipv6_addr",
            };
            out.push_str(&format!(
                "    set {} {{\n        type {};\n        flags interval;\n        elements = {{ {} }}\n    }}\n",
                address_set_name(&group.name, family),
                set_type,
                elements.join(", ")
            ));
        }
    }
    for group in &config.port_groups {
        let ranges = normalized_ports(&group.entries);
        if ranges.is_empty() {
            continue;
        }
        let elements: Vec<String> = ranges
            .iter()
            .map(|&(start, end)| {
                if start == end {
                    start.to_string()
                } else {
                    format!("{start}-{end}")
                }
            })
            .collect();
        out.push_str(&format!(
            "    set {} {{\n        type inet_service;\n        flags interval;\n        elements = {{ {} }}\n    }}\n",
            port_set_name(&group.name),
            elements.join(", ")
        ));
    }
    out
}

fn timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("Unix timestamp: {}", duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::fixtures::{rich, sample_configs};
    use std::io::Write;
    use std::process::{Command, Stdio};

    #[test]
    fn quoted_text_cannot_end_a_string() {
        assert_eq!(quoted("a\"b\\c"), "a'b'c");
    }

    #[test]
    fn interface_sets_are_quoted_for_one_and_many() {
        assert_eq!(interface_set(&["eth0".to_string()]), "\"eth0\"");
        assert_eq!(
            interface_set(&["eth0".to_string(), "eth1".to_string()]),
            "{ \"eth0\", \"eth1\" }"
        );
    }

    #[test]
    fn port_text_uses_the_transport_payload() {
        assert_eq!(
            port_text(Side::Destination, "th", &Ports::Range(8000, 8100)),
            "th dport 8000-8100"
        );
        assert_eq!(
            port_text(Side::Source, "udp", &Ports::Single(547)),
            "udp sport 547"
        );
    }

    /// Every sample preview is accepted by the nftables parser. Only syntax
    /// errors fail the test: an unprivileged `nft -c` stops at the kernel
    /// check, which is not a failure here. Skipped when nft is absent.
    #[test]
    fn preview_parses_as_nftables_syntax() {
        if Command::new("nft").arg("--version").output().is_err() {
            return;
        }
        for (name, config) in sample_configs() {
            let text = generate_preview(&config);
            let mut child = Command::new("nft")
                .args(["-c", "-f", "-"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("nft starts");
            child
                .stdin
                .take()
                .expect("stdin")
                .write_all(text.as_bytes())
                .expect("write preview");
            let output = child.wait_with_output().expect("nft finishes");
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                !stderr.contains("syntax error"),
                "{name} preview does not parse:\n{stderr}"
            );
        }
    }

    #[test]
    fn hairpin_snat_is_written_as_address_then_port_match() {
        let text = generate_preview(&rich());
        assert!(
            text.contains("ip daddr 192.168.1.100 th dport 80 counter masquerade"),
            "{text}"
        );
        assert!(!text.contains("tcp+udp"), "{text}");
    }

    #[test]
    fn preview_lists_only_rules_that_are_applied() {
        let text = generate_preview(&rich());
        assert!(!text.contains("Invalid rate"), "{text}");
        assert!(!text.contains("Unknown zone"), "{text}");
        assert!(!text.contains("Disabled rule"), "{text}");
    }
}
