//! Human-readable preview generation for nftables rulesets
//!
//! This module generates a human-readable representation of the firewall
//! configuration in nftables syntax format.

use crate::firewall::generate::{
    FILTER_TABLE, NAT_TABLE, find_ipv4_masquerade_zones, find_wan_zones, rule_comment,
};
use crate::firewall::groups::{
    Family, GroupIndex, address_set_name, family_variants, normalized_networks, normalized_ports,
    port_set_name, side_families,
};
use crate::firewall::rules::Side;
use keystone_core::{
    FirewallConfig, FirewallPolicy, ForwardRule, InputRule, PortForward, RuleProtocol,
};
use std::{collections::HashMap, net::IpAddr};

fn address_family(addr: &str) -> &'static str {
    match addr.split('/').next().unwrap_or(addr).parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => "ip6",
        _ => "ip",
    }
}

/// Generate a human-readable preview of the firewall rules
pub fn generate_preview(
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
    output.push_str(&set_definitions(config));

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
    // DHCPv6 unicast replies to multicast solicitations may not match
    // conntrack's established state; preserve them before invalid DROP.
    let mut wan_interfaces = find_wan_zones(&config.zones)
        .into_iter()
        .flat_map(|zone| zone.interfaces.iter().cloned())
        .collect::<Vec<_>>();
    wan_interfaces.sort();
    wan_interfaces.dedup();
    if !wan_interfaces.is_empty() {
        output.push_str("        # Accept DHCPv6 server replies on WAN\n");
        output.push_str(&format!(
            "        iifname {} meta nfproto ipv6 meta l4proto udp udp sport 547 udp dport 546 counter accept\n",
            format_interface_set(&wan_interfaces)
        ));
    }
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
    let wan_zone_names_preview: Vec<&str> =
        wan_zones_preview.iter().map(|z| z.name.as_str()).collect();

    if config.global_settings.ping_lan_enabled {
        output.push_str("        # Allow ping from LAN zones\n");
        for zone in &config.zones {
            if !wan_zone_names_preview.contains(&zone.name.as_str()) && !zone.interfaces.is_empty()
            {
                let ifaces = format_interface_set(&zone.interfaces);
                output.push_str(&format!(
                    "        iifname {} icmp type echo-request counter accept  # IPv4 ping from {}\n",
                    ifaces, zone.name
                ));
                output.push_str(&format!(
                    "        iifname {} icmpv6 type echo-request counter accept  # IPv6 ping from {}\n",
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
                    "        iifname {} icmp type echo-request counter accept  # IPv4 ping from {}\n",
                    ifaces, zone.name
                ));
                output.push_str(&format!(
                    "        iifname {} icmpv6 type echo-request counter accept  # IPv6 ping from {}\n",
                    ifaces, zone.name
                ));
            }
        }
    }

    output
        .push_str("        # Allow essential ICMP types (required for proper network operation)\n");
    output.push_str("        icmp type { destination-unreachable, time-exceeded, parameter-problem } counter accept\n");
    output.push_str(
        "        # Essential ICMPv6 error, neighbour/router discovery, and MLD traffic\n",
    );
    output.push_str("        icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, mld-listener-query, mld-listener-report, mld-listener-done, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, mld2-listener-report } counter accept\n");
    output.push_str("        \n");
    output.push_str("        # Priority 4: User Input Rules\n");

    let mut sorted_input_rules: Vec<_> = config.input_rules.iter().filter(|r| r.enabled).collect();
    sorted_input_rules.sort_by_key(|r| r.position);

    let groups = GroupIndex::new(&config.address_groups, &config.port_groups);
    for rule in &sorted_input_rules {
        for line in format_input_rule(rule, zone_interfaces, &groups) {
            output.push_str(&format!("        {}\n", line));
        }
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
    if let Some(upnp) = &config.upnp_forward {
        output.push_str("        # UPnP / NAT-PMP mappings (DNATed traffic, WAN to UPnP LANs)\n");
        output.push_str(&format!(
            "        iifname \"{}\" oifname {} ct status dnat accept comment \"ks:upnp\"\n",
            upnp.wan_interface,
            format_interface_set(&upnp.lan_interfaces)
        ));
        output.push_str("        \n");
    }
    output.push_str("        # Priority 3: User Forward Rules\n");

    let mut sorted_forward_rules: Vec<_> =
        config.forward_rules.iter().filter(|r| r.enabled).collect();
    sorted_forward_rules.sort_by_key(|r| r.position);

    for rule in &sorted_forward_rules {
        for line in format_forward_rule(rule, zone_interfaces, &groups) {
            output.push_str(&format!("        {}\n", line));
        }
    }

    output.push_str("        \n");
    output.push_str("        # Priority 4: Zone-to-Zone Policies\n");
    for policy in &config.zone_forwards {
        if policy.enabled
            && let (Some(src_ifaces), Some(dst_ifaces)) = (
                zone_interfaces.get(&policy.source_zone),
                zone_interfaces.get(&policy.dest_zone),
            )
            && !src_ifaces.is_empty()
            && !dst_ifaces.is_empty()
        {
            let src = format_interface_set(src_ifaces);
            let dst = format_interface_set(dst_ifaces);
            output.push_str(&format!(
                "        iifname {} oifname {} {}  # {} -> {}\n",
                src, dst, policy.policy, policy.source_zone, policy.dest_zone
            ));
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
    output.push_str(&set_definitions(config));

    // Prerouting chain
    output.push_str("    # ========================================\n");
    output.push_str("    # DNAT (Port Forwards)\n");
    output.push_str("    # ========================================\n");
    output.push_str("    chain prerouting {\n");
    output.push_str("        type nat hook prerouting priority dstnat;\n");
    output.push_str("        \n");
    output.push_str("        # Port forwards\n");

    for pf in &config.port_forwards {
        if pf.enabled
            && pf.dest_ip.parse::<std::net::Ipv4Addr>().is_ok()
            && let Some(line) = format_port_forward(pf, zone_interfaces, &groups)
        {
            output.push_str(&format!("        {}\n", line));
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
                if pf.enabled && pf.dest_ip.parse::<std::net::Ipv4Addr>().is_ok() {
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
                if pf.enabled && pf.dest_ip.parse::<std::net::Ipv4Addr>().is_ok() {
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

    let masquerade_zones = find_ipv4_masquerade_zones(&config.zones);
    for zone in masquerade_zones {
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
            output.push_str(&format!(
                "        meta nfproto ipv4 oifname \"{}\" masquerade\n",
                iface
            ));
        }
    }

    output.push_str("    }\n");
    output.push_str("}\n");

    output
}

/// Address match text for one side of a rule in one family. Literal addresses
/// print as written; a group prints the named set for that family.
fn address_text(
    side: Side,
    literal: Option<&str>,
    group: Option<&str>,
    family: Option<Family>,
) -> Option<String> {
    let field = match side {
        Side::Source => "saddr",
        Side::Destination => "daddr",
    };
    if let Some(literal) = literal {
        return Some(format!("{} {} {}", address_family(literal), field, literal));
    }
    let (group, family) = (group?, family?);
    Some(format!(
        "{} {} @{}",
        family.payload(),
        field,
        address_set_name(group, family)
    ))
}

/// Protocol and destination-port text for a rule. A port group prints as a set
/// lookup, a literal range as a range.
fn push_protocol_and_ports(
    parts: &mut Vec<String>,
    protocol: Option<&RuleProtocol>,
    port_start: Option<u16>,
    port_end: Option<u16>,
    port_group: Option<&str>,
) {
    let port = match port_group {
        Some(group) => Some(format!("@{}", port_set_name(group))),
        None => port_start.map(|start| format_port_range(start, port_end)),
    };
    match protocol {
        None | Some(RuleProtocol::Any) => {}
        Some(RuleProtocol::Tcp | RuleProtocol::Udp) => {
            parts.push(protocol.map(|p| p.to_string()).unwrap_or_default());
            if let Some(port) = port {
                parts.push(format!("dport {}", port));
            }
        }
        Some(RuleProtocol::TcpUdp) => {
            parts.push("meta l4proto { tcp, udp }".to_string());
            if let Some(port) = port {
                parts.push(format!("dport {}", port));
            }
        }
        Some(RuleProtocol::Icmp) => parts.push("icmp".to_string()),
        Some(RuleProtocol::Icmpv6) => parts.push("icmpv6".to_string()),
    }
}

/// Format an input rule for preview: one line per address family it covers.
fn format_input_rule(
    rule: &InputRule,
    zone_interfaces: &HashMap<String, Vec<String>>,
    groups: &GroupIndex,
) -> Vec<String> {
    let Ok(source) = side_families(
        rule.source_ip.as_deref(),
        rule.source_group.as_deref(),
        groups,
    ) else {
        return Vec::new();
    };
    family_variants(&[source])
        .into_iter()
        .map(|family| {
            let mut parts = Vec::new();

            if let Some(ref zone_name) = rule.zone
                && let Some(interfaces) = zone_interfaces.get(zone_name)
                && !interfaces.is_empty()
            {
                parts.push(format!("iifname {}", format_interface_set(interfaces)));
            }

            if let Some(text) = address_text(
                Side::Source,
                rule.source_ip.as_deref(),
                rule.source_group.as_deref(),
                family,
            ) {
                parts.push(text);
            }

            push_protocol_and_ports(
                &mut parts,
                rule.protocol.as_ref(),
                rule.port_start,
                rule.port_end,
                rule.dest_port_group.as_deref(),
            );

            if let Some(ref rate) = rule.rate_limit {
                parts.push(format!("limit rate {}", rate));
            }

            if rule.log_enabled {
                let prefix = rule.log_prefix.as_deref().unwrap_or(&rule.name);
                parts.push(format!("log prefix \"{}\"", prefix));
            }

            parts.push(format!("{}", rule.action));
            parts.push(format!(
                "comment \"{}\"",
                rule_comment("input", rule.id, &rule.name)
            ));

            parts.join(" ")
        })
        .collect()
}

/// Format a forward rule for preview: one line per address family it covers.
fn format_forward_rule(
    rule: &ForwardRule,
    zone_interfaces: &HashMap<String, Vec<String>>,
    groups: &GroupIndex,
) -> Vec<String> {
    let source = side_families(
        rule.source_ip.as_deref(),
        rule.source_group.as_deref(),
        groups,
    );
    let dest = side_families(rule.dest_ip.as_deref(), rule.dest_group.as_deref(), groups);
    let (Ok(source), Ok(dest)) = (source, dest) else {
        return Vec::new();
    };
    family_variants(&[source, dest])
        .into_iter()
        .map(|family| {
            let mut parts = Vec::new();

            if let Some(ref zone_name) = rule.source_zone
                && let Some(interfaces) = zone_interfaces.get(zone_name)
                && !interfaces.is_empty()
            {
                parts.push(format!("iifname {}", format_interface_set(interfaces)));
            }

            if let Some(ref zone_name) = rule.dest_zone
                && let Some(interfaces) = zone_interfaces.get(zone_name)
                && !interfaces.is_empty()
            {
                parts.push(format!("oifname {}", format_interface_set(interfaces)));
            }

            if let Some(text) = address_text(
                Side::Source,
                rule.source_ip.as_deref(),
                rule.source_group.as_deref(),
                family,
            ) {
                parts.push(text);
            }

            if let Some(text) = address_text(
                Side::Destination,
                rule.dest_ip.as_deref(),
                rule.dest_group.as_deref(),
                family,
            ) {
                parts.push(text);
            }

            push_protocol_and_ports(
                &mut parts,
                rule.protocol.as_ref(),
                rule.dest_port_start,
                rule.dest_port_end,
                rule.dest_port_group.as_deref(),
            );

            if let Some(ref rate) = rule.rate_limit {
                parts.push(format!("limit rate {}", rate));
            }

            if rule.log_enabled {
                let prefix = rule.log_prefix.as_deref().unwrap_or(&rule.name);
                parts.push(format!("log prefix \"{}\"", prefix));
            }

            parts.push(format!("{}", rule.action));
            parts.push(format!(
                "comment \"{}\"",
                rule_comment("forward", rule.id, &rule.name)
            ));

            parts.join(" ")
        })
        .collect()
}

/// Format a port forward for preview. Port forwards are DNAT and therefore
/// IPv4 only: a source group without IPv4 entries yields no line.
pub fn format_port_forward(
    pf: &PortForward,
    zone_interfaces: &HashMap<String, Vec<String>>,
    groups: &GroupIndex,
) -> Option<String> {
    let families =
        side_families(pf.source_ip.as_deref(), pf.source_group.as_deref(), groups).ok()?;
    if families.is_some_and(|families| !families.contains(&Family::V4)) {
        return None;
    }

    let mut parts = Vec::new();

    if let Some(ref zone_name) = pf.source_zone
        && let Some(interfaces) = zone_interfaces.get(zone_name)
        && !interfaces.is_empty()
    {
        parts.push(format!("iifname {}", format_interface_set(interfaces)));
    }

    if let Some(text) = address_text(
        Side::Source,
        pf.source_ip.as_deref(),
        pf.source_group.as_deref(),
        Some(Family::V4),
    ) {
        parts.push(text);
    }

    parts.push(format!("{}", pf.protocol));
    parts.push(format!(
        "dport {}",
        format_port_range(pf.external_port_start, pf.external_port_end)
    ));

    let dest_port = pf.dest_port.unwrap_or(pf.external_port_start);
    parts.push(format!("dnat to {}:{}", pf.dest_ip, dest_port));
    parts.push(format!(
        "comment \"{}\"",
        rule_comment("portfwd", pf.id, &pf.name)
    ));

    Some(parts.join(" "))
}

/// nftables set definitions for every group, as they appear in each table.
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
            .map(|&(start, end)| format_port_range(start, Some(end)))
            .collect();
        out.push_str(&format!(
            "    set {} {{\n        type inet_service;\n        flags interval;\n        elements = {{ {} }}\n    }}\n",
            port_set_name(&group.name),
            elements.join(", ")
        ));
    }
    out
}

/// Format an interface set for preview
pub fn format_interface_set(interfaces: &[String]) -> String {
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
pub fn format_port_range(start: u16, end: Option<u16>) -> String {
    if let Some(e) = end
        && e > start
    {
        return format!("{}-{}", start, e);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_port_range() {
        assert_eq!(format_port_range(80, None), "80");
        assert_eq!(format_port_range(80, Some(80)), "80");
        assert_eq!(format_port_range(80, Some(90)), "80-90");
    }

    #[test]
    fn test_format_interface_set() {
        assert_eq!(format_interface_set(&["eth0".to_string()]), "\"eth0\"");
        assert_eq!(
            format_interface_set(&["eth0".to_string(), "eth1".to_string()]),
            "{ \"eth0\", \"eth1\" }"
        );
    }
}
