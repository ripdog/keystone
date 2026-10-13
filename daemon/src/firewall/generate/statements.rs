//! Helper functions for creating nftables statements
//!
//! This module provides reusable functions for building nftables match statements
//! and other expression components used across chain generation.

use crate::firewall::groups::{Family, port_set_name};
use keystone_core::RuleProtocol;
use nftables::{
    expr::{Expression, Meta, MetaKey, Payload, PayloadField},
    stmt::{Limit, Match, Operator, Statement},
};
use std::{borrow::Cow, net::IpAddr};

/// Which address of a packet an address constraint matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Source,
    Destination,
}

/// Address match for one side of a rule, restricted to `family`.
///
/// A literal address matches itself. A group matches the named set for
/// `family`, and yields `None` when no family is given (the caller then emits
/// no rule for that family). `None` also means the side is unconstrained.
pub fn address_match(
    side: Side,
    literal: Option<&str>,
    group: Option<&str>,
    family: Option<Family>,
) -> Option<Statement<'static>> {
    if let Some(literal) = literal {
        return Some(match side {
            Side::Source => create_saddr_match(literal),
            Side::Destination => create_daddr_match(literal),
        });
    }
    let (Some(group), Some(family)) = (group, family) else {
        return None;
    };
    Some(create_address_set_match(
        family,
        side,
        &crate::firewall::groups::address_set_name(group, family),
    ))
}

/// Match an address against a named nftables set, e.g. `ip saddr @lan_v4`.
pub fn create_address_set_match(family: Family, side: Side, set: &str) -> Statement<'static> {
    let field = match side {
        Side::Source => "saddr",
        Side::Destination => "daddr",
    };
    Statement::Match(Match {
        left: Expression::Named(nftables::expr::NamedExpression::Payload(
            Payload::PayloadField(PayloadField {
                protocol: Cow::Borrowed(family.payload()),
                field: Cow::Borrowed(field),
            }),
        )),
        right: Expression::String(Cow::Owned(format!("@{set}"))),
        op: Operator::EQ,
    })
}

/// Match the destination port against a named port set, e.g. `th dport @web_ports`.
pub fn create_port_set_match(set: &str) -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(nftables::expr::NamedExpression::Payload(
            Payload::PayloadField(PayloadField {
                protocol: Cow::Borrowed("th"),
                field: Cow::Borrowed("dport"),
            }),
        )),
        right: Expression::String(Cow::Owned(format!("@{set}"))),
        op: Operator::EQ,
    })
}

/// Pick the packet address family (also accepts CIDR strings).
fn address_payload_family(addr: &str) -> &'static str {
    match addr.split('/').next().unwrap_or(addr).parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => "ip6",
        _ => "ip",
    }
}

/// NAT forwarding is IPv4-only; it must not accidentally match IPv6 traffic.
pub fn create_ipv4_match() -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(nftables::expr::NamedExpression::Meta(Meta {
            key: MetaKey::Nfproto,
        })),
        right: Expression::String(Cow::Borrowed("ipv4")),
        op: Operator::EQ,
    })
}

/// Create a match statement for input interface(s)
pub fn create_iif_match(interfaces: &[String]) -> Statement<'static> {
    let ifaces: Vec<Cow<'static, str>> = interfaces.iter().map(|s| Cow::Owned(s.clone())).collect();

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
pub fn create_oif_match(interfaces: &[String]) -> Statement<'static> {
    let ifaces: Vec<Cow<'static, str>> = interfaces.iter().map(|s| Cow::Owned(s.clone())).collect();

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
pub fn create_saddr_match(addr: &str) -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(nftables::expr::NamedExpression::Payload(
            Payload::PayloadField(PayloadField {
                protocol: Cow::Borrowed(address_payload_family(addr)),
                field: Cow::Borrowed("saddr"),
            }),
        )),
        right: Expression::String(Cow::Owned(addr.to_string())),
        op: Operator::EQ,
    })
}

/// Create a match statement for destination address
pub fn create_daddr_match(addr: &str) -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(nftables::expr::NamedExpression::Payload(
            Payload::PayloadField(PayloadField {
                protocol: Cow::Borrowed(address_payload_family(addr)),
                field: Cow::Borrowed("daddr"),
            }),
        )),
        right: Expression::String(Cow::Owned(addr.to_string())),
        op: Operator::EQ,
    })
}

/// Create a match statement for protocol
pub fn create_protocol_match(protocol: &'static str) -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(nftables::expr::NamedExpression::Meta(Meta {
            key: MetaKey::L4proto,
        })),
        right: Expression::String(Cow::Borrowed(protocol)),
        op: Operator::EQ,
    })
}

/// Create a match statement for destination port(s)
pub fn create_dport_match(port_start: u16, port_end: Option<u16>) -> Statement<'static> {
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
pub fn parse_rate_limit(rate_str: &str) -> Option<Statement<'static>> {
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

/// Expand a RuleProtocol into concrete protocol strings for nftables.
///
/// nftables JSON doesn't support matching multiple protocols in a single rule,
/// so TcpUdp must be expanded into separate rules for each protocol.
/// Returns None for protocols that don't need explicit matching (Any).
pub fn expand_protocol(protocol: &RuleProtocol) -> Vec<Option<&'static str>> {
    match protocol {
        RuleProtocol::Any => vec![None],
        RuleProtocol::Tcp => vec![Some("tcp")],
        RuleProtocol::Udp => vec![Some("udp")],
        RuleProtocol::TcpUdp => vec![Some("tcp"), Some("udp")],
        RuleProtocol::Icmp => vec![Some("icmp")],
        RuleProtocol::Icmpv6 => vec![Some("ipv6-icmp")],
    }
}

/// Add protocol matching statements to the expression list.
///
/// This handles the common pattern of matching protocol and optionally port(s).
/// The `protocol` parameter should be a concrete protocol string from `expand_protocol()`.
///
/// For TcpUdp, callers should iterate over the result of `expand_protocol()` and
/// generate separate rules for each protocol.
pub fn add_protocol_match_concrete(
    exprs: &mut Vec<Statement<'static>>,
    protocol: Option<&'static str>,
    port_start: Option<u16>,
    port_end: Option<u16>,
) {
    if let Some(proto) = protocol {
        exprs.push(create_protocol_match(proto));
        // Only add port matching for TCP/UDP
        if (proto == "tcp" || proto == "udp")
            && let Some(start) = port_start
        {
            exprs.push(create_dport_match(start, port_end));
        }
    }
}

/// Protocol and destination-port matches for a rule: either a literal port
/// range or a port group, which matches the group's named set.
pub fn push_port_matches(
    exprs: &mut Vec<Statement<'static>>,
    protocol: Option<&'static str>,
    port_start: Option<u16>,
    port_end: Option<u16>,
    port_group: Option<&str>,
) {
    match port_group {
        Some(group) => {
            if let Some(proto) = protocol {
                exprs.push(create_protocol_match(proto));
                exprs.push(create_port_set_match(&port_set_name(group)));
            }
        }
        None => add_protocol_match_concrete(exprs, protocol, port_start, port_end),
    }
}

/// Check that a rule's port and rate-limit options can be expressed exactly.
///
/// Ports (a literal range or a port group) are only matchable for tcp/udp and
/// an unparsable rate limit cannot be emitted; in either case silently dropping
/// the option would widen the rule, so callers must emit no rule (this logs a
/// warning).
pub fn rule_options_are_safe(
    protocol: Option<&'static str>,
    has_port_match: bool,
    rate_limit: Option<&str>,
    rule_name: &str,
) -> bool {
    if has_port_match && !matches!(protocol, Some("tcp" | "udp")) {
        tracing::warn!("Skipping rule '{rule_name}': ports require protocol tcp or udp");
        return false;
    }
    if let Some(rate) = rate_limit
        && parse_rate_limit(rate).is_none()
    {
        tracing::warn!("Skipping rule '{rule_name}': invalid rate limit '{rate}'");
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rate_limit() {
        assert!(parse_rate_limit("10/minute").is_some());
        assert!(parse_rate_limit("100/second").is_some());
        assert!(parse_rate_limit("5/hour").is_some());
        assert!(parse_rate_limit("invalid").is_none());
    }
}
