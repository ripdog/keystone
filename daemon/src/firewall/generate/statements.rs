//! Helper functions for creating nftables statements
//!
//! This module provides reusable functions for building nftables match statements
//! and other expression components used across chain generation.

use keystone_core::RuleProtocol;
use nftables::{
    expr::{Expression, Meta, MetaKey, Payload, PayloadField},
    stmt::{Limit, Match, Operator, Statement},
};
use std::{borrow::Cow, net::IpAddr};

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
