//! Helper functions for creating nftables statements
//!
//! This module provides reusable functions for building nftables match statements
//! and other expression components used across chain generation.

use keystone_core::RuleProtocol;
use nftables::{
    expr::{Expression, Meta, MetaKey, Payload, PayloadField},
    stmt::{Limit, Match, Operator, Statement},
};
use std::borrow::Cow;

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
                protocol: Cow::Borrowed("ip"),
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
                protocol: Cow::Borrowed("ip"),
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

/// Create a match statement for TCP+UDP protocols
pub fn create_tcpudp_match() -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(nftables::expr::NamedExpression::Meta(Meta {
            key: MetaKey::L4proto,
        })),
        right: Expression::List(vec![
            Expression::String(Cow::Borrowed("tcp")),
            Expression::String(Cow::Borrowed("udp")),
        ]),
        op: Operator::IN,
    })
}

/// Add protocol matching statements to the expression list based on RuleProtocol.
///
/// This handles the common pattern of matching protocol and optionally port(s).
/// Returns true if any statements were added.
pub fn add_protocol_match(
    exprs: &mut Vec<Statement<'static>>,
    protocol: &RuleProtocol,
    port_start: Option<u16>,
    port_end: Option<u16>,
) {
    match protocol {
        RuleProtocol::Any => {}
        RuleProtocol::Tcp => {
            exprs.push(create_protocol_match("tcp"));
            if let Some(start) = port_start {
                exprs.push(create_dport_match(start, port_end));
            }
        }
        RuleProtocol::Udp => {
            exprs.push(create_protocol_match("udp"));
            if let Some(start) = port_start {
                exprs.push(create_dport_match(start, port_end));
            }
        }
        RuleProtocol::TcpUdp => {
            exprs.push(create_tcpudp_match());
            if let Some(start) = port_start {
                exprs.push(create_dport_match(start, port_end));
            }
        }
        RuleProtocol::Icmp => {
            exprs.push(create_protocol_match("icmp"));
        }
        RuleProtocol::Icmpv6 => {
            exprs.push(create_protocol_match("icmpv6"));
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
