//! Translation of the shared rule model into nftables JSON objects.
//!
//! Every [`Cond`] becomes exactly one statement, in the order the model lists
//! them. The rule's log, counter and verdict follow the conditions.

use crate::firewall::groups::{Family, address_set_name, port_set_name};
use crate::firewall::rules::{Addr, Cond, Ports, RuleSpec, Side, Verdict};
use nftables::{
    expr::{
        CT, Expression, Fib, FibFlag, FibResult, Meta, MetaKey, NamedExpression, Payload,
        PayloadField, Prefix, Range, SetItem,
    },
    schema::Rule,
    stmt::{Counter, Limit, Log, Match, NAT, Operator, Statement},
    types::NfFamily,
};
use std::borrow::Cow;
use std::net::IpAddr;

/// The nftables rule for `spec`, in `chain` of `table`.
pub(crate) fn rule_object(
    spec: &RuleSpec,
    table: &'static str,
    chain: &'static str,
) -> Rule<'static> {
    let mut expr: Vec<Statement<'static>> = spec.conds.iter().map(cond_statement).collect();
    if let Some(prefix) = &spec.log {
        expr.push(Statement::Log(Some(Log {
            prefix: Some(Cow::Owned(prefix.clone())),
            group: None,
            snaplen: None,
            queue_threshold: None,
            level: None,
            flags: None,
        })));
    }
    expr.push(Statement::Counter(Counter::Anonymous(None)));
    expr.push(verdict_statement(spec.verdict));
    Rule {
        family: NfFamily::INet,
        table: Cow::Borrowed(table),
        chain: Cow::Borrowed(chain),
        expr: expr.into(),
        comment: Some(Cow::Owned(spec.comment.clone())),
        ..Default::default()
    }
}

fn cond_statement(cond: &Cond) -> Statement<'static> {
    match cond {
        Cond::Iif(interfaces) => interface_match(MetaKey::Iifname, interfaces),
        Cond::Oif(interfaces) => interface_match(MetaKey::Oifname, interfaces),
        Cond::Nfproto(family) => {
            let version = match family {
                Family::V4 => "ipv4",
                Family::V6 => "ipv6",
            };
            compare(meta(MetaKey::Nfproto), string(version), Operator::EQ)
        }
        Cond::Addr { side, addr } => address_match(*side, addr, Operator::EQ),
        Cond::NotAddr { side, addr } => address_match(*side, addr, Operator::NEQ),
        Cond::L4(protocol) => compare(meta(MetaKey::L4proto), string(protocol), Operator::EQ),
        Cond::Port {
            side,
            payload,
            ports,
        } => port_match(*side, payload, ports),
        Cond::IcmpType { v6, icmp_type } => {
            let protocol = if *v6 { "icmpv6" } else { "icmp" };
            compare(
                payload(protocol, "type"),
                number(u32::from(*icmp_type)),
                Operator::EQ,
            )
        }
        Cond::CtStateIn(states) => compare(
            ct("state"),
            Expression::List(states.iter().map(|state| string(state)).collect()),
            Operator::IN,
        ),
        Cond::CtStateIs(state) => compare(ct("state"), string(state), Operator::EQ),
        Cond::CtDnat => compare(ct("status"), string("dnat"), Operator::IN),
        Cond::FibLocal => compare(fib(&[FibFlag::Daddr]), string("local"), Operator::EQ),
        Cond::FibNotLocal => compare(fib(&[FibFlag::Daddr]), string("local"), Operator::NEQ),
        Cond::FibNotOnIngress => compare(
            fib(&[FibFlag::Daddr, FibFlag::Iif]),
            string("local"),
            Operator::NEQ,
        ),
        Cond::RateLimit { rate, per } => Statement::Limit(Limit {
            rate: *rate,
            rate_unit: None,
            per: Some(Cow::Borrowed(per)),
            burst: None,
            burst_unit: None,
            inv: None,
        }),
    }
}

fn verdict_statement(verdict: Verdict) -> Statement<'static> {
    match verdict {
        Verdict::Accept => Statement::Accept(None),
        Verdict::Drop => Statement::Drop(None),
        Verdict::Reject => Statement::Reject(None),
        Verdict::Dnat { addr, port } => Statement::DNAT(Some(NAT {
            addr: Some(string(&addr.to_string())),
            family: None,
            port: port.map(|port| number(u32::from(port))),
            flags: None,
        })),
        Verdict::Masquerade => Statement::Masquerade(None),
        Verdict::Redirect { port } => Statement::Redirect(Some(NAT {
            addr: None,
            family: None,
            port: Some(number(u32::from(port))),
            flags: None,
        })),
    }
}

/// Address match: a literal (`ip saddr 10.0.0.1`, `ip6 daddr 2001:db8::/32`)
/// or a membership test on a group's set (`ip saddr @lan_hosts_v4`), negated
/// with `Operator::NEQ` (`ip saddr != @lan_hosts_v4`).
fn address_match(side: Side, addr: &Addr, op: Operator) -> Statement<'static> {
    let field = match side {
        Side::Source => "saddr",
        Side::Destination => "daddr",
    };
    match addr {
        Addr::Literal(text) => {
            let family = match text.split('/').next().unwrap_or(text).parse::<IpAddr>() {
                Ok(IpAddr::V6(_)) => "ip6",
                _ => "ip",
            };
            compare(payload(family, field), address_literal(text), op)
        }
        Addr::Group { name, family } => compare(
            payload(family.payload(), field),
            string(&format!("@{}", address_set_name(name, *family))),
            op,
        ),
    }
}

/// A host address as a string, a network as a prefix. nft reads a string
/// holding `/` as a host name to resolve, and refuses the batch.
fn address_literal(text: &str) -> Expression<'static> {
    match text.split_once('/') {
        Some((addr, len)) => match len.parse::<u32>() {
            Ok(len) => Expression::Named(NamedExpression::Prefix(Prefix {
                addr: Box::new(string(addr)),
                len,
            })),
            Err(_) => string(text),
        },
        None => string(text),
    }
}

fn port_match(side: Side, protocol: &'static str, ports: &Ports) -> Statement<'static> {
    let field = match side {
        Side::Source => "sport",
        Side::Destination => "dport",
    };
    let left = payload(protocol, field);
    match ports {
        Ports::Single(port) => compare(left, number(u32::from(*port)), Operator::EQ),
        Ports::Range(start, end) => compare(
            left,
            Expression::Range(Box::new(Range {
                range: [number(u32::from(*start)), number(u32::from(*end))],
            })),
            Operator::IN,
        ),
        Ports::Group(group) => compare(
            left,
            string(&format!("@{}", port_set_name(group))),
            Operator::EQ,
        ),
    }
}

/// `iifname "eth1"`, or `iifname { "eth1", "eth2" }` for several interfaces.
/// Several interfaces are an anonymous set: nft reads a bare JSON list as a
/// bitmask, which interface names are not, and refuses the whole batch.
fn interface_match(key: MetaKey, interfaces: &[String]) -> Statement<'static> {
    if let [interface] = interfaces {
        compare(meta(key), string(interface), Operator::EQ)
    } else {
        compare(
            meta(key),
            Expression::Named(NamedExpression::Set(
                interfaces
                    .iter()
                    .map(|name| SetItem::Element(string(name)))
                    .collect(),
            )),
            Operator::EQ,
        )
    }
}

fn compare(
    left: Expression<'static>,
    right: Expression<'static>,
    op: Operator,
) -> Statement<'static> {
    Statement::Match(Match { left, right, op })
}

fn string(value: &str) -> Expression<'static> {
    Expression::String(Cow::Owned(value.to_string()))
}

fn number(value: u32) -> Expression<'static> {
    Expression::Number(value)
}

fn meta(key: MetaKey) -> Expression<'static> {
    Expression::Named(NamedExpression::Meta(Meta { key }))
}

fn payload(protocol: &'static str, field: &'static str) -> Expression<'static> {
    Expression::Named(NamedExpression::Payload(Payload::PayloadField(
        PayloadField {
            protocol: Cow::Borrowed(protocol),
            field: Cow::Borrowed(field),
        },
    )))
}

fn ct(key: &'static str) -> Expression<'static> {
    Expression::Named(NamedExpression::CT(CT {
        key: Cow::Borrowed(key),
        ..Default::default()
    }))
}

fn fib(flags: &[FibFlag]) -> Expression<'static> {
    Expression::Named(NamedExpression::Fib(Fib {
        result: FibResult::Type,
        flags: flags.iter().copied().collect(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::rules::{Origin, SECTION_USER_INPUT};

    fn spec(conds: Vec<Cond>, verdict: Verdict) -> RuleSpec {
        RuleSpec {
            origin: Origin::Builtin,
            comment: "test".into(),
            section: SECTION_USER_INPUT,
            conds,
            log: None,
            verdict,
        }
    }

    #[test]
    fn every_condition_precedes_the_counter_and_verdict() {
        let rule = rule_object(
            &spec(vec![Cond::L4("tcp"), Cond::FibLocal], Verdict::Accept),
            "t",
            "c",
        );
        let json = serde_json::to_value(&rule).unwrap();
        let expr = json["expr"].as_array().unwrap();
        assert!(expr[0]["match"].is_object());
        assert!(expr[1]["match"].is_object());
        assert!(expr[2].get("counter").is_some());
        assert!(expr[3].get("accept").is_some());
    }

    #[test]
    fn negated_fib_match_uses_not_equal() {
        let rule = rule_object(&spec(vec![Cond::FibNotOnIngress], Verdict::Drop), "t", "c");
        let text = serde_json::to_string(&rule).unwrap();
        assert!(text.contains("\"op\":\"!=\""), "{text}");
    }

    #[test]
    fn several_interfaces_are_an_anonymous_set() {
        let rule = rule_object(
            &spec(
                vec![Cond::Iif(vec!["eth1".into(), "eth2".into()])],
                Verdict::Accept,
            ),
            "t",
            "c",
        );
        let json = serde_json::to_value(&rule).unwrap();
        let matched = &json["expr"][0]["match"];
        assert_eq!(matched["op"], "==");
        assert_eq!(matched["right"]["set"], serde_json::json!(["eth1", "eth2"]));
    }

    #[test]
    fn a_literal_network_is_a_prefix_and_a_host_a_string() {
        let network = address_literal("198.51.100.0/24");
        assert_eq!(
            serde_json::to_value(&network).unwrap(),
            serde_json::json!({"prefix": {"addr": "198.51.100.0", "len": 24}})
        );
        assert_eq!(
            serde_json::to_value(address_literal("2001:db8::1")).unwrap(),
            serde_json::json!("2001:db8::1")
        );
    }

    #[test]
    fn redirect_names_only_the_port() {
        let rule = rule_object(&spec(vec![], Verdict::Redirect { port: 53 }), "t", "c");
        let json = serde_json::to_value(&rule).unwrap();
        let expr = json["expr"].as_array().unwrap();
        assert_eq!(
            expr.last().unwrap()["redirect"],
            serde_json::json!({"port": 53})
        );
    }
}
