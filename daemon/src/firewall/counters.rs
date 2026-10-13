//! Hit counters for user-configured rules.
//!
//! Every user rule is generated with a `counter` statement and a comment
//! `ks:<kind>:<id> <name>` (see `generate::rule_comment`). This module lists
//! the applied Keystone tables as JSON and sums the counters of each rule back
//! to its kind and database ID. Rules over mixed-family groups are emitted as
//! several nftables rules, so their counters are added together.

use crate::firewall::generate::{FILTER_TABLE, NAT_TABLE};
use anyhow::{Context, Result};
use keystone_core::FirewallRuleCounter;
use serde_json::Value;
use std::collections::BTreeMap;
use std::process::Stdio;
use tokio::process::Command;

/// Hit counters of every user rule in the applied Keystone tables. Rules
/// that were never matched, and tables that are not applied, are omitted.
pub async fn read_rule_counters() -> Result<Vec<FirewallRuleCounter>> {
    let mut ruleset = Vec::new();
    for table in [FILTER_TABLE, NAT_TABLE] {
        let output = Command::new("nft")
            .args(["-j", "list", "table", "inet", table])
            .stdin(Stdio::null())
            .output()
            .await
            .with_context(|| format!("Failed to run nft to list table {table}"))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // The table does not exist until the first apply: nothing has hits.
            if stderr.contains("No such file or directory") {
                continue;
            }
            anyhow::bail!("Failed to list nftables table {table}: {}", stderr.trim());
        }
        let value: Value = serde_json::from_slice(&output.stdout)
            .with_context(|| format!("nft returned invalid JSON for table {table}"))?;
        ruleset.push(value);
    }
    Ok(parse_rule_counters(&ruleset))
}

/// Parse a comment written by `generate::rule_comment` into `(kind, id)`.
fn parse_comment(comment: &str) -> Option<(&str, i64)> {
    let rest = comment.strip_prefix("ks:")?;
    let (kind, after) = rest.split_once(':')?;
    let id: i64 = after.split(' ').next()?.parse().ok()?;
    let plausible_kind = !kind.is_empty()
        && kind
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'-');
    plausible_kind.then_some((kind, id))
}

/// Sum the counters of every rule that carries a Keystone comment.
///
/// Each element is the output of `nft -j list table ...`, a JSON object with a
/// `nftables` array of objects, one of which may be `{"rule": {...}}`. Anything
/// unexpected is skipped rather than treated as an error: counters are
/// informational and must not break the firewall page.
pub fn parse_rule_counters(tables: &[Value]) -> Vec<FirewallRuleCounter> {
    let mut totals: BTreeMap<(&str, i64), (u64, u64)> = BTreeMap::new();
    for table in tables {
        let objects = table
            .get("nftables")
            .and_then(Value::as_array)
            .into_iter()
            .flatten();
        for object in objects {
            let Some(rule) = object.get("rule") else {
                continue;
            };
            let Some((kind, id)) = rule
                .get("comment")
                .and_then(Value::as_str)
                .and_then(parse_comment)
            else {
                continue;
            };
            let statements = rule.get("expr").and_then(Value::as_array);
            for statement in statements.into_iter().flatten() {
                let Some(counter) = statement.get("counter") else {
                    continue;
                };
                let packets = counter.get("packets").and_then(Value::as_u64).unwrap_or(0);
                let bytes = counter.get("bytes").and_then(Value::as_u64).unwrap_or(0);
                let total = totals.entry((kind, id)).or_default();
                total.0 = total.0.saturating_add(packets);
                total.1 = total.1.saturating_add(bytes);
            }
        }
    }
    totals
        .into_iter()
        .map(|((kind, rule_id), (packets, bytes))| FirewallRuleCounter {
            kind: kind.to_string(),
            rule_id,
            packets,
            bytes,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Shaped like `nft -j list table inet keystone` on nftables 1.0.x.
    fn filter_fixture() -> Value {
        json!({"nftables": [
            {"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak", "json_schema_version": 1}},
            {"table": {"family": "inet", "name": "keystone", "handle": 1}},
            {"chain": {"family": "inet", "table": "keystone", "name": "input", "handle": 2,
                       "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
            {"rule": {"family": "inet", "table": "keystone", "chain": "input", "handle": 5,
                      "expr": [
                          {"match": {"op": "in", "left": {"ct": {"key": "state"}},
                                     "right": ["established", "related"]}},
                          {"counter": {"packets": 1204, "bytes": 98211}},
                          {"accept": null}
                      ],
                      "comment": "Accept established/related"}},
            {"rule": {"family": "inet", "table": "keystone", "chain": "input", "handle": 9,
                      "expr": [
                          {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": "tcp"}},
                          {"match": {"op": "==", "left": {"payload": {"protocol": "th", "field": "dport"}}, "right": 22}},
                          {"counter": {"packets": 42, "bytes": 3360}},
                          {"accept": null}
                      ],
                      "comment": "ks:input:3 Allow SSH from LAN"}},
            {"rule": {"family": "inet", "table": "keystone", "chain": "input", "handle": 10,
                      "expr": [
                          {"match": {"op": "==", "left": {"payload": {"protocol": "ip6", "field": "saddr"}}, "right": "@lan_v6"}},
                          {"counter": {"packets": 8, "bytes": 640}},
                          {"accept": null}
                      ],
                      "comment": "ks:input:3 Allow SSH from LAN"}},
            {"rule": {"family": "inet", "table": "keystone", "chain": "forward", "handle": 14,
                      "expr": [
                          {"counter": {"packets": 0, "bytes": 0}},
                          {"drop": null}
                      ],
                      "comment": "ks:forward:7 Block IoT to LAN"}},
            {"rule": {"family": "inet", "table": "keystone", "chain": "forward", "handle": 15,
                      "expr": [{"accept": null}],
                      "comment": "ks:forward:8 no counter statement"}},
            {"rule": {"family": "inet", "table": "keystone", "chain": "forward", "handle": 16,
                      "expr": [{"counter": {"packets": 3, "bytes": 180}}, {"accept": null}],
                      "comment": "ks:portfwd-accept:2 web DNAT accept (tcp)"}},
            {"rule": {"family": "inet", "table": "keystone", "chain": "forward", "handle": 17,
                      "expr": [{"counter": {"packets": 1, "bytes": 60}}, {"accept": null}],
                      "comment": "ks:bogus-kind:99 unknown kinds still parse"}},
            {"rule": {"family": "inet", "table": "keystone", "chain": "forward", "handle": 18,
                      "expr": [{"counter": {"packets": 5, "bytes": 5}}],
                      "comment": "ks:forward:notanid broken"}}
        ]})
    }

    /// Shaped like `nft -j list table inet keystone_nat`.
    fn nat_fixture() -> Value {
        json!({"nftables": [
            {"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak", "json_schema_version": 1}},
            {"table": {"family": "inet", "name": "keystone_nat", "handle": 2}},
            {"chain": {"family": "inet", "table": "keystone_nat", "name": "prerouting", "handle": 3,
                       "type": "nat", "hook": "prerouting", "prio": -100}},
            {"rule": {"family": "inet", "table": "keystone_nat", "chain": "prerouting", "handle": 4,
                      "expr": [
                          {"match": {"op": "==", "left": {"meta": {"key": "nfproto"}}, "right": "ipv4"}},
                          {"counter": {"packets": 17, "bytes": 1020}},
                          {"dnat": {"addr": "192.168.1.10", "port": 80}}
                      ],
                      "comment": "ks:portfwd:2 web (tcp)"}},
            {"rule": {"family": "inet", "table": "keystone_nat", "chain": "postrouting", "handle": 5,
                      "expr": [{"counter": {"packets": 9, "bytes": 900}}, {"masquerade": null}],
                      "comment": "Masquerade for eth0"}}
        ]})
    }

    #[test]
    fn comments_are_parsed_into_kind_and_id() {
        assert_eq!(parse_comment("ks:input:3 Allow SSH"), Some(("input", 3)));
        assert_eq!(parse_comment("ks:input:3"), Some(("input", 3)));
        assert_eq!(
            parse_comment("ks:portfwd-hairpin:12 web hairpin (udp)"),
            Some(("portfwd-hairpin", 12))
        );
        assert_eq!(parse_comment("Accept loopback"), None);
        assert_eq!(parse_comment("ks::1"), None);
        assert_eq!(parse_comment("ks:Input:1"), None);
        assert_eq!(parse_comment("ks:input:x"), None);
    }

    #[test]
    fn counters_are_summed_per_rule_across_families_and_tables() {
        let counters = parse_rule_counters(&[filter_fixture(), nat_fixture()]);
        let find = |kind: &str, id: i64| {
            counters
                .iter()
                .find(|c| c.kind == kind && c.rule_id == id)
                .unwrap_or_else(|| panic!("missing {kind}:{id} in {counters:?}"))
        };

        // Two nftables rules (IPv4 and IPv6) carry the same comment.
        let ssh = find("input", 3);
        assert_eq!((ssh.packets, ssh.bytes), (50, 4000));

        let blocked = find("forward", 7);
        assert_eq!((blocked.packets, blocked.bytes), (0, 0));

        assert_eq!(find("portfwd-accept", 2).packets, 3);
        assert_eq!(find("portfwd", 2).bytes, 1020);
        assert_eq!(find("bogus-kind", 99).packets, 1);

        // Rules without a counter or a usable comment are not reported.
        assert!(!counters.iter().any(|c| c.rule_id == 8 || c.rule_id == 0));
        assert!(
            !counters
                .iter()
                .any(|c| c.kind == "forward" && c.rule_id == 0)
        );
        assert_eq!(counters.len(), 5, "{counters:?}");
    }

    #[test]
    fn unexpected_json_is_skipped_not_fatal() {
        assert!(parse_rule_counters(&[json!({})]).is_empty());
        assert!(parse_rule_counters(&[json!({"nftables": "nope"})]).is_empty());
        assert!(parse_rule_counters(&[json!({"nftables": [{"rule": {"comment": 5}}]})]).is_empty());
    }
}
