//! Named nftables sets for address and port groups.
//!
//! Each address group becomes one `ipv4_addr` set and/or one `ipv6_addr` set,
//! named `<group>_v4` and `<group>_v6`, and each port group becomes one
//! `inet_service` set named `<group>_ports`. All are interval sets. The same
//! sets are written into both Keystone tables, since a set is only visible to
//! rules in its own table.

use crate::firewall::groups::{
    Family, address_set_name, normalized_networks, normalized_ports, port_set_name,
};
use keystone_core::FirewallConfig;
use nftables::{
    expr::{Expression, NamedExpression, Prefix, Range},
    schema::{NfListObject, Set, SetFlag, SetType, SetTypeValue},
    types::NfFamily,
};
use std::borrow::Cow;
use std::collections::HashSet;

/// Every group set, as objects to add to a batch before any rule uses them.
pub fn group_set_objects(
    config: &FirewallConfig,
    table: &'static str,
) -> Vec<NfListObject<'static>> {
    let mut objects = Vec::new();

    for group in &config.address_groups {
        for family in [Family::V4, Family::V6] {
            let nets = normalized_networks(&group.entries, family);
            if nets.is_empty() {
                continue;
            }
            let elements = nets
                .iter()
                .map(|net| {
                    let host_len = if net.addr().is_ipv4() { 32 } else { 128 };
                    if net.prefix_len() == host_len {
                        Expression::String(Cow::Owned(net.addr().to_string()))
                    } else {
                        Expression::Named(NamedExpression::Prefix(Prefix {
                            addr: Box::new(Expression::String(Cow::Owned(net.addr().to_string()))),
                            len: u32::from(net.prefix_len()),
                        }))
                    }
                })
                .collect();
            objects.push(set_object(
                table,
                address_set_name(&group.name, family),
                match family {
                    Family::V4 => SetType::Ipv4Addr,
                    Family::V6 => SetType::Ipv6Addr,
                },
                elements,
            ));
        }
    }

    for group in &config.port_groups {
        let ranges = normalized_ports(&group.entries);
        if ranges.is_empty() {
            continue;
        }
        let elements = ranges
            .into_iter()
            .map(|(start, end)| {
                if start == end {
                    Expression::Number(u32::from(start))
                } else {
                    Expression::Range(Box::new(Range {
                        range: [
                            Expression::Number(u32::from(start)),
                            Expression::Number(u32::from(end)),
                        ],
                    }))
                }
            })
            .collect();
        objects.push(set_object(
            table,
            port_set_name(&group.name),
            SetType::InetService,
            elements,
        ));
    }

    objects
}

fn set_object(
    table: &'static str,
    name: String,
    set_type: SetType,
    elements: Vec<Expression<'static>>,
) -> NfListObject<'static> {
    NfListObject::Set(Box::new(Set {
        family: NfFamily::INet,
        table: Cow::Borrowed(table),
        name: Cow::Owned(name),
        set_type: SetTypeValue::Single(set_type),
        flags: Some(HashSet::from([SetFlag::Interval])),
        elem: Some(Cow::Owned(elements)),
        ..Default::default()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use keystone_core::{AddressGroup, PortGroup};

    fn config() -> FirewallConfig {
        FirewallConfig {
            address_groups: vec![AddressGroup {
                name: "mixed".into(),
                entries: vec!["10.0.0.0/8".into(), "fd00::1".into()],
                ..Default::default()
            }],
            port_groups: vec![PortGroup {
                name: "web".into(),
                entries: vec!["443".into(), "8000-8100".into()],
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn json_of(objects: &[NfListObject<'static>]) -> serde_json::Value {
        serde_json::to_value(objects).unwrap()
    }

    #[test]
    fn mixed_group_yields_one_set_per_family() {
        let objects = group_set_objects(&config(), "keystone");
        let json = json_of(&objects);
        let text = json.to_string();
        assert!(text.contains("\"mixed_v4\""), "{text}");
        assert!(text.contains("\"mixed_v6\""), "{text}");
        assert!(
            text.contains("ipv4_addr") && text.contains("ipv6_addr"),
            "{text}"
        );
        assert!(text.contains("\"interval\""), "{text}");
        assert!(text.contains("\"prefix\""), "{text}");
        // The single IPv6 host is a plain address, not a prefix.
        assert!(text.contains("fd00::1"), "{text}");
    }

    #[test]
    fn v4_only_group_has_no_v6_set() {
        let mut cfg = config();
        cfg.address_groups[0].entries = vec!["192.0.2.0/24".into()];
        let text = json_of(&group_set_objects(&cfg, "keystone")).to_string();
        assert!(text.contains("mixed_v4"));
        assert!(!text.contains("mixed_v6"));
    }

    #[test]
    fn port_group_becomes_inet_service_interval_set() {
        let text = json_of(&group_set_objects(&config(), "keystone")).to_string();
        assert!(text.contains("\"web_ports\""), "{text}");
        assert!(text.contains("inet_service"), "{text}");
        assert!(text.contains("\"range\""), "{text}");
        assert!(text.contains("8100"), "{text}");
    }

    #[test]
    fn sets_are_written_into_the_requested_table() {
        let text = json_of(&group_set_objects(&config(), "keystone_nat")).to_string();
        assert!(text.contains("keystone_nat"));
        assert!(!text.contains("\"table\":\"keystone\""));
    }
}
