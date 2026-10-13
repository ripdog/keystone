//! Named address and port groups.
//!
//! Entry syntax and name rules live in `keystone_core::validation` so the web
//! UI can give the same feedback. This module holds what only the daemon
//! needs: group lookup, address-family handling for rules, the canonical
//! element lists that generation writes into nftables sets, and validation of
//! whole groups.

use ipnet::IpNet;
use keystone_core::validation::{
    address_group_entry, group_name, is_single_line, port_group_entry,
};
use keystone_core::{AddressGroup, PortGroup};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// IP family of an address or of an address group entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    fn of_net(net: &IpNet) -> Family {
        if net.addr().is_ipv4() {
            Family::V4
        } else {
            Family::V6
        }
    }

    /// Suffix of the nftables set that holds this family's addresses.
    pub fn suffix(self) -> &'static str {
        match self {
            Family::V4 => "v4",
            Family::V6 => "v6",
        }
    }

    /// Packet payload expression for this family's addresses.
    pub fn payload(self) -> &'static str {
        match self {
            Family::V4 => "ip",
            Family::V6 => "ip6",
        }
    }
}

/// Name of the nftables set holding one family of an address group.
pub fn address_set_name(group: &str, family: Family) -> String {
    format!("{group}_{}", family.suffix())
}

/// Name of the nftables set holding a port group.
pub fn port_set_name(group: &str) -> String {
    format!("{group}_ports")
}

/// Family of a literal address or CIDR, as written in a rule.
pub fn literal_family(value: &str) -> Option<Family> {
    let address: IpAddr = value.split('/').next()?.parse().ok()?;
    Some(if address.is_ipv4() {
        Family::V4
    } else {
        Family::V6
    })
}

/// Lookup of configured groups by name.
#[derive(Default)]
pub struct GroupIndex<'a> {
    address: HashMap<&'a str, &'a AddressGroup>,
    port: HashMap<&'a str, &'a PortGroup>,
}

impl<'a> GroupIndex<'a> {
    pub fn new(address_groups: &'a [AddressGroup], port_groups: &'a [PortGroup]) -> Self {
        Self {
            address: address_groups
                .iter()
                .map(|group| (group.name.as_str(), group))
                .collect(),
            port: port_groups
                .iter()
                .map(|group| (group.name.as_str(), group))
                .collect(),
        }
    }

    pub fn has_address(&self, name: &str) -> bool {
        self.address.contains_key(name)
    }

    pub fn has_port(&self, name: &str) -> bool {
        self.port.contains_key(name)
    }

    /// Families that have at least one valid entry in an address group, or
    /// `None` when no such group exists.
    pub fn families(&self, name: &str) -> Option<Vec<Family>> {
        let group = self.address.get(name)?;
        let nets: Vec<IpNet> = group
            .entries
            .iter()
            .filter_map(|entry| address_group_entry(entry).ok())
            .collect();
        Some(
            [Family::V4, Family::V6]
                .into_iter()
                .filter(|family| nets.iter().any(|net| Family::of_net(net) == *family))
                .collect(),
        )
    }
}

/// Families one address side of a rule allows. A literal address has one
/// family, a group has every family among its entries, and `None` means the
/// side does not constrain the address at all.
pub fn side_families(
    literal: Option<&str>,
    group: Option<&str>,
    groups: &GroupIndex,
) -> Result<Option<Vec<Family>>, String> {
    match (literal, group) {
        (Some(value), _) => literal_family(value)
            .map(|family| Some(vec![family]))
            .ok_or_else(|| format!("{value:?} is not an IP address or CIDR network")),
        (None, Some(name)) => groups
            .families(name)
            .map(Some)
            .ok_or_else(|| format!("address group '{name}' does not exist")),
        (None, None) => Ok(None),
    }
}

/// The families a rule must be generated for, given every constrained address
/// side. `[None]` means no side constrains the family. An empty result means
/// no packet can satisfy both sides, so the rule must not be emitted.
pub fn family_variants(sides: &[Option<Vec<Family>>]) -> Vec<Option<Family>> {
    let mut allowed: Option<Vec<Family>> = None;
    for side in sides.iter().flatten() {
        allowed = Some(match allowed {
            None => side.clone(),
            Some(current) => current
                .into_iter()
                .filter(|family| side.contains(family))
                .collect(),
        });
    }
    match allowed {
        None => vec![None],
        Some(families) => families.into_iter().map(Some).collect(),
    }
}

/// Entries of one family as canonical, non-overlapping networks, sorted.
///
/// nftables rejects overlapping elements in an interval set and the JSON types
/// used here cannot request the `auto-merge` flag, so duplicates and networks
/// contained in another entry are dropped here. Only entries of `family` are
/// returned.
pub fn normalized_networks(entries: &[String], family: Family) -> Vec<IpNet> {
    let mut nets: Vec<IpNet> = entries
        .iter()
        .filter_map(|entry| address_group_entry(entry).ok())
        .filter(|net| Family::of_net(net) == family)
        .collect();
    // Within one family, sorting by (address, prefix length) puts every
    // network before the networks it contains.
    nets.sort();
    nets.dedup();
    let mut kept: Vec<IpNet> = Vec::new();
    for net in nets {
        // Networks are either nested or disjoint, and kept networks are
        // disjoint, so the last kept network is the only candidate container.
        if let Some(last) = kept.last()
            && last.contains(&net)
        {
            continue;
        }
        kept.push(net);
    }
    kept
}

/// Port-group entries as sorted inclusive ranges, with overlapping and adjacent
/// ranges merged.
pub fn normalized_ports(entries: &[String]) -> Vec<(u16, u16)> {
    let mut ranges: Vec<(u16, u16)> = entries
        .iter()
        .filter_map(|entry| port_group_entry(entry).ok())
        .collect();
    ranges.sort();
    let mut merged: Vec<(u16, u16)> = Vec::new();
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1.saturating_add(1) => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

/// Validate one address group's own fields.
pub fn validate_address_group(group: &AddressGroup) -> Vec<String> {
    let what = format!("Address group '{}'", group.name);
    let mut errors = Vec::new();
    if let Err(error) = group_name(&group.name) {
        errors.push(format!("{what}: {error}"));
    }
    if let Some(description) = &group.description
        && !is_single_line(description)
    {
        errors.push(format!("{what}: description contains control characters"));
    }
    if group.entries.is_empty() {
        errors.push(format!("{what} needs at least one address or network"));
    }
    for (index, entry) in group.entries.iter().enumerate() {
        if let Err(error) = address_group_entry(entry) {
            errors.push(format!("{what}: entry {}: {error}", index + 1));
        }
    }
    errors
}

/// Validate one port group's own fields.
pub fn validate_port_group(group: &PortGroup) -> Vec<String> {
    let what = format!("Port group '{}'", group.name);
    let mut errors = Vec::new();
    if let Err(error) = group_name(&group.name) {
        errors.push(format!("{what}: {error}"));
    }
    if let Some(description) = &group.description
        && !is_single_line(description)
    {
        errors.push(format!("{what}: description contains control characters"));
    }
    if group.entries.is_empty() {
        errors.push(format!("{what} needs at least one port or range"));
    }
    for (index, entry) in group.entries.iter().enumerate() {
        if let Err(error) = port_group_entry(entry) {
            errors.push(format!("{what}: entry {}: {error}", index + 1));
        }
    }
    errors
}

/// Address and port groups share one namespace, so a name may be used once.
pub fn validate_group_names(
    address_groups: &[AddressGroup],
    port_groups: &[PortGroup],
) -> Vec<String> {
    let mut seen: HashSet<&str> = HashSet::new();
    let mut errors = Vec::new();
    let names = address_groups
        .iter()
        .map(|group| group.name.as_str())
        .chain(port_groups.iter().map(|group| group.name.as_str()));
    for name in names {
        if !seen.insert(name) {
            errors.push(format!(
                "group name '{name}' is used by more than one address or port group"
            ));
        }
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn family_variants_intersects_constrained_sides() {
        let v4 = Some(vec![Family::V4]);
        let both = Some(vec![Family::V4, Family::V6]);
        assert_eq!(family_variants(&[None, None]), vec![None]);
        assert_eq!(
            family_variants(&[None, both.clone()]),
            vec![Some(Family::V4), Some(Family::V6)]
        );
        assert_eq!(family_variants(&[v4.clone(), both]), vec![Some(Family::V4)]);
        let v6 = Some(vec![Family::V6]);
        assert!(family_variants(&[v4, v6]).is_empty());
    }

    #[test]
    fn normalized_networks_drops_duplicates_and_nested_entries() {
        let entries = strings(&[
            "10.1.0.0/16",
            "10.0.0.0/8",
            "10.0.0.0/8",
            "10.1.2.3",
            "192.168.1.0/24",
            "fd00::/64",
        ]);
        let v4: Vec<String> = normalized_networks(&entries, Family::V4)
            .iter()
            .map(|net| net.to_string())
            .collect();
        assert_eq!(v4, vec!["10.0.0.0/8", "192.168.1.0/24"]);
        let v6: Vec<String> = normalized_networks(&entries, Family::V6)
            .iter()
            .map(|net| net.to_string())
            .collect();
        assert_eq!(v6, vec!["fd00::/64"]);
    }

    #[test]
    fn normalized_ports_merges_overlaps_and_adjacent_ranges() {
        let entries = strings(&["443", "80-90", "85-100", "101", "8080"]);
        assert_eq!(
            normalized_ports(&entries),
            vec![(80, 101), (443, 443), (8080, 8080)]
        );
    }

    #[test]
    fn group_objects_are_validated() {
        let good = AddressGroup {
            name: "lan_hosts".into(),
            entries: strings(&["10.0.0.0/8", "fd00::1"]),
            ..Default::default()
        };
        assert!(validate_address_group(&good).is_empty());

        let bad = AddressGroup {
            name: "1bad".into(),
            description: Some("two\nlines".into()),
            entries: strings(&["10.0.0.1/24", "example.com"]),
            ..Default::default()
        };
        let errors = validate_address_group(&bad);
        assert!(
            errors.iter().any(|e| e.contains("must start with")),
            "{errors:?}"
        );
        assert!(errors.iter().any(|e| e.contains("control characters")));
        assert!(errors.iter().any(|e| e.contains("host bits")), "{errors:?}");
        assert!(
            errors.iter().any(|e| e.contains("example.com")),
            "{errors:?}"
        );

        let empty = PortGroup {
            name: "web".into(),
            ..Default::default()
        };
        assert!(validate_port_group(&empty)[0].contains("at least one"));
    }

    #[test]
    fn group_names_are_unique_across_both_kinds() {
        let addresses = vec![AddressGroup {
            name: "shared".into(),
            ..Default::default()
        }];
        let ports = vec![PortGroup {
            name: "shared".into(),
            ..Default::default()
        }];
        assert_eq!(validate_group_names(&addresses, &ports).len(), 1);
        assert!(validate_group_names(&addresses, &[]).is_empty());
    }

    #[test]
    fn side_families_reports_missing_groups() {
        let groups: Vec<AddressGroup> = vec![AddressGroup {
            name: "mixed".into(),
            entries: strings(&["10.0.0.1", "fd00::1"]),
            ..Default::default()
        }];
        let index = GroupIndex::new(&groups, &[]);
        assert_eq!(
            side_families(None, Some("mixed"), &index).unwrap(),
            Some(vec![Family::V4, Family::V6])
        );
        assert_eq!(
            side_families(Some("fd00::/8"), None, &index).unwrap(),
            Some(vec![Family::V6])
        );
        assert!(side_families(None, Some("nope"), &index).is_err());
        assert_eq!(side_families(None, None, &index).unwrap(), None);
    }
}
