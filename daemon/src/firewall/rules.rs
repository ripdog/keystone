//! Firewall rules as data, in the order nftables evaluates them.
//!
//! [`build`] turns a [`FirewallConfig`] into a [`Ruleset`]: for every chain, the
//! rules nftables will try, in order, each as a list of conditions and a
//! verdict. Three consumers read this one model:
//!
//! - the nftables generator (`generate::emit`), which writes the JSON ruleset;
//! - the human-readable preview (`generate::preview`);
//! - the packet tester (`trace`), which walks the same rules against a packet.
//!
//! Each rule's predicate, action and position is decided once, here, so the
//! outputs cannot drift apart. Rules that the generator would skip (unknown
//! zone or group, unparsable rate limit, port on a non-port protocol, and so
//! on) are absent from the model, and so from all three outputs.

use crate::firewall::generate::{
    find_ipv4_masquerade_zones, find_wan_zones, resolve_zone_interfaces, rule_comment,
};
use crate::firewall::groups::{Family, GroupIndex, family_variants, side_families};
use keystone_core::validation::ipv6_suffix;
use keystone_core::{
    FirewallAction, FirewallConfig, FirewallZone, ForwardRule, InputRule, PortForward, RuleProtocol,
};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Mask selecting the interface identifier (low 64 bits) of an IPv6 address.
pub(crate) const IPV6_SUFFIX_MASK: &str = "::ffff:ffff:ffff:ffff";

/// Which address or port of a packet a condition examines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Side {
    Source,
    Destination,
}

/// An address constraint of a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Addr {
    /// A literal host address or CIDR network, as written in the rule.
    Literal(String),
    /// Membership of a named address group, for one address family.
    Group { name: String, family: Family },
}

/// Destination or source ports a rule matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Ports {
    Single(u16),
    /// Inclusive range, with `start < end`.
    Range(u16, u16),
    /// A named port group.
    Group(String),
}

impl Ports {
    /// Ports from a literal start and optional end. An end that is not above
    /// the start is ignored, so a single port is never written as a range.
    fn literal(start: u16, end: Option<u16>) -> Self {
        match end {
            Some(end) if end > start => Ports::Range(start, end),
            _ => Ports::Single(start),
        }
    }
}

/// One condition of a rule. Each condition corresponds to exactly one
/// nftables statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Cond {
    /// The packet arrived on one of these interfaces (`iifname`).
    Iif(Vec<String>),
    /// The packet leaves through one of these interfaces (`oifname`).
    Oif(Vec<String>),
    /// IP version of the packet (`meta nfproto`).
    Nfproto(Family),
    /// The packet's source or destination address.
    Addr { side: Side, addr: Addr },
    /// The packet's source or destination address is outside `addr`.
    NotAddr { side: Side, addr: Addr },
    /// The low 64 bits of the packet's IPv6 source or destination address
    /// equal `suffix`, whatever the prefix (`ip6 daddr & ::ffff:ffff:ffff:ffff == suffix`).
    Ipv6Suffix { side: Side, suffix: Ipv6Addr },
    /// Layer-4 protocol (`meta l4proto`): `tcp`, `udp`, `icmp` or `ipv6-icmp`.
    L4(&'static str),
    /// Transport port, read through `payload` (`th` for either protocol).
    Port {
        side: Side,
        payload: &'static str,
        ports: Ports,
    },
    /// ICMP type (`icmp type`), or ICMPv6 type when `v6` is set.
    IcmpType { v6: bool, icmp_type: u8 },
    /// Conntrack state is one of these.
    CtStateIn(&'static [&'static str]),
    /// Conntrack state is exactly this.
    CtStateIs(&'static str),
    /// The connection has been destination-NATed.
    CtDnat,
    /// The packet's destination is an address of this router.
    FibLocal,
    /// The packet's destination is not an address of this router.
    FibNotLocal,
    /// The packet's destination is not an address of the ingress interface.
    FibNotOnIngress,
    /// Rate limit. Matches while the limit is not exceeded.
    RateLimit { rate: u32, per: &'static str },
}

/// What a matched rule does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Accept,
    Drop,
    Reject,
    /// Rewrite the destination (and port, when given). Terminal in NAT chains.
    Dnat {
        addr: Ipv4Addr,
        port: Option<u16>,
    },
    /// Rewrite the source to the router's address on the egress interface.
    Masquerade,
    /// Rewrite the destination to the router's own address on the ingress
    /// interface, and the port to `port`. Terminal in NAT chains.
    Redirect {
        port: u16,
    },
}

impl From<FirewallAction> for Verdict {
    fn from(action: FirewallAction) -> Self {
        match action {
            FirewallAction::Accept => Verdict::Accept,
            FirewallAction::Drop => Verdict::Drop,
            FirewallAction::Reject => Verdict::Reject,
        }
    }
}

/// Where a rule comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Origin {
    /// Keystone's own rule, such as the established/related accept.
    Builtin,
    /// A zone-level policy: a zone-to-zone forward policy or a zone default.
    Policy,
    /// The accept for UPnP / NAT-PMP mappings, written by Keystone for miniupnpd.
    Upnp,
    /// A rule the user configured. `kind` is the prefix written into the
    /// nftables comment (`input`, `forward`, `portfwd`, ...).
    User {
        kind: &'static str,
        id: Option<i64>,
        name: String,
    },
}

/// One nftables rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuleSpec {
    pub origin: Origin,
    /// Comment written into the nftables rule. Also shown in the preview and
    /// in packet traces.
    pub comment: String,
    /// Heading for the preview section this rule belongs to.
    pub section: &'static str,
    /// Conditions, in the order nftables evaluates them.
    pub conds: Vec<Cond>,
    /// Log prefix, when matched packets are logged.
    pub log: Option<String>,
    pub verdict: Verdict,
}

/// One nftables chain: its default policy and rules in evaluation order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChainSpec {
    /// `input`, `forward`, `prerouting` or `postrouting`.
    pub name: &'static str,
    /// Verdict applied when no rule matches. `None` for NAT chains, which
    /// have no policy.
    pub policy: Option<Verdict>,
    pub rules: Vec<RuleSpec>,
}

/// Every chain Keystone generates. The output chain is permissive and has no
/// rules, so it is not modelled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ruleset {
    pub prerouting: ChainSpec,
    pub input: ChainSpec,
    pub forward: ChainSpec,
    pub postrouting: ChainSpec,
}

pub(crate) const SECTION_ESTABLISHED: &str = "Priority 1: Established/related connections";
pub(crate) const SECTION_DHCPV6: &str = "Priority 1: DHCPv6 replies on WAN";
pub(crate) const SECTION_INVALID: &str = "Priority 2: Invalid packets";
pub(crate) const SECTION_LOOPBACK: &str = "Priority 3: Loopback";
pub(crate) const SECTION_ICMP_SAFETY: &str = "Priority 3.5: Dangerous ICMP (always dropped)";
pub(crate) const SECTION_CADDY: &str = "Priority 3.7: Caddy web server (generated)";
pub(crate) const SECTION_USER_INPUT: &str = "Priority 4: User input rules";
pub(crate) const SECTION_BUILTIN_ICMP: &str = "Priority 4.5: Built-in ICMP accepts";
pub(crate) const SECTION_ZONE_DEFAULTS: &str = "Priority 5: Zone default policies";
pub(crate) const SECTION_PORTFWD_ACCEPT: &str = "Priority 3: Accept port-forwarded traffic";
pub(crate) const SECTION_UPNP: &str = "Priority 3: Accept UPnP / NAT-PMP mappings";
pub(crate) const SECTION_USER_FORWARD: &str = "Priority 4: User forward rules";
pub(crate) const SECTION_ZONE_POLICIES: &str = "Priority 5: Zone-to-zone policies";
pub(crate) const SECTION_DNS_REDIRECT: &str = "Redirect LAN DNS to the router";
pub(crate) const SECTION_DOT_BLOCK: &str = "Priority 3: Block DNS-over-TLS from LAN";
pub(crate) const SECTION_DNAT: &str = "Port forwards and hairpin NAT, in order";
pub(crate) const SECTION_HAIRPIN_SNAT: &str = "Hairpin NAT masquerade";
pub(crate) const SECTION_MASQUERADE: &str = "Egress masquerade";

/// Build every chain for `config`, in evaluation order.
pub(crate) fn build(config: &FirewallConfig) -> Ruleset {
    let zones = ZoneFacts::new(&config.zones);
    let groups = GroupIndex::new(&config.address_groups, &config.port_groups);
    Ruleset {
        prerouting: prerouting(config, &zones, &groups),
        input: input(config, &zones, &groups),
        forward: forward(config, &zones, &groups),
        postrouting: postrouting(config, &zones, &groups),
    }
}

/// Zone facts that several chains need.
pub(crate) struct ZoneFacts<'a> {
    /// Zone name to interfaces. Rules reference zones by name.
    pub interfaces: HashMap<String, Vec<String>>,
    /// Names of the Internet-facing zones.
    wan_names: Vec<&'a str>,
    /// Interfaces of every zone that is not Internet-facing. Not deduplicated.
    pub lan_interfaces: Vec<String>,
    /// Interfaces of the Internet-facing zones, sorted and deduplicated.
    pub wan_interfaces: Vec<String>,
}

impl<'a> ZoneFacts<'a> {
    fn new(zones: &'a [FirewallZone]) -> Self {
        let wan_names: Vec<&str> = find_wan_zones(zones)
            .into_iter()
            .map(|zone| zone.name.as_str())
            .collect();
        let lan_interfaces = zones
            .iter()
            .filter(|zone| !wan_names.contains(&zone.name.as_str()))
            .flat_map(|zone| zone.interfaces.iter().cloned())
            .collect();
        let mut wan_interfaces: Vec<String> = find_wan_zones(zones)
            .into_iter()
            .flat_map(|zone| zone.interfaces.iter().cloned())
            .collect();
        wan_interfaces.sort();
        wan_interfaces.dedup();
        Self {
            interfaces: zones
                .iter()
                .map(|zone| (zone.name.clone(), zone.interfaces.clone()))
                .collect(),
            wan_names,
            lan_interfaces,
            wan_interfaces,
        }
    }

    fn is_wan(&self, zone: &str) -> bool {
        self.wan_names.contains(&zone)
    }

    /// Interfaces of a zone, when it has any.
    fn nonempty(&self, zone: &str) -> Option<&[String]> {
        self.interfaces
            .get(zone)
            .filter(|interfaces| !interfaces.is_empty())
            .map(Vec::as_slice)
    }
}

// ============================================================================
// Shared helpers
// ============================================================================

fn builtin(section: &'static str, comment: &str, conds: Vec<Cond>, verdict: Verdict) -> RuleSpec {
    RuleSpec {
        origin: Origin::Builtin,
        comment: comment.to_string(),
        section,
        conds,
        log: None,
        verdict,
    }
}

fn established(section: &'static str) -> RuleSpec {
    builtin(
        section,
        "Accept established/related",
        vec![Cond::CtStateIn(&["established", "related"])],
        Verdict::Accept,
    )
}

fn invalid_drop(section: &'static str) -> RuleSpec {
    builtin(
        section,
        "Drop invalid packets",
        vec![Cond::CtStateIs("invalid")],
        Verdict::Drop,
    )
}

/// Expand a protocol into the concrete nftables protocols of the rule.
/// `None` in the result means the rule does not constrain the protocol.
fn expand_optional(protocol: Option<&RuleProtocol>) -> Vec<Option<&'static str>> {
    match protocol {
        Some(protocol) => expand_protocol(protocol),
        None => vec![None],
    }
}

/// Expand a [`RuleProtocol`] into concrete protocols. nftables cannot match
/// several protocols in one rule, so `tcp+udp` becomes one rule per protocol.
/// `Any` yields `None`, meaning no protocol match.
pub(crate) fn expand_protocol(protocol: &RuleProtocol) -> Vec<Option<&'static str>> {
    match protocol {
        RuleProtocol::Any => vec![None],
        RuleProtocol::Tcp => vec![Some("tcp")],
        RuleProtocol::Udp => vec![Some("udp")],
        RuleProtocol::TcpUdp => vec![Some("tcp"), Some("udp")],
        RuleProtocol::Icmp => vec![Some("icmp")],
        RuleProtocol::Icmpv6 => vec![Some("ipv6-icmp")],
    }
}

/// Parse a rate limit such as `10/minute` into a count and a unit.
pub(crate) fn parse_rate_limit(rate: &str) -> Option<(u32, &'static str)> {
    let (count, unit) = rate.split_once('/')?;
    let count: u32 = count.parse().ok()?;
    let unit = match unit.to_lowercase().as_str() {
        "second" | "sec" | "s" => "second",
        "minute" | "min" | "m" => "minute",
        "hour" | "hr" | "h" => "hour",
        "day" | "d" => "day",
        _ => return None,
    };
    Some((count, unit))
}

/// Longest log prefix the kernel keeps: `NF_LOG_PREFIXLEN` (128) less the
/// terminating NUL.
pub(crate) const MAX_LOG_PREFIX_BYTES: usize = 127;

/// Log prefix of a logging rule: a stable `ks:<kind>:<id> ` tag, then the
/// human prefix. The tag lets the live log attribute each line to its rule.
/// The human part keeps quotes, backslashes, control characters and `=`
/// replaced, since `=` would confuse the key=value fields the kernel prints
/// after the prefix. The whole prefix is cut to the kernel limit at a
/// character boundary, and the tag is never cut.
pub(crate) fn log_prefix(kind: &str, id: Option<i64>, human: &str) -> String {
    let tag = format!("ks:{kind}:{} ", id.unwrap_or_default());
    let human: String = human
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '"' | '\\' | '=') {
                '_'
            } else {
                c
            }
        })
        .collect();
    let mut prefix = format!("{tag}{human}");
    while prefix.len() > MAX_LOG_PREFIX_BYTES {
        prefix.pop();
    }
    prefix
}

/// Check that a rule's port and rate-limit options can be expressed exactly.
///
/// Ports are only matchable for tcp and udp, and an unparsable rate limit
/// cannot be emitted. Silently dropping either would widen the rule, so the
/// rule is skipped instead.
pub(crate) fn rule_options_are_safe(
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

/// Address condition for one side of a rule, restricted to `family`. A literal
/// matches itself; a group matches its set for that family and needs a family.
fn address_cond(
    side: Side,
    literal: Option<&str>,
    group: Option<&str>,
    family: Option<Family>,
) -> Option<Cond> {
    if let Some(literal) = literal {
        return Some(Cond::Addr {
            side,
            addr: Addr::Literal(literal.to_string()),
        });
    }
    let (group, family) = (group?, family?);
    Some(Cond::Addr {
        side,
        addr: Addr::Group {
            name: group.to_string(),
            family,
        },
    })
}

/// Protocol and destination-port conditions of a rule. A port group is a set
/// lookup and needs a protocol; a literal range needs tcp or udp.
fn port_conds(
    protocol: Option<&'static str>,
    port_start: Option<u16>,
    port_end: Option<u16>,
    port_group: Option<&str>,
) -> Vec<Cond> {
    match port_group {
        Some(group) => match protocol {
            Some(protocol) => vec![
                Cond::L4(protocol),
                Cond::Port {
                    side: Side::Destination,
                    payload: "th",
                    ports: Ports::Group(group.to_string()),
                },
            ],
            None => Vec::new(),
        },
        None => {
            let mut conds = Vec::new();
            if let Some(protocol) = protocol {
                conds.push(Cond::L4(protocol));
                if matches!(protocol, "tcp" | "udp")
                    && let Some(start) = port_start
                {
                    conds.push(Cond::Port {
                        side: Side::Destination,
                        payload: "th",
                        ports: Ports::literal(start, port_end),
                    });
                }
            }
            conds
        }
    }
}

fn rate_conds(rate: Option<&str>) -> Vec<Cond> {
    rate.and_then(parse_rate_limit)
        .map(|(rate, per)| Cond::RateLimit { rate, per })
        .into_iter()
        .collect()
}

// ============================================================================
// Input chain
// ============================================================================

fn input(config: &FirewallConfig, zones: &ZoneFacts, groups: &GroupIndex) -> ChainSpec {
    let mut rules = vec![established(SECTION_ESTABLISHED)];

    // DHCPv6 server replies come from the server's unicast address, which
    // conntrack need not classify as established, so they are accepted before
    // the invalid-state drop.
    if !zones.wan_interfaces.is_empty() {
        rules.push(builtin(
            SECTION_DHCPV6,
            "Allow DHCPv6 server replies on WAN",
            vec![
                Cond::Iif(zones.wan_interfaces.clone()),
                Cond::Nfproto(Family::V6),
                Cond::L4("udp"),
                Cond::Port {
                    side: Side::Source,
                    payload: "udp",
                    ports: Ports::Single(547),
                },
                Cond::Port {
                    side: Side::Destination,
                    payload: "udp",
                    ports: Ports::Single(546),
                },
            ],
            Verdict::Accept,
        ));
    }

    rules.push(invalid_drop(SECTION_INVALID));
    rules.push(builtin(
        SECTION_LOOPBACK,
        "Accept loopback",
        vec![Cond::Iif(vec!["lo".to_string()])],
        Verdict::Accept,
    ));
    rules.extend(dangerous_icmp_drops());

    // Caddy fronts the web UI, so its LAN listeners are always reachable. This
    // runs before user rules so that no rule edit can lock the UI out.
    rules.extend(caddy_input_accepts(config));

    // User rules run before the built-in ICMP accepts, so a user rule can drop
    // or limit ping. The dangerous-ICMP drops above can never be overridden.
    let mut user_rules: Vec<&InputRule> = config.input_rules.iter().filter(|r| r.enabled).collect();
    user_rules.sort_by_key(|rule| rule.position);
    for rule in user_rules {
        rules.extend(input_rule(rule, zones, groups));
    }

    rules.extend(builtin_icmp_accepts(config, zones));
    rules.extend(zone_default_inputs(config));

    ChainSpec {
        name: "input",
        policy: Some(Verdict::Drop),
        rules,
    }
}

/// Accepts for the ports Caddy listens on, present only while Caddy is enabled.
fn caddy_input_accepts(config: &FirewallConfig) -> Vec<RuleSpec> {
    let Some(caddy) = &config.caddy_input else {
        return Vec::new();
    };
    caddy
        .ports
        .iter()
        .map(|&port| {
            builtin(
                SECTION_CADDY,
                &format!("Allow Caddy on {} tcp/{port}", caddy.interface),
                vec![
                    Cond::Iif(vec![caddy.interface.clone()]),
                    Cond::L4("tcp"),
                    Cond::Port {
                        side: Side::Destination,
                        payload: "th",
                        ports: Ports::Single(port),
                    },
                ],
                Verdict::Accept,
            )
        })
        .collect()
}

/// ICMP types that leak information or enable redirects. Always dropped.
fn dangerous_icmp_drops() -> Vec<RuleSpec> {
    [
        (13, "Drop ICMP timestamp"),
        (14, "Drop ICMP timestamp-reply"),
        (5, "Drop ICMP redirect"),
        (17, "Drop ICMP address-mask-request"),
        (18, "Drop ICMP address-mask-reply"),
    ]
    .into_iter()
    .map(|(icmp_type, comment)| {
        builtin(
            SECTION_ICMP_SAFETY,
            comment,
            vec![
                Cond::L4("icmp"),
                Cond::IcmpType {
                    v6: false,
                    icmp_type,
                },
            ],
            Verdict::Drop,
        )
    })
    .collect()
}

fn input_rule(rule: &InputRule, zones: &ZoneFacts, groups: &GroupIndex) -> Vec<RuleSpec> {
    let source = match side_families(
        rule.source_ip.as_deref(),
        rule.source_group.as_deref(),
        groups,
    ) {
        Ok(source) => source,
        Err(error) => {
            tracing::warn!("Skipping rule '{}': {error}", rule.name);
            return Vec::new();
        }
    };
    let families = family_variants(&[source]);
    if families.is_empty() {
        tracing::warn!(
            "Skipping rule '{}': no address in its source group",
            rule.name
        );
        return Vec::new();
    }
    let protocols = expand_optional(rule.protocol.as_ref());
    families
        .iter()
        .flat_map(|family| protocols.iter().map(move |proto| (*family, *proto)))
        .filter_map(|(family, proto)| input_rule_for_protocol(rule, zones, proto, family))
        .collect()
}

fn input_rule_for_protocol(
    rule: &InputRule,
    zones: &ZoneFacts,
    protocol: Option<&'static str>,
    family: Option<Family>,
) -> Option<RuleSpec> {
    let has_port_match = rule.port_start.is_some() || rule.dest_port_group.is_some();
    if !rule_options_are_safe(
        protocol,
        has_port_match,
        rule.rate_limit.as_deref(),
        &rule.name,
    ) {
        return None;
    }

    // An unresolvable zone fails closed: the rule is skipped, never widened.
    let mut conds = Vec::new();
    if let Some(interfaces) =
        resolve_zone_interfaces(rule.zone.as_deref(), &zones.interfaces, &rule.name).ok()?
    {
        conds.push(Cond::Iif(interfaces.to_vec()));
    }
    conds.extend(address_cond(
        Side::Source,
        rule.source_ip.as_deref(),
        rule.source_group.as_deref(),
        family,
    ));
    conds.extend(port_conds(
        protocol,
        rule.port_start,
        rule.port_end,
        rule.dest_port_group.as_deref(),
    ));
    conds.extend(rate_conds(rule.rate_limit.as_deref()));

    Some(RuleSpec {
        origin: Origin::User {
            kind: "input",
            id: rule.id,
            name: rule.name.clone(),
        },
        comment: rule_comment("input", rule.id, &rule.name),
        section: SECTION_USER_INPUT,
        conds,
        log: rule.log_enabled.then(|| {
            let human = rule
                .log_prefix
                .clone()
                .unwrap_or_else(|| format!("keystone-input-{}: ", rule.name));
            log_prefix("input", rule.id, &human)
        }),
        verdict: rule.action.into(),
    })
}

/// Built-in accepts placed after the user input rules: ping per the global
/// settings, and the ICMP types that normal operation depends on.
fn builtin_icmp_accepts(config: &FirewallConfig, zones: &ZoneFacts) -> Vec<RuleSpec> {
    let mut rules = Vec::new();
    let settings = &config.global_settings;

    if settings.ping_lan_enabled {
        for zone in &config.zones {
            if !zones.is_wan(&zone.name)
                && let Some(interfaces) = zones.nonempty(&zone.name)
            {
                rules.extend(ping_accepts(interfaces, &format!("{} (LAN)", zone.name)));
            }
        }
    }
    if settings.ping_wan_enabled {
        for zone in find_wan_zones(&config.zones) {
            if let Some(interfaces) = zones.nonempty(&zone.name) {
                rules.extend(ping_accepts(interfaces, &format!("{} (WAN)", zone.name)));
            }
        }
    }

    rules.extend(
        [
            (3, "Accept ICMP destination-unreachable"),
            (11, "Accept ICMP time-exceeded"),
            (12, "Accept ICMP parameter-problem"),
        ]
        .into_iter()
        .map(|(icmp_type, comment)| {
            builtin(
                SECTION_BUILTIN_ICMP,
                comment,
                vec![
                    Cond::L4("icmp"),
                    Cond::IcmpType {
                        v6: false,
                        icmp_type,
                    },
                ],
                Verdict::Accept,
            )
        }),
    );

    // ICMPv6 error reporting, neighbour and router discovery, and multicast
    // listener discovery. Blocking these breaks IPv6.
    rules.extend(
        [
            (1, "Accept ICMPv6 destination-unreachable"),
            (2, "Accept ICMPv6 packet-too-big"),
            (3, "Accept ICMPv6 time-exceeded"),
            (4, "Accept ICMPv6 parameter-problem"),
            (130, "Accept ICMPv6 MLD query"),
            (131, "Accept ICMPv6 MLD report"),
            (132, "Accept ICMPv6 MLD done"),
            (133, "Accept ICMPv6 router-solicitation"),
            (134, "Accept ICMPv6 router-advertisement"),
            (135, "Accept ICMPv6 neighbour-solicitation"),
            (136, "Accept ICMPv6 neighbour-advertisement"),
            (143, "Accept ICMPv6 MLDv2 report"),
        ]
        .into_iter()
        .map(|(icmp_type, comment)| {
            builtin(
                SECTION_BUILTIN_ICMP,
                comment,
                vec![
                    Cond::L4("ipv6-icmp"),
                    Cond::IcmpType {
                        v6: true,
                        icmp_type,
                    },
                ],
                Verdict::Accept,
            )
        }),
    );
    rules
}

/// Echo-request accepts for IPv4 and IPv6 on one set of interfaces.
fn ping_accepts(interfaces: &[String], label: &str) -> Vec<RuleSpec> {
    vec![
        builtin(
            SECTION_BUILTIN_ICMP,
            &format!("Allow IPv4 ping from {label}"),
            vec![
                Cond::Iif(interfaces.to_vec()),
                Cond::L4("icmp"),
                Cond::IcmpType {
                    v6: false,
                    icmp_type: 8,
                },
            ],
            Verdict::Accept,
        ),
        builtin(
            SECTION_BUILTIN_ICMP,
            &format!("Allow IPv6 ping from {label}"),
            vec![
                Cond::Iif(interfaces.to_vec()),
                Cond::L4("ipv6-icmp"),
                Cond::IcmpType {
                    v6: true,
                    icmp_type: 128,
                },
            ],
            Verdict::Accept,
        ),
    ]
}

/// Accept everything from a zone whose default input policy is accept.
fn zone_default_inputs(config: &FirewallConfig) -> Vec<RuleSpec> {
    config
        .zones
        .iter()
        .filter(|zone| {
            !zone.interfaces.is_empty()
                && zone.default_input_policy == keystone_core::FirewallPolicy::Accept
        })
        .map(|zone| RuleSpec {
            origin: Origin::Policy,
            comment: format!("{} zone default: accept input", zone.name),
            section: SECTION_ZONE_DEFAULTS,
            conds: vec![Cond::Iif(zone.interfaces.clone())],
            log: None,
            verdict: Verdict::Accept,
        })
        .collect()
}

// ============================================================================
// Forward chain
// ============================================================================

fn forward(config: &FirewallConfig, zones: &ZoneFacts, groups: &GroupIndex) -> ChainSpec {
    let mut rules = vec![
        established(SECTION_ESTABLISHED),
        invalid_drop(SECTION_INVALID),
    ];

    // Port-forwarded traffic is accepted before user forward rules. Without
    // this, a raw port forward would have no matching forward rule and the
    // chain's default policy would drop it.
    for pf in config.port_forwards.iter().filter(|pf| pf.enabled) {
        rules.extend(port_forward_accepts(pf));
        rules.extend(port_forward_v6_accepts(pf, zones, groups));
    }

    // UPnP / NAT-PMP mappings are DNATed by miniupnpd's own table. This accept
    // lets those packets through: it matches only DNATed packets, arriving on
    // the UPnP WAN and leaving for a UPnP LAN. Present only while UPnP is enabled.
    if let Some(upnp) = &config.upnp_forward
        && !upnp.lan_interfaces.is_empty()
    {
        rules.push(RuleSpec {
            origin: Origin::Upnp,
            comment: "ks:upnp".to_string(),
            section: SECTION_UPNP,
            conds: vec![
                Cond::Iif(vec![upnp.wan_interface.clone()]),
                Cond::Oif(upnp.lan_interfaces.clone()),
                Cond::CtDnat,
            ],
            log: None,
            verdict: Verdict::Accept,
        });
    }

    // Encrypted DNS is rejected before user rules, so that a broad user
    // accept (LAN to WAN) does not let it through.
    rules.extend(dns_over_tls_rejects(config, zones, groups));

    let mut user_rules: Vec<&ForwardRule> =
        config.forward_rules.iter().filter(|r| r.enabled).collect();
    user_rules.sort_by_key(|rule| rule.position);
    for rule in user_rules {
        rules.extend(forward_rule(rule, zones, groups));
    }

    for policy in config.zone_forwards.iter().filter(|policy| policy.enabled) {
        if let (Some(src), Some(dst)) = (
            zones.nonempty(&policy.source_zone),
            zones.nonempty(&policy.dest_zone),
        ) {
            rules.push(RuleSpec {
                origin: Origin::Policy,
                comment: format!(
                    "{} -> {}: {}",
                    policy.source_zone, policy.dest_zone, policy.policy
                ),
                section: SECTION_ZONE_POLICIES,
                conds: vec![Cond::Iif(src.to_vec()), Cond::Oif(dst.to_vec())],
                log: None,
                verdict: policy.policy.into(),
            });
        }
    }

    ChainSpec {
        name: "forward",
        policy: Some(Verdict::Drop),
        rules,
    }
}

/// Accept packets the DNAT of a port forward has redirected. Matches the
/// translated destination and port, and only IPv4 (DNAT is IPv4-only).
fn port_forward_accepts(pf: &PortForward) -> Vec<RuleSpec> {
    let Ok(addr) = pf.dest_ip.parse::<Ipv4Addr>() else {
        return Vec::new();
    };
    // Translated destination port(s): the explicit dest port, or the external range.
    let (start, end) = match pf.dest_port {
        Some(port) => (port, None),
        None => (pf.external_port_start, pf.external_port_end),
    };
    expand_protocol(&pf.protocol)
        .into_iter()
        .flatten()
        .filter(|proto| matches!(*proto, "tcp" | "udp"))
        .map(|proto| RuleSpec {
            origin: Origin::User {
                kind: "portfwd-accept",
                id: pf.id,
                name: pf.name.clone(),
            },
            comment: rule_comment(
                "portfwd-accept",
                pf.id,
                &format!("{} DNAT accept ({})", pf.name, proto),
            ),
            section: SECTION_PORTFWD_ACCEPT,
            conds: vec![
                Cond::Nfproto(Family::V4),
                Cond::CtDnat,
                Cond::Addr {
                    side: Side::Destination,
                    addr: Addr::Literal(addr.to_string()),
                },
                Cond::L4(proto),
                Cond::Port {
                    side: Side::Destination,
                    payload: "th",
                    ports: Ports::literal(start, end),
                },
            ],
            log: None,
            verdict: Verdict::Accept,
        })
        .collect()
}

/// Accept IPv6 traffic to the port-forwarded service. IPv6 is routed, not
/// translated: the rule matches the host by its interface-identifier suffix,
/// so it keeps working when the ISP renumbers the delegated prefix, and the
/// external ports are the destination ports.
fn port_forward_v6_accepts(
    pf: &PortForward,
    zones: &ZoneFacts,
    groups: &GroupIndex,
) -> Vec<RuleSpec> {
    let Some(suffix) = pf
        .dest_ipv6_suffix
        .as_deref()
        .and_then(|text| ipv6_suffix(text).ok())
    else {
        return Vec::new();
    };
    let source = match side_families(pf.source_ip.as_deref(), pf.source_group.as_deref(), groups) {
        Ok(None) => None,
        Ok(Some(families)) if families.contains(&Family::V6) => address_cond(
            Side::Source,
            pf.source_ip.as_deref(),
            pf.source_group.as_deref(),
            Some(Family::V6),
        ),
        Ok(Some(_)) => {
            tracing::warn!(
                "Skipping IPv6 accept for port forward '{}': its source has no IPv6 address",
                pf.name
            );
            return Vec::new();
        }
        Err(error) => {
            tracing::warn!(
                "Skipping IPv6 accept for port forward '{}': {error}",
                pf.name
            );
            return Vec::new();
        }
    };
    let zone = match resolve_zone_interfaces(pf.source_zone.as_deref(), &zones.interfaces, &pf.name)
    {
        Ok(zone) => zone.map(|interfaces| Cond::Iif(interfaces.to_vec())),
        Err(_) => return Vec::new(),
    };
    port_forward_protocols(pf.protocol)
        .iter()
        .map(|&proto| {
            let mut conds = vec![Cond::Nfproto(Family::V6)];
            conds.extend(zone.clone());
            conds.extend(source.clone());
            conds.push(Cond::Ipv6Suffix {
                side: Side::Destination,
                suffix,
            });
            conds.push(Cond::L4(proto));
            conds.push(Cond::Port {
                side: Side::Destination,
                payload: "th",
                ports: Ports::literal(pf.external_port_start, pf.external_port_end),
            });
            RuleSpec {
                origin: Origin::User {
                    kind: "portfwd-accept",
                    id: pf.id,
                    name: pf.name.clone(),
                },
                comment: rule_comment(
                    "portfwd-accept",
                    pf.id,
                    &format!("{} IPv6 accept ({})", pf.name, proto),
                ),
                section: SECTION_PORTFWD_ACCEPT,
                conds,
                log: None,
                verdict: Verdict::Accept,
            }
        })
        .collect()
}

/// Address families a forward rule's destination can match. A suffix is IPv6.
pub(crate) fn forward_dest_families(
    rule: &ForwardRule,
    groups: &GroupIndex,
) -> Result<Option<Vec<Family>>, String> {
    if let Some(suffix) = rule.dest_ipv6_suffix.as_deref() {
        ipv6_suffix(suffix)?;
        return Ok(Some(vec![Family::V6]));
    }
    side_families(rule.dest_ip.as_deref(), rule.dest_group.as_deref(), groups)
}

fn forward_rule(rule: &ForwardRule, zones: &ZoneFacts, groups: &GroupIndex) -> Vec<RuleSpec> {
    let source = side_families(
        rule.source_ip.as_deref(),
        rule.source_group.as_deref(),
        groups,
    );
    let dest = forward_dest_families(rule, groups);
    let (source, dest) = match (source, dest) {
        (Ok(source), Ok(dest)) => (source, dest),
        (Err(error), _) | (_, Err(error)) => {
            tracing::warn!("Skipping rule '{}': {error}", rule.name);
            return Vec::new();
        }
    };
    let families = family_variants(&[source, dest]);
    if families.is_empty() {
        tracing::warn!(
            "Skipping rule '{}': its source and destination addresses share no IP family",
            rule.name
        );
        return Vec::new();
    }
    let protocols = expand_optional(rule.protocol.as_ref());
    families
        .iter()
        .flat_map(|family| protocols.iter().map(move |proto| (*family, *proto)))
        .filter_map(|(family, proto)| forward_rule_for_protocol(rule, zones, proto, family))
        .collect()
}

fn forward_rule_for_protocol(
    rule: &ForwardRule,
    zones: &ZoneFacts,
    protocol: Option<&'static str>,
    family: Option<Family>,
) -> Option<RuleSpec> {
    let has_port_match = rule.dest_port_start.is_some() || rule.dest_port_group.is_some();
    if !rule_options_are_safe(
        protocol,
        has_port_match,
        rule.rate_limit.as_deref(),
        &rule.name,
    ) {
        return None;
    }

    let mut conds = Vec::new();
    if let Some(interfaces) =
        resolve_zone_interfaces(rule.source_zone.as_deref(), &zones.interfaces, &rule.name).ok()?
    {
        conds.push(Cond::Iif(interfaces.to_vec()));
    }
    if let Some(interfaces) =
        resolve_zone_interfaces(rule.dest_zone.as_deref(), &zones.interfaces, &rule.name).ok()?
    {
        conds.push(Cond::Oif(interfaces.to_vec()));
    }
    conds.extend(address_cond(
        Side::Source,
        rule.source_ip.as_deref(),
        rule.source_group.as_deref(),
        family,
    ));
    conds.extend(address_cond(
        Side::Destination,
        rule.dest_ip.as_deref(),
        rule.dest_group.as_deref(),
        family,
    ));
    if let Some(suffix) = rule.dest_ipv6_suffix.as_deref() {
        conds.push(Cond::Ipv6Suffix {
            side: Side::Destination,
            suffix: ipv6_suffix(suffix).ok()?,
        });
    }
    conds.extend(port_conds(
        protocol,
        rule.dest_port_start,
        rule.dest_port_end,
        rule.dest_port_group.as_deref(),
    ));
    conds.extend(rate_conds(rule.rate_limit.as_deref()));

    Some(RuleSpec {
        origin: Origin::User {
            kind: "forward",
            id: rule.id,
            name: rule.name.clone(),
        },
        comment: rule_comment("forward", rule.id, &rule.name),
        section: SECTION_USER_FORWARD,
        conds,
        log: rule.log_enabled.then(|| {
            let human = rule
                .log_prefix
                .clone()
                .unwrap_or_else(|| format!("keystone-fwd-{}: ", rule.name));
            log_prefix("forward", rule.id, &human)
        }),
        verdict: rule.action.into(),
    })
}

// ============================================================================
// NAT chains
// ============================================================================

/// Protocols a port forward applies to, in the order its rules are written.
fn port_forward_protocols(protocol: RuleProtocol) -> &'static [&'static str] {
    match protocol {
        RuleProtocol::TcpUdp => &["tcp", "udp"],
        RuleProtocol::Tcp => &["tcp"],
        RuleProtocol::Udp => &["udp"],
        RuleProtocol::Any | RuleProtocol::Icmp | RuleProtocol::Icmpv6 => &[],
    }
}

/// Destination port a port forward translates to, or `None` to keep the
/// original port. A range without an explicit destination port keeps each port
/// as-is instead of collapsing the whole range onto its first port.
pub(crate) fn dnat_port(pf: &PortForward) -> Option<u16> {
    match pf.dest_port {
        Some(port) => Some(port),
        None if pf
            .external_port_end
            .is_some_and(|end| end > pf.external_port_start) =>
        {
            None
        }
        None => Some(pf.external_port_start),
    }
}

/// Source restriction of a port forward. DNAT only matches IPv4, so a source
/// group needs IPv4 entries. `Ok(None)` means the forward is unrestricted.
fn port_forward_source(pf: &PortForward, groups: &GroupIndex) -> Result<Option<Cond>, String> {
    match side_families(pf.source_ip.as_deref(), pf.source_group.as_deref(), groups)? {
        None => Ok(None),
        Some(families) if families.contains(&Family::V4) => Ok(address_cond(
            Side::Source,
            pf.source_ip.as_deref(),
            pf.source_group.as_deref(),
            Some(Family::V4),
        )),
        Some(_) => Err(format!(
            "port forward '{}' has no IPv4 source to match",
            pf.name
        )),
    }
}

fn prerouting(config: &FirewallConfig, zones: &ZoneFacts, groups: &GroupIndex) -> ChainSpec {
    let hairpin = config.global_settings.hairpin_nat_enabled && !zones.lan_interfaces.is_empty();
    // DNS redirects only match traffic to outside addresses, and port
    // forwards only traffic to the router, so their order does not matter.
    let mut rules = dns_redirects(config, zones, groups);
    for pf in config.port_forwards.iter().filter(|pf| pf.enabled) {
        let protocols = port_forward_protocols(pf.protocol);
        rules.extend(
            protocols
                .iter()
                .filter_map(|proto| port_forward_dnat(pf, zones, groups, proto)),
        );
        if hairpin {
            rules.extend(
                protocols
                    .iter()
                    .copied()
                    .filter_map(|proto| hairpin_dnat(pf, &zones.lan_interfaces, groups, proto)),
            );
        }
    }
    ChainSpec {
        name: "prerouting",
        policy: None,
        rules,
    }
}

/// DNAT of a port forward. Only traffic addressed to the router itself may be
/// translated, so LAN clients' outbound traffic to the same port is not hijacked.
fn port_forward_dnat(
    pf: &PortForward,
    zones: &ZoneFacts,
    groups: &GroupIndex,
    protocol: &'static str,
) -> Option<RuleSpec> {
    let addr = pf.dest_ip.parse::<Ipv4Addr>().ok()?;
    let source = match port_forward_source(pf, groups) {
        Ok(source) => source,
        Err(error) => {
            tracing::warn!("Skipping port forward '{}': {error}", pf.name);
            return None;
        }
    };

    let mut conds = vec![Cond::Nfproto(Family::V4)];
    if let Some(interfaces) =
        resolve_zone_interfaces(pf.source_zone.as_deref(), &zones.interfaces, &pf.name).ok()?
    {
        conds.push(Cond::Iif(interfaces.to_vec()));
    }
    conds.push(Cond::FibLocal);
    conds.extend(source);
    conds.push(Cond::L4(protocol));
    conds.push(Cond::Port {
        side: Side::Destination,
        payload: "th",
        ports: Ports::literal(pf.external_port_start, pf.external_port_end),
    });

    Some(RuleSpec {
        origin: Origin::User {
            kind: "portfwd",
            id: pf.id,
            name: pf.name.clone(),
        },
        comment: rule_comment("portfwd", pf.id, &format!("{} ({})", pf.name, protocol)),
        section: SECTION_DNAT,
        conds,
        log: None,
        verdict: Verdict::Dnat {
            addr,
            port: dnat_port(pf),
        },
    })
}

/// Hairpin NAT: LAN clients reach a port forward through the router's own
/// addresses. Matches packets from LAN interfaces addressed to a router
/// address other than the one on the ingress interface, which must keep
/// reaching the router (for example Caddy on the LAN address).
fn hairpin_dnat(
    pf: &PortForward,
    lan_interfaces: &[String],
    groups: &GroupIndex,
    protocol: &'static str,
) -> Option<RuleSpec> {
    if lan_interfaces.is_empty() {
        return None;
    }
    let addr = pf.dest_ip.parse::<Ipv4Addr>().ok()?;
    let source = match port_forward_source(pf, groups) {
        Ok(source) => source,
        Err(error) => {
            tracing::warn!("Skipping hairpin rule for '{}': {error}", pf.name);
            return None;
        }
    };

    let mut conds = vec![
        Cond::Nfproto(Family::V4),
        Cond::Iif(lan_interfaces.to_vec()),
    ];
    // The source restriction applies to LAN clients too.
    conds.extend(source);
    conds.extend([
        Cond::L4(protocol),
        Cond::Port {
            side: Side::Destination,
            payload: "th",
            ports: Ports::literal(pf.external_port_start, pf.external_port_end),
        },
        Cond::FibLocal,
        Cond::FibNotOnIngress,
    ]);

    Some(RuleSpec {
        origin: Origin::User {
            kind: "portfwd-hairpin",
            id: pf.id,
            name: pf.name.clone(),
        },
        comment: rule_comment(
            "portfwd-hairpin",
            pf.id,
            &format!("{} hairpin ({})", pf.name, protocol),
        ),
        section: SECTION_DNAT,
        conds,
        log: None,
        verdict: Verdict::Dnat {
            addr,
            port: dnat_port(pf),
        },
    })
}

/// Plain DNS port.
const DNS_PORT: u16 = 53;
/// DNS-over-TLS (TCP) and DNS-over-QUIC (UDP) port.
const DNS_OVER_TLS_PORT: u16 = 853;

/// Rules that apply the DNS enforcement settings: one per address family and
/// protocol, matching packets from LAN interfaces to `port` on a host other
/// than the router. Members of the exempt group are excluded on both sides,
/// so an exempt host may use any DNS server and may also serve DNS to LAN
/// clients (for example a separate resolver on another subnet).
fn dns_enforcement_rules(
    config: &FirewallConfig,
    zones: &ZoneFacts,
    groups: &GroupIndex,
    port: u16,
    protocols: &[&'static str],
    rule: impl Fn(Vec<Cond>, Family, &'static str) -> RuleSpec,
) -> Vec<RuleSpec> {
    if zones.lan_interfaces.is_empty() {
        return Vec::new();
    }
    let exempt = config.global_settings.dns_exempt_group.as_deref();
    let exempt_families = match exempt {
        Some(name) => groups.families(name).unwrap_or_else(|| {
            tracing::warn!("DNS exempt group '{name}' does not exist; no host is exempt");
            Vec::new()
        }),
        None => Vec::new(),
    };
    let mut rules = Vec::new();
    for family in [Family::V4, Family::V6] {
        for &protocol in protocols {
            let mut conds = vec![
                Cond::Nfproto(family),
                Cond::Iif(zones.lan_interfaces.clone()),
            ];
            // A group without entries of this family has no set for it, and
            // no member that could match.
            if let Some(name) = exempt
                && exempt_families.contains(&family)
            {
                for side in [Side::Source, Side::Destination] {
                    conds.push(Cond::NotAddr {
                        side,
                        addr: Addr::Group {
                            name: name.to_string(),
                            family,
                        },
                    });
                }
            }
            conds.extend([
                Cond::L4(protocol),
                Cond::Port {
                    side: Side::Destination,
                    payload: "th",
                    ports: Ports::Single(port),
                },
                Cond::FibNotLocal,
            ]);
            rules.push(rule(conds, family, protocol));
        }
    }
    rules
}

fn family_name(family: Family) -> &'static str {
    match family {
        Family::V4 => "IPv4",
        Family::V6 => "IPv6",
    }
}

/// Redirect plain DNS from LAN clients to outside servers to the router's own
/// DNS server, when `force_local_dns` is set.
fn dns_redirects(config: &FirewallConfig, zones: &ZoneFacts, groups: &GroupIndex) -> Vec<RuleSpec> {
    if !config.global_settings.force_local_dns {
        return Vec::new();
    }
    dns_enforcement_rules(
        config,
        zones,
        groups,
        DNS_PORT,
        &["udp", "tcp"],
        |conds, family, protocol| {
            builtin(
                SECTION_DNS_REDIRECT,
                &format!(
                    "Redirect LAN DNS to the router ({}, {protocol})",
                    family_name(family)
                ),
                conds,
                Verdict::Redirect { port: DNS_PORT },
            )
        },
    )
}

/// Reject DNS-over-TLS (TCP) and DNS-over-QUIC (UDP) from LAN clients to
/// outside servers, when `block_dns_over_tls` is set. Clients then fall back
/// to plain DNS. DNS-over-HTTPS shares port 443 with all web traffic and
/// cannot be told apart here.
fn dns_over_tls_rejects(
    config: &FirewallConfig,
    zones: &ZoneFacts,
    groups: &GroupIndex,
) -> Vec<RuleSpec> {
    if !config.global_settings.block_dns_over_tls {
        return Vec::new();
    }
    dns_enforcement_rules(
        config,
        zones,
        groups,
        DNS_OVER_TLS_PORT,
        &["tcp", "udp"],
        |conds, family, protocol| {
            builtin(
                SECTION_DOT_BLOCK,
                &format!(
                    "Reject LAN DNS-over-TLS ({}, {protocol})",
                    family_name(family)
                ),
                conds,
                Verdict::Reject,
            )
        },
    )
}

fn postrouting(config: &FirewallConfig, zones: &ZoneFacts, groups: &GroupIndex) -> ChainSpec {
    let mut rules = Vec::new();
    if config.global_settings.hairpin_nat_enabled && !zones.lan_interfaces.is_empty() {
        for pf in config.port_forwards.iter().filter(|pf| pf.enabled) {
            for &protocol in port_forward_protocols(pf.protocol) {
                rules.extend(hairpin_snat(pf, &zones.lan_interfaces, groups, protocol));
            }
        }
    }
    for zone in find_ipv4_masquerade_zones(&config.zones) {
        for interface in &zone.interfaces {
            rules.push(RuleSpec {
                origin: Origin::Builtin,
                comment: format!("Masquerade for {interface}"),
                section: SECTION_MASQUERADE,
                conds: vec![
                    Cond::Nfproto(Family::V4),
                    Cond::Oif(vec![interface.clone()]),
                ],
                log: None,
                verdict: Verdict::Masquerade,
            });
        }
    }
    ChainSpec {
        name: "postrouting",
        policy: None,
        rules,
    }
}

/// Masquerade hairpin traffic, so the internal server replies to the router and
/// not directly to the LAN client. Matches exactly the traffic the hairpin DNAT
/// redirects.
fn hairpin_snat(
    pf: &PortForward,
    lan_interfaces: &[String],
    groups: &GroupIndex,
    protocol: &'static str,
) -> Option<RuleSpec> {
    if lan_interfaces.is_empty() {
        return None;
    }
    pf.dest_ip.parse::<Ipv4Addr>().ok()?;
    let source = match port_forward_source(pf, groups) {
        Ok(source) => source,
        Err(error) => {
            tracing::warn!("Skipping hairpin SNAT for '{}': {error}", pf.name);
            return None;
        }
    };

    let mut conds = vec![
        Cond::Nfproto(Family::V4),
        Cond::Iif(lan_interfaces.to_vec()),
    ];
    conds.extend(source);
    conds.extend([
        Cond::L4(protocol),
        Cond::Addr {
            side: Side::Destination,
            addr: Addr::Literal(pf.dest_ip.clone()),
        },
        Cond::Port {
            side: Side::Destination,
            payload: "th",
            ports: match dnat_port(pf) {
                Some(port) => Ports::Single(port),
                None => Ports::literal(pf.external_port_start, pf.external_port_end),
            },
        },
    ]);

    Some(RuleSpec {
        origin: Origin::User {
            kind: "portfwd-hairpin-snat",
            id: pf.id,
            name: pf.name.clone(),
        },
        comment: rule_comment(
            "portfwd-hairpin-snat",
            pf.id,
            &format!("{} hairpin SNAT ({})", pf.name, protocol),
        ),
        section: SECTION_HAIRPIN_SNAT,
        conds,
        log: None,
        verdict: Verdict::Masquerade,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rate_limit_accepts_units_and_rejects_garbage() {
        assert_eq!(parse_rate_limit("10/minute"), Some((10, "minute")));
        assert_eq!(parse_rate_limit("100/SEC"), Some((100, "second")));
        assert_eq!(parse_rate_limit("5/h"), Some((5, "hour")));
        assert_eq!(parse_rate_limit("invalid"), None);
        assert_eq!(parse_rate_limit("10/fortnight"), None);
    }

    #[test]
    fn literal_ports_only_become_ranges_when_the_end_is_larger() {
        assert_eq!(Ports::literal(80, None), Ports::Single(80));
        assert_eq!(Ports::literal(80, Some(80)), Ports::Single(80));
        assert_eq!(Ports::literal(80, Some(90)), Ports::Range(80, 90));
    }

    #[test]
    fn range_without_dest_port_keeps_the_original_port() {
        let pf = PortForward {
            external_port_start: 5000,
            external_port_end: Some(5010),
            ..Default::default()
        };
        assert_eq!(dnat_port(&pf), None);
        let pf = PortForward {
            external_port_start: 8080,
            dest_port: Some(80),
            ..Default::default()
        };
        assert_eq!(dnat_port(&pf), Some(80));
    }

    #[test]
    fn log_prefix_carries_the_rule_tag_and_respects_the_kernel_limit() {
        assert_eq!(
            log_prefix("input", Some(12), "drop: "),
            "ks:input:12 drop: "
        );
        let long = log_prefix("forward", Some(3), &"x".repeat(300));
        assert_eq!(long.len(), MAX_LOG_PREFIX_BYTES);
        assert!(long.starts_with("ks:forward:3 "), "{long}");
        // Cutting never splits a character, so the result stays valid UTF-8.
        let wide = log_prefix("input", Some(1), &"é".repeat(200));
        assert!(wide.len() <= MAX_LOG_PREFIX_BYTES);
        assert!(wide.starts_with("ks:input:1 "));
    }

    #[test]
    fn log_prefix_neutralises_characters_that_break_the_log_line() {
        assert_eq!(
            log_prefix("input", None, "a=\"b\\c\n"),
            "ks:input:0 a__b_c_"
        );
    }

    #[test]
    fn logging_input_rule_prefix_is_tagged_with_its_id() {
        let config = FirewallConfig {
            input_rules: vec![InputRule {
                id: Some(12),
                name: "Drop scans".into(),
                log_enabled: true,
                log_prefix: Some("scan: ".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let ruleset = build(&config);
        let rule = ruleset
            .input
            .rules
            .iter()
            .find(|rule| rule.comment.starts_with("ks:input:12 "))
            .expect("the logging rule is modelled");
        assert_eq!(rule.log.as_deref(), Some("ks:input:12 scan: "));
    }

    fn pf_with(start: u16, end: Option<u16>, dest_port: Option<u16>) -> PortForward {
        PortForward {
            id: None,
            name: "pf".into(),
            enabled: true,
            protocol: RuleProtocol::Tcp,
            external_port_start: start,
            external_port_end: end,
            dest_ip: "192.168.1.10".into(),
            dest_port,
            ..Default::default()
        }
    }

    fn lan() -> Vec<String> {
        vec!["eth1".into()]
    }

    fn dnat_port_of(rule: &RuleSpec) -> Option<u16> {
        match rule.verdict {
            Verdict::Dnat { port, .. } => port,
            other => panic!("expected a DNAT verdict, got {other:?}"),
        }
    }

    #[test]
    fn explicit_destination_port_is_the_translated_port() {
        let zones = ZoneFacts::new(&[]);
        let groups = GroupIndex::default();
        let single = port_forward_dnat(&pf_with(8080, None, None), &zones, &groups, "tcp").unwrap();
        assert_eq!(dnat_port_of(&single), Some(8080));
        let explicit =
            port_forward_dnat(&pf_with(8080, None, Some(80)), &zones, &groups, "tcp").unwrap();
        assert_eq!(dnat_port_of(&explicit), Some(80));
        let hairpin = hairpin_dnat(&pf_with(8080, None, Some(80)), &lan(), &groups, "tcp").unwrap();
        assert_eq!(dnat_port_of(&hairpin), Some(80));
    }

    #[test]
    fn hairpin_dnat_excludes_router_addresses_on_the_ingress_interface() {
        let hairpin = hairpin_dnat(
            &pf_with(443, None, None),
            &lan(),
            &GroupIndex::default(),
            "tcp",
        )
        .unwrap();
        assert!(hairpin.conds.contains(&Cond::FibLocal));
        assert!(hairpin.conds.contains(&Cond::FibNotOnIngress));
        assert!(hairpin.conds.contains(&Cond::Iif(lan())));
    }

    #[test]
    fn hairpin_snat_matches_the_whole_range_when_the_port_is_preserved() {
        let pf = pf_with(5000, Some(5010), None);
        let snat = hairpin_snat(&pf, &lan(), &GroupIndex::default(), "tcp").unwrap();
        assert!(snat.conds.contains(&Cond::Port {
            side: Side::Destination,
            payload: "th",
            ports: Ports::Range(5000, 5010),
        }));
        assert_eq!(snat.verdict, Verdict::Masquerade);
    }

    #[test]
    fn hairpin_dnat_and_snat_honour_a_literal_source_restriction() {
        let pf = PortForward {
            source_ip: Some("198.51.100.0/24".into()),
            ..pf_with(27000, Some(27050), None)
        };
        let groups = GroupIndex::default();
        let restriction = Cond::Addr {
            side: Side::Source,
            addr: Addr::Literal("198.51.100.0/24".into()),
        };
        let dnat = hairpin_dnat(&pf, &lan(), &groups, "udp").unwrap();
        let snat = hairpin_snat(&pf, &lan(), &groups, "udp").unwrap();
        assert!(dnat.conds.contains(&restriction));
        assert!(snat.conds.contains(&restriction));
    }

    #[test]
    fn hairpin_dnat_and_snat_honour_a_group_source_restriction() {
        let pf = PortForward {
            source_group: Some("trusted".into()),
            ..pf_with(27000, None, None)
        };
        let address_groups = vec![keystone_core::AddressGroup {
            name: "trusted".into(),
            entries: vec!["198.51.100.0/24".into()],
            ..Default::default()
        }];
        let groups = GroupIndex::new(&address_groups, &[]);
        let restriction = Cond::Addr {
            side: Side::Source,
            addr: Addr::Group {
                name: "trusted".into(),
                family: Family::V4,
            },
        };
        assert!(
            hairpin_dnat(&pf, &lan(), &groups, "tcp")
                .unwrap()
                .conds
                .contains(&restriction)
        );
        assert!(
            hairpin_snat(&pf, &lan(), &groups, "tcp")
                .unwrap()
                .conds
                .contains(&restriction)
        );
    }

    #[test]
    fn hairpin_rules_are_skipped_for_a_source_group_without_ipv4() {
        let pf = PortForward {
            source_group: Some("v6_only".into()),
            ..pf_with(9000, None, None)
        };
        let address_groups = vec![keystone_core::AddressGroup {
            name: "v6_only".into(),
            entries: vec!["2001:db8::/32".into()],
            ..Default::default()
        }];
        let groups = GroupIndex::new(&address_groups, &[]);
        assert!(hairpin_dnat(&pf, &lan(), &groups, "tcp").is_none());
        assert!(hairpin_snat(&pf, &lan(), &groups, "tcp").is_none());
    }

    fn dns_config(force: bool, block_dot: bool, exempt: Option<&str>) -> FirewallConfig {
        let mut config = crate::firewall::fixtures::rich();
        config.global_settings.force_local_dns = force;
        config.global_settings.block_dns_over_tls = block_dot;
        config.global_settings.dns_exempt_group = exempt.map(str::to_string);
        config
    }

    fn in_section<'a>(chain: &'a ChainSpec, section: &str) -> Vec<&'a RuleSpec> {
        chain
            .rules
            .iter()
            .filter(|rule| rule.section == section)
            .collect()
    }

    #[test]
    fn dns_enforcement_is_off_by_default() {
        let ruleset = build(&dns_config(false, false, None));
        assert!(in_section(&ruleset.prerouting, SECTION_DNS_REDIRECT).is_empty());
        assert!(in_section(&ruleset.forward, SECTION_DOT_BLOCK).is_empty());
    }

    #[test]
    fn forced_dns_redirects_lan_dns_for_outside_hosts_in_both_families() {
        let config = dns_config(true, false, None);
        let zones = ZoneFacts::new(&config.zones);
        let ruleset = build(&config);
        let redirects = in_section(&ruleset.prerouting, SECTION_DNS_REDIRECT);
        for family in [Family::V4, Family::V6] {
            for protocol in ["udp", "tcp"] {
                assert!(redirects.iter().any(|rule| {
                    rule.conds.contains(&Cond::Nfproto(family))
                        && rule.conds.contains(&Cond::L4(protocol))
                }));
            }
        }
        for rule in &redirects {
            assert_eq!(rule.verdict, Verdict::Redirect { port: 53 });
            assert!(
                rule.conds
                    .contains(&Cond::Iif(zones.lan_interfaces.clone()))
            );
            assert!(rule.conds.contains(&Cond::FibNotLocal));
            assert!(rule.conds.contains(&Cond::Port {
                side: Side::Destination,
                payload: "th",
                ports: Ports::Single(53),
            }));
            assert!(
                !rule
                    .conds
                    .iter()
                    .any(|cond| matches!(cond, Cond::NotAddr { .. }))
            );
        }
    }

    #[test]
    fn dns_exemption_covers_both_sides_for_the_families_the_group_has() {
        let ruleset = build(&dns_config(true, true, Some("iot_hosts")));
        let exemption = |family| {
            [Side::Source, Side::Destination].map(|side| Cond::NotAddr {
                side,
                addr: Addr::Group {
                    name: "iot_hosts".into(),
                    family,
                },
            })
        };
        let rules = in_section(&ruleset.prerouting, SECTION_DNS_REDIRECT)
            .into_iter()
            .chain(in_section(&ruleset.forward, SECTION_DOT_BLOCK));
        for rule in rules {
            // iot_hosts only has IPv4 entries, so there is no IPv6 set to test.
            if rule.conds.contains(&Cond::Nfproto(Family::V4)) {
                for cond in exemption(Family::V4) {
                    assert!(rule.conds.contains(&cond));
                }
            } else {
                assert!(
                    !rule
                        .conds
                        .iter()
                        .any(|cond| matches!(cond, Cond::NotAddr { .. }))
                );
            }
        }
    }

    #[test]
    fn dns_over_tls_is_rejected_before_user_forward_rules() {
        let ruleset = build(&dns_config(false, true, None));
        let position = |section: &str| {
            ruleset
                .forward
                .rules
                .iter()
                .position(|rule| rule.section == section)
                .unwrap()
        };
        assert!(position(SECTION_DOT_BLOCK) < position(SECTION_USER_FORWARD));
        for rule in in_section(&ruleset.forward, SECTION_DOT_BLOCK) {
            assert_eq!(rule.verdict, Verdict::Reject);
            assert!(rule.conds.contains(&Cond::Port {
                side: Side::Destination,
                payload: "th",
                ports: Ports::Single(853),
            }));
        }
    }
}
