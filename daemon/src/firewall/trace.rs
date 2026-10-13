//! Packet tracing: what the firewall does to one packet.
//!
//! The trace walks the shared [`Ruleset`](crate::firewall::rules::Ruleset), the
//! same model the generator emits, in the same order: prerouting (port forward
//! DNAT, hairpin included), the routing decision, the input or forward chain,
//! then postrouting for forwarded packets. Each rule's conditions are checked
//! against this packet, so a step is exact for the packet's addresses, ports
//! and interfaces. What cannot be known from the configuration (connection
//! state, rate-limit counters, kernel behaviour) is stated in the notes.

use crate::firewall::groups::{Family, normalized_networks, normalized_ports};
use crate::firewall::rules::{self, Addr, ChainSpec, Cond, Origin, Ports, RuleSpec, Side, Verdict};
use ipnet::IpNet;
use keystone_core::{
    FirewallConfig, FirewallPolicy, RuleProtocol, TestPacketRequest, TestPacketResponse, TraceDnat,
    TraceOrigin, TraceStage, TraceStep, TraceVerdict,
};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

/// Layer-4 protocol of a traced packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PacketProtocol {
    /// Protocol not specified: rules that need a protocol cannot match.
    Any,
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
}

impl PacketProtocol {
    /// The `meta l4proto` name of the protocol, if it has one.
    fn l4(self) -> Option<&'static str> {
        match self {
            PacketProtocol::Any => None,
            PacketProtocol::Tcp => Some("tcp"),
            PacketProtocol::Udp => Some("udp"),
            PacketProtocol::Icmp => Some("icmp"),
            PacketProtocol::Icmpv6 => Some("ipv6-icmp"),
        }
    }
}

/// The interface a forwarded packet leaves through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Egress {
    /// Chosen by the routing table, for the destination after DNAT.
    Routing,
    /// Given by the request.
    Fixed(String),
}

/// A packet arriving at the router, fully described.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Packet {
    /// Interfaces the packet may arrive on: one interface, or a zone's.
    pub ingress: Vec<String>,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: PacketProtocol,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub icmp_type: Option<u8>,
    pub egress: Egress,
}

/// The router's own view of its addresses and default routes. It decides
/// whether a destination is local, and which interface a forwarded packet
/// leaves through.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RouterView {
    addresses: BTreeMap<String, Vec<IpNet>>,
    default_v4: Option<String>,
    default_v6: Option<String>,
}

impl RouterView {
    pub(crate) fn new(
        addresses: BTreeMap<String, Vec<IpNet>>,
        default_v4: Option<String>,
        default_v6: Option<String>,
    ) -> Self {
        Self {
            addresses,
            default_v4,
            default_v6,
        }
    }

    /// Whether `address` is one of the router's addresses (`fib daddr type local`).
    pub(crate) fn is_local(&self, address: IpAddr) -> bool {
        self.addresses
            .values()
            .flatten()
            .any(|net| net.addr() == address)
    }

    /// Whether `address` is assigned to one of `interfaces`.
    fn assigned_to(&self, address: IpAddr, interfaces: &[String]) -> bool {
        interfaces.iter().any(|interface| {
            self.addresses
                .get(interface)
                .is_some_and(|nets| nets.iter().any(|net| net.addr() == address))
        })
    }

    /// The interface a packet to `destination` leaves through: the interface
    /// whose subnet holds it, else the default route's interface.
    pub(crate) fn egress_for(&self, destination: IpAddr) -> Option<String> {
        self.addresses
            .iter()
            .find(|(_, nets)| nets.iter().any(|net| net.contains(&destination)))
            .map(|(name, _)| name.clone())
            .or_else(|| match destination {
                IpAddr::V4(_) => self.default_v4.clone(),
                IpAddr::V6(_) => self.default_v6.clone(),
            })
    }

    /// Build the view from `ip -j addr show` and the default-route output of
    /// `ip -j route show default` for each family.
    pub(crate) fn from_ip_json(
        addr_json: &[u8],
        default_v4_json: &[u8],
        default_v6_json: &[u8],
    ) -> Result<Self, serde_json::Error> {
        Ok(Self::new(
            parse_addresses(addr_json)?,
            parse_default_interface(default_v4_json)?,
            parse_default_interface(default_v6_json)?,
        ))
    }
}

#[derive(Deserialize)]
struct AddressEntry {
    ifname: String,
    #[serde(default)]
    addr_info: Vec<AddressInfo>,
}

#[derive(Deserialize)]
struct AddressInfo {
    local: Option<String>,
    prefixlen: Option<u8>,
}

#[derive(Deserialize)]
struct RouteEntry {
    dev: Option<String>,
}

/// Interface name to its addresses with prefix lengths. Entries that do not
/// parse are skipped.
pub(crate) fn parse_addresses(
    json: &[u8],
) -> Result<BTreeMap<String, Vec<IpNet>>, serde_json::Error> {
    let entries: Vec<AddressEntry> = serde_json::from_slice(json)?;
    Ok(entries
        .into_iter()
        .map(|entry| {
            let nets = entry
                .addr_info
                .iter()
                .filter_map(|info| {
                    let address: IpAddr = info.local.as_deref()?.parse().ok()?;
                    IpNet::new(address, info.prefixlen?).ok()
                })
                .collect();
            (entry.ifname, nets)
        })
        .collect())
}

/// Interface of the first default route in `ip -j route show default` output.
pub(crate) fn parse_default_interface(json: &[u8]) -> Result<Option<String>, serde_json::Error> {
    let routes: Vec<RouteEntry> = serde_json::from_slice(json)?;
    Ok(routes.into_iter().find_map(|route| route.dev))
}

/// Read the router's live addresses and default routes with `ip`. Each
/// command runs with an argument vector and no shell.
pub(crate) async fn live_view() -> anyhow::Result<RouterView> {
    use anyhow::Context;
    use std::process::Stdio;
    use tokio::process::Command;

    async fn ip(args: &[&str]) -> anyhow::Result<Vec<u8>> {
        let output = Command::new("ip")
            .args(args)
            .stdin(Stdio::null())
            .output()
            .await
            .with_context(|| format!("failed to run ip {}", args.join(" ")))?;
        anyhow::ensure!(
            output.status.success(),
            "ip {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(output.stdout)
    }

    let addresses = ip(&["-j", "addr", "show"]).await?;
    // A missing default route is normal (a router without an IPv6 uplink), so
    // a failed route lookup means no default route rather than an error.
    let default_v4 = ip(&["-j", "-4", "route", "show", "default"])
        .await
        .unwrap_or_default();
    let default_v6 = ip(&["-j", "-6", "route", "show", "default"])
        .await
        .unwrap_or_default();
    Ok(RouterView::from_ip_json(
        &addresses,
        &default_v4,
        &default_v6,
    )?)
}

/// Where the packet is, as the trace moves it through the pipeline.
#[derive(Clone)]
struct Flow {
    destination: IpAddr,
    destination_port: Option<u16>,
    dnat: Option<(Ipv4Addr, Option<u16>)>,
    /// Outgoing interface, known once the destination is (after DNAT).
    egress: Option<String>,
}

struct Context<'a> {
    config: &'a FirewallConfig,
    view: &'a RouterView,
    packet: &'a Packet,
}

/// Trace `packet` through `config`, with the router's addresses in `view`.
/// The baseline fields of the response are left at their saved-configuration
/// values for the caller to set.
pub(crate) fn trace(
    config: &FirewallConfig,
    view: &RouterView,
    packet: &Packet,
) -> TestPacketResponse {
    let ruleset = rules::build(config);
    let ctx = Context {
        config,
        view,
        packet,
    };
    let mut flow = Flow {
        destination: packet.destination,
        destination_port: packet.destination_port,
        dnat: None,
        egress: None,
    };
    let mut steps = Vec::new();

    if let Some(Verdict::Dnat { addr, port }) = run_chain(
        &ruleset.prerouting,
        TraceStage::Prerouting,
        &ctx,
        &flow,
        &mut steps,
    ) {
        flow.destination = IpAddr::V4(addr);
        flow.destination_port = port.or(flow.destination_port);
        flow.dnat = Some((addr, port));
    }

    // Routing sees the destination after DNAT, so the egress is chosen here.
    flow.egress = match &packet.egress {
        Egress::Fixed(interface) => Some(interface.clone()),
        Egress::Routing => view.egress_for(flow.destination),
    };
    let local = view.is_local(flow.destination);
    let path = if local {
        TraceStage::Input
    } else {
        TraceStage::Forward
    };
    steps.push(TraceStep {
        stage: TraceStage::Routing,
        origin: TraceOrigin::Routing,
        label: "Routing decision".to_string(),
        matched: true,
        decisive: false,
        reason: if local {
            format!("{} is a router address: input chain", flow.destination)
        } else {
            format!(
                "{} is not a router address: forward chain",
                flow.destination
            )
        },
    });

    let chain = if local {
        &ruleset.input
    } else {
        &ruleset.forward
    };
    let verdict = match run_chain(chain, path, &ctx, &flow, &mut steps) {
        Some(Verdict::Accept) => Verdict::Accept,
        Some(Verdict::Reject) => Verdict::Reject,
        _ => Verdict::Drop,
    };

    // Source NAT happens after routing, and only for packets that are
    // forwarded and accepted.
    let masquerade = !local
        && verdict == Verdict::Accept
        && matches!(
            run_chain(
                &ruleset.postrouting,
                TraceStage::Postrouting,
                &ctx,
                &flow,
                &mut steps
            ),
            Some(Verdict::Masquerade)
        );

    TestPacketResponse {
        baseline: "saved".to_string(),
        applied_snapshot_id: None,
        ingress: packet.ingress.clone(),
        egress: if path == TraceStage::Forward {
            flow.egress.clone()
        } else {
            None
        },
        path,
        dnat: flow.dnat.map(|(addr, port)| TraceDnat {
            address: addr.to_string(),
            port,
        }),
        masquerade,
        steps,
        verdict: match verdict {
            Verdict::Accept => TraceVerdict::Accept,
            Verdict::Reject => TraceVerdict::Reject,
            _ => TraceVerdict::Drop,
        },
        notes: notes(config, flow.egress.as_deref(), path),
    }
}

/// Evaluate `chain` against the packet. Appends one step per rule up to the
/// first match, then the chain policy if nothing matched. Returns the verdict
/// that ended the chain, or `None` when the chain has no policy and no rule
/// matched.
fn run_chain(
    chain: &ChainSpec,
    stage: TraceStage,
    ctx: &Context,
    flow: &Flow,
    steps: &mut Vec<TraceStep>,
) -> Option<Verdict> {
    for rule in &chain.rules {
        let (matched, reason) = match evaluate_rule(rule, ctx, flow) {
            Ok(reason) => (true, reason),
            Err(reason) => (false, reason),
        };
        steps.push(TraceStep {
            stage,
            origin: trace_origin(&rule.origin),
            label: rule_label(rule),
            matched,
            decisive: matched,
            reason,
        });
        if matched {
            return Some(rule.verdict);
        }
    }
    let policy = chain.policy?;
    steps.push(TraceStep {
        stage,
        origin: TraceOrigin::ChainPolicy,
        label: format!("{} chain policy", chain.name),
        matched: true,
        decisive: true,
        reason: format!(
            "no rule matched; the chain policy is {}",
            verdict_word(policy)
        ),
    });
    Some(policy)
}

/// Check every condition of a rule. `Ok` carries what matched, `Err` the first
/// condition that failed.
fn evaluate_rule(rule: &RuleSpec, ctx: &Context, flow: &Flow) -> Result<String, String> {
    let mut matched = Vec::with_capacity(rule.conds.len());
    for cond in &rule.conds {
        matched.push(evaluate_cond(cond, ctx, flow)?);
    }
    let mut reason = if matched.is_empty() {
        "matches every packet".to_string()
    } else {
        matched.join(", ")
    };
    if rule.log.is_some() {
        reason.push_str(" (logged)");
    }
    Ok(reason)
}

fn evaluate_cond(cond: &Cond, ctx: &Context, flow: &Flow) -> Result<String, String> {
    let packet = ctx.packet;
    match cond {
        Cond::Iif(names) => {
            let arrives = packet.ingress.join("/");
            if packet.ingress.iter().any(|name| names.contains(name)) {
                Ok(format!("arrives on {arrives}"))
            } else {
                Err(format!("arrives on {arrives}, not {}", names.join("/")))
            }
        }
        Cond::Oif(names) => match &flow.egress {
            Some(egress) if names.contains(egress) => Ok(format!("leaves via {egress}")),
            Some(egress) => Err(format!("leaves via {egress}, not {}", names.join("/"))),
            None => Err("the outgoing interface is unknown".to_string()),
        },
        Cond::Nfproto(family) => {
            let is_v4 = packet.source.is_ipv4();
            match (family, is_v4) {
                (Family::V4, true) | (Family::V6, false) => {
                    Ok(format!("packet is IPv{}", if is_v4 { 4 } else { 6 }))
                }
                _ => Err(format!(
                    "packet is IPv{}, not IPv{}",
                    if is_v4 { 4 } else { 6 },
                    if *family == Family::V4 { 4 } else { 6 }
                )),
            }
        }
        Cond::Addr { side, addr } => {
            let (field, address) = match side {
                Side::Source => ("source", packet.source),
                Side::Destination => ("destination", flow.destination),
            };
            match addr {
                Addr::Literal(text) => {
                    let network = parse_network(text)?;
                    if network.contains(&address) {
                        Ok(format!("{field} {address} is in {text}"))
                    } else {
                        Err(format!("{field} {address} is not in {text}"))
                    }
                }
                Addr::Group { name, family } => {
                    let networks = group_networks(ctx.config, name, *family);
                    if networks.iter().any(|net| net.contains(&address)) {
                        Ok(format!("{field} {address} is in group {name}"))
                    } else {
                        Err(format!("{field} {address} is not in group {name}"))
                    }
                }
            }
        }
        Cond::L4(protocol) => match packet.protocol.l4() {
            Some(actual) if actual == *protocol => Ok(format!("protocol {protocol}")),
            Some(actual) => Err(format!("protocol is {actual}, not {protocol}")),
            None => Err(format!("protocol is unspecified, not {protocol}")),
        },
        Cond::Port {
            side,
            payload,
            ports,
        } => {
            let protocol = packet.protocol.l4();
            if *payload == "udp" && protocol != Some("udp") {
                return Err("packet is not UDP".to_string());
            }
            if *payload == "th" && !matches!(protocol, Some("tcp" | "udp")) {
                return Err("packet has no TCP or UDP ports".to_string());
            }
            let (field, value) = match side {
                Side::Source => ("source port", packet.source_port),
                Side::Destination => ("destination port", flow.destination_port),
            };
            let value = value.ok_or_else(|| format!("packet has no {field}"))?;
            let matches = match ports {
                Ports::Single(port) => value == *port,
                Ports::Range(start, end) => (*start..=*end).contains(&value),
                Ports::Group(group) => port_group_ranges(ctx.config, group)
                    .iter()
                    .any(|(start, end)| (*start..=*end).contains(&value)),
            };
            let wanted = match ports {
                Ports::Single(port) => port.to_string(),
                Ports::Range(start, end) => format!("{start}-{end}"),
                Ports::Group(group) => format!("port group {group}"),
            };
            if matches {
                Ok(format!("{field} {value} is in {wanted}"))
            } else {
                Err(format!("{field} {value} is not in {wanted}"))
            }
        }
        Cond::IcmpType { v6, icmp_type } => {
            let needed = if *v6 {
                PacketProtocol::Icmpv6
            } else {
                PacketProtocol::Icmp
            };
            if packet.protocol != needed {
                return Err(format!("packet is not {}", protocol_name(needed)));
            }
            let default = if *v6 { 128 } else { 8 };
            let actual = packet.icmp_type.unwrap_or(default);
            if actual == *icmp_type {
                Ok(format!("ICMP type {actual}"))
            } else {
                Err(format!("ICMP type {actual} is not {icmp_type}"))
            }
        }
        // Connection state is not tracked: every traced packet starts a new
        // connection, which is neither established nor related nor invalid.
        Cond::CtStateIn(states) => Err(format!(
            "packet starts a new connection, not {} (conntrack state not modelled)",
            states.join(" or ")
        )),
        Cond::CtStateIs(state) => Err(format!(
            "packet starts a new connection, not {state} (conntrack state not modelled)"
        )),
        Cond::CtDnat => match flow.dnat {
            Some(_) => Ok("translated by a port forward".to_string()),
            None => Err("not translated by a port forward".to_string()),
        },
        Cond::FibLocal => {
            if ctx.view.is_local(flow.destination) {
                Ok(format!("{} is a router address", flow.destination))
            } else {
                Err(format!("{} is not a router address", flow.destination))
            }
        }
        Cond::FibNotOnIngress => {
            if ctx.view.assigned_to(flow.destination, &packet.ingress) {
                Err(format!("{} is on the ingress interface", flow.destination))
            } else {
                Ok(format!(
                    "{} is not on the ingress interface",
                    flow.destination
                ))
            }
        }
        Cond::RateLimit { rate, per } => Ok(format!(
            "within {rate}/{per} (rate limit assumed not exceeded)"
        )),
    }
}

fn trace_origin(origin: &Origin) -> TraceOrigin {
    match origin {
        Origin::Builtin | Origin::Upnp => TraceOrigin::Builtin,
        Origin::Policy => TraceOrigin::Policy,
        Origin::User { kind, id, .. } => TraceOrigin::User {
            rule_kind: (*kind).to_string(),
            rule_id: *id,
        },
    }
}

/// The user's name for a user rule; the description for built-in and policy rules.
fn rule_label(rule: &RuleSpec) -> String {
    match &rule.origin {
        Origin::User { name, .. } => name.clone(),
        Origin::Upnp => "UPnP / NAT-PMP mappings (accepted DNAT traffic)".to_string(),
        Origin::Builtin | Origin::Policy => rule.comment.clone(),
    }
}

fn verdict_word(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Accept => "accept",
        Verdict::Drop => "drop",
        Verdict::Reject => "reject",
        Verdict::Dnat { .. } => "dnat",
        Verdict::Masquerade => "masquerade",
    }
}

fn protocol_name(protocol: PacketProtocol) -> &'static str {
    match protocol {
        PacketProtocol::Any => "any protocol",
        PacketProtocol::Tcp => "TCP",
        PacketProtocol::Udp => "UDP",
        PacketProtocol::Icmp => "ICMP",
        PacketProtocol::Icmpv6 => "ICMPv6",
    }
}

/// Networks of a group for one family, as the generated set holds them.
fn group_networks(config: &FirewallConfig, name: &str, family: Family) -> Vec<IpNet> {
    config
        .address_groups
        .iter()
        .find(|group| group.name == name)
        .map(|group| normalized_networks(&group.entries, family))
        .unwrap_or_default()
}

/// Port ranges of a group, as the generated set holds them.
fn port_group_ranges(config: &FirewallConfig, name: &str) -> Vec<(u16, u16)> {
    config
        .port_groups
        .iter()
        .find(|group| group.name == name)
        .map(|group| normalized_ports(&group.entries))
        .unwrap_or_default()
}

fn parse_network(text: &str) -> Result<IpNet, String> {
    if text.contains('/') {
        IpNet::from_str(text).map_err(|error| format!("{text}: {error}"))
    } else {
        let address = IpAddr::from_str(text).map_err(|error| format!("{text}: {error}"))?;
        let prefix = if address.is_ipv4() { 32 } else { 128 };
        IpNet::new(address, prefix).map_err(|error| format!("{text}: {error}"))
    }
}

/// What the simulation cannot model, and facts that shape the verdict.
fn notes(config: &FirewallConfig, egress: Option<&str>, path: TraceStage) -> Vec<String> {
    let mut notes = vec![
        "Connections are treated as new: established/related accepts never match and invalid-state drops never apply. Replies to outbound traffic are not simulated.".to_string(),
        "Rate limits are assumed not to be exceeded, so a rate-limited rule accepts every packet it matches.".to_string(),
        "Logging does not change the verdict.".to_string(),
        "Traffic the router originates, and the output chain, are not simulated.".to_string(),
    ];
    if path == TraceStage::Forward && egress.is_none() {
        notes.push(
            "The outgoing interface is unknown, so rules that match on it cannot match."
                .to_string(),
        );
    }
    if config.upnp_forward.is_some() {
        notes.push("UPnP / NAT-PMP is enabled. The mappings are made by miniupnpd, whose table is not modelled: a UPnP-mapped connection is accepted here only if this trace also DNATs it through a rule above.".to_string());
    }
    if config.zones.iter().any(|zone| {
        zone.default_forward_policy == FirewallPolicy::Accept && !zone.interfaces.is_empty()
    }) {
        notes.push("A zone's default forward policy of accept is stored but not generated: traffic that no forward rule accepts is dropped by the forward chain's policy.".to_string());
    }
    notes
}

/// Validate a request at the daemon boundary and build the packet it describes.
/// Errors are returned as messages for the client.
pub(crate) fn packet_from_request(
    request: &TestPacketRequest,
    config: &FirewallConfig,
) -> Result<Packet, String> {
    use keystone_core::validation::interface_name;

    let ingress = match (&request.ingress_interface, &request.ingress_zone) {
        (Some(interface), None) => {
            interface_name(interface)?;
            vec![interface.clone()]
        }
        (None, Some(zone)) => {
            let zone_def = config
                .zones
                .iter()
                .find(|candidate| &candidate.name == zone)
                .ok_or_else(|| format!("zone '{zone}' does not exist"))?;
            if zone_def.interfaces.is_empty() {
                return Err(format!("zone '{zone}' has no interfaces"));
            }
            zone_def.interfaces.clone()
        }
        _ => return Err("set exactly one of ingress_interface and ingress_zone".to_string()),
    };

    let source = parse_address("source_ip", &request.source_ip)?;
    let destination = parse_address("destination_ip", &request.destination_ip)?;
    if source.is_ipv4() != destination.is_ipv4() {
        return Err("source and destination must be the same IP version".to_string());
    }

    let protocol = match request.protocol {
        RuleProtocol::Any => PacketProtocol::Any,
        RuleProtocol::Tcp => PacketProtocol::Tcp,
        RuleProtocol::Udp => PacketProtocol::Udp,
        RuleProtocol::Icmp => PacketProtocol::Icmp,
        RuleProtocol::Icmpv6 => PacketProtocol::Icmpv6,
        RuleProtocol::TcpUdp => {
            return Err("a packet has one protocol: choose tcp or udp".to_string());
        }
    };
    match protocol {
        PacketProtocol::Tcp | PacketProtocol::Udp => {
            if request.destination_port.is_none() {
                return Err("tcp and udp packets need a destination port".to_string());
            }
        }
        _ => {
            if request.destination_port.is_some() || request.source_port.is_some() {
                return Err("ports apply only to tcp and udp packets".to_string());
            }
        }
    }
    if [request.source_port, request.destination_port]
        .iter()
        .flatten()
        .any(|port| *port == 0)
    {
        return Err("ports start at 1".to_string());
    }
    if request.icmp_type.is_some()
        && !matches!(protocol, PacketProtocol::Icmp | PacketProtocol::Icmpv6)
    {
        return Err("icmp_type applies only to icmp and icmpv6 packets".to_string());
    }
    match protocol {
        PacketProtocol::Icmp if destination.is_ipv6() => {
            return Err("icmp packets are IPv4: use icmpv6 for IPv6".to_string());
        }
        PacketProtocol::Icmpv6 if destination.is_ipv4() => {
            return Err("icmpv6 packets are IPv6: use icmp for IPv4".to_string());
        }
        _ => {}
    }

    let egress = match &request.egress_interface {
        Some(interface) => {
            interface_name(interface)?;
            Egress::Fixed(interface.clone())
        }
        None => Egress::Routing,
    };

    Ok(Packet {
        ingress,
        source,
        destination,
        protocol,
        source_port: request.source_port,
        destination_port: request.destination_port,
        icmp_type: request.icmp_type,
        egress,
    })
}

fn parse_address(field: &str, text: &str) -> Result<IpAddr, String> {
    text.trim()
        .parse()
        .map_err(|_| format!("{field} '{text}' is not an IP address"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::fixtures::{rich, rich_quiet, sample_configs};
    use keystone_core::{FirewallAction, InputRule, RuleProtocol};

    fn net(text: &str) -> IpNet {
        text.parse().unwrap()
    }

    /// The router of the `rich` fixture: WAN eth0, LAN eth1 and eth2, DMZ eth3,
    /// IoT eth4, plus loopback.
    fn view() -> RouterView {
        RouterView::new(
            BTreeMap::from([
                ("lo".to_string(), vec![net("127.0.0.1/8"), net("::1/128")]),
                (
                    "eth0".to_string(),
                    vec![net("203.0.113.5/24"), net("2001:db8:ffff::1/64")],
                ),
                ("eth1".to_string(), vec![net("192.168.1.1/24")]),
                ("eth2".to_string(), vec![net("10.20.0.1/16")]),
                ("eth3".to_string(), vec![net("192.168.60.1/24")]),
                ("eth4".to_string(), vec![net("192.168.50.1/24")]),
            ]),
            Some("eth0".to_string()),
            Some("eth0".to_string()),
        )
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    /// A packet from `ingress` to `destination`, with its egress as the live
    /// routing table would choose it.
    fn packet(
        ingress: &str,
        source: &str,
        destination: &str,
        protocol: PacketProtocol,
        destination_port: Option<u16>,
    ) -> Packet {
        let destination = ip(destination);
        Packet {
            ingress: vec![ingress.to_string()],
            source: ip(source),
            destination,
            protocol,
            source_port: None,
            destination_port,
            icmp_type: None,
            egress: Egress::Routing,
        }
    }

    fn tcp(ingress: &str, source: &str, destination: &str, port: u16) -> Packet {
        packet(
            ingress,
            source,
            destination,
            PacketProtocol::Tcp,
            Some(port),
        )
    }

    fn udp(ingress: &str, source: &str, destination: &str, port: u16) -> Packet {
        packet(
            ingress,
            source,
            destination,
            PacketProtocol::Udp,
            Some(port),
        )
    }

    fn icmp(ingress: &str, source: &str, destination: &str, icmp_type: Option<u8>) -> Packet {
        Packet {
            icmp_type,
            ..packet(ingress, source, destination, PacketProtocol::Icmp, None)
        }
    }

    fn run(config: &FirewallConfig, packet: &Packet) -> TestPacketResponse {
        trace(config, &view(), packet)
    }

    /// The step that ended the trace: the last step, which is decisive.
    fn decisive(response: &TestPacketResponse) -> &TraceStep {
        response
            .steps
            .iter()
            .rev()
            .find(|step| step.decisive)
            .expect("every trace ends in a decisive step")
    }

    fn label_of(response: &TestPacketResponse) -> &str {
        &decisive(response).label
    }

    /// The decision of the input or forward chain. Postrouting may decide
    /// after it, so `decisive` is not the verdict's rule for forwarded traffic.
    fn chain_decision(response: &TestPacketResponse, stage: TraceStage) -> &TraceStep {
        response
            .steps
            .iter()
            .rev()
            .find(|step| step.decisive && step.stage == stage)
            .expect("the chain decides the packet")
    }

    #[test]
    fn lan_client_reaches_ssh_on_the_router_through_its_user_rule() {
        let response = run(&rich(), &tcp("eth1", "192.168.1.20", "192.168.1.1", 22));
        assert_eq!(response.verdict, TraceVerdict::Accept);
        assert_eq!(response.path, TraceStage::Input);
        assert_eq!(label_of(&response), "Allow SSH from LAN");
        assert!(response.dnat.is_none());
    }

    #[test]
    fn lan_zone_default_accepts_other_ports_to_the_router() {
        let response = run(&rich(), &udp("eth1", "192.168.1.20", "192.168.1.1", 5353));
        assert_eq!(response.verdict, TraceVerdict::Accept);
        assert!(matches!(decisive(&response).origin, TraceOrigin::Policy));
    }

    #[test]
    fn iot_host_is_dropped_by_the_zero_position_rule_even_though_listed_later() {
        let response = run(&rich(), &tcp("eth4", "192.168.50.10", "192.168.50.1", 22));
        assert_eq!(response.verdict, TraceVerdict::Drop);
        assert_eq!(label_of(&response), "Drop IoT to router");
        // The position 0 rule ends the chain before the position 1 rule is reached.
        assert!(
            response
                .steps
                .iter()
                .all(|step| step.label != "Allow SSH from LAN"),
            "{:?}",
            response.steps
        );
    }

    #[test]
    fn wan_traffic_to_the_router_is_denied_by_default() {
        let response = run(&rich(), &tcp("eth0", "198.51.100.7", "203.0.113.5", 23));
        assert_eq!(response.verdict, TraceVerdict::Drop);
        assert!(matches!(
            decisive(&response).origin,
            TraceOrigin::ChainPolicy
        ));
    }

    #[test]
    fn rate_limited_wan_ssh_is_accepted_and_says_so() {
        let response = run(&rich(), &tcp("eth0", "198.51.100.7", "203.0.113.5", 22));
        assert_eq!(response.verdict, TraceVerdict::Accept);
        assert_eq!(label_of(&response), "Limited SSH from WAN");
        assert!(
            response
                .notes
                .iter()
                .any(|note| note.contains("Rate limits are assumed")),
            "{:?}",
            response.notes
        );
    }

    #[test]
    fn wan_echo_request_follows_the_ping_setting() {
        let on = run(&rich(), &icmp("eth0", "198.51.100.7", "203.0.113.5", None));
        assert_eq!(on.verdict, TraceVerdict::Accept);
        assert_eq!(label_of(&on), "Allow IPv4 ping from wan (WAN)");

        let off = run(
            &rich_quiet(),
            &icmp("eth0", "198.51.100.7", "203.0.113.5", None),
        );
        assert_eq!(off.verdict, TraceVerdict::Drop);
    }

    #[test]
    fn user_rule_drops_lan_ping_before_the_built_in_ping_accept() {
        let response = run(&rich(), &icmp("eth1", "192.168.1.20", "192.168.1.1", None));
        assert_eq!(response.verdict, TraceVerdict::Drop);
        assert_eq!(label_of(&response), "Drop LAN ping");
    }

    #[test]
    fn dangerous_icmp_is_dropped_even_when_a_user_rule_accepts_everything() {
        let mut config = rich();
        config.input_rules.push(InputRule {
            id: Some(99),
            name: "Accept all ICMP".into(),
            enabled: true,
            position: -5,
            protocol: Some(RuleProtocol::Icmp),
            action: FirewallAction::Accept,
            ..Default::default()
        });
        for sender in [
            ("eth1", "192.168.1.20", "192.168.1.1"),
            ("eth0", "198.51.100.7", "203.0.113.5"),
            ("eth4", "192.168.50.10", "192.168.50.1"),
        ] {
            for icmp_type in [5, 13, 14, 17, 18] {
                let response = run(
                    &config,
                    &icmp(sender.0, sender.1, sender.2, Some(icmp_type)),
                );
                assert_eq!(
                    response.verdict,
                    TraceVerdict::Drop,
                    "type {icmp_type} from {}",
                    sender.1
                );
                assert!(matches!(decisive(&response).origin, TraceOrigin::Builtin));
            }
        }
    }

    #[test]
    fn loopback_traffic_to_a_router_address_is_accepted() {
        let response = run(&rich(), &tcp("lo", "127.0.0.1", "127.0.0.1", 9999));
        assert_eq!(response.verdict, TraceVerdict::Accept);
        assert_eq!(label_of(&response), "Accept loopback");
    }

    #[test]
    fn dhcpv6_server_replies_on_wan_are_accepted_before_the_invalid_drop() {
        let mut packet = udp("eth0", "2001:db8:ffff::2", "2001:db8:ffff::1", 546);
        packet.source_port = Some(547);
        let response = run(&rich(), &packet);
        assert_eq!(response.verdict, TraceVerdict::Accept);
        assert_eq!(label_of(&response), "Allow DHCPv6 server replies on WAN");
    }

    #[test]
    fn mixed_group_grants_ntp_per_family_only() {
        let accepted = run(
            &rich(),
            &udp("eth0", "2001:db8:1::5", "2001:db8:ffff::1", 123),
        );
        assert_eq!(accepted.verdict, TraceVerdict::Accept);
        assert_eq!(label_of(&accepted), "Mixed group NTP");

        let refused = run(
            &rich(),
            &udp("eth0", "2001:db8:2::5", "2001:db8:ffff::1", 123),
        );
        assert_eq!(refused.verdict, TraceVerdict::Drop);
    }

    #[test]
    fn dmz_admin_port_rejects_the_listed_source_and_drops_others() {
        let listed = run(&rich(), &tcp("eth3", "192.168.50.7", "192.168.60.1", 8443));
        assert_eq!(listed.verdict, TraceVerdict::Reject);
        assert_eq!(label_of(&listed), "Reject DMZ admin");

        let other = run(&rich(), &tcp("eth3", "192.168.60.9", "192.168.60.1", 8443));
        assert_eq!(other.verdict, TraceVerdict::Drop);
    }

    #[test]
    fn lan_to_internet_is_forwarded_and_masqueraded_on_wan() {
        let response = run(&rich(), &tcp("eth1", "192.168.1.20", "1.1.1.1", 443));
        assert_eq!(response.path, TraceStage::Forward);
        assert_eq!(response.verdict, TraceVerdict::Accept);
        assert_eq!(response.egress.as_deref(), Some("eth0"));
        assert!(response.masquerade);
        assert_eq!(
            chain_decision(&response, TraceStage::Forward).label,
            "lan -> wan: accept"
        );
    }

    #[test]
    fn lan_to_dmz_is_rejected_by_the_zone_policy() {
        let response = run(&rich(), &tcp("eth1", "192.168.1.20", "192.168.60.10", 80));
        assert_eq!(response.verdict, TraceVerdict::Reject);
        assert_eq!(label_of(&response), "lan -> dmz: reject");
    }

    #[test]
    fn iot_to_lan_is_dropped_by_the_forward_rule() {
        let response = run(&rich(), &tcp("eth4", "192.168.50.10", "192.168.1.20", 80));
        assert_eq!(response.verdict, TraceVerdict::Drop);
        assert_eq!(label_of(&response), "IoT to LAN");
        assert!(matches!(
            decisive(&response).origin,
            TraceOrigin::User { ref rule_kind, .. } if rule_kind == "forward"
        ));
    }

    #[test]
    fn port_forward_translates_wan_traffic_and_its_accept_applies() {
        let response = run(&rich(), &tcp("eth0", "198.51.100.7", "203.0.113.5", 8080));
        assert_eq!(response.verdict, TraceVerdict::Accept);
        assert_eq!(
            response.dnat,
            Some(TraceDnat {
                address: "192.168.1.100".to_string(),
                port: Some(80),
            })
        );
        assert_eq!(response.path, TraceStage::Forward);
        assert_eq!(chain_decision(&response, TraceStage::Forward).label, "Web");
        assert!(matches!(
            chain_decision(&response, TraceStage::Forward).origin,
            TraceOrigin::User { ref rule_kind, .. } if rule_kind == "portfwd-accept"
        ));
        assert!(!response.masquerade);
    }

    #[test]
    fn range_port_forward_keeps_the_original_port() {
        let response = run(&rich(), &udp("eth0", "198.51.100.9", "203.0.113.5", 27010));
        assert_eq!(response.verdict, TraceVerdict::Accept);
        assert_eq!(
            response.dnat,
            Some(TraceDnat {
                address: "192.168.1.50".to_string(),
                port: None,
            })
        );
    }

    #[test]
    fn port_forward_source_restriction_applies_on_wan() {
        let response = run(&rich(), &udp("eth0", "203.0.113.9", "203.0.113.5", 27010));
        assert!(response.dnat.is_none());
        assert_eq!(response.verdict, TraceVerdict::Drop);
    }

    #[test]
    fn hairpin_nat_lets_lan_clients_reach_a_forward_through_the_wan_address() {
        let response = run(&rich(), &tcp("eth1", "192.168.1.20", "203.0.113.5", 8080));
        assert_eq!(response.verdict, TraceVerdict::Accept);
        assert_eq!(
            response.dnat,
            Some(TraceDnat {
                address: "192.168.1.100".to_string(),
                port: Some(80),
            })
        );
        assert!(response.masquerade, "hairpin SNAT applies");
    }

    /// A LAN client the source-restricted forward excludes must not be
    /// redirected by hairpin NAT (regression for the source restriction fix).
    #[test]
    fn hairpin_nat_respects_the_forward_source_restriction() {
        let response = run(&rich(), &udp("eth1", "192.168.1.20", "203.0.113.5", 27010));
        assert!(response.dnat.is_none());
        assert_eq!(response.path, TraceStage::Input);
        assert!(!response.masquerade);
        // The hairpin rule of the forward is the one that reaches the source check.
        let hairpin = response
            .steps
            .iter()
            .find(|step| step.label == "Game" && step.reason.contains("source 192.168.1.20"))
            .expect("the hairpin rule is evaluated");
        assert!(!hairpin.matched);
        assert!(
            hairpin.reason.contains("is not in 198.51.100.0/24"),
            "{}",
            hairpin.reason
        );
    }

    #[test]
    fn source_group_forward_is_reachable_from_its_members_on_any_interface() {
        let response = run(&rich(), &udp("eth4", "192.168.50.10", "203.0.113.5", 2222));
        assert_eq!(response.verdict, TraceVerdict::Accept);
        assert_eq!(
            response.dnat,
            Some(TraceDnat {
                address: "192.168.1.20".to_string(),
                port: Some(22),
            })
        );
    }

    #[test]
    fn disabled_and_invalid_rules_never_appear_in_a_trace() {
        let response = run(&rich(), &tcp("eth1", "192.168.1.20", "1.1.1.1", 443));
        for step in &response.steps {
            assert!(
                !matches!(
                    step.label.as_str(),
                    "Disabled rule" | "Disabled forward" | "Invalid rate" | "Unknown zone"
                ),
                "{step:?}"
            );
        }
    }

    #[test]
    fn unknown_egress_cannot_match_zone_policies() {
        // With no routes at all, a forwarded packet has no known egress.
        let packet = tcp("eth1", "192.168.1.20", "1.1.1.1", 443);
        let response = trace(&rich(), &RouterView::default(), &packet);
        assert_eq!(response.verdict, TraceVerdict::Drop);
        assert!(
            response
                .steps
                .iter()
                .any(|step| step.reason.contains("outgoing interface is unknown"))
        );
    }

    /// The UPnP accept matches only DNATed packets. For an ordinary forwarded
    /// packet the step is listed and reported as not matched, and the trace says
    /// that miniupnpd's mappings are not modelled.
    #[test]
    fn upnp_accept_matches_only_dnated_packets_and_says_so() {
        let config = crate::firewall::fixtures::rich_upnp();
        // Leaves through the LAN, so the UPnP interface match holds and only the DNAT condition can fail.
        let response = run(&config, &tcp("eth0", "198.51.100.7", "192.168.1.77", 80));
        let upnp = response
            .steps
            .iter()
            .find(|step| step.label.starts_with("UPnP"))
            .expect("the UPnP accept is evaluated");
        assert!(!upnp.matched);
        assert!(
            upnp.reason.contains("not translated by a port forward"),
            "{}",
            upnp.reason
        );
        assert!(response.notes.iter().any(|note| note.contains("miniupnpd")));
    }

    #[test]
    fn upnp_note_is_absent_when_upnp_is_disabled() {
        let response = run(&rich(), &tcp("eth0", "198.51.100.7", "1.1.1.1", 443));
        assert!(
            response
                .notes
                .iter()
                .all(|note| !note.contains("miniupnpd"))
        );
        assert!(
            response
                .steps
                .iter()
                .all(|step| !step.label.starts_with("UPnP"))
        );
    }

    /// Invariants that hold for every packet, checked over a grid of sources,
    /// destinations, protocols and ports, for every sample configuration.
    #[test]
    fn traces_satisfy_the_pipeline_invariants_over_many_packets() {
        let sources = [
            "192.168.1.20",
            "192.168.50.10",
            "192.168.60.9",
            "198.51.100.7",
            "198.51.100.9",
            "203.0.113.9",
            "192.0.2.10",
            "2001:db8:1::5",
            "2001:db8:ffff::2",
        ];
        let destinations = [
            "203.0.113.5",
            "192.168.1.1",
            "192.168.50.1",
            "192.168.60.1",
            "192.168.1.100",
            "1.1.1.1",
            "2001:db8:ffff::1",
        ];
        let ports = [22, 23, 53, 80, 123, 443, 2222, 8080, 8443, 27010];
        let ingresses = ["eth0", "eth1", "eth3", "eth4"];
        let view = view();
        for (name, config) in sample_configs() {
            // The LAN and IoT invariants describe the zones of the `rich` configs.
            let has_lan_and_iot = name.starts_with("rich");
            for ingress in ingresses {
                for source in sources {
                    for destination in destinations {
                        // Mixed-family packets do not exist.
                        if ip(source).is_ipv4() != ip(destination).is_ipv4() {
                            continue;
                        }
                        for protocol in [PacketProtocol::Tcp, PacketProtocol::Udp] {
                            for port in ports {
                                let packet =
                                    packet(ingress, source, destination, protocol, Some(port));
                                let response = trace(&config, &view, &packet);
                                let context = format!(
                                    "{name}: {ingress} {source} -> {destination} {protocol:?}/{port}"
                                );
                                assert!(response.steps.iter().any(|s| s.decisive), "{context}");
                                let final_destination = response
                                    .dnat
                                    .as_ref()
                                    .map(|dnat| ip(&dnat.address))
                                    .unwrap_or(ip(destination));
                                assert_eq!(
                                    response.path == TraceStage::Input,
                                    view.is_local(final_destination),
                                    "{context}"
                                );
                                if response.masquerade {
                                    assert_eq!(response.path, TraceStage::Forward, "{context}");
                                    assert_eq!(response.verdict, TraceVerdict::Accept, "{context}");
                                }
                                // Traffic from the IoT zone to its own router address is
                                // dropped by the zero-position rule. Port 2222 is excluded:
                                // the source-restricted port forward without a source zone
                                // DNATs it on any router address, as configured.
                                if has_lan_and_iot
                                    && ingress == "eth4"
                                    && destination == "192.168.50.1"
                                    && port != 2222
                                {
                                    assert_eq!(response.verdict, TraceVerdict::Drop, "{context}");
                                }
                                // Traffic from the LAN zone to the router is accepted:
                                // the zone default accepts whatever no rule drops.
                                if has_lan_and_iot
                                    && ingress == "eth1"
                                    && destination == "192.168.1.1"
                                {
                                    assert_eq!(response.verdict, TraceVerdict::Accept, "{context}");
                                }
                                // Default deny on WAN: only SSH (rate limited) and the
                                // port-forwarded TCP ports reach the router's own addresses.
                                if ingress == "eth0"
                                    && destination == "203.0.113.5"
                                    && protocol == PacketProtocol::Tcp
                                    && !matches!(port, 22 | 8080 | 27010)
                                {
                                    assert_eq!(response.verdict, TraceVerdict::Drop, "{context}");
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn request(
        ingress_interface: Option<&str>,
        source: &str,
        destination: &str,
        protocol: RuleProtocol,
        destination_port: Option<u16>,
    ) -> TestPacketRequest {
        TestPacketRequest {
            ingress_interface: ingress_interface.map(str::to_string),
            ingress_zone: None,
            source_ip: source.to_string(),
            destination_ip: destination.to_string(),
            protocol,
            source_port: None,
            destination_port,
            icmp_type: None,
            egress_interface: None,
        }
    }

    #[test]
    fn requests_are_checked_at_the_boundary() {
        let config = rich();
        let build = |request: &TestPacketRequest| packet_from_request(request, &config);

        // Valid TCP request: egress is left to the routing table.
        let valid = build(&request(
            Some("eth1"),
            "192.168.1.20",
            "1.1.1.1",
            RuleProtocol::Tcp,
            Some(443),
        ))
        .unwrap();
        assert_eq!(valid.egress, Egress::Routing);

        let rejected = [
            request(
                None,
                "192.168.1.20",
                "1.1.1.1",
                RuleProtocol::Tcp,
                Some(443),
            ),
            request(
                Some("eth1"),
                "not-an-ip",
                "1.1.1.1",
                RuleProtocol::Tcp,
                Some(443),
            ),
            request(
                Some("eth1"),
                "192.168.1.20",
                "2001:db8::1",
                RuleProtocol::Tcp,
                Some(443),
            ),
            request(
                Some("eth1"),
                "192.168.1.20",
                "1.1.1.1",
                RuleProtocol::TcpUdp,
                Some(443),
            ),
            request(
                Some("eth1"),
                "192.168.1.20",
                "1.1.1.1",
                RuleProtocol::Tcp,
                None,
            ),
            request(
                Some("eth1"),
                "192.168.1.20",
                "1.1.1.1",
                RuleProtocol::Tcp,
                Some(0),
            ),
            request(
                Some("eth1"),
                "192.168.1.20",
                "1.1.1.1",
                RuleProtocol::Icmp,
                Some(80),
            ),
            request(
                Some("eth1"),
                "192.168.1.20",
                "2001:db8::1",
                RuleProtocol::Icmp,
                None,
            ),
            request(
                Some("bad name"),
                "192.168.1.20",
                "1.1.1.1",
                RuleProtocol::Tcp,
                Some(443),
            ),
        ];
        for request in &rejected {
            assert!(build(request).is_err(), "accepted {request:?}");
        }

        let mut unknown_zone = request(None, "192.168.1.20", "1.1.1.1", RuleProtocol::Tcp, Some(1));
        unknown_zone.ingress_zone = Some("ghost".to_string());
        assert!(build(&unknown_zone).is_err());
    }

    #[test]
    fn a_zone_ingress_arrives_on_any_of_its_interfaces() {
        let config = rich();
        let view = view();
        let mut request = request(
            None,
            "192.168.1.20",
            "192.168.1.1",
            RuleProtocol::Tcp,
            Some(22),
        );
        request.ingress_zone = Some("lan".to_string());
        let packet = packet_from_request(&request, &config).unwrap();
        assert_eq!(packet.ingress, vec!["eth1".to_string(), "eth2".to_string()]);
        let response = trace(&config, &view, &packet);
        assert_eq!(response.verdict, TraceVerdict::Accept);
    }

    #[test]
    fn router_view_parses_ip_json_and_routes_forwarded_traffic() {
        let addr = br#"[
            {"ifname":"lo","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8}]},
            {"ifname":"eth0","addr_info":[
                {"family":"inet","local":"203.0.113.5","prefixlen":24},
                {"family":"inet6","local":"2001:db8:ffff::1","prefixlen":64}]},
            {"ifname":"eth1","addr_info":[{"family":"inet","local":"192.168.1.1","prefixlen":24}]}
        ]"#;
        let v4 = br#"[{"dst":"default","dev":"eth0","protocol":"dhcp"}]"#;
        let v6 = b"[]";
        let view = RouterView::from_ip_json(addr, v4, v6).unwrap();
        assert!(view.is_local(ip("203.0.113.5")));
        assert!(view.is_local(ip("2001:db8:ffff::1")));
        assert!(!view.is_local(ip("192.168.1.2")));
        assert_eq!(view.egress_for(ip("192.168.1.99")).as_deref(), Some("eth1"));
        assert_eq!(view.egress_for(ip("1.1.1.1")).as_deref(), Some("eth0"));
        assert_eq!(view.egress_for(ip("2001:db8:5::1")), None);
    }
}
