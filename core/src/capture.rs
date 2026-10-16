//! Packet capture: the request a client sends, the filter it is built from, and
//! the status and output the daemon reports.
//!
//! The filter is a list of typed clauses, never a free-form expression. The
//! daemon turns it into a pcap filter with [`CaptureFilter::to_expression`],
//! which rebuilds every token from a parsed address, port or enum value. Nothing
//! a client typed reaches `tcpdump` unparsed.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Fewest bytes of each packet that may be captured.
pub const MIN_SNAPLEN: u32 = 64;
/// Most bytes of each packet that may be captured.
pub const MAX_SNAPLEN: u32 = 65535;
pub const DEFAULT_SNAPLEN: u32 = 1600;
/// Most packets one capture may take.
pub const MAX_PACKETS: u32 = 100_000;
pub const DEFAULT_PACKETS: u32 = 1000;
/// Longest a capture may run, in seconds.
pub const MAX_SECONDS: u32 = 600;
pub const DEFAULT_SECONDS: u32 = 60;
/// Most capture-file bytes kept. The file lives in memory-backed storage.
pub const MAX_CAPTURE_BYTES: u64 = 64 * 1024 * 1024;
/// Most conditions in one filter, counting every alternative.
pub const MAX_CLAUSES: usize = 24;
/// Most groups in one filter.
pub const MAX_GROUPS: usize = 12;
/// Pseudo-interface that captures on all interfaces at once.
pub const ANY_INTERFACE: &str = "any";

/// Which end of a packet a host, network, port or MAC address must match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureDirection {
    /// Source or destination.
    #[default]
    Any,
    Src,
    Dst,
}

impl CaptureDirection {
    fn prefix(self) -> &'static str {
        match self {
            CaptureDirection::Any => "",
            CaptureDirection::Src => "src ",
            CaptureDirection::Dst => "dst ",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureProtocol {
    Ip,
    Ip6,
    Arp,
    Icmp,
    Icmp6,
    Tcp,
    Udp,
}

impl CaptureProtocol {
    pub const ALL: [CaptureProtocol; 7] = [
        CaptureProtocol::Ip,
        CaptureProtocol::Ip6,
        CaptureProtocol::Arp,
        CaptureProtocol::Icmp,
        CaptureProtocol::Icmp6,
        CaptureProtocol::Tcp,
        CaptureProtocol::Udp,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            CaptureProtocol::Ip => "ip",
            CaptureProtocol::Ip6 => "ip6",
            CaptureProtocol::Arp => "arp",
            CaptureProtocol::Icmp => "icmp",
            CaptureProtocol::Icmp6 => "icmp6",
            CaptureProtocol::Tcp => "tcp",
            CaptureProtocol::Udp => "udp",
        }
    }
}

/// The DHCPv4 message types (option 53) a filter can pick out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DhcpMessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
}

impl DhcpMessageType {
    pub const ALL: [DhcpMessageType; 8] = [
        DhcpMessageType::Discover,
        DhcpMessageType::Offer,
        DhcpMessageType::Request,
        DhcpMessageType::Decline,
        DhcpMessageType::Ack,
        DhcpMessageType::Nak,
        DhcpMessageType::Release,
        DhcpMessageType::Inform,
    ];

    /// The option 53 value (RFC 2132).
    pub const fn code(self) -> u8 {
        match self {
            DhcpMessageType::Discover => 1,
            DhcpMessageType::Offer => 2,
            DhcpMessageType::Request => 3,
            DhcpMessageType::Decline => 4,
            DhcpMessageType::Ack => 5,
            DhcpMessageType::Nak => 6,
            DhcpMessageType::Release => 7,
            DhcpMessageType::Inform => 8,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            DhcpMessageType::Discover => "DISCOVER",
            DhcpMessageType::Offer => "OFFER",
            DhcpMessageType::Request => "REQUEST",
            DhcpMessageType::Decline => "DECLINE",
            DhcpMessageType::Ack => "ACK",
            DhcpMessageType::Nak => "NAK",
            DhcpMessageType::Release => "RELEASE",
            DhcpMessageType::Inform => "INFORM",
        }
    }
}

/// One condition of a filter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FilterTerm {
    Protocol {
        protocol: CaptureProtocol,
    },
    /// A single IPv4 or IPv6 address.
    Host {
        #[serde(default)]
        direction: CaptureDirection,
        address: String,
    },
    /// An IPv4 or IPv6 network in CIDR notation.
    Net {
        #[serde(default)]
        direction: CaptureDirection,
        network: String,
    },
    /// A TCP/UDP port, or an inclusive range when `last` is set.
    Port {
        #[serde(default)]
        direction: CaptureDirection,
        first: u16,
        #[serde(default)]
        last: Option<u16>,
    },
    /// An Ethernet address.
    Mac {
        #[serde(default)]
        direction: CaptureDirection,
        address: String,
    },
    /// A DHCPv4 message of one type (UDP ports 67 and 68, IPv4 only). It reads
    /// option 53 at its usual place, right after the magic cookie, where
    /// systemd-networkd, dhcpcd, dnsmasq and ISC software all put it. A packet
    /// that lists it later is not matched.
    DhcpMessage {
        message_type: DhcpMessageType,
    },
}

/// A term, optionally negated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureClause {
    #[serde(default)]
    pub negate: bool,
    #[serde(flatten)]
    pub term: FilterTerm,
}

/// Conditions of which at least one must match. A group of one is just that
/// condition. `negate` inverts the whole group, so a negated group of two
/// means "neither".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureGroup {
    #[serde(default)]
    pub negate: bool,
    pub any: Vec<CaptureClause>,
}

impl CaptureGroup {
    /// A group holding one condition.
    pub fn single(term: FilterTerm) -> Self {
        Self {
            negate: false,
            any: vec![CaptureClause {
                negate: false,
                term,
            }],
        }
    }
}

/// Groups that must all match. An empty filter captures everything.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureFilter {
    #[serde(default)]
    pub groups: Vec<CaptureGroup>,
}

fn parse_mac(text: &str) -> Result<String, String> {
    let invalid = || format!("'{text}' is not a MAC address (expected aa:bb:cc:dd:ee:ff)");
    let parts: Vec<&str> = text.split([':', '-']).collect();
    if parts.len() != 6 {
        return Err(invalid());
    }
    let mut octets = Vec::with_capacity(6);
    for part in parts {
        if part.is_empty() || part.len() > 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(invalid());
        }
        octets.push(format!(
            "{:02x}",
            u8::from_str_radix(part, 16).map_err(|_| invalid())?
        ));
    }
    Ok(octets.join(":"))
}

impl FilterTerm {
    /// The pcap-filter primitive for this term, rebuilt from parsed values.
    pub fn to_expression(&self) -> Result<String, String> {
        Ok(match self {
            FilterTerm::Protocol { protocol } => protocol.as_str().to_string(),
            FilterTerm::Host { direction, address } => {
                let address: IpAddr = address
                    .trim()
                    .parse()
                    .map_err(|_| format!("'{address}' is not an IP address"))?;
                format!("{}host {address}", direction.prefix())
            }
            FilterTerm::Net { direction, network } => {
                let network: IpNet = network.trim().parse().map_err(|_| {
                    format!("'{network}' is not a network in CIDR form (e.g. 10.0.0.0/8)")
                })?;
                // pcap-filter refuses a network with host bits set.
                format!("{}net {}", direction.prefix(), network.trunc())
            }
            FilterTerm::Port {
                direction,
                first,
                last,
            } => {
                if *first == 0 {
                    return Err("port 0 is not valid".to_string());
                }
                match last {
                    None => format!("{}port {first}", direction.prefix()),
                    Some(last) if last < first || *last == 0 => {
                        return Err(format!("port range {first}-{last} is backwards"));
                    }
                    Some(last) if last == first => format!("{}port {first}", direction.prefix()),
                    Some(last) => format!("{}portrange {first}-{last}", direction.prefix()),
                }
            }
            FilterTerm::DhcpMessage { message_type } => format!(
                // Option 53 starts 240 bytes into the UDP payload: 8 bytes of
                // UDP header, 236 of BOOTP, 4 of magic cookie. Its code is at
                // 248, its length at 249 and the message type at 250. Checking
                // the code too stops other options' data from matching.
                "(udp portrange 67-68 and udp[248] = 53 and udp[250] = {})",
                message_type.code()
            ),
            FilterTerm::Mac { direction, address } => {
                let direction = match direction {
                    CaptureDirection::Any => "host ",
                    CaptureDirection::Src => "src ",
                    CaptureDirection::Dst => "dst ",
                };
                format!("ether {direction}{}", parse_mac(address.trim())?)
            }
        })
    }
}

impl CaptureFilter {
    /// The pcap filter expression, or an error naming the first bad condition.
    pub fn to_expression(&self) -> Result<String, String> {
        if self.groups.len() > MAX_GROUPS {
            return Err(format!("a filter may have at most {MAX_GROUPS} groups"));
        }
        let total: usize = self.groups.iter().map(|group| group.any.len()).sum();
        if total > MAX_CLAUSES {
            return Err(format!(
                "a filter may have at most {MAX_CLAUSES} conditions"
            ));
        }
        let mut parts = Vec::with_capacity(self.groups.len());
        for (group_index, group) in self.groups.iter().enumerate() {
            if group.any.is_empty() {
                return Err(format!(
                    "condition {}: it has no alternatives",
                    group_index + 1
                ));
            }
            let mut alternatives = Vec::with_capacity(group.any.len());
            for (index, clause) in group.any.iter().enumerate() {
                let primitive = clause.term.to_expression().map_err(|error| {
                    if group.any.len() == 1 {
                        format!("condition {}: {error}", group_index + 1)
                    } else {
                        format!(
                            "condition {}, alternative {}: {error}",
                            group_index + 1,
                            index + 1
                        )
                    }
                })?;
                alternatives.push(if clause.negate {
                    format!("not ({primitive})")
                } else {
                    primitive
                });
            }
            parts.push(match (alternatives.len(), group.negate) {
                (1, false) => alternatives.remove(0),
                (_, false) => format!("({})", alternatives.join(" or ")),
                (_, true) => format!("not ({})", alternatives.join(" or ")),
            });
        }
        Ok(parts.join(" and "))
    }
}

/// How much of each packet the live view decodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureDetail {
    /// One line per packet.
    #[default]
    Normal,
    /// Adds the IP header fields and protocol details such as DHCP options.
    Verbose,
    /// Adds more protocol detail still.
    VeryVerbose,
}

/// Start a capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureRequest {
    /// Interface name, or [`ANY_INTERFACE`].
    pub interface: String,
    #[serde(default)]
    pub filter: CaptureFilter,
    #[serde(default = "default_snaplen")]
    pub snaplen: u32,
    #[serde(default = "default_packets")]
    pub max_packets: u32,
    #[serde(default = "default_seconds")]
    pub max_seconds: u32,
    /// Only changes the live view; the pcap file always has the whole packet.
    #[serde(default)]
    pub detail: CaptureDetail,
    /// Show Ethernet addresses in the live view.
    #[serde(default)]
    pub link_level: bool,
}

fn default_snaplen() -> u32 {
    DEFAULT_SNAPLEN
}
fn default_packets() -> u32 {
    DEFAULT_PACKETS
}
fn default_seconds() -> u32 {
    DEFAULT_SECONDS
}

impl CaptureRequest {
    /// Check every field and return the filter expression to hand to tcpdump.
    pub fn validate(&self) -> Result<String, String> {
        if self.interface != ANY_INTERFACE {
            crate::validation::interface_name(&self.interface)?;
        }
        if !(MIN_SNAPLEN..=MAX_SNAPLEN).contains(&self.snaplen) {
            return Err(format!(
                "snapshot length must be {MIN_SNAPLEN}-{MAX_SNAPLEN} bytes"
            ));
        }
        if !(1..=MAX_PACKETS).contains(&self.max_packets) {
            return Err(format!("packet limit must be 1-{MAX_PACKETS}"));
        }
        if !(1..=MAX_SECONDS).contains(&self.max_seconds) {
            return Err(format!("time limit must be 1-{MAX_SECONDS} seconds"));
        }
        self.filter.to_expression()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureState {
    Running,
    /// Ended by itself: the packet limit was reached.
    Finished,
    /// Ended early: stopped by the user, or the time or size limit was reached.
    Stopped,
    Failed,
}

/// The current capture. There is at most one, and its file is kept until the
/// next capture starts or it is discarded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureInfo {
    pub request: CaptureRequest,
    /// The filter expression that was passed to tcpdump.
    pub expression: String,
    pub state: CaptureState,
    pub started_at: u64,
    pub ended_at: Option<u64>,
    pub packets: u64,
    pub bytes: u64,
    /// Packets the kernel dropped because the capture could not keep up.
    pub dropped_by_kernel: Option<u64>,
    /// Why it stopped, or the error tcpdump gave.
    pub message: Option<String>,
    /// Whether there is a file to download.
    pub has_pcap: bool,
}

/// `GET /capture`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureStateResponse {
    pub capture: Option<CaptureInfo>,
    /// Interfaces to choose from, including [`ANY_INTERFACE`].
    pub interfaces: Vec<String>,
}

/// One line of tcpdump's decoded output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureLine {
    pub seq: u64,
    pub text: String,
}

/// `GET /capture/packets?since=<seq>`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturePacketsResponse {
    pub lines: Vec<CaptureLine>,
    /// Pass as `since` on the next poll.
    pub next: u64,
    /// Lines that left the daemon's buffer before this poll could read them.
    pub lost: u64,
    pub info: Option<CaptureInfo>,
}

/// Empty body for endpoints that act on the current capture.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CaptureNoRequest {}

#[cfg(test)]
mod tests {
    use super::*;

    fn clause(negate: bool, term: FilterTerm) -> CaptureClause {
        CaptureClause { negate, term }
    }

    fn proto(protocol: CaptureProtocol) -> FilterTerm {
        FilterTerm::Protocol { protocol }
    }

    fn port(direction: CaptureDirection, first: u16, last: Option<u16>) -> FilterTerm {
        FilterTerm::Port {
            direction,
            first,
            last,
        }
    }

    fn any_of(terms: Vec<FilterTerm>) -> CaptureGroup {
        CaptureGroup {
            negate: false,
            any: terms.into_iter().map(|term| clause(false, term)).collect(),
        }
    }

    fn filter(groups: Vec<CaptureGroup>) -> CaptureFilter {
        CaptureFilter { groups }
    }

    fn request(groups: Vec<CaptureGroup>) -> CaptureRequest {
        CaptureRequest {
            interface: "eth1".into(),
            filter: filter(groups),
            snaplen: DEFAULT_SNAPLEN,
            max_packets: DEFAULT_PACKETS,
            max_seconds: DEFAULT_SECONDS,
            detail: CaptureDetail::Normal,
            link_level: false,
        }
    }

    #[test]
    fn groups_are_anded_and_negation_is_parenthesised() {
        let f = filter(vec![
            CaptureGroup::single(proto(CaptureProtocol::Tcp)),
            CaptureGroup::single(FilterTerm::Host {
                direction: CaptureDirection::Src,
                address: "192.168.1.20".into(),
            }),
            CaptureGroup {
                negate: false,
                any: vec![clause(true, port(CaptureDirection::Any, 22, None))],
            },
        ]);
        assert_eq!(
            f.to_expression().unwrap(),
            "tcp and src host 192.168.1.20 and not (port 22)"
        );
    }

    #[test]
    fn alternatives_are_ored_inside_parentheses() {
        let f = filter(vec![
            CaptureGroup::single(FilterTerm::Host {
                direction: CaptureDirection::Any,
                address: "10.0.0.1".into(),
            }),
            any_of(vec![
                proto(CaptureProtocol::Tcp),
                proto(CaptureProtocol::Udp),
            ]),
        ]);
        assert_eq!(f.to_expression().unwrap(), "host 10.0.0.1 and (tcp or udp)");
        // Without the parentheses "or" would bind looser than "and" and the
        // host would only constrain the first alternative.
        assert!(f.to_expression().unwrap().contains("(tcp or udp)"));
    }

    #[test]
    fn a_negated_group_means_none_of_them() {
        let mut group = any_of(vec![
            proto(CaptureProtocol::Arp),
            proto(CaptureProtocol::Icmp),
        ]);
        group.negate = true;
        assert_eq!(
            filter(vec![group]).to_expression().unwrap(),
            "not (arp or icmp)"
        );
        // A negated alternative inside an unnegated group.
        let group = CaptureGroup {
            negate: false,
            any: vec![
                clause(false, proto(CaptureProtocol::Tcp)),
                clause(true, port(CaptureDirection::Dst, 443, None)),
            ],
        };
        assert_eq!(
            filter(vec![group]).to_expression().unwrap(),
            "(tcp or not (dst port 443))"
        );
    }

    #[test]
    fn empty_filter_captures_everything() {
        assert_eq!(CaptureFilter::default().to_expression().unwrap(), "");
    }

    #[test]
    fn dhcp_messages_match_option_53_in_its_usual_place() {
        let f = filter(vec![CaptureGroup::single(FilterTerm::DhcpMessage {
            message_type: DhcpMessageType::Discover,
        })]);
        assert_eq!(
            f.to_expression().unwrap(),
            "(udp portrange 67-68 and udp[248] = 53 and udp[250] = 1)"
        );
        let codes: Vec<u8> = DhcpMessageType::ALL.iter().map(|m| m.code()).collect();
        assert_eq!(codes, [1, 2, 3, 4, 5, 6, 7, 8]);
        // Safe to OR with other conditions: the term is self-contained.
        let either = any_of(vec![
            FilterTerm::DhcpMessage {
                message_type: DhcpMessageType::Offer,
            },
            FilterTerm::DhcpMessage {
                message_type: DhcpMessageType::Ack,
            },
        ]);
        let text = filter(vec![either]).to_expression().unwrap();
        assert!(
            text.starts_with("((udp portrange 67-68") && text.contains(") or ("),
            "{text}"
        );
    }

    #[test]
    fn networks_are_truncated_and_addresses_canonicalised() {
        let net = FilterTerm::Net {
            direction: CaptureDirection::Dst,
            network: "10.1.2.3/8".into(),
        };
        assert_eq!(net.to_expression().unwrap(), "dst net 10.0.0.0/8");
        let host = FilterTerm::Host {
            direction: CaptureDirection::Any,
            address: " 2001:DB8:0:0::1 ".into(),
        };
        assert_eq!(host.to_expression().unwrap(), "host 2001:db8::1");
    }

    #[test]
    fn port_ranges_collapse_and_reject_nonsense() {
        let p = |first, last| port(CaptureDirection::Any, first, last);
        assert_eq!(p(80, Some(80)).to_expression().unwrap(), "port 80");
        assert_eq!(
            p(1000, Some(2000)).to_expression().unwrap(),
            "portrange 1000-2000"
        );
        assert!(p(0, None).to_expression().is_err());
        assert!(p(2000, Some(1000)).to_expression().is_err());
    }

    #[test]
    fn mac_addresses_are_normalised() {
        let mac = |address: &str| FilterTerm::Mac {
            direction: CaptureDirection::Src,
            address: address.into(),
        };
        assert_eq!(
            mac("AA-bb-0c-1-2-FF").to_expression().unwrap(),
            "ether src aa:bb:0c:01:02:ff"
        );
        assert!(mac("aa:bb:cc:dd:ee").to_expression().is_err());
        assert!(mac("aa:bb:cc:dd:ee:gg").to_expression().is_err());
    }

    #[test]
    fn nothing_typed_survives_into_the_expression() {
        // Each of these would change the filter, or a command line, if it were
        // copied through. Each must be refused instead.
        for bad in [
            "1.2.3.4 or host 5.6.7.8",
            "1.2.3.4)",
            "$(reboot)",
            "1.2.3.4\nhost 9.9.9.9",
            "-w /etc/passwd",
            "",
        ] {
            let host = FilterTerm::Host {
                direction: CaptureDirection::Any,
                address: bad.into(),
            };
            assert!(host.to_expression().is_err(), "{bad:?}");
            let net = FilterTerm::Net {
                direction: CaptureDirection::Any,
                network: bad.into(),
            };
            assert!(net.to_expression().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn errors_say_which_condition_and_alternative() {
        let bad_host = FilterTerm::Host {
            direction: CaptureDirection::Any,
            address: "nope".into(),
        };
        let single = filter(vec![
            CaptureGroup::single(proto(CaptureProtocol::Tcp)),
            CaptureGroup::single(bad_host.clone()),
        ]);
        assert!(
            single
                .to_expression()
                .unwrap_err()
                .starts_with("condition 2:")
        );
        let nested = filter(vec![any_of(vec![proto(CaptureProtocol::Tcp), bad_host])]);
        assert!(
            nested
                .to_expression()
                .unwrap_err()
                .starts_with("condition 1, alternative 2:")
        );
        let empty = filter(vec![CaptureGroup {
            negate: false,
            any: vec![],
        }]);
        assert!(empty.to_expression().is_err());
    }

    #[test]
    fn request_limits_are_enforced() {
        assert!(request(vec![]).validate().is_ok());
        let mut r = request(vec![]);
        r.interface = "any".into();
        assert!(r.validate().is_ok());
        r.interface = "eth1; reboot".into();
        assert!(r.validate().is_err());
        let mut r = request(vec![]);
        r.snaplen = 10;
        assert!(r.validate().is_err());
        let mut r = request(vec![]);
        r.max_packets = MAX_PACKETS + 1;
        assert!(r.validate().is_err());
        let mut r = request(vec![]);
        r.max_seconds = 0;
        assert!(r.validate().is_err());

        let one = || CaptureGroup::single(proto(CaptureProtocol::Ip));
        assert!(request(vec![one(); MAX_GROUPS]).validate().is_ok());
        assert!(request(vec![one(); MAX_GROUPS + 1]).validate().is_err());
        let wide = any_of(vec![proto(CaptureProtocol::Ip); MAX_CLAUSES + 1]);
        assert!(request(vec![wide]).validate().is_err());
    }

    #[test]
    fn requests_round_trip_through_json_and_default_missing_fields() {
        let mut r = request(vec![CaptureGroup {
            negate: true,
            any: vec![clause(
                true,
                FilterTerm::Host {
                    direction: CaptureDirection::Dst,
                    address: "10.0.0.1".into(),
                },
            )],
        }]);
        r.detail = CaptureDetail::Verbose;
        r.link_level = true;
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"kind\":\"host\""), "{json}");
        assert!(json.contains("\"detail\":\"verbose\""), "{json}");
        let back: CaptureRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);

        let minimal: CaptureRequest = serde_json::from_str(r#"{"interface":"eth0"}"#).unwrap();
        assert_eq!(minimal.snaplen, DEFAULT_SNAPLEN);
        assert_eq!(minimal.detail, CaptureDetail::Normal);
        assert!(!minimal.link_level);
        assert!(minimal.filter.groups.is_empty());
    }
}
