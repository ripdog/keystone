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
/// Most clauses in one filter.
pub const MAX_CLAUSES: usize = 16;
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
}

/// A term, optionally negated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureClause {
    #[serde(default)]
    pub negate: bool,
    #[serde(flatten)]
    pub term: FilterTerm,
}

/// Clauses that must all match. An empty filter captures everything.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureFilter {
    #[serde(default)]
    pub clauses: Vec<CaptureClause>,
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
    /// The pcap filter expression, or an error naming the first bad clause.
    pub fn to_expression(&self) -> Result<String, String> {
        if self.clauses.len() > MAX_CLAUSES {
            return Err(format!(
                "a filter may have at most {MAX_CLAUSES} conditions"
            ));
        }
        let mut parts = Vec::with_capacity(self.clauses.len());
        for (index, clause) in self.clauses.iter().enumerate() {
            let primitive = clause
                .term
                .to_expression()
                .map_err(|error| format!("condition {}: {error}", index + 1))?;
            parts.push(if clause.negate {
                format!("not ({primitive})")
            } else {
                primitive
            });
        }
        Ok(parts.join(" and "))
    }
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

    fn request(clauses: Vec<CaptureClause>) -> CaptureRequest {
        CaptureRequest {
            interface: "eth1".into(),
            filter: CaptureFilter { clauses },
            snaplen: DEFAULT_SNAPLEN,
            max_packets: DEFAULT_PACKETS,
            max_seconds: DEFAULT_SECONDS,
        }
    }

    #[test]
    fn clauses_are_anded_and_negation_is_parenthesised() {
        let filter = CaptureFilter {
            clauses: vec![
                clause(
                    false,
                    FilterTerm::Protocol {
                        protocol: CaptureProtocol::Tcp,
                    },
                ),
                clause(
                    false,
                    FilterTerm::Host {
                        direction: CaptureDirection::Src,
                        address: "192.168.1.20".into(),
                    },
                ),
                clause(
                    true,
                    FilterTerm::Port {
                        direction: CaptureDirection::Any,
                        first: 22,
                        last: None,
                    },
                ),
            ],
        };
        assert_eq!(
            filter.to_expression().unwrap(),
            "tcp and src host 192.168.1.20 and not (port 22)"
        );
    }

    #[test]
    fn empty_filter_captures_everything() {
        assert_eq!(CaptureFilter::default().to_expression().unwrap(), "");
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
        let port = |first, last| FilterTerm::Port {
            direction: CaptureDirection::Any,
            first,
            last,
        };
        assert_eq!(port(80, Some(80)).to_expression().unwrap(), "port 80");
        assert_eq!(
            port(1000, Some(2000)).to_expression().unwrap(),
            "portrange 1000-2000"
        );
        assert!(port(0, None).to_expression().is_err());
        assert!(port(2000, Some(1000)).to_expression().is_err());
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
        let too_many = vec![
            clause(
                false,
                FilterTerm::Protocol {
                    protocol: CaptureProtocol::Ip
                }
            );
            MAX_CLAUSES + 1
        ];
        assert!(request(too_many).validate().is_err());
    }

    #[test]
    fn clauses_round_trip_through_json() {
        let r = request(vec![clause(
            true,
            FilterTerm::Host {
                direction: CaptureDirection::Dst,
                address: "10.0.0.1".into(),
            },
        )]);
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"kind\":\"host\""), "{json}");
        let back: CaptureRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
        // Omitted optional fields take their defaults.
        let minimal: CaptureRequest = serde_json::from_str(r#"{"interface":"eth0"}"#).unwrap();
        assert_eq!(minimal.snaplen, DEFAULT_SNAPLEN);
        assert!(minimal.filter.clauses.is_empty());
    }
}
