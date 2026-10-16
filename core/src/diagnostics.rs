//! Network diagnostics: ping, traceroute, DNS lookup and TCP port checks.
//!
//! The daemon runs the tools on request and returns their output. Every field
//! that reaches a command line is validated here, so the daemon and the web UI
//! agree on what is accepted.

use crate::validation;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Most echo requests one ping run may send.
pub const PING_MAX_COUNT: u8 = 20;
/// Most hops a traceroute may probe.
pub const TRACEROUTE_MAX_HOPS: u8 = 30;

/// IP version a tool should use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum IpFamily {
    /// Whatever the name resolves to first.
    #[default]
    Any,
    V4,
    V6,
}

/// DNS record type to look up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsRecordType {
    #[default]
    A,
    AAAA,
    CNAME,
    MX,
    NS,
    PTR,
    SOA,
    SRV,
    TXT,
}

impl DnsRecordType {
    pub const ALL: [DnsRecordType; 9] = [
        DnsRecordType::A,
        DnsRecordType::AAAA,
        DnsRecordType::CNAME,
        DnsRecordType::MX,
        DnsRecordType::NS,
        DnsRecordType::PTR,
        DnsRecordType::SOA,
        DnsRecordType::SRV,
        DnsRecordType::TXT,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            DnsRecordType::A => "A",
            DnsRecordType::AAAA => "AAAA",
            DnsRecordType::CNAME => "CNAME",
            DnsRecordType::MX => "MX",
            DnsRecordType::NS => "NS",
            DnsRecordType::PTR => "PTR",
            DnsRecordType::SOA => "SOA",
            DnsRecordType::SRV => "SRV",
            DnsRecordType::TXT => "TXT",
        }
    }
}

/// One diagnostic to run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "tool", rename_all = "snake_case")]
pub enum DiagnosticRequest {
    Ping {
        host: String,
        count: u8,
        #[serde(default)]
        family: IpFamily,
        /// Send from this interface.
        #[serde(default)]
        interface: Option<String>,
    },
    Traceroute {
        host: String,
        max_hops: u8,
        #[serde(default)]
        family: IpFamily,
    },
    DnsLookup {
        /// A name, or an IP address for a reverse (PTR) lookup.
        name: String,
        #[serde(default)]
        record_type: DnsRecordType,
        /// Ask this resolver instead of the router's own.
        #[serde(default)]
        server: Option<String>,
    },
    /// Open a TCP connection and close it again.
    TcpConnect { host: String, port: u16 },
}

/// A started diagnostic. Its output is read with
/// `GET /diagnostics/jobs/{id}?after=<offset>` until `outcome` is set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticStarted {
    pub id: String,
}

/// How a diagnostic ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DiagnosticOutcome {
    /// The tool ran and reported success (for ping: a reply arrived).
    pub success: bool,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    /// The run hit its time limit and was stopped.
    pub timed_out: bool,
    /// The user stopped the run.
    pub stopped: bool,
    /// The output was cut to the size limit.
    pub truncated: bool,
}

/// Output of a diagnostic from an offset on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DiagnosticProgress {
    /// What is being run, for display. Never run through a shell.
    pub command: String,
    /// Output after the requested offset.
    pub output: String,
    /// Offset (in bytes) to ask for next.
    pub next: u64,
    /// Set once the run has ended and `output` reaches its end.
    pub outcome: Option<DiagnosticOutcome>,
}

/// Empty body for endpoints that act on an existing diagnostic.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiagnosticNoRequest {}

/// A hostname (underscores allowed, for names like `_dmarc`) with an optional
/// trailing dot, or an IP address.
fn dns_name(name: &str) -> Result<(), String> {
    let invalid = || "Expected a DNS name or IP address".to_owned();
    if name.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    if trimmed.is_empty()
        || trimmed.len() > 253
        || trimmed.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
    {
        return Err(invalid());
    }
    Ok(())
}

fn target_host(host: &str) -> Result<(), String> {
    let host = host.trim();
    if host.is_empty() {
        return Err("Enter a host name or IP address".to_owned());
    }
    validation::hostname_or_ip(host)
}

impl DiagnosticRequest {
    /// Check every field before anything is executed.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            DiagnosticRequest::Ping {
                host,
                count,
                interface,
                ..
            } => {
                target_host(host)?;
                if !(1..=PING_MAX_COUNT).contains(count) {
                    return Err(format!("Count must be between 1 and {PING_MAX_COUNT}"));
                }
                if let Some(interface) = interface {
                    validation::interface_name(interface)?;
                }
                Ok(())
            }
            DiagnosticRequest::Traceroute { host, max_hops, .. } => {
                target_host(host)?;
                if !(1..=TRACEROUTE_MAX_HOPS).contains(max_hops) {
                    return Err(format!(
                        "Maximum hops must be between 1 and {TRACEROUTE_MAX_HOPS}"
                    ));
                }
                Ok(())
            }
            DiagnosticRequest::DnsLookup { name, server, .. } => {
                if name.trim().is_empty() {
                    return Err("Enter a name or IP address".to_owned());
                }
                dns_name(name.trim())?;
                if let Some(server) = server {
                    // A resolver is addressed by IP or by name; drill's own
                    // `@server` syntax carries nothing else.
                    validation::hostname_or_ip(server.trim())
                        .map_err(|_| "Resolver must be an IP address or host name".to_owned())?;
                }
                Ok(())
            }
            DiagnosticRequest::TcpConnect { host, port } => {
                target_host(host)?;
                if *port == 0 {
                    return Err("Port must be between 1 and 65535".to_owned());
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ping(host: &str) -> DiagnosticRequest {
        DiagnosticRequest::Ping {
            host: host.into(),
            count: 4,
            family: IpFamily::Any,
            interface: None,
        }
    }

    #[test]
    fn hosts_cannot_smuggle_options_or_shell_syntax() {
        for bad in [
            "-f",
            "--help",
            "-c1",
            "a b",
            "host;reboot",
            "$(id)",
            "a|b",
            "host\nname",
            "fe80::1%eth0",
            "",
            "  ",
        ] {
            assert!(ping(bad).validate().is_err(), "{bad:?} must be rejected");
        }
        for good in ["example.com", "192.0.2.1", "2001:db8::1", "a-b.example"] {
            assert!(ping(good).validate().is_ok(), "{good:?} must be accepted");
        }
    }

    #[test]
    fn counts_and_hops_are_bounded() {
        let ping_count = |count| DiagnosticRequest::Ping {
            host: "example.com".into(),
            count,
            family: IpFamily::Any,
            interface: None,
        };
        assert!(ping_count(0).validate().is_err());
        assert!(ping_count(PING_MAX_COUNT).validate().is_ok());
        assert!(ping_count(PING_MAX_COUNT + 1).validate().is_err());
        let hops = |max_hops| DiagnosticRequest::Traceroute {
            host: "example.com".into(),
            max_hops,
            family: IpFamily::Any,
        };
        assert!(hops(0).validate().is_err());
        assert!(hops(TRACEROUTE_MAX_HOPS).validate().is_ok());
        assert!(hops(TRACEROUTE_MAX_HOPS + 1).validate().is_err());
    }

    #[test]
    fn the_interface_name_is_validated() {
        let with_interface = |interface: &str| DiagnosticRequest::Ping {
            host: "example.com".into(),
            count: 1,
            family: IpFamily::Any,
            interface: Some(interface.into()),
        };
        assert!(with_interface("enp3s0").validate().is_ok());
        assert!(with_interface("-I").validate().is_err());
        assert!(with_interface("a b").validate().is_err());
    }

    #[test]
    fn dns_names_allow_service_labels_and_a_trailing_dot() {
        let lookup = |name: &str| DiagnosticRequest::DnsLookup {
            name: name.into(),
            record_type: DnsRecordType::TXT,
            server: None,
        };
        assert!(lookup("_dmarc.example.com").validate().is_ok());
        assert!(lookup("example.com.").validate().is_ok());
        assert!(lookup("192.0.2.1").validate().is_ok());
        assert!(lookup("-x").validate().is_err());
        assert!(lookup("a..b").validate().is_err());
        assert!(lookup("bad name").validate().is_err());
    }

    #[test]
    fn the_dns_resolver_is_validated() {
        let with_server = |server: &str| DiagnosticRequest::DnsLookup {
            name: "example.com".into(),
            record_type: DnsRecordType::A,
            server: Some(server.into()),
        };
        assert!(with_server("1.1.1.1").validate().is_ok());
        assert!(with_server("dns.example").validate().is_ok());
        assert!(with_server("-4").validate().is_err());
        assert!(with_server("@x").validate().is_err());
    }

    #[test]
    fn tcp_ports_are_nonzero() {
        let port = |port| DiagnosticRequest::TcpConnect {
            host: "example.com".into(),
            port,
        };
        assert!(port(0).validate().is_err());
        assert!(port(443).validate().is_ok());
    }

    #[test]
    fn requests_round_trip_with_a_tool_tag() {
        let request = DiagnosticRequest::DnsLookup {
            name: "example.com".into(),
            record_type: DnsRecordType::MX,
            server: None,
        };
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["tool"], "dns_lookup");
        assert_eq!(json["record_type"], "MX");
        assert_eq!(
            serde_json::from_value::<DiagnosticRequest>(json).unwrap(),
            request
        );
    }
}
