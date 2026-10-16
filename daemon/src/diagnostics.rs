//! Network diagnostics run on demand from the web UI: ping, traceroute, DNS
//! lookup and TCP port checks.
//!
//! The tools are `ping` and `tracepath` (iputils) and `drill` (ldns). They run
//! without a shell, with arguments built from fields that
//! [`DiagnosticRequest::validate`] has already checked, under a time limit and
//! an output limit, and at most [`MAX_CONCURRENT`] at once.
//!
//! The daemon's sandbox needs nothing extra: ping and tracepath open raw
//! sockets (`CAP_NET_RAW`, already granted), and nothing is written to disk.

use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{Json, Router, http::StatusCode, routing::post};
use keystone_core::api::{Endpoint, Req, Res, RunDiagnostic};
use keystone_core::diagnostics::{DiagnosticRequest, DiagnosticResponse, IpFamily};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::{TcpStream, lookup_host};
use tokio::process::Command;
use tokio::sync::Semaphore;

use crate::AppState;

/// Diagnostics that may run at the same time.
const MAX_CONCURRENT: usize = 4;
/// Longest output kept; the rest is dropped.
const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const PING_TIMEOUT: Duration = Duration::from_secs(40);
const TRACEROUTE_TIMEOUT: Duration = Duration::from_secs(90);
const DNS_TIMEOUT: Duration = Duration::from_secs(20);
const TCP_TIMEOUT: Duration = Duration::from_secs(5);

static SLOTS: Semaphore = Semaphore::const_new(MAX_CONCURRENT);

/// A program to run and its arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Invocation {
    program: &'static str,
    args: Vec<String>,
    timeout: Duration,
}

impl Invocation {
    /// The command line for display. The arguments are validated, so this is
    /// only ever shown, never executed.
    fn display(&self) -> String {
        std::iter::once(self.program)
            .chain(self.args.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

fn family_flag(family: IpFamily) -> Option<&'static str> {
    match family {
        IpFamily::Any => None,
        IpFamily::V4 => Some("-4"),
        IpFamily::V6 => Some("-6"),
    }
}

/// The command for a validated request, or `None` for the built-in TCP check.
fn invocation(request: &DiagnosticRequest) -> Option<Invocation> {
    match request {
        DiagnosticRequest::Ping {
            host,
            count,
            family,
            interface,
        } => {
            let mut args = vec!["-n".to_owned(), "-c".into(), count.to_string()];
            args.extend(["-W".into(), "2".into()]);
            args.extend(family_flag(*family).map(str::to_owned));
            if let Some(interface) = interface {
                args.extend(["-I".into(), interface.clone()]);
            }
            args.push(host.trim().to_owned());
            Some(Invocation {
                program: "ping",
                args,
                timeout: PING_TIMEOUT,
            })
        }
        DiagnosticRequest::Traceroute {
            host,
            max_hops,
            family,
        } => {
            let mut args = vec!["-n".to_owned(), "-m".into(), max_hops.to_string()];
            args.extend(family_flag(*family).map(str::to_owned));
            args.push(host.trim().to_owned());
            Some(Invocation {
                program: "tracepath",
                args,
                timeout: TRACEROUTE_TIMEOUT,
            })
        }
        DiagnosticRequest::DnsLookup {
            name,
            record_type,
            server,
        } => {
            let name = name.trim();
            let mut args = Vec::new();
            if name.parse::<std::net::IpAddr>().is_ok() {
                // An address means a reverse lookup, whatever type was picked.
                args.extend(["-x".to_owned(), name.to_owned()]);
            } else {
                args.extend([name.to_owned(), record_type.as_str().to_owned()]);
            }
            if let Some(server) = server.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                args.push(format!("@{server}"));
            }
            Some(Invocation {
                program: "drill",
                args,
                timeout: DNS_TIMEOUT,
            })
        }
        DiagnosticRequest::TcpConnect { .. } => None,
    }
}

/// Keep reading until the stream ends, storing at most [`MAX_OUTPUT_BYTES`].
/// Returns whether anything was dropped.
async fn drain(mut stream: impl AsyncRead + Unpin, buffer: &mut Vec<u8>) -> bool {
    let mut truncated = false;
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return truncated,
            Ok(read) => {
                let room = MAX_OUTPUT_BYTES.saturating_sub(buffer.len());
                buffer.extend_from_slice(&chunk[..read.min(room)]);
                truncated |= read > room;
            }
        }
    }
}

/// Run `invocation` and collect its output. On timeout the process is killed
/// and the output so far is returned.
async fn run(invocation: &Invocation) -> DiagnosticResponse {
    let started = Instant::now();
    let mut response = DiagnosticResponse {
        command: invocation.display(),
        ..Default::default()
    };
    let spawned = Command::new(invocation.program)
        .args(&invocation.args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            response.output = if error.kind() == std::io::ErrorKind::NotFound {
                format!("{} is not installed on this router.\n", invocation.program)
            } else {
                format!("Could not start {}: {error}\n", invocation.program)
            };
            return response;
        }
    };
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        response.output = "Could not capture output.\n".to_owned();
        return response;
    };

    let mut out = Vec::new();
    let mut err = Vec::new();
    let finished = tokio::time::timeout(invocation.timeout, async {
        let (out_cut, err_cut) = tokio::join!(drain(stdout, &mut out), drain(stderr, &mut err));
        let status = child.wait().await;
        (out_cut || err_cut, status)
    })
    .await;

    match finished {
        Ok((truncated, status)) => {
            response.truncated = truncated;
            if let Ok(status) = status {
                response.exit_code = status.code();
                response.success = status.success();
            }
        }
        Err(_) => {
            response.timed_out = true;
            let _ = child.kill().await;
        }
    }
    let mut text = String::from_utf8_lossy(&out).into_owned();
    if !err.is_empty() {
        text.push_str(&String::from_utf8_lossy(&err));
    }
    if response.timed_out {
        text.push_str(&format!(
            "\nStopped after {} seconds.\n",
            invocation.timeout.as_secs()
        ));
    }
    response.output = text;
    response.duration_ms = started.elapsed().as_millis() as u64;
    response
}

/// Connect to `host:port` and report how long it took.
async fn tcp_connect(host: &str, port: u16) -> DiagnosticResponse {
    let started = Instant::now();
    let host = host.trim();
    let mut response = DiagnosticResponse {
        command: format!("tcp connect {host}:{port}"),
        ..Default::default()
    };
    let attempt = async {
        let addresses: Vec<_> = lookup_host((host, port)).await?.collect();
        if addresses.is_empty() {
            return Err(std::io::Error::other("no addresses found"));
        }
        let mut report = String::new();
        let mut reached = false;
        for address in addresses {
            let began = Instant::now();
            match TcpStream::connect(address).await {
                Ok(_) => {
                    reached = true;
                    report.push_str(&format!(
                        "{address}: open ({} ms)\n",
                        began.elapsed().as_millis()
                    ));
                }
                Err(error) => report.push_str(&format!("{address}: {error}\n")),
            }
        }
        Ok((reached, report))
    };
    match tokio::time::timeout(TCP_TIMEOUT, attempt).await {
        Ok(Ok((reached, report))) => {
            response.success = reached;
            response.output = report;
        }
        Ok(Err(error)) => response.output = format!("{host}: {error}\n"),
        Err(_) => {
            response.timed_out = true;
            response.output = format!("Timed out after {} seconds.\n", TCP_TIMEOUT.as_secs());
        }
    }
    response.duration_ms = started.elapsed().as_millis() as u64;
    response
}

async fn run_diagnostic(
    Json(request): Json<Req<RunDiagnostic>>,
) -> Result<Json<Res<RunDiagnostic>>, (StatusCode, Json<serde_json::Value>)> {
    let error = |status, message: &str| (status, Json(serde_json::json!({ "error": message })));
    request
        .validate()
        .map_err(|message| error(StatusCode::BAD_REQUEST, &message))?;
    let _slot = SLOTS.try_acquire().map_err(|_| {
        error(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many diagnostics are already running",
        )
    })?;
    let response = match (invocation(&request), &request) {
        (Some(invocation), _) => run(&invocation).await,
        (None, DiagnosticRequest::TcpConnect { host, port }) => tcp_connect(host, *port).await,
        (None, _) => unreachable!("every other tool runs a program"),
    };
    Ok(Json(response))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route(RunDiagnostic::PATH, post(run_diagnostic))
}

#[cfg(test)]
mod tests {
    use super::*;
    use keystone_core::diagnostics::DnsRecordType;

    fn args(request: &DiagnosticRequest) -> Vec<String> {
        invocation(request).unwrap().args
    }

    #[test]
    fn ping_arguments_put_the_host_last() {
        let request = DiagnosticRequest::Ping {
            host: " example.com ".into(),
            count: 3,
            family: IpFamily::V6,
            interface: Some("enp3s0".into()),
        };
        assert_eq!(
            args(&request),
            [
                "-n",
                "-c",
                "3",
                "-W",
                "2",
                "-6",
                "-I",
                "enp3s0",
                "example.com"
            ]
        );
    }

    #[test]
    fn traceroute_uses_tracepath_without_name_lookups() {
        let request = DiagnosticRequest::Traceroute {
            host: "192.0.2.1".into(),
            max_hops: 12,
            family: IpFamily::Any,
        };
        let invocation = invocation(&request).unwrap();
        assert_eq!(invocation.program, "tracepath");
        assert_eq!(invocation.args, ["-n", "-m", "12", "192.0.2.1"]);
    }

    #[test]
    fn dns_lookups_pass_the_resolver_as_at_server() {
        let request = DiagnosticRequest::DnsLookup {
            name: "example.com".into(),
            record_type: DnsRecordType::MX,
            server: Some("1.1.1.1".into()),
        };
        assert_eq!(args(&request), ["example.com", "MX", "@1.1.1.1"]);
    }

    #[test]
    fn an_address_is_looked_up_in_reverse() {
        let request = DiagnosticRequest::DnsLookup {
            name: "192.0.2.1".into(),
            record_type: DnsRecordType::A,
            server: None,
        };
        assert_eq!(args(&request), ["-x", "192.0.2.1"]);
    }

    #[test]
    fn the_tcp_check_runs_no_program() {
        let request = DiagnosticRequest::TcpConnect {
            host: "example.com".into(),
            port: 443,
        };
        assert!(invocation(&request).is_none());
    }

    fn shell(script: &str, timeout: Duration) -> Invocation {
        Invocation {
            program: "sh",
            args: vec!["-c".into(), script.into()],
            timeout,
        }
    }

    #[tokio::test]
    async fn output_and_exit_status_are_reported() {
        let ok = run(&shell("echo hello; echo oops >&2", Duration::from_secs(5))).await;
        assert!(ok.success);
        assert_eq!(ok.exit_code, Some(0));
        assert!(ok.output.contains("hello") && ok.output.contains("oops"));
        let failed = run(&shell("exit 3", Duration::from_secs(5))).await;
        assert!(!failed.success);
        assert_eq!(failed.exit_code, Some(3));
    }

    #[tokio::test]
    async fn a_slow_tool_is_stopped_and_its_partial_output_kept() {
        let started = Instant::now();
        let response = run(&shell("echo first; sleep 30", Duration::from_millis(300))).await;
        assert!(response.timed_out);
        assert!(!response.success);
        assert!(response.output.contains("first"));
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[tokio::test]
    async fn runaway_output_is_cut_to_the_limit() {
        let response = run(&shell("head -c 1000000 /dev/zero", Duration::from_secs(10))).await;
        assert!(response.truncated);
        assert!(response.output.len() <= MAX_OUTPUT_BYTES + 64);
    }

    #[tokio::test]
    async fn a_missing_program_is_explained() {
        let response = run(&Invocation {
            program: "keystone-no-such-tool",
            args: vec![],
            timeout: Duration::from_secs(1),
        })
        .await;
        assert!(!response.success);
        assert!(response.output.contains("not installed"));
    }

    #[tokio::test]
    async fn tcp_connect_reports_open_and_closed_ports() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let open = tcp_connect("127.0.0.1", port).await;
        assert!(open.success, "{}", open.output);
        // Bound but never listening: refuses connections, and keeps the port
        // from being handed to another test.
        let idle = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap();
        idle.bind(
            &"127.0.0.1:0"
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .into(),
        )
        .unwrap();
        let idle_port = idle.local_addr().unwrap().as_socket().unwrap().port();
        let closed = tcp_connect("127.0.0.1", idle_port).await;
        assert!(!closed.success, "{}", closed.output);
    }

    #[test]
    fn the_packaged_daemon_keeps_the_raw_socket_capability() {
        // ping and tracepath send ICMP through raw sockets.
        let unit = include_str!("../../packaging/arch/keystone-daemon.service");
        for key in ["CapabilityBoundingSet=", "AmbientCapabilities="] {
            let line = unit
                .lines()
                .find(|line| line.starts_with(key))
                .unwrap_or_else(|| panic!("{key} is missing"));
            assert!(line.contains("CAP_NET_RAW"), "{line}");
        }
        assert!(
            !unit
                .lines()
                .any(|line| line.starts_with("RestrictAddressFamilies=")),
            "diagnostics need AF_INET, AF_INET6 and AF_PACKET-free raw sockets"
        );
    }
}
