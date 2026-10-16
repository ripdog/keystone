//! Network diagnostics run on demand from the web UI: ping, traceroute, DNS
//! lookup and TCP port checks.
//!
//! The tools are `ping` and `tracepath` (iputils) and `drill` (ldns). They run
//! without a shell, with arguments built from fields that
//! [`DiagnosticRequest::validate`] has already checked, under a time limit and
//! an output limit, and at most [`MAX_CONCURRENT`] at once.
//!
//! A run is a job. `POST /diagnostics/run` starts it and returns its id; the
//! output grows in memory as the tool prints, and the page reads it with
//! `GET /diagnostics/jobs/{id}?after=<offset>` until the outcome is set.
//! `POST /diagnostics/jobs/{id}/stop` ends a run early. Finished jobs are kept
//! briefly so a reload can still show them.
//!
//! The daemon's sandbox needs nothing extra: ping and tracepath open raw
//! sockets (`CAP_NET_RAW`, already granted), and nothing is written to disk.

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use axum::{
    Json, Router,
    extract::{Path, Query},
    http::StatusCode,
    routing::{get, post},
};
use keystone_core::api::{Endpoint, Req, Res, StartDiagnostic, StopDiagnostic};
use keystone_core::diagnostics::{
    DiagnosticOutcome, DiagnosticProgress, DiagnosticRequest, DiagnosticStarted, IpFamily,
};
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::net::{TcpStream, lookup_host};
use tokio::process::Command;
use tokio::sync::{Notify, Semaphore};

use crate::AppState;

/// Diagnostics that may run at the same time.
const MAX_CONCURRENT: usize = 4;
/// Longest output kept; the rest is dropped.
const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const PING_TIMEOUT: Duration = Duration::from_secs(40);
const TRACEROUTE_TIMEOUT: Duration = Duration::from_secs(90);
const DNS_TIMEOUT: Duration = Duration::from_secs(20);
const TCP_TIMEOUT: Duration = Duration::from_secs(5);

/// Finished jobs are dropped after this long.
const FINISHED_JOB_TTL: Duration = Duration::from_secs(10 * 60);
/// Most jobs kept, running or finished.
const MAX_JOBS: usize = 50;

static SLOTS: Semaphore = Semaphore::const_new(MAX_CONCURRENT);
static JOBS: LazyLock<Mutex<HashMap<String, Arc<Job>>>> = LazyLock::new(Mutex::default);

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

/// One diagnostic run and what it has printed so far.
struct Job {
    command: String,
    started: Instant,
    stop: Notify,
    state: Mutex<JobState>,
}

#[derive(Default)]
struct JobState {
    output: String,
    truncated: bool,
    outcome: Option<DiagnosticOutcome>,
    finished_at: Option<Instant>,
}

/// How a run ended, before it is turned into a [`DiagnosticOutcome`].
#[derive(Default)]
struct Ending {
    success: bool,
    exit_code: Option<i32>,
    timed_out: bool,
    stopped: bool,
}

impl Job {
    fn new(command: String) -> Arc<Self> {
        Arc::new(Job {
            command,
            started: Instant::now(),
            stop: Notify::new(),
            state: Mutex::default(),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, JobState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Add output, keeping at most [`MAX_OUTPUT_BYTES`] in total.
    fn append(&self, text: &str) {
        let mut state = self.state();
        let room = MAX_OUTPUT_BYTES.saturating_sub(state.output.len());
        if text.len() > room {
            state.truncated = true;
        }
        let mut end = text.len().min(room);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        state.output.push_str(&text[..end]);
    }

    fn finish(&self, ending: Ending) {
        let mut state = self.state();
        if state.outcome.is_some() {
            return;
        }
        state.outcome = Some(DiagnosticOutcome {
            success: ending.success,
            exit_code: ending.exit_code,
            duration_ms: self.started.elapsed().as_millis() as u64,
            timed_out: ending.timed_out,
            stopped: ending.stopped,
            truncated: state.truncated,
        });
        state.finished_at = Some(Instant::now());
    }

    /// Output from byte offset `after` (clamped to a character boundary).
    fn progress(&self, after: u64) -> DiagnosticProgress {
        let state = self.state();
        let mut start = (after as usize).min(state.output.len());
        while !state.output.is_char_boundary(start) {
            start -= 1;
        }
        DiagnosticProgress {
            command: self.command.clone(),
            output: state.output[start..].to_owned(),
            next: state.output.len() as u64,
            outcome: state.outcome.clone(),
        }
    }
}

/// Append every line of `stream` to the job. Lines are decoded one at a time,
/// so a multi-byte character is never split between two reads.
async fn pump(stream: impl AsyncRead + Unpin, job: &Job) {
    let mut reader = BufReader::new(stream);
    let mut line = Vec::new();
    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line).await {
            Ok(0) | Err(_) => return,
            Ok(_) => job.append(&String::from_utf8_lossy(&line)),
        }
    }
}

/// Run `invocation`, feeding its output to the job. The process is killed on
/// timeout and when the job is stopped.
async fn run(job: &Job, invocation: &Invocation) {
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
            job.append(&if error.kind() == std::io::ErrorKind::NotFound {
                format!("{} is not installed on this router.\n", invocation.program)
            } else {
                format!("Could not start {}: {error}\n", invocation.program)
            });
            job.finish(Ending::default());
            return;
        }
    };
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        job.append("Could not capture output.\n");
        job.finish(Ending::default());
        return;
    };

    enum Event {
        Exited(std::io::Result<std::process::ExitStatus>),
        TimedOut,
        Stopped,
    }
    let event = {
        let work = async {
            tokio::join!(pump(stdout, job), pump(stderr, job));
            child.wait().await
        };
        tokio::select! {
            result = tokio::time::timeout(invocation.timeout, work) => match result {
                Ok(status) => Event::Exited(status),
                Err(_) => Event::TimedOut,
            },
            _ = job.stop.notified() => Event::Stopped,
        }
    };
    match event {
        Event::Exited(status) => {
            let status = status.ok();
            job.finish(Ending {
                success: status.is_some_and(|s| s.success()),
                exit_code: status.and_then(|s| s.code()),
                ..Ending::default()
            });
        }
        Event::TimedOut => {
            let _ = child.kill().await;
            job.append(&format!(
                "\nStopped after {} seconds.\n",
                invocation.timeout.as_secs()
            ));
            job.finish(Ending {
                timed_out: true,
                ..Ending::default()
            });
        }
        Event::Stopped => {
            let _ = child.kill().await;
            job.append("\nStopped.\n");
            job.finish(Ending {
                stopped: true,
                ..Ending::default()
            });
        }
    }
}

/// Connect to `host:port`, one address at a time, reporting each result.
async fn tcp_connect(job: &Job, host: &str, port: u16) {
    let host = host.trim();
    let attempt = async {
        let addresses: Vec<_> = match lookup_host((host, port)).await {
            Ok(addresses) => addresses.collect(),
            Err(error) => {
                job.append(&format!("{host}: {error}\n"));
                return false;
            }
        };
        if addresses.is_empty() {
            job.append(&format!("{host}: no addresses found\n"));
            return false;
        }
        let mut reached = false;
        for address in addresses {
            let began = Instant::now();
            match TcpStream::connect(address).await {
                Ok(_) => {
                    reached = true;
                    job.append(&format!(
                        "{address}: open ({} ms)\n",
                        began.elapsed().as_millis()
                    ));
                }
                Err(error) => job.append(&format!("{address}: {error}\n")),
            }
        }
        reached
    };
    tokio::select! {
        result = tokio::time::timeout(TCP_TIMEOUT, attempt) => match result {
            Ok(success) => job.finish(Ending { success, ..Ending::default() }),
            Err(_) => {
                job.append(&format!("Timed out after {} seconds.\n", TCP_TIMEOUT.as_secs()));
                job.finish(Ending { timed_out: true, ..Ending::default() });
            }
        },
        _ = job.stop.notified() => {
            job.append("\nStopped.\n");
            job.finish(Ending { stopped: true, ..Ending::default() });
        }
    }
}

/// Drop old finished jobs, then the oldest finished ones beyond [`MAX_JOBS`].
fn prune(jobs: &mut HashMap<String, Arc<Job>>) {
    let now = Instant::now();
    let finished_at = |job: &Arc<Job>| job.state().finished_at;
    jobs.retain(|_, job| finished_at(job).is_none_or(|at| now - at < FINISHED_JOB_TTL));
    while jobs.len() >= MAX_JOBS {
        let oldest = jobs
            .iter()
            .filter_map(|(id, job)| finished_at(job).map(|at| (at, id.clone())))
            .min();
        match oldest {
            Some((_, id)) => jobs.remove(&id),
            None => break,
        };
    }
}

type ApiError = (StatusCode, Json<serde_json::Value>);

fn api_error(status: StatusCode, message: &str) -> ApiError {
    (status, Json(serde_json::json!({ "error": message })))
}

fn find(id: &str) -> Result<Arc<Job>, ApiError> {
    JOBS.lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(id)
        .cloned()
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "No such diagnostic"))
}

async fn start_diagnostic(
    Json(request): Json<Req<StartDiagnostic>>,
) -> Result<Json<Res<StartDiagnostic>>, ApiError> {
    request
        .validate()
        .map_err(|message| api_error(StatusCode::BAD_REQUEST, &message))?;
    let slot = SLOTS.try_acquire().map_err(|_| {
        api_error(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many diagnostics are already running",
        )
    })?;
    let program = invocation(&request);
    let command = match (&program, &request) {
        (Some(program), _) => program.display(),
        (None, DiagnosticRequest::TcpConnect { host, port }) => {
            format!("tcp connect {}:{port}", host.trim())
        }
        (None, _) => unreachable!("every other tool runs a program"),
    };
    let job = Job::new(command);
    let id = uuid::Uuid::new_v4().simple().to_string();
    {
        let mut jobs = JOBS.lock().unwrap_or_else(|e| e.into_inner());
        prune(&mut jobs);
        jobs.insert(id.clone(), job.clone());
    }
    tokio::spawn(async move {
        let _slot = slot;
        match (program, request) {
            (Some(program), _) => run(&job, &program).await,
            (None, DiagnosticRequest::TcpConnect { host, port }) => {
                tcp_connect(&job, &host, port).await
            }
            (None, _) => {}
        }
    });
    Ok(Json(DiagnosticStarted { id }))
}

#[derive(Debug, Deserialize)]
struct ProgressQuery {
    #[serde(default)]
    after: u64,
}

async fn get_progress(
    Path(id): Path<String>,
    Query(query): Query<ProgressQuery>,
) -> Result<Json<DiagnosticProgress>, ApiError> {
    Ok(Json(find(&id)?.progress(query.after)))
}

async fn stop_diagnostic(
    Path(id): Path<String>,
    Json(_): Json<Req<StopDiagnostic>>,
) -> Result<Json<Res<StopDiagnostic>>, ApiError> {
    let job = find(&id)?;
    job.stop.notify_one();
    // Shows the run as it is now; the page keeps polling until it has ended.
    Ok(Json(job.progress(u64::MAX)))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(StartDiagnostic::PATH, post(start_diagnostic))
        .route("/diagnostics/jobs/{id}", get(get_progress))
        .route(StopDiagnostic::PATH, post(stop_diagnostic))
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

    async fn run_to_end(invocation: &Invocation) -> (String, DiagnosticOutcome) {
        let job = Job::new(invocation.display());
        run(&job, invocation).await;
        let progress = job.progress(0);
        (progress.output, progress.outcome.expect("run has ended"))
    }

    #[tokio::test]
    async fn output_and_exit_status_are_reported() {
        let (output, ok) =
            run_to_end(&shell("echo hello; echo oops >&2", Duration::from_secs(5))).await;
        assert!(ok.success);
        assert_eq!(ok.exit_code, Some(0));
        assert!(output.contains("hello") && output.contains("oops"));
        let (_, failed) = run_to_end(&shell("exit 3", Duration::from_secs(5))).await;
        assert!(!failed.success);
        assert_eq!(failed.exit_code, Some(3));
    }

    #[tokio::test]
    async fn output_can_be_read_while_the_tool_is_still_running() {
        let job = Job::new("test".into());
        let task = {
            let job = job.clone();
            tokio::spawn(async move {
                run(
                    &job,
                    &shell("echo first; sleep 1; echo second", Duration::from_secs(10)),
                )
                .await
            })
        };
        let mut offset = 0;
        let mut seen_while_running = false;
        let mut text = String::new();
        loop {
            let progress = job.progress(offset);
            offset = progress.next;
            text.push_str(&progress.output);
            if progress.outcome.is_some() {
                break;
            }
            seen_while_running |= text.contains("first") && !text.contains("second");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        task.await.unwrap();
        assert!(seen_while_running, "first line was not visible early");
        assert_eq!(text, "first\nsecond\n");
    }

    #[tokio::test]
    async fn a_slow_tool_is_stopped_and_its_partial_output_kept() {
        let started = Instant::now();
        let (output, outcome) =
            run_to_end(&shell("echo first; sleep 30", Duration::from_millis(300))).await;
        assert!(outcome.timed_out);
        assert!(!outcome.success);
        assert!(output.contains("first"));
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[tokio::test]
    async fn a_running_tool_can_be_stopped() {
        let job = Job::new("test".into());
        let task = {
            let job = job.clone();
            tokio::spawn(async move {
                run(
                    &job,
                    &shell("echo first; sleep 30", Duration::from_secs(60)),
                )
                .await
            })
        };
        while !job.progress(0).output.contains("first") {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        job.stop.notify_one();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("stop took too long")
            .unwrap();
        let outcome = job.progress(0).outcome.unwrap();
        assert!(outcome.stopped && !outcome.timed_out && !outcome.success);
    }

    #[tokio::test]
    async fn runaway_output_is_cut_to_the_limit() {
        let (output, outcome) = run_to_end(&shell(
            "head -c 1000000 /dev/zero | tr '\\0' x; echo",
            Duration::from_secs(10),
        ))
        .await;
        assert!(outcome.truncated);
        assert!(output.len() <= MAX_OUTPUT_BYTES);
    }

    #[test]
    fn appending_never_splits_a_character() {
        let job = Job::new("test".into());
        job.append(&"é".repeat(MAX_OUTPUT_BYTES));
        let progress = job.progress(0);
        assert!(progress.output.len() <= MAX_OUTPUT_BYTES);
        assert!(job.state().truncated);
        // An offset inside a character reads from the character's start.
        assert!(job.progress(1).output.starts_with('é'));
    }

    #[tokio::test]
    async fn a_missing_program_is_explained() {
        let (output, outcome) = run_to_end(&Invocation {
            program: "keystone-no-such-tool",
            args: vec![],
            timeout: Duration::from_secs(1),
        })
        .await;
        assert!(!outcome.success);
        assert!(output.contains("not installed"));
    }

    #[tokio::test]
    async fn tcp_connect_reports_open_and_closed_ports() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let job = Job::new("test".into());
        tcp_connect(&job, "127.0.0.1", port).await;
        let open = job.progress(0);
        assert!(open.outcome.as_ref().unwrap().success, "{}", open.output);
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
        let job = Job::new("test".into());
        tcp_connect(&job, "127.0.0.1", idle_port).await;
        let closed = job.progress(0);
        assert!(
            !closed.outcome.as_ref().unwrap().success,
            "{}",
            closed.output
        );
    }

    #[test]
    fn finished_jobs_are_pruned_but_running_ones_are_kept() {
        let mut jobs = HashMap::new();
        let running = Job::new("running".into());
        jobs.insert("running".to_owned(), running);
        for n in 0..MAX_JOBS {
            let job = Job::new(format!("done {n}"));
            job.finish(Ending::default());
            jobs.insert(format!("done{n}"), job);
        }
        prune(&mut jobs);
        assert!(jobs.len() < MAX_JOBS);
        assert!(jobs.contains_key("running"));
    }

    async fn call(
        app: &Router,
        method: &str,
        uri: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        use axum::body::Body;
        use tower::ServiceExt;
        let request = axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    #[tokio::test]
    async fn a_diagnostic_is_started_and_read_over_http() {
        let app: Router = routes().with_state(Arc::new(crate::AppState::new(
            Arc::new(crate::auth::AuthManager::new(vec![7; 32])),
            crate::db::Database::new_in_memory().await.unwrap(),
            Arc::new(crate::firewall::FirewallApplyManager::new(
                Arc::new(crate::db::Database::new_in_memory().await.unwrap()),
                Arc::new(crate::networkd::NetworkdApplyManager::system()),
            )),
        )));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (status, started) = call(
            &app,
            "POST",
            "/diagnostics/run",
            serde_json::json!({"tool": "tcp_connect", "host": "127.0.0.1", "port": port}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let id = started["id"].as_str().unwrap().to_owned();
        let mut progress = serde_json::Value::Null;
        for _ in 0..100 {
            (_, progress) = call(
                &app,
                "GET",
                &format!("/diagnostics/jobs/{id}?after=0"),
                serde_json::json!({}),
            )
            .await;
            if !progress["outcome"].is_null() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(progress["outcome"]["success"], true, "{progress}");
        assert!(progress["output"].as_str().unwrap().contains("open"));

        let (status, _) = call(&app, "GET", "/diagnostics/jobs/nope", serde_json::json!({})).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = call(
            &app,
            "POST",
            "/diagnostics/run",
            serde_json::json!({"tool": "ping", "host": "-f", "count": 1}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
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
