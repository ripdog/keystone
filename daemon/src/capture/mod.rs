//! Packet capture with tcpdump, for the diagnostics page.
//!
//! Two processes do the work so that nothing parses packets with privilege:
//!
//! * the capture process, `tcpdump -w -`, inherits the daemon's capabilities,
//!   opens the interface and writes raw pcap to a pipe. With `-w` it decodes
//!   nothing.
//! * the viewer, `tcpdump -r -`, decodes those packets into text lines. It runs
//!   as `nobody` with no capabilities and no supplementary groups, through
//!   `setpriv`, because packet dissectors have a history of memory bugs.
//!
//! The daemon copies the capture pipe into a file under `/run/keystone` and
//! feeds the viewer from that file, so a slow reader of the live view can never
//! make the capture drop packets. The filter is built from typed clauses (see
//! `keystone_core::capture`) and handed over as one argument, never through a
//! shell.
//!
//! One capture exists at a time. Its file stays until the next capture starts,
//! it is discarded, or the daemon restarts.

pub mod pcap;
pub mod routes;
#[cfg(test)]
pub(crate) mod test_support;

use std::collections::VecDeque;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use keystone_core::capture::{
    ANY_INTERFACE, CaptureInfo, CaptureLine, CapturePacketsResponse, CaptureRequest, CaptureState,
    MAX_CAPTURE_BYTES,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::{Mutex, Notify};
use tracing::{info, warn};

use self::pcap::PcapCounter;

/// Directory for the capture file. `/run/keystone` is the daemon's
/// `RuntimeDirectory=`, so it exists and is writable inside the sandbox.
pub const CAPTURE_DIR: &str = "/run/keystone/capture";
const CAPTURE_FILE_NAME: &str = "capture.pcap";
/// Decoded lines kept for the live view. Older lines are dropped, never the
/// capture file.
const MAX_BUFFERED_LINES: usize = 5000;
/// Longest decoded line kept.
const MAX_LINE_BYTES: usize = 1000;
/// Lines returned by one poll.
const MAX_LINES_PER_POLL: usize = 1000;
/// Uid and gid the viewer runs as.
const UNPRIVILEGED_ID: u32 = 65534;
/// How long a stop request waits for the capture to wind down.
const STOP_WAIT: Duration = Duration::from_secs(3);
/// Smallest file that holds a pcap header and so can be downloaded.
const MIN_PCAP_BYTES: u64 = 24;

/// Paths of the things a capture touches. Tests point these at a scratch
/// directory and stand-in programs.
#[derive(Clone)]
pub struct CaptureEnv {
    pub dir: PathBuf,
    pub tcpdump: PathBuf,
    pub setpriv: PathBuf,
    pub net_dir: PathBuf,
}

impl CaptureEnv {
    pub fn system() -> Self {
        Self {
            dir: PathBuf::from(CAPTURE_DIR),
            tcpdump: PathBuf::from("/usr/bin/tcpdump"),
            setpriv: PathBuf::from("/usr/bin/setpriv"),
            net_dir: PathBuf::from("/sys/class/net"),
        }
    }

    pub fn pcap_path(&self) -> PathBuf {
        self.dir.join(CAPTURE_FILE_NAME)
    }
}

#[derive(Debug)]
pub enum CaptureError {
    Invalid(String),
    NotFound(String),
    Conflict(String),
    Internal(anyhow::Error),
}

impl From<std::io::Error> for CaptureError {
    fn from(error: std::io::Error) -> Self {
        CaptureError::Internal(error.into())
    }
}

struct Shared {
    info: CaptureInfo,
    lines: VecDeque<CaptureLine>,
    next_seq: u64,
    /// Why a stop was asked for by the daemon itself rather than the user.
    stop_reason: Option<String>,
}

struct Session {
    shared: StdMutex<Shared>,
    /// A stop was requested: by the user, or by the daemon at the size limit.
    stop: Notify,
    /// The capture file grew; wakes the task that feeds the viewer.
    grew: Notify,
    /// The capture pipe reached its end, so the file is complete.
    written: AtomicBool,
}

impl Session {
    fn lock(&self) -> std::sync::MutexGuard<'_, Shared> {
        self.shared
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn push_line(&self, text: String) {
        let mut shared = self.lock();
        let seq = shared.next_seq;
        shared.next_seq += 1;
        shared.lines.push_back(CaptureLine { seq, text });
        while shared.lines.len() > MAX_BUFFERED_LINES {
            shared.lines.pop_front();
        }
    }
}

pub struct CaptureManager {
    env: CaptureEnv,
    current: Mutex<Option<Arc<Session>>>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Arguments for the capture process. The filter is one argument after `--`.
pub fn capture_args(request: &CaptureRequest, expression: &str) -> Vec<String> {
    let mut args: Vec<String> = [
        "-i",
        request.interface.as_str(),
        // No promiscuous mode: a router sees the traffic it forwards, and
        // switching a LAN port to promiscuous would change the link.
        "-p",
        // Deliver each packet as it arrives instead of in kernel-sized batches.
        "--immediate-mode",
        "-U",
        "-s",
    ]
    .iter()
    .map(|arg| arg.to_string())
    .collect();
    args.push(request.snaplen.to_string());
    args.push("-c".into());
    args.push(request.max_packets.to_string());
    // This process only writes raw packets, so there is nothing to drop
    // privileges for. Naming root stops tcpdump choosing a user itself.
    args.extend(["-Z", "root", "-w", "-"].map(String::from));
    if !expression.is_empty() {
        args.push("--".into());
        args.push(expression.to_string());
    }
    args
}

/// Arguments for the viewer, run through `setpriv`.
pub fn viewer_args(tcpdump: &Path) -> Vec<String> {
    vec![
        format!("--reuid={UNPRIVILEGED_ID}"),
        format!("--regid={UNPRIVILEGED_ID}"),
        "--clear-groups".into(),
        "--no-new-privs".into(),
        tcpdump.display().to_string(),
        "-r".into(),
        "-".into(),
        "-n".into(),
        "-l".into(),
    ]
}

/// Parse tcpdump's "N packets dropped by kernel" summary line.
fn dropped_by_kernel(line: &str) -> Option<u64> {
    let (count, rest) = line.trim().split_once(' ')?;
    rest.starts_with("packets dropped by kernel")
        .then(|| count.parse().ok())
        .flatten()
}

impl CaptureManager {
    pub fn new(env: CaptureEnv) -> Arc<Self> {
        // A file left by an earlier run of the daemon is of no use to anyone.
        let _ = std::fs::remove_file(env.pcap_path());
        Arc::new(Self {
            env,
            current: Mutex::new(None),
        })
    }

    /// Interfaces to offer, including the all-interfaces pseudo-device.
    pub fn interfaces(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.env.net_dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| keystone_core::validation::interface_name(name).is_ok())
            .collect();
        names.sort();
        names.insert(0, ANY_INTERFACE.to_string());
        names
    }

    pub async fn info(&self) -> Option<CaptureInfo> {
        let current = self.current.lock().await;
        current.as_ref().map(|session| session.lock().info.clone())
    }

    pub async fn start(
        self: &Arc<Self>,
        request: CaptureRequest,
    ) -> Result<CaptureInfo, CaptureError> {
        let expression = request.validate().map_err(CaptureError::Invalid)?;
        if request.interface != ANY_INTERFACE && !self.env.net_dir.join(&request.interface).exists()
        {
            return Err(CaptureError::NotFound(format!(
                "interface {} does not exist",
                request.interface
            )));
        }

        let mut current = self.current.lock().await;
        if let Some(session) = current.as_ref()
            && session.lock().info.state == CaptureState::Running
        {
            return Err(CaptureError::Conflict(
                "a capture is already running; stop it first".into(),
            ));
        }

        tokio::fs::create_dir_all(&self.env.dir).await?;
        set_private(&self.env.dir, 0o700)?;
        let path = self.env.pcap_path();
        match tokio::fs::remove_file(&path).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        // Created here, with owner-only permissions, before tcpdump writes to it.
        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .await?;

        let info = CaptureInfo {
            request: request.clone(),
            expression: expression.clone(),
            state: CaptureState::Running,
            started_at: now(),
            ended_at: None,
            packets: 0,
            bytes: 0,
            dropped_by_kernel: None,
            message: None,
            has_pcap: false,
        };
        let session = Arc::new(Session {
            shared: StdMutex::new(Shared {
                info: info.clone(),
                lines: VecDeque::new(),
                next_seq: 0,
                stop_reason: None,
            }),
            stop: Notify::new(),
            grew: Notify::new(),
            written: AtomicBool::new(false),
        });
        *current = Some(session.clone());
        drop(current);

        let env = self.env.clone();
        tokio::spawn(async move {
            let outcome = run(&env, &session, &request, &expression, file).await;
            finish(&session, outcome, &env.pcap_path());
        });
        Ok(info)
    }

    /// Ask the running capture to stop and wait briefly for it to do so.
    pub async fn stop(&self) -> Result<CaptureInfo, CaptureError> {
        let session = self
            .current
            .lock()
            .await
            .clone()
            .ok_or_else(|| CaptureError::NotFound("no capture".into()))?;
        if session.lock().info.state == CaptureState::Running {
            session.stop.notify_one();
            let deadline = tokio::time::Instant::now() + STOP_WAIT;
            while session.lock().info.state == CaptureState::Running
                && tokio::time::Instant::now() < deadline
            {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
        let info = session.lock().info.clone();
        Ok(info)
    }

    /// Delete a finished capture and its file.
    pub async fn discard(&self) -> Result<(), CaptureError> {
        let mut current = self.current.lock().await;
        if let Some(session) = current.as_ref()
            && session.lock().info.state == CaptureState::Running
        {
            return Err(CaptureError::Conflict("stop the capture first".into()));
        }
        *current = None;
        match tokio::fs::remove_file(self.env.pcap_path()).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Decoded lines from sequence number `since`, for the live view.
    pub async fn packets(&self, since: u64) -> CapturePacketsResponse {
        let current = self.current.lock().await;
        let Some(session) = current.as_ref() else {
            return CapturePacketsResponse {
                lines: Vec::new(),
                next: since,
                lost: 0,
                info: None,
            };
        };
        let shared = session.lock();
        let first = shared
            .lines
            .front()
            .map(|line| line.seq)
            .unwrap_or(shared.next_seq);
        let lines: Vec<CaptureLine> = shared
            .lines
            .iter()
            .filter(|line| line.seq >= since)
            .take(MAX_LINES_PER_POLL)
            .cloned()
            .collect();
        let next = lines
            .last()
            .map(|line| line.seq + 1)
            .unwrap_or(since.max(first));
        CapturePacketsResponse {
            lines,
            next,
            lost: first.saturating_sub(since),
            info: Some(shared.info.clone()),
        }
    }

    /// Path of the finished capture's file, for download.
    pub async fn pcap_for_download(&self) -> Result<(PathBuf, CaptureInfo), CaptureError> {
        let info = self
            .info()
            .await
            .ok_or_else(|| CaptureError::NotFound("no capture".into()))?;
        if info.state == CaptureState::Running {
            return Err(CaptureError::Conflict(
                "the capture is still running; stop it to download".into(),
            ));
        }
        if !info.has_pcap {
            return Err(CaptureError::NotFound("the capture has no packets".into()));
        }
        Ok((self.env.pcap_path(), info))
    }
}

fn set_private(path: &Path, mode: u32) -> std::io::Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// How the capture process ended.
enum Outcome {
    /// It exited by itself, successfully.
    Completed,
    /// It exited by itself with an error.
    Failed(String),
    /// It was stopped: by the user, the time limit or the size limit.
    Stopped(String),
    /// A process could not be started.
    Unavailable(String),
}

/// Run the capture and the viewer until the capture ends.
async fn run(
    env: &CaptureEnv,
    session: &Arc<Session>,
    request: &CaptureRequest,
    expression: &str,
    file: tokio::fs::File,
) -> Outcome {
    let mut capture = match Command::new(&env.tcpdump)
        .args(capture_args(request, expression))
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            return Outcome::Unavailable(format!(
                "could not start {}: {error}. Install the tcpdump package.",
                env.tcpdump.display()
            ));
        }
    };
    let mut viewer = match Command::new(&env.setpriv)
        .args(viewer_args(&env.tcpdump))
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            let _ = capture.kill().await;
            return Outcome::Unavailable(format!(
                "could not start {}: {error}. It is part of util-linux.",
                env.setpriv.display()
            ));
        }
    };

    let (Some(capture_out), Some(capture_err), Some(viewer_in), Some(viewer_out)) = (
        capture.stdout.take(),
        capture.stderr.take(),
        viewer.stdin.take(),
        viewer.stdout.take(),
    ) else {
        return Outcome::Unavailable("a capture pipe was not created".into());
    };

    let pump = tokio::spawn(pump(session.clone(), capture_out, file));
    let errors = tokio::spawn(read_errors(session.clone(), capture_err));
    let feeder = tokio::spawn(feed_viewer(session.clone(), env.pcap_path(), viewer_in));
    let reader = tokio::spawn(read_viewer(session.clone(), viewer_out));

    let limit = Duration::from_secs(u64::from(request.max_seconds));
    let ended = tokio::select! {
        status = capture.wait() => Ok(status),
        () = tokio::time::sleep(limit) => Err("time limit reached".to_string()),
        () = session.stop.notified() => Err(
            session.lock().stop_reason.clone().unwrap_or_else(|| "stopped".to_string()),
        ),
    };
    let outcome = match ended {
        Ok(status) => match status {
            Ok(status) if status.success() => Outcome::Completed,
            Ok(status) => Outcome::Failed(format!("tcpdump exited with {status}")),
            Err(error) => Outcome::Failed(format!("waiting for tcpdump failed: {error}")),
        },
        Err(reason) => {
            // Every packet is flushed to the pipe as it arrives (-U), so
            // killing loses nothing that was captured.
            let _ = capture.kill().await;
            Outcome::Stopped(reason)
        }
    };

    // The pipes close with the process, so each task normally ends by itself
    // once it has drained them. A pipe held open by something else must not
    // keep the capture "running" for ever, so the wait is bounded.
    tokio::join!(join_bounded(pump), join_bounded(errors));
    // Whatever reached the file is all there will be; let the feeder finish.
    session.written.store(true, Ordering::SeqCst);
    session.grew.notify_one();
    tokio::join!(join_bounded(feeder), join_bounded(reader));
    if tokio::time::timeout(Duration::from_secs(10), viewer.wait())
        .await
        .is_err()
    {
        let _ = viewer.kill().await;
    }
    match outcome {
        Outcome::Failed(message) => {
            let detail = session.lock().info.message.clone();
            Outcome::Failed(detail.unwrap_or(message))
        }
        other => other,
    }
}

/// Wait a short while for a task to end, then abort it.
async fn join_bounded<T>(mut task: tokio::task::JoinHandle<T>) {
    if tokio::time::timeout(Duration::from_secs(2), &mut task)
        .await
        .is_err()
    {
        task.abort();
    }
}

/// Copy the capture pipe into the file, counting packets and enforcing the
/// size limit.
async fn pump(
    session: Arc<Session>,
    mut source: tokio::process::ChildStdout,
    mut file: tokio::fs::File,
) {
    let mut counter = PcapCounter::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = match source.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        total += read as u64;
        if file.write_all(&buffer[..read]).await.is_err() {
            session.lock().stop_reason = Some("could not write the capture file".into());
            session.stop.notify_one();
            break;
        }
        counter.feed(&buffer[..read]);
        if counter.is_invalid() {
            session.lock().stop_reason = Some("tcpdump did not produce a pcap stream".into());
            session.stop.notify_one();
            break;
        }
        {
            let mut shared = session.lock();
            shared.info.bytes = total;
            shared.info.packets = counter.packets();
        }
        session.grew.notify_one();
        if total >= MAX_CAPTURE_BYTES {
            session.lock().stop_reason = Some(format!(
                "size limit of {} MiB reached",
                MAX_CAPTURE_BYTES / (1024 * 1024)
            ));
            session.stop.notify_one();
            break;
        }
    }
    let _ = file.flush().await;
    session.written.store(true, Ordering::SeqCst);
    session.grew.notify_one();
}

/// Keep the end of the capture process's messages and its drop count.
async fn read_errors(session: Arc<Session>, stderr: tokio::process::ChildStderr) {
    let mut lines = BufReader::new(stderr).lines();
    let mut tail: VecDeque<String> = VecDeque::new();
    while let Ok(Some(line)) = lines.next_line().await {
        if let Some(dropped) = dropped_by_kernel(&line) {
            session.lock().info.dropped_by_kernel = Some(dropped);
        }
        // The "listening on" and count lines are not errors.
        if line.contains("listening on")
            || line.contains("packets captured")
            || line.contains("packets received by filter")
            || line.contains("packets dropped by kernel")
            || line.trim().is_empty()
        {
            continue;
        }
        tail.push_back(line.chars().take(300).collect());
        if tail.len() > 3 {
            tail.pop_front();
        }
    }
    if !tail.is_empty() {
        session.lock().info.message = Some(tail.into_iter().collect::<Vec<_>>().join("; "));
    }
}

/// Stream the capture file to the viewer as it grows.
async fn feed_viewer(
    session: Arc<Session>,
    path: PathBuf,
    mut viewer_in: tokio::process::ChildStdin,
) {
    let Ok(mut file) = tokio::fs::File::open(&path).await else {
        return;
    };
    let mut offset = 0u64;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        // Read the flag first: data written after it was cleared is read next
        // time round, data written before it is already in the file.
        let complete = session.written.load(Ordering::SeqCst);
        if file.seek(std::io::SeekFrom::Start(offset)).await.is_err() {
            return;
        }
        match file.read(&mut buffer).await {
            Ok(read) if read > 0 => {
                offset += read as u64;
                if viewer_in.write_all(&buffer[..read]).await.is_err() {
                    // The viewer is gone; the capture itself carries on.
                    return;
                }
            }
            Ok(_) if complete => return,
            Ok(_) => {
                tokio::select! {
                    () = session.grew.notified() => {}
                    () = tokio::time::sleep(Duration::from_millis(250)) => {}
                }
            }
            Err(_) => return,
        }
    }
}

/// Collect the viewer's decoded lines.
async fn read_viewer(session: Arc<Session>, stdout: tokio::process::ChildStdout) {
    let mut reader = BufReader::new(stdout);
    let mut raw = Vec::new();
    loop {
        raw.clear();
        match reader.read_until(b'\n', &mut raw).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let text = String::from_utf8_lossy(&raw);
        let text = text.trim_end_matches(['\r', '\n']);
        if text.is_empty() {
            continue;
        }
        let mut line: String = text.chars().take(MAX_LINE_BYTES).collect();
        if text.chars().count() > MAX_LINE_BYTES {
            line.push('…');
        }
        session.push_line(line);
    }
}

/// Record how the capture ended.
fn finish(session: &Session, outcome: Outcome, path: &Path) {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let mut shared = session.lock();
    shared.info.ended_at = Some(now());
    shared.info.has_pcap = size >= MIN_PCAP_BYTES && shared.info.packets > 0;
    let (state, message) = match outcome {
        // tcpdump's notes ("listening on ...") are not worth showing when
        // nothing went wrong.
        Outcome::Completed => (CaptureState::Finished, None),
        Outcome::Stopped(reason) => (CaptureState::Stopped, Some(reason)),
        Outcome::Failed(message) | Outcome::Unavailable(message) => {
            (CaptureState::Failed, Some(message))
        }
    };
    shared.info.state = state;
    shared.info.message = message;
    info!(
        "Capture ended: {:?}, {} packets, {} bytes",
        shared.info.state, shared.info.packets, shared.info.bytes
    );
    if shared.info.state == CaptureState::Failed {
        warn!(
            "Capture failed: {}",
            shared.info.message.as_deref().unwrap_or("unknown error")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use keystone_core::capture::{CaptureClause, CaptureDirection, FilterTerm};

    async fn wait_until_done(manager: &CaptureManager) -> CaptureInfo {
        for _ in 0..200 {
            let info = manager.info().await.unwrap();
            if info.state != CaptureState::Running {
                return info;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("capture did not end");
    }

    #[test]
    fn the_filter_is_one_argument_after_a_separator() {
        let filter = vec![CaptureClause {
            negate: false,
            term: FilterTerm::Host {
                direction: CaptureDirection::Src,
                address: "10.0.0.1".into(),
            },
        }];
        let request = request(filter);
        let expression = request.validate().unwrap();
        let args = capture_args(&request, &expression);
        let split = args.iter().position(|arg| arg == "--").unwrap();
        assert_eq!(args.len(), split + 2, "{args:?}");
        assert_eq!(args[split + 1], "src host 10.0.0.1");
        // Raw output, no privilege drop to a user tcpdump picks itself, and
        // no promiscuous mode.
        for wanted in ["-w", "-p", "-Z", "root", "--immediate-mode", "-U"] {
            assert!(args.iter().any(|arg| arg == wanted), "{wanted} in {args:?}");
        }
        assert_eq!(
            args[args.iter().position(|a| a == "-i").unwrap() + 1],
            "eth1"
        );
        // No filter, no separator.
        let plain = capture_args(&request, "");
        assert!(!plain.iter().any(|arg| arg == "--"));
    }

    #[test]
    fn the_viewer_gives_up_every_privilege_before_it_decodes() {
        let args = viewer_args(Path::new("/usr/bin/tcpdump"));
        assert_eq!(args[0], "--reuid=65534");
        assert_eq!(args[1], "--regid=65534");
        assert!(args.contains(&"--clear-groups".to_string()));
        assert!(args.contains(&"--no-new-privs".to_string()));
        let program = args.iter().position(|a| a == "/usr/bin/tcpdump").unwrap();
        assert!(args[..program].iter().all(|arg| arg.starts_with("--")));
        // Reads the capture from stdin; it cannot be pointed at a file.
        assert_eq!(&args[program + 1..program + 3], ["-r", "-"]);
    }

    /// The capture opens a raw socket (CAP_NET_RAW) and the viewer is started
    /// as `nobody` (CAP_SETUID, CAP_SETGID); the file goes under
    /// /run/keystone. Tightening the unit must not silently break either.
    #[test]
    fn service_unit_grants_what_capture_needs() {
        let unit = include_str!("../../../packaging/arch/keystone-daemon.service");
        for directive in ["CapabilityBoundingSet=", "AmbientCapabilities="] {
            let caps = unit
                .lines()
                .find_map(|line| line.strip_prefix(directive))
                .unwrap();
            for cap in ["CAP_NET_RAW", "CAP_SETUID", "CAP_SETGID"] {
                assert!(
                    caps.split_ascii_whitespace().any(|c| c == cap),
                    "{directive} missing {cap}"
                );
            }
        }
        assert!(
            unit.lines()
                .filter_map(|line| line.strip_prefix("ReadWritePaths="))
                .flat_map(str::split_ascii_whitespace)
                .any(|path| path == "/run/keystone"),
            "/run/keystone must be writable"
        );
        assert!(CAPTURE_DIR.starts_with("/run/keystone/"));
    }

    #[test]
    fn the_kernel_drop_summary_is_parsed() {
        assert_eq!(dropped_by_kernel("12 packets dropped by kernel"), Some(12));
        assert_eq!(dropped_by_kernel("12 packets captured"), None);
        assert_eq!(dropped_by_kernel("tcpdump: eth0: No such device"), None);
    }

    #[tokio::test]
    async fn a_capture_runs_to_its_packet_limit_and_can_be_downloaded() {
        let fx = fixture(sample_command);
        let manager = CaptureManager::new(fx.env.clone());
        let started = manager.start(request(vec![])).await.unwrap();
        assert_eq!(started.state, CaptureState::Running);

        let info = wait_until_done(&manager).await;
        assert_eq!(info.state, CaptureState::Finished, "{info:?}");
        assert_eq!(info.packets, 3);
        assert_eq!(info.bytes, sample_pcap(3).len() as u64);
        assert_eq!(info.dropped_by_kernel, Some(1));
        assert!(info.has_pcap);
        // tcpdump's notes are not an error to show.
        assert_eq!(info.message, None);

        // The live view got the viewer's lines, in order, and nothing is lost.
        let packets = manager.packets(0).await;
        let text: Vec<&str> = packets.lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(text, ["line one", "line two", "line three"]);
        assert_eq!(packets.lost, 0);
        assert_eq!(packets.next, 3);
        // Polling again from `next` returns nothing new.
        assert!(manager.packets(packets.next).await.lines.is_empty());

        let (path, _) = manager.pcap_for_download().await.unwrap();
        assert_eq!(std::fs::read(path).unwrap(), sample_pcap(3));
    }

    #[tokio::test]
    async fn the_capture_file_is_private_to_the_daemon() {
        let fx = fixture(sample_command);
        let manager = CaptureManager::new(fx.env.clone());
        manager.start(request(vec![])).await.unwrap();
        wait_until_done(&manager).await;
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&fx.env.dir), 0o700);
        assert_eq!(mode(&fx.env.pcap_path()), 0o600);
    }

    #[tokio::test]
    async fn stopping_ends_a_running_capture_and_keeps_what_it_got() {
        let fx = fixture(|root| format!("cat {}; sleep 30", root.join("sample.pcap").display()));
        let manager = CaptureManager::new(fx.env.clone());
        manager.start(request(vec![])).await.unwrap();

        // A second capture is refused while one runs.
        let second = manager.start(request(vec![])).await;
        assert!(
            matches!(second, Err(CaptureError::Conflict(_))),
            "{second:?}"
        );
        // So are downloading and discarding.
        assert!(matches!(
            manager.pcap_for_download().await,
            Err(CaptureError::Conflict(_))
        ));
        assert!(matches!(
            manager.discard().await,
            Err(CaptureError::Conflict(_))
        ));

        // Wait for the packets to arrive, then stop.
        for _ in 0..100 {
            if manager.info().await.unwrap().packets == 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let info = manager.stop().await.unwrap();
        assert_eq!(info.state, CaptureState::Stopped, "{info:?}");
        assert_eq!(info.packets, 3);
        assert!(info.has_pcap);
        assert_eq!(info.message.as_deref(), Some("stopped"));
        assert_eq!(manager.packets(0).await.lines.len(), 3);

        // Discarding removes the file and the capture.
        manager.discard().await.unwrap();
        assert!(manager.info().await.is_none());
        assert!(!fx.env.pcap_path().exists());
    }

    #[tokio::test]
    async fn the_time_limit_stops_a_capture() {
        let fx = fixture(|_| "sleep 30".to_string());
        let manager = CaptureManager::new(fx.env.clone());
        let mut limited = request(vec![]);
        limited.max_seconds = 1;
        manager.start(limited).await.unwrap();
        let info = wait_until_done(&manager).await;
        assert_eq!(info.state, CaptureState::Stopped);
        assert_eq!(info.message.as_deref(), Some("time limit reached"));
        // Nothing arrived, so there is nothing to download.
        assert!(!info.has_pcap);
        assert!(matches!(
            manager.pcap_for_download().await,
            Err(CaptureError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn a_tcpdump_error_is_reported() {
        let fx = fixture(|_| "echo 'tcpdump: eth1: No such device exists' >&2; exit 1".into());
        let manager = CaptureManager::new(fx.env.clone());
        manager.start(request(vec![])).await.unwrap();
        let info = wait_until_done(&manager).await;
        assert_eq!(info.state, CaptureState::Failed);
        assert!(
            info.message
                .as_deref()
                .unwrap_or("")
                .contains("No such device"),
            "{info:?}"
        );
        assert!(!info.has_pcap);
    }

    #[tokio::test]
    async fn output_that_is_not_pcap_is_a_failure_not_a_download() {
        let fx = fixture(|_| "echo 'not a capture, not a capture, not a capture'".into());
        let manager = CaptureManager::new(fx.env.clone());
        manager.start(request(vec![])).await.unwrap();
        let info = wait_until_done(&manager).await;
        assert!(!info.has_pcap, "{info:?}");
        assert_eq!(info.packets, 0);
    }

    #[tokio::test]
    async fn a_missing_tcpdump_says_what_to_install() {
        let mut fx = fixture(sample_command);
        fx.env.tcpdump = fx.root.join("does-not-exist");
        let manager = CaptureManager::new(fx.env.clone());
        manager.start(request(vec![])).await.unwrap();
        let info = wait_until_done(&manager).await;
        assert_eq!(info.state, CaptureState::Failed);
        assert!(
            info.message
                .unwrap()
                .contains("Install the tcpdump package")
        );
    }

    #[tokio::test]
    async fn requests_are_checked_before_anything_runs() {
        let fx = fixture(sample_command);
        let manager = CaptureManager::new(fx.env.clone());

        let mut bad = request(vec![]);
        bad.interface = "eth1; reboot".into();
        assert!(matches!(
            manager.start(bad).await,
            Err(CaptureError::Invalid(_))
        ));

        let mut missing = request(vec![]);
        missing.interface = "eth9".into();
        assert!(matches!(
            manager.start(missing).await,
            Err(CaptureError::NotFound(_))
        ));

        let mut any = request(vec![]);
        any.interface = ANY_INTERFACE.into();
        manager.start(any).await.unwrap();
        wait_until_done(&manager).await;

        // None of the refused requests left a capture or a file behind.
        assert_eq!(manager.interfaces(), ["any", "eth1"]);
    }

    #[tokio::test]
    async fn live_view_reports_lines_that_fell_out_of_the_buffer() {
        let fx = fixture(sample_command);
        let manager = CaptureManager::new(fx.env.clone());
        manager.start(request(vec![])).await.unwrap();
        wait_until_done(&manager).await;
        let session = manager.current.lock().await.clone().unwrap();
        for n in 0..(MAX_BUFFERED_LINES + 10) {
            session.push_line(format!("extra {n}"));
        }
        let response = manager.packets(0).await;
        assert!(response.lost > 0);
        assert_eq!(response.lines.len(), MAX_LINES_PER_POLL);
        // Following `next` reaches the newest line without gaps.
        let mut next = response.next;
        let mut last = String::new();
        loop {
            let page = manager.packets(next).await;
            if page.lines.is_empty() {
                break;
            }
            last = page.lines.last().unwrap().text.clone();
            next = page.next;
        }
        assert_eq!(last, format!("extra {}", MAX_BUFFERED_LINES + 9));
    }
}
