//! Applying SQM with `tc` and `ip`.
//!
//! A configuration becomes a list of [`Step`]s. The steps are built by pure
//! functions, so the same text can be shown in the pending-changes diff and run
//! against the kernel. Every command is an argument vector; nothing goes through
//! a shell.
//!
//! Upload is shaped on the WAN interface (egress). Download is shaped on an IFB
//! device that WAN ingress traffic is redirected to.

use std::collections::BTreeSet;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use keystone_core::sqm::{
    SQM_MAX_KBIT, SQM_MIN_KBIT, SQM_MPU_MAX, SQM_OVERHEAD_MAX, SQM_OVERHEAD_MIN, SqmConfig,
    SqmDiffserv, SqmIsolation, SqmLinkPreset,
};
use serde_json::Value;
use tracing::{info, warn};

use super::db::{load_applied, load_sqm_config, save_applied};
use crate::db::Database;

/// Kernel limit on interface names, excluding the terminating NUL.
pub const IFNAMSIZ_MAX: usize = 15;

/// Prefix of the IFB device that shapes the download direction of a WAN.
const IFB_PREFIX: &str = "ifb4";

/// How often the reconciler checks that the shaper is still in place.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(15);

const CAKE_MISSING_HINT: &str =
    "sch_cake kernel module not loaded; reboot or run `modprobe sch_cake`";
const FILTER_MISSING_HINT: &str = "cls_matchall or act_mirred kernel module not loaded; reboot or run `modprobe cls_matchall act_mirred`";
const IFB_MISSING_HINT: &str = "ifb kernel module not loaded; reboot or run `modprobe ifb`";

/// Serialises applies, so the reconciler never races a user-triggered apply.
static APPLY_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Build a `Vec<String>` argument list from displayable parts.
macro_rules! argv {
    ($($part:expr),* $(,)?) => {
        vec![$(($part).to_string()),*]
    };
}

/// Check a Linux interface name: 1 to 15 characters of `[A-Za-z0-9_.-]`.
pub fn validate_interface_name(name: &str) -> Result<(), String> {
    let valid = !name.is_empty()
        && name.len() <= IFNAMSIZ_MAX
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(format!(
            "invalid interface name {name:?}: use 1 to {IFNAMSIZ_MAX} letters, digits, '_', '.' or '-'"
        ))
    }
}

/// Name of the IFB device for a WAN interface, cut to the kernel limit.
pub fn ifb_name(wan: &str) -> String {
    format!("{IFB_PREFIX}{wan}")
        .chars()
        .take(IFNAMSIZ_MAX)
        .collect()
}

/// Check a configuration at the daemon boundary. `interfaces` lists the names
/// of the configured interfaces. An enabled configuration must name one of them.
pub fn validate_config(config: &SqmConfig, interfaces: &[String]) -> Result<(), String> {
    if !config.interface.is_empty() {
        validate_interface_name(&config.interface)?;
    }
    for (label, kbit) in [
        ("download", config.download_kbit),
        ("upload", config.upload_kbit),
    ] {
        if kbit != 0 && !(SQM_MIN_KBIT..=SQM_MAX_KBIT).contains(&kbit) {
            return Err(format!(
                "{label} rate must be 0 (unshaped) or between {SQM_MIN_KBIT} and {SQM_MAX_KBIT} kbit/s"
            ));
        }
    }
    if let Some(overhead) = config.overhead
        && !(SQM_OVERHEAD_MIN..=SQM_OVERHEAD_MAX).contains(&overhead)
    {
        return Err(format!(
            "overhead must be between {SQM_OVERHEAD_MIN} and {SQM_OVERHEAD_MAX} bytes"
        ));
    }
    if let Some(mpu) = config.mpu
        && mpu > SQM_MPU_MAX
    {
        return Err(format!("mpu must be between 0 and {SQM_MPU_MAX} bytes"));
    }
    if config.enabled {
        if config.interface.is_empty() {
            return Err("choose the WAN interface to shape".to_string());
        }
        if !interfaces.contains(&config.interface) {
            return Err(format!("interface {} is not configured", config.interface));
        }
        if config.download_kbit == 0 && config.upload_kbit == 0 {
            return Err("set a download or upload rate, or disable traffic shaping".to_string());
        }
    }
    Ok(())
}

// ============================================================================
// Plan
// ============================================================================

/// A `tc` or `ip` invocation as an argument vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub program: &'static str,
    pub args: Vec<String>,
}

impl Command {
    /// The command as a line of text, as an administrator would type it.
    pub fn render(&self) -> String {
        std::iter::once(self.program)
            .chain(self.args.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

fn tc(args: Vec<String>) -> Command {
    Command {
        program: "tc",
        args,
    }
}

fn ip(args: Vec<String>) -> Command {
    Command {
        program: "ip",
        args,
    }
}

/// Which direction a CAKE qdisc shapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Upload,
    Download,
}

/// Something this module creates, and may therefore remove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Removal {
    /// The CAKE root qdisc of the WAN interface (upload).
    EgressCake,
    /// The ingress qdisc of the WAN interface, with its redirect filter.
    IngressQdisc,
    /// The IFB device carrying the download shaper.
    IfbDevice,
}

/// One action of a plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Always run.
    Run(Command),
    /// Create the IFB device unless it already exists.
    CreateIfb { name: String, command: Command },
    /// Remove something this module owns, if it is present.
    Remove {
        what: Removal,
        device: String,
        command: Command,
    },
}

impl Step {
    /// The command this step runs, as text.
    pub fn render(&self) -> String {
        match self {
            Step::Run(command) | Step::CreateIfb { command, .. } | Step::Remove { command, .. } => {
                command.render()
            }
        }
    }
}

/// Render a plan as one command per line, for the pending-changes diff.
pub fn render_steps(steps: &[Step]) -> String {
    steps
        .iter()
        .map(|step| format!("{}\n", step.render()))
        .collect()
}

fn link_params(config: &SqmConfig) -> Vec<String> {
    let preset = match config.link_preset {
        SqmLinkPreset::None => "raw",
        SqmLinkPreset::Ethernet => "ethernet",
        SqmLinkPreset::Docsis => "docsis",
        SqmLinkPreset::PppoePtm => "pppoe-ptm",
        SqmLinkPreset::BridgedPtm => "bridged-ptm",
        SqmLinkPreset::PppoeVcmux => "pppoe-vcmux",
    };
    let mut args = argv![preset];
    if let Some(overhead) = config.overhead {
        args.extend(argv!["overhead", overhead]);
    }
    if let Some(mpu) = config.mpu {
        args.extend(argv!["mpu", mpu]);
    }
    args
}

fn diffserv_keyword(mode: SqmDiffserv) -> &'static str {
    mode.as_str()
}

fn isolation_keyword(mode: SqmIsolation, direction: Direction) -> &'static str {
    match (mode, direction) {
        (SqmIsolation::Dual, Direction::Upload) => "dual-srchost",
        (SqmIsolation::Dual, Direction::Download) => "dual-dsthost",
        (SqmIsolation::Triflow, _) => "triple-isolate",
        (SqmIsolation::Flows, _) => "flows",
        (SqmIsolation::Hosts, _) => "hosts",
    }
}

/// The CAKE parameters for one direction, after `root cake`.
pub fn cake_params(config: &SqmConfig, direction: Direction) -> Vec<String> {
    let kbit = match direction {
        Direction::Upload => config.upload_kbit,
        Direction::Download => config.download_kbit,
    };
    let mut args = argv!["bandwidth", format!("{kbit}kbit")];
    args.extend(link_params(config));
    args.extend(argv![
        diffserv_keyword(config.diffserv),
        isolation_keyword(config.isolation, direction)
    ]);
    if config.nat {
        args.push("nat".to_string());
    }
    if config.wash {
        args.push("wash".to_string());
    }
    match direction {
        Direction::Upload => {
            args.push("egress".to_string());
            if config.ack_filter {
                args.push("ack-filter".to_string());
            }
        }
        Direction::Download => args.push("ingress".to_string()),
    }
    args
}

fn upload_command(config: &SqmConfig) -> Command {
    let mut args = argv!["qdisc", "replace", "dev", config.interface, "root", "cake"];
    args.extend(cake_params(config, Direction::Upload));
    tc(args)
}

fn download_steps(config: &SqmConfig, ifb: &str) -> Vec<Step> {
    let wan = config.interface.as_str();
    let mut cake = argv!["qdisc", "replace", "dev", ifb, "root", "cake"];
    cake.extend(cake_params(config, Direction::Download));
    vec![
        Step::CreateIfb {
            name: ifb.to_string(),
            command: ip(argv!["link", "add", "name", ifb, "type", "ifb"]),
        },
        Step::Run(ip(argv!["link", "set", "dev", ifb, "up"])),
        Step::Run(tc(argv![
            "qdisc", "replace", "dev", wan, "handle", "ffff:", "ingress"
        ])),
        Step::Run(tc(argv![
            "filter", "replace", "dev", wan, "parent", "ffff:", "protocol", "all", "prio", "1",
            "matchall", "action", "mirred", "egress", "redirect", "dev", ifb
        ])),
        Step::Run(tc(cake)),
    ]
}

fn remove_egress(wan: &str) -> Step {
    Step::Remove {
        what: Removal::EgressCake,
        device: wan.to_string(),
        command: tc(argv!["qdisc", "del", "dev", wan, "root"]),
    }
}

fn remove_ingress(wan: &str) -> Step {
    Step::Remove {
        what: Removal::IngressQdisc,
        device: wan.to_string(),
        command: tc(argv!["qdisc", "del", "dev", wan, "ingress"]),
    }
}

fn remove_ifb(ifb: &str) -> Step {
    Step::Remove {
        what: Removal::IfbDevice,
        device: ifb.to_string(),
        command: ip(argv!["link", "del", "dev", ifb]),
    }
}

/// Steps that leave the system as if `wan` were never shaped.
pub fn teardown_steps(wan: &str) -> Vec<Step> {
    vec![
        remove_egress(wan),
        remove_ingress(wan),
        remove_ifb(&ifb_name(wan)),
    ]
}

/// The steps that bring the system to `config`. A disabled configuration has
/// no steps here; turning shaping off is handled by [`apply_config`].
pub fn desired_steps(config: &SqmConfig) -> Vec<Step> {
    if !config.enabled {
        return Vec::new();
    }
    let wan = config.interface.as_str();
    let ifb = ifb_name(wan);
    let mut steps = Vec::new();
    if config.upload_kbit > 0 {
        steps.push(Step::Run(upload_command(config)));
    } else {
        steps.push(remove_egress(wan));
    }
    if config.download_kbit > 0 {
        steps.extend(download_steps(config, &ifb));
    } else {
        steps.push(remove_ingress(wan));
        steps.push(remove_ifb(&ifb));
    }
    steps
}

/// The text of the plan for the saved configuration, used by the pending-changes
/// diff. Empty when shaping is disabled.
pub async fn preview_sqm(pool: &sqlx::SqlitePool) -> Result<String> {
    let config = load_sqm_config(pool).await?;
    Ok(render_steps(&desired_steps(&config)))
}

// ============================================================================
// Execution
// ============================================================================

/// Explain a known failure in terms of the kernel modules that are missing.
pub fn explain_failure(command: &Command, stderr: &str) -> Option<&'static str> {
    let lowered = stderr.to_ascii_lowercase();
    if lowered.contains("specified qdisc kind is unknown") {
        return Some(CAKE_MISSING_HINT);
    }
    if command.program == "ip"
        && command.args.iter().any(|arg| arg == "ifb")
        && lowered.contains("unknown device type")
    {
        return Some(IFB_MISSING_HINT);
    }
    if command.program == "tc"
        && command.args.iter().any(|arg| arg == "matchall")
        && (lowered.contains("unknown") || lowered.contains("failed to find"))
    {
        return Some(FILTER_MISSING_HINT);
    }
    None
}

async fn run_checked(command: &Command) -> Result<()> {
    let output = tokio::process::Command::new(command.program)
        .args(&command.args)
        .output()
        .await
        .with_context(|| format!("failed to start {}", command.program))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    match explain_failure(command, &stderr) {
        Some(hint) => bail!("`{}` failed: {stderr} ({hint})", command.render()),
        None => bail!("`{}` failed: {stderr}", command.render()),
    }
}

/// Run a command and return its stdout, or `None` when it fails. Used for
/// read-only queries, where a missing device is an ordinary answer.
async fn query(program: &str, args: &[&str]) -> Option<String> {
    let output = tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

pub(super) async fn link_exists(name: &str) -> bool {
    query("ip", &["-j", "link", "show", "dev", name])
        .await
        .is_some()
}

/// The qdiscs attached to `dev`, with statistics, as reported by `tc -j`.
/// `None` when the device does not exist.
pub(super) async fn qdisc_list(dev: &str) -> Option<Vec<Value>> {
    let text = query("tc", &["-s", "-j", "qdisc", "show", "dev", dev]).await?;
    let value: Value = serde_json::from_str(&text).ok()?;
    Some(match value {
        Value::Array(items) => items,
        other => vec![other],
    })
}

/// Whether a qdisc is a CAKE qdisc attached at the root of its device (not a
/// child class of another qdisc).
pub(super) fn is_root_cake(qdisc: &Value) -> bool {
    qdisc.get("kind").and_then(Value::as_str) == Some("cake")
        && (qdisc.get("root").and_then(Value::as_bool) == Some(true)
            || qdisc.get("parent").is_none())
}

/// Whether `ifb` exists and is an IFB device, judged from `ip -d -j`.
async fn ifb_present(ifb: &str) -> bool {
    let Some(text) = query("ip", &["-d", "-j", "link", "show", "dev", ifb]).await else {
        return false;
    };
    serde_json::from_str::<Vec<Value>>(&text)
        .ok()
        .and_then(|links| links.into_iter().next())
        .and_then(|link| {
            link.pointer("/linkinfo/info_kind")
                .and_then(Value::as_str)
                .map(|kind| kind == "ifb")
        })
        .unwrap_or(false)
}

/// Whether `qdiscs` include an ingress qdisc.
fn has_ingress_qdisc(qdiscs: &[Value]) -> bool {
    qdiscs
        .iter()
        .any(|qdisc| qdisc.get("kind").and_then(Value::as_str) == Some("ingress"))
}

async fn removal_present(what: Removal, device: &str) -> bool {
    match what {
        Removal::EgressCake => qdisc_list(device)
            .await
            .is_some_and(|qdiscs| qdiscs.iter().any(is_root_cake)),
        // Only an ingress qdisc with this WAN's IFB device behind it is ours.
        // Another ingress qdisc on the WAN is left alone.
        Removal::IngressQdisc => {
            qdisc_list(device)
                .await
                .is_some_and(|qdiscs| has_ingress_qdisc(&qdiscs))
                && ifb_present(&ifb_name(device)).await
        }
        Removal::IfbDevice => ifb_present(device).await,
    }
}

async fn execute(steps: &[Step]) -> Result<()> {
    for step in steps {
        match step {
            Step::Run(command) => run_checked(command).await?,
            Step::CreateIfb { name, command } => {
                if !link_exists(name).await {
                    run_checked(command).await?;
                }
            }
            Step::Remove {
                what,
                device,
                command,
            } => {
                if removal_present(*what, device).await {
                    run_checked(command).await?;
                }
            }
        }
    }
    Ok(())
}

/// Bring the system to `config`. `previous` is the configuration last applied:
/// its WAN interface is cleaned up when it changed or shaping was disabled.
pub async fn apply_config(config: &SqmConfig, previous: Option<&SqmConfig>) -> Result<()> {
    let mut targets = BTreeSet::new();
    if let Some(previous) = previous
        && !previous.interface.is_empty()
        && (!config.enabled || previous.interface != config.interface)
    {
        targets.insert(previous.interface.clone());
    }
    if !config.enabled && !config.interface.is_empty() {
        targets.insert(config.interface.clone());
    }

    let mut steps = Vec::new();
    for wan in &targets {
        steps.extend(teardown_steps(wan));
    }
    steps.extend(desired_steps(config));
    execute(&steps).await
}

async fn interface_names(db: &Database) -> Result<Vec<String>> {
    Ok(db
        .get_interface_configs()
        .await?
        .into_iter()
        .map(|iface| iface.name)
        .collect())
}

/// Apply the saved configuration and record it as the applied state. The
/// caller records the snapshot.
pub async fn apply_saved(db: &Database) -> Result<()> {
    let _guard = APPLY_LOCK.lock().await;
    let pool = db.pool();
    let config = load_sqm_config(pool).await?;
    let interfaces = interface_names(db).await?;
    validate_config(&config, &interfaces).map_err(|error| anyhow!(error))?;
    let previous = load_applied(pool).await?;
    apply_config(&config, previous.as_ref()).await?;
    save_applied(pool, &config).await?;
    info!(
        "SQM applied: enabled={} interface={:?} download={} kbit upload={} kbit",
        config.enabled, config.interface, config.download_kbit, config.upload_kbit
    );
    Ok(())
}

// ============================================================================
// Reconciliation
// ============================================================================

/// Whether the shaper qdiscs the applied configuration needs are missing. A
/// WAN link that does not exist yet is not an error: the check waits for it.
async fn shaping_missing(applied: &SqmConfig) -> bool {
    let wan = applied.interface.as_str();
    if applied.upload_kbit > 0
        && !qdisc_list(wan)
            .await
            .is_some_and(|qdiscs| qdiscs.iter().any(is_root_cake))
    {
        return true;
    }
    if applied.download_kbit > 0 {
        let has_ingress = qdisc_list(wan)
            .await
            .is_some_and(|qdiscs| has_ingress_qdisc(&qdiscs));
        let ifb = ifb_name(wan);
        let has_ifb_cake = qdisc_list(&ifb)
            .await
            .is_some_and(|qdiscs| qdiscs.iter().any(is_root_cake));
        if !has_ingress || !has_ifb_cake {
            return true;
        }
    }
    false
}

/// Re-apply the last applied configuration when its qdiscs are gone, for
/// example after a reboot or when the WAN link was recreated. Unapplied edits
/// in the database are never used here.
async fn reconcile(db: &Database) -> Result<()> {
    let _guard = APPLY_LOCK.lock().await;
    let Some(applied) = load_applied(db.pool()).await? else {
        return Ok(());
    };
    if !applied.enabled || !link_exists(&applied.interface).await {
        return Ok(());
    }
    if shaping_missing(&applied).await {
        warn!(
            "SQM shaping is missing on {}; re-applying the last applied configuration",
            applied.interface
        );
        apply_config(&applied, None).await?;
    }
    Ok(())
}

/// Start the SQM reconciler.
pub fn start_reconciler(db: Database) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(RECONCILE_INTERVAL);
        loop {
            interval.tick().await;
            if let Err(err) = reconcile(&db).await {
                warn!("SQM reconciliation: {err:#}");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled(download: u32, upload: u32) -> SqmConfig {
        SqmConfig {
            enabled: true,
            interface: "enp1s0".to_string(),
            download_kbit: download,
            upload_kbit: upload,
            ..SqmConfig::default()
        }
    }

    fn rendered(config: &SqmConfig) -> Vec<String> {
        desired_steps(config).iter().map(Step::render).collect()
    }

    #[test]
    fn interface_names_are_strictly_validated() {
        assert!(validate_interface_name("eth0").is_ok());
        assert!(validate_interface_name("enp1s0.10").is_ok());
        assert!(validate_interface_name("wan_1-a").is_ok());
        assert!(validate_interface_name("").is_err());
        assert!(validate_interface_name("abcdefghijklmnop").is_err());
        assert!(validate_interface_name("eth 0").is_err());
        assert!(validate_interface_name("eth0;reboot").is_err());
        assert!(validate_interface_name("..").is_err());
        assert!(validate_interface_name("eth0\n").is_err());
    }

    #[test]
    fn ifb_name_is_truncated_to_the_kernel_limit() {
        assert_eq!(ifb_name("eth0"), "ifb4eth0");
        assert_eq!(ifb_name("enp1s0"), "ifb4enp1s0");
        let name = ifb_name("enp3s0f1u2u3c4");
        assert_eq!(name.len(), IFNAMSIZ_MAX);
        assert!(name.starts_with("ifb4enp3s0"));
    }

    #[test]
    fn default_egress_arguments() {
        let config = enabled(0, 20_000);
        let steps = desired_steps(&config);
        assert_eq!(
            steps[0],
            Step::Run(Command {
                program: "tc",
                args: argv![
                    "qdisc",
                    "replace",
                    "dev",
                    "enp1s0",
                    "root",
                    "cake",
                    "bandwidth",
                    "20000kbit",
                    "ethernet",
                    "diffserv4",
                    "dual-srchost",
                    "nat",
                    "egress"
                ],
            })
        );
    }

    #[test]
    fn download_uses_ifb_redirect_and_ingress_cake() {
        assert_eq!(
            rendered(&enabled(90_000, 0)),
            vec![
                "tc qdisc del dev enp1s0 root",
                "ip link add name ifb4enp1s0 type ifb",
                "ip link set dev ifb4enp1s0 up",
                "tc qdisc replace dev enp1s0 handle ffff: ingress",
                "tc filter replace dev enp1s0 parent ffff: protocol all prio 1 matchall action mirred egress redirect dev ifb4enp1s0",
                "tc qdisc replace dev ifb4enp1s0 root cake bandwidth 90000kbit ethernet diffserv4 dual-dsthost nat ingress",
            ]
        );
    }

    #[test]
    fn options_map_to_cake_keywords() {
        let config = SqmConfig {
            enabled: true,
            interface: "eth0".to_string(),
            download_kbit: 50_000,
            upload_kbit: 5_000,
            link_preset: SqmLinkPreset::PppoeVcmux,
            overhead: Some(8),
            mpu: Some(64),
            diffserv: SqmDiffserv::Besteffort,
            isolation: SqmIsolation::Triflow,
            nat: false,
            ack_filter: true,
            wash: true,
        };
        let steps = rendered(&config);
        assert_eq!(
            steps[0],
            "tc qdisc replace dev eth0 root cake bandwidth 5000kbit pppoe-vcmux overhead 8 mpu 64 besteffort triple-isolate wash egress ack-filter"
        );
        assert_eq!(
            steps[5],
            "tc qdisc replace dev ifb4eth0 root cake bandwidth 50000kbit pppoe-vcmux overhead 8 mpu 64 besteffort triple-isolate wash ingress"
        );
    }

    #[test]
    fn isolation_and_preset_keywords() {
        assert_eq!(
            isolation_keyword(SqmIsolation::Dual, Direction::Upload),
            "dual-srchost"
        );
        assert_eq!(
            isolation_keyword(SqmIsolation::Dual, Direction::Download),
            "dual-dsthost"
        );
        assert_eq!(
            isolation_keyword(SqmIsolation::Flows, Direction::Upload),
            "flows"
        );
        assert_eq!(
            isolation_keyword(SqmIsolation::Hosts, Direction::Download),
            "hosts"
        );
        let mut config = enabled(0, 1_000);
        config.link_preset = SqmLinkPreset::None;
        assert!(rendered(&config)[0].contains(" root cake bandwidth 1000kbit raw "));
        config.link_preset = SqmLinkPreset::Docsis;
        assert!(rendered(&config)[0].contains(" docsis "));
    }

    #[test]
    fn disabled_configuration_has_no_plan_but_teardown_is_known() {
        let config = SqmConfig {
            enabled: false,
            ..enabled(10_000, 10_000)
        };
        assert!(desired_steps(&config).is_empty());
        let teardown: Vec<String> = teardown_steps("enp1s0").iter().map(Step::render).collect();
        assert_eq!(
            teardown,
            vec![
                "tc qdisc del dev enp1s0 root",
                "tc qdisc del dev enp1s0 ingress",
                "ip link del dev ifb4enp1s0",
            ]
        );
    }

    #[test]
    fn enabled_both_directions_plans_upload_then_download() {
        let steps = rendered(&enabled(90_000, 18_000));
        assert_eq!(steps.len(), 6);
        assert!(steps[0].starts_with("tc qdisc replace dev enp1s0 root cake bandwidth 18000kbit"));
        assert_eq!(steps[1], "ip link add name ifb4enp1s0 type ifb");
        assert!(
            steps[5].starts_with("tc qdisc replace dev ifb4enp1s0 root cake bandwidth 90000kbit")
        );
    }

    #[test]
    fn validation_enforces_ranges_and_interfaces() {
        let interfaces = vec!["enp1s0".to_string(), "eth1".to_string()];
        assert!(validate_config(&enabled(90_000, 18_000), &interfaces).is_ok());
        assert!(validate_config(&enabled(63, 0), &interfaces).is_err());
        assert!(validate_config(&enabled(100_000_001, 0), &interfaces).is_err());
        assert!(validate_config(&enabled(0, 0), &interfaces).is_err());

        let mut config = enabled(90_000, 0);
        config.overhead = Some(257);
        assert!(validate_config(&config, &interfaces).is_err());
        config.overhead = Some(-64);
        assert!(validate_config(&config, &interfaces).is_ok());
        config.mpu = Some(257);
        assert!(validate_config(&config, &interfaces).is_err());

        let unknown = SqmConfig {
            interface: "wlan9".to_string(),
            ..enabled(90_000, 0)
        };
        assert!(validate_config(&unknown, &interfaces).is_err());
        let bad_name = SqmConfig {
            interface: "eth0; reboot".to_string(),
            ..enabled(90_000, 0)
        };
        assert!(validate_config(&bad_name, &interfaces).is_err());

        // A disabled configuration may keep a stale interface name.
        let stale = SqmConfig {
            enabled: false,
            interface: "wlan9".to_string(),
            ..SqmConfig::default()
        };
        assert!(validate_config(&stale, &interfaces).is_ok());
    }

    #[test]
    fn missing_kernel_modules_get_a_clear_hint() {
        let cake = Command {
            program: "tc",
            args: argv!["qdisc", "replace", "dev", "eth0", "root", "cake"],
        };
        let hint = explain_failure(&cake, "Error: Specified qdisc kind is unknown.");
        assert_eq!(hint, Some(CAKE_MISSING_HINT));
        assert!(explain_failure(&cake, "Error: Cannot find device").is_none());

        let filter = Command {
            program: "tc",
            args: argv!["filter", "replace", "dev", "eth0", "matchall"],
        };
        assert_eq!(
            explain_failure(&filter, "Error: unknown filter kind"),
            Some(FILTER_MISSING_HINT)
        );

        let ifb = Command {
            program: "ip",
            args: argv!["link", "add", "name", "ifb4eth0", "type", "ifb"],
        };
        assert_eq!(
            explain_failure(&ifb, "RTNETLINK answers: Unknown device type."),
            Some(IFB_MISSING_HINT)
        );
    }
}
