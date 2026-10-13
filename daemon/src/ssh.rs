//! Keystone-managed OpenSSH listener. Changes only our own drop-in, never the
//! administrator's sshd_config or other files in sshd_config.d.
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    net::IpAddr,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    process::Command,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use keystone_core::{
    FirewallAction, InputRule, InterfaceRole, RuleProtocol, SshApplyResponse, SshConfig,
    SshStateResponse,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::{AppError, AppState, db::Database};

const SETTINGS: &str = "/var/lib/keystone/ssh.json";
const DROP_IN: &str = "/etc/ssh/sshd_config.d/00-keystone.conf";
static APPLY_LOCK: Mutex<()> = Mutex::const_new(());

#[derive(Serialize, Deserialize)]
struct StoredSsh {
    #[serde(flatten)]
    config: SshConfig,
    #[serde(default)]
    last_addresses: Vec<IpAddr>,
}

fn load_stored() -> Result<StoredSsh> {
    match fs::read(SETTINGS) {
        Ok(bytes) => serde_json::from_slice(&bytes).context("Invalid Keystone SSH settings"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(StoredSsh {
            config: SshConfig::default(),
            last_addresses: Vec::new(),
        }),
        Err(e) => Err(e).context("Reading Keystone SSH settings"),
    }
}

fn load_config() -> Result<SshConfig> {
    Ok(load_stored()?.config)
}

/// Port of the Keystone-managed SSH listener, if SSH management is enabled.
pub(crate) fn enabled_port() -> Option<u16> {
    load_config().ok().filter(|c| c.enabled).map(|c| c.port)
}

fn store_config(config: &SshConfig, addresses: &[IpAddr]) -> Result<()> {
    let record = StoredSsh {
        config: config.clone(),
        last_addresses: addresses.to_vec(),
    };
    write_atomic(SETTINGS, &serde_json::to_vec_pretty(&record)?)
}

/// A login-capable local account found in passwd data.
struct LoginUser {
    home: std::path::PathBuf,
}

/// Non-root accounts (uid >= 1000) with a real login shell.
fn parse_login_users(passwd: &str) -> Vec<LoginUser> {
    passwd
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            let [_name, _pw, uid, _gid, _gecos, home, shell] = fields[..] else {
                return None;
            };
            let uid: u32 = uid.parse().ok()?;
            let shell_name = shell.rsplit('/').next().unwrap_or(shell);
            let no_login = shell.is_empty() || matches!(shell_name, "nologin" | "false");
            (uid >= 1000 && !no_login && !home.is_empty()).then(|| LoginUser { home: home.into() })
        })
        .collect()
}

/// An authorized_keys file counts when it holds at least one non-comment line.
fn has_authorized_key(contents: &str) -> bool {
    contents.lines().any(|line| {
        let line = line.trim();
        !line.is_empty() && !line.starts_with('#')
    })
}

/// Fail if disabling passwords would leave no account able to log in.
/// `read` returns the contents of a file, or `None` if unreadable/missing.
fn ensure_key_login_possible(passwd: &str, read: impl Fn(&Path) -> Option<String>) -> Result<()> {
    let any_keys = parse_login_users(passwd).iter().any(|user| {
        read(&user.home.join(".ssh/authorized_keys")).is_some_and(|c| has_authorized_key(&c))
    });
    ensure!(
        any_keys,
        "Public-key-only SSH would lock everyone out: no user has ~/.ssh/authorized_keys"
    );
    Ok(())
}

fn validate(config: &SshConfig) -> Result<()> {
    validate_with(config, || {
        let passwd = fs::read_to_string("/etc/passwd").context("Reading /etc/passwd")?;
        Ok((passwd, |path: &Path| fs::read_to_string(path).ok()))
    })
}

/// `users` supplies passwd data and a file reader; it is only evaluated when
/// the key-only lockout check applies, so tests can inject both.
fn validate_with<R: Fn(&Path) -> Option<String>>(
    config: &SshConfig,
    users: impl FnOnce() -> Result<(String, R)>,
) -> Result<()> {
    ensure!(config.port != 0, "SSH port must be between 1 and 65535");
    ensure!(
        config.ipv4 || config.ipv6,
        "Enable at least one address family"
    );
    ensure!(
        config.password_authentication || config.public_key_authentication,
        "Enable at least one authentication method"
    );
    if !config.password_authentication {
        let (passwd, read) = users()?;
        ensure_key_login_possible(&passwd, read)?;
    }
    Ok(())
}

fn render(config: &SshConfig, addresses: &[IpAddr]) -> String {
    let mut result = format!(
        "# Managed by Keystone; other OpenSSH configuration remains administrator-owned.\n\
         Port {}\nPermitRootLogin no\nPasswordAuthentication {}\nPubkeyAuthentication {}\n",
        config.port,
        if config.password_authentication {
            "yes"
        } else {
            "no"
        },
        if config.public_key_authentication {
            "yes"
        } else {
            "no"
        },
    );
    // With passwords disabled, keyboard-interactive (PAM) passwords must not
    // remain as an unintended alternative. Otherwise leave MFA/PAM policy alone.
    if !config.password_authentication {
        result.push_str("KbdInteractiveAuthentication no\n");
    }
    // Explicit addresses, never a wildcard. Loopback preserves local recovery
    // when the LAN has no address (e.g. during networkd reconfiguration).
    let mut ips = BTreeSet::new();
    if config.ipv4 {
        ips.insert(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    }
    if config.ipv6 {
        ips.insert(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));
    }
    ips.extend(addresses.iter().copied());
    for ip in ips {
        result.push_str(&format!("ListenAddress {ip}\n"));
    }
    result
}

#[derive(Deserialize)]
struct IpLink {
    ifname: String,
    #[serde(default)]
    addr_info: Vec<IpInfo>,
}
#[derive(Deserialize)]
struct IpInfo {
    local: Option<String>,
    scope: Option<String>,
    #[serde(default)]
    tentative: bool,
    #[serde(default)]
    dadfailed: bool,
}

async fn desired_addresses(db: &Database, config: &SshConfig) -> Result<Vec<IpAddr>> {
    let names: BTreeSet<_> = db
        .get_interface_configs()
        .await?
        .into_iter()
        .filter(|iface| {
            iface.enabled
                && (iface.role == InterfaceRole::LAN
                    || (config.wan_access && iface.role == InterfaceRole::WAN))
        })
        .map(|iface| iface.name)
        .collect();
    if names.is_empty() {
        return Ok(Vec::new());
    }
    let output = tokio::process::Command::new("ip")
        .args(["-j", "address", "show"])
        .output()
        .await
        .context("Enumerating interface addresses")?;
    ensure!(
        output.status.success(),
        "ip address failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let links: Vec<IpLink> = serde_json::from_slice(&output.stdout)?;
    let mut ips = BTreeSet::new();
    for link in links {
        if !names.contains(&link.ifname) {
            continue;
        }
        for info in link.addr_info {
            if info.scope.as_deref() != Some("global") || info.tentative || info.dadfailed {
                continue;
            }
            if let Some(Ok(ip)) = info.local.as_deref().map(str::parse::<IpAddr>)
                && ((config.ipv4 && ip.is_ipv4()) || (config.ipv6 && ip.is_ipv6()))
            {
                ips.insert(ip);
            }
        }
    }
    Ok(ips.into_iter().collect())
}

fn update_listener_lines(previous: &str, config: &SshConfig, addresses: &[IpAddr]) -> String {
    let retained = previous
        .lines()
        .filter(|line| !line.trim_start().starts_with("ListenAddress "))
        .collect::<Vec<_>>()
        .join("\n");
    let listeners = render(config, addresses)
        .lines()
        .filter(|line| line.starts_with("ListenAddress "))
        .collect::<Vec<_>>()
        .join("\n");
    format!("{retained}\n{listeners}\n")
}

fn write_atomic(path: &str, content: &[u8]) -> Result<()> {
    let p = Path::new(path);
    fs::create_dir_all(p.parent().context("Missing parent directory")?)?;
    let temp = p.with_extension(format!("keystone-{}", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(content)?;
        file.sync_all()?;
        fs::rename(&temp, p)?;
        Ok::<_, anyhow::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.context(format!("Writing {}", path))
}

fn restore(path: &str, data: Option<&[u8]>) -> Result<()> {
    match data {
        Some(bytes) => write_atomic(path, bytes),
        None => match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        },
    }
}

fn run_systemctl(args: &[&str]) -> Result<()> {
    let result = Command::new("systemctl")
        .args(args)
        .output()
        .context("Launching systemctl")?;
    ensure!(
        result.status.success(),
        "systemctl {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(())
}
fn unit_active() -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", "sshd.service"])
        .status()
        .is_ok_and(|s| s.success())
}
fn unit_enabled() -> bool {
    Command::new("systemctl")
        .args(["is-enabled", "--quiet", "sshd.service"])
        .status()
        .is_ok_and(|s| s.success())
}
fn reject_socket_activation() -> Result<()> {
    ensure!(
        !Command::new("systemctl")
            .args(["is-active", "--quiet", "sshd.socket"])
            .status()
            .is_ok_and(|s| s.success()),
        "sshd.socket is active; disable socket activation before Keystone can manage SSH listeners"
    );
    Ok(())
}
fn validate_sshd() -> Result<()> {
    let output = Command::new("sshd")
        .args(["-t", "-f", "/etc/ssh/sshd_config"])
        .output()
        .context("Running sshd -t (is openssh installed?)")?;
    ensure!(
        output.status.success(),
        "sshd -t: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

async fn reconcile(db: &Database) -> Result<()> {
    let _guard = APPLY_LOCK.lock().await;
    // Never take over an existing OpenSSH installation until explicitly configured.
    if !Path::new(DROP_IN).exists() || !Path::new(SETTINGS).exists() {
        return Ok(());
    }
    let stored = load_stored()?;
    if !stored.config.enabled {
        return Ok(());
    }
    let addresses = desired_addresses(db, &stored.config).await?;
    // Compare with addresses we last applied, not with the SSH config file.
    // An administrator may edit OpenSSH settings without Keystone nagging or
    // undoing them. Only an actual interface-address change causes a reload.
    if addresses == stored.last_addresses {
        return Ok(());
    }
    reject_socket_activation()?;
    let previous = fs::read(DROP_IN)?;
    let old_settings = fs::read(SETTINGS)?;
    let previous_content =
        String::from_utf8(previous.clone()).context("Keystone SSH drop-in is not valid UTF-8")?;
    let generated = update_listener_lines(&previous_content, &stored.config, &addresses);
    write_atomic(DROP_IN, generated.as_bytes())?;
    let action = validate_sshd()
        .and_then(|()| run_systemctl(&["reload-or-restart", "sshd.service"]))
        .and_then(|()| store_config(&stored.config, &addresses));
    if let Err(err) = action {
        restore(DROP_IN, Some(&previous))?;
        restore(SETTINGS, Some(&old_settings))?;
        // Reloading the old config is best-effort; do not conceal the failure.
        if let Err(e) = run_systemctl(&["reload-or-restart", "sshd.service"]) {
            warn!("Failed to reload restored SSH config: {e:#}");
        }
        bail!("SSH address reconciliation failed (restored prior configuration): {err:#}");
    }
    info!("Updated SSH listener addresses after interface change");
    Ok(())
}

pub fn start_reconciler(db: Database) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            if let Err(err) = reconcile(&db).await {
                warn!("SSH listener update: {err:#}");
            }
        }
    });
}

async fn state(State(state): State<Arc<AppState>>) -> Result<Json<SshStateResponse>, AppError> {
    let config = load_config()?;
    let addresses = desired_addresses(&state.db, &config).await?;
    let managed = Path::new(DROP_IN).exists();
    let warning = if managed && !unit_active() && config.enabled {
        Some("sshd is not running; check the service status or journal".to_string())
    } else {
        None
    };
    Ok(Json(SshStateResponse {
        interface_addresses: addresses.iter().map(ToString::to_string).collect(),
        listening_addresses: if managed {
            render(&config, &addresses)
                .lines()
                .filter_map(|line| line.strip_prefix("ListenAddress ").map(str::to_string))
                .collect()
        } else {
            vec![]
        },
        running: unit_active(),
        managed,
        config,
        warning,
    }))
}

async fn save(
    State(state): State<Arc<AppState>>,
    Json(config): Json<SshConfig>,
) -> Result<Json<SshApplyResponse>, AppError> {
    if state
        .db
        .get_global_settings()
        .await?
        .config_changes_disabled
    {
        return Ok(Json(SshApplyResponse {
            success: false,
            message: "Configuration changes are locked".into(),
            firewall_session_id: None,
        }));
    }
    if let Err(e) = validate(&config) {
        return Ok(Json(SshApplyResponse {
            success: false,
            message: e.to_string(),
            firewall_session_id: None,
        }));
    }
    let _guard = APPLY_LOCK.lock().await;
    let result = apply_with_firewall(&state, &config).await;
    Ok(Json(match result {
        Ok(session_id) => SshApplyResponse {
            success: true,
            message: if session_id.is_some() {
                "SSH applied. Confirm the firewall change within 60 seconds.".into()
            } else {
                "SSH configuration applied".into()
            },
            firewall_session_id: session_id,
        },
        Err(e) => SshApplyResponse {
            success: false,
            message: format!("{e:#}"),
            firewall_session_id: None,
        },
    }))
}

/// Restore only Keystone's two named input rules if the combined operation fails.
async fn restore_rules(db: &Database, original: &[(String, Option<InputRule>)]) -> Result<()> {
    for (name, before) in original {
        if let Some(rule) = before {
            db.save_input_rule(rule).await?;
        } else if let Some(rule) = db
            .get_input_rules()
            .await?
            .into_iter()
            .find(|r| r.name == *name)
            && let Some(id) = rule.id
        {
            db.delete_input_rule(id).await?;
        }
    }
    Ok(())
}

async fn stage_ssh_rules(
    db: &Database,
    config: &SshConfig,
) -> Result<Vec<(String, Option<InputRule>)>> {
    let existing = db.get_input_rules().await?;
    let mut changes = Vec::new();
    let action: Result<()> = async {
        for (zone, name, exposed) in [
            ("lan", "Keystone SSH LAN access", config.enabled),
            (
                "wan",
                "Keystone SSH WAN access",
                config.enabled && config.wan_access,
            ),
        ] {
            let old = existing.iter().find(|r| r.name == name).cloned();
            if db.get_firewall_zone_by_name(zone).await?.is_none() {
                ensure!(
                    !exposed || zone != "wan",
                    "Configure the WAN firewall zone before exposing SSH on WAN"
                );
                continue;
            }
            // Do not create a redundant WAN rule when WAN access is disabled.
            if old.is_none() && !exposed {
                continue;
            }
            let desired = InputRule {
                id: old.as_ref().and_then(|r| r.id),
                name: name.into(),
                description: Some("Generated by Keystone SSH settings".into()),
                enabled: exposed,
                position: -250,
                zone: Some(zone.into()),
                protocol: Some(RuleProtocol::Tcp),
                port_start: Some(config.port),
                action: FirewallAction::Accept,
                ..Default::default()
            };
            if old.as_ref() != Some(&desired) {
                changes.push((name.to_string(), old));
                db.save_input_rule(&desired).await?;
            }
        }
        Ok(())
    }
    .await;
    if let Err(err) = action {
        if let Err(e) = restore_rules(db, &changes).await {
            warn!("Could not revert staged SSH firewall changes: {e:#}");
        }
        bail!("{err:#}");
    }
    Ok(changes)
}

async fn apply_with_firewall(state: &AppState, config: &SshConfig) -> Result<Option<String>> {
    reject_socket_activation()?;
    // Validate listener and interface discovery before changing firewall policy.
    let _ = desired_addresses(&state.db, config).await?;
    let prior_rules = stage_ssh_rules(&state.db, config).await?;
    let mut firewall_session = None;
    let result: Result<()> = async {
        if !prior_rules.is_empty() {
            let response = state.firewall_manager.apply(Some(60)).await?;
            ensure!(
                response.success,
                "Cannot apply SSH firewall rules: {}",
                response.message
            );
            firewall_session = response.session_id;
        }
        apply_config(&state.db, config).await?;
        Ok(())
    }
    .await;
    if let Err(err) = result {
        if firewall_session.is_some()
            && let Err(e) = state.firewall_manager.rollback().await
        {
            warn!("SSH firewall rollback failed: {e:#}");
        }
        if let Err(e) = restore_rules(&state.db, &prior_rules).await {
            warn!("SSH firewall rule restoration failed: {e:#}");
        }
        bail!("{err:#}");
    }
    Ok(firewall_session)
}

async fn apply_config(db: &Database, config: &SshConfig) -> Result<()> {
    reject_socket_activation()?;
    let previous = fs::read(DROP_IN).ok();
    let old_settings = fs::read(SETTINGS).ok();
    let was_enabled = unit_enabled();
    let was_running = unit_active();
    let addresses = desired_addresses(db, config).await?;
    // SSHD's config will be present even when the service is disabled, for
    // an administrator who starts it manually.
    write_atomic(DROP_IN, render(config, &addresses).as_bytes())?;
    let action = (|| -> Result<()> {
        validate_sshd()?;
        if config.enabled {
            run_systemctl(&["enable", "--now", "sshd.service"])?;
            // enable --now won't replace listeners on an already-running daemon.
            run_systemctl(&["reload-or-restart", "sshd.service"])?;
        } else {
            run_systemctl(&["disable", "--now", "sshd.service"])?;
        }
        store_config(config, &addresses)?;
        Ok(())
    })();
    if let Err(err) = action {
        let file_rollback = restore(DROP_IN, previous.as_deref())
            .and_then(|()| restore(SETTINGS, old_settings.as_deref()));
        let service_rollback = (|| -> Result<()> {
            if was_enabled {
                run_systemctl(&["enable", "sshd.service"])?;
            } else {
                run_systemctl(&["disable", "sshd.service"])?;
            }
            if was_running {
                run_systemctl(&["restart", "sshd.service"])?;
            } else {
                run_systemctl(&["stop", "sshd.service"])?;
            }
            Ok(())
        })();
        if let Err(e) = file_rollback {
            warn!("SSH rollback file error: {e:#}");
        }
        if let Err(e) = service_rollback {
            warn!("SSH rollback service error: {e:#}");
        }
        bail!("SSH apply failed; previous settings restored: {err:#}");
    }
    Ok(())
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/ssh", get(state))
        .route("/ssh/apply", post(save))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn packaged_daemon_can_write_ssh_drop_in() {
        // ProtectSystem=strict makes /etc read-only. Keep the SSH exception
        // and the directory provisioning together to avoid an EROFS at apply.
        let unit = include_str!("../../packaging/arch/keystone-daemon.service");
        assert!(unit.lines().any(|line| {
            line.strip_prefix("ReadWritePaths=").is_some_and(|paths| {
                paths
                    .split_whitespace()
                    .any(|path| path == "/etc/ssh/sshd_config.d")
            })
        }));
        let tmpfiles = include_str!("../../packaging/arch/tmpfiles.conf");
        assert!(tmpfiles.lines().any(|line| {
            let mut fields = line.split_whitespace();
            fields.next() == Some("d") && fields.next() == Some("/etc/ssh/sshd_config.d")
        }));
    }

    #[test]
    fn defaults_are_lan_only_and_root_is_not_configurable() {
        let config = SshConfig::default();
        assert!(!config.wan_access);
        let conf = render(&config, &[IpAddr::V4("192.168.1.1".parse().unwrap())]);
        assert!(conf.contains("PermitRootLogin no\n"));
        assert!(conf.contains("ListenAddress 192.168.1.1\n"));
        assert!(!conf.contains("ListenAddress 0.0.0.0"));
        assert!(!conf.contains("ListenAddress ::\n"));
        assert!(serde_json::from_str::<SshConfig>(
            "{\"enabled\":true,\"port\":22,\"ipv4\":true,\"ipv6\":true,\"wan_access\":false,\"password_authentication\":true,\"public_key_authentication\":true,\"permit_root_login\":true}"
        ).is_ok()); // unknown admin-supplied fields cannot influence generated policy
    }

    #[test]
    fn address_updates_preserve_administrator_changes() {
        let old = "# Admin-modified Keystone config\nPermitRootLogin yes\nPort 2222\nListenAddress 192.168.1.1\n";
        let updated = update_listener_lines(
            old,
            &SshConfig::default(),
            &["192.168.2.1".parse().unwrap()],
        );
        assert!(updated.contains("PermitRootLogin yes\n"));
        assert!(updated.contains("Port 2222\n"));
        assert!(!updated.contains("ListenAddress 192.168.1.1"));
        assert!(updated.contains("ListenAddress 192.168.2.1"));
    }

    #[test]
    fn invalid_port_and_locked_out_auth_are_rejected() {
        let mut config = SshConfig {
            port: 0,
            ..Default::default()
        };
        assert!(validate(&config).is_err());
        config.port = 22;
        config.password_authentication = false;
        config.public_key_authentication = false;
        assert!(validate(&config).is_err());
    }

    #[test]
    fn key_only_ssh_requires_a_user_with_authorized_keys() {
        let passwd = "root:x:0:0::/root:/bin/bash\n\
            daemon:x:2:2::/:/usr/bin/nologin\n\
            svc:x:1001:1001::/home/svc:/usr/bin/false\n\
            alice:x:1000:1000::/home/alice:/bin/bash\n";
        let users = parse_login_users(passwd);
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].home, Path::new("/home/alice"));

        let with_keys = |path: &Path| {
            (path == Path::new("/home/alice/.ssh/authorized_keys"))
                .then(|| "# comment\nssh-ed25519 AAAA alice\n".to_string())
        };
        assert!(ensure_key_login_possible(passwd, with_keys).is_ok());
        let comments_only = |_: &Path| Some("# nothing\n\n".to_string());
        assert!(ensure_key_login_possible(passwd, comments_only).is_err());
        assert!(ensure_key_login_possible(passwd, |_: &Path| None).is_err());
        // Keys on root (or a nologin account) do not count.
        let root_only = |path: &Path| {
            (path == Path::new("/root/.ssh/authorized_keys")).then(|| "ssh-ed25519 AAAA".into())
        };
        assert!(ensure_key_login_possible(passwd, root_only).is_err());
    }

    type Reader = fn(&Path) -> Option<String>;

    #[test]
    fn password_auth_skips_the_key_lookup() {
        let config = SshConfig::default();
        assert!(config.password_authentication);
        let result = validate_with(&config, || -> Result<(String, Reader)> {
            panic!("passwd must not be consulted while passwords are enabled")
        });
        assert!(result.is_ok());
        let key_only = SshConfig {
            password_authentication: false,
            ..Default::default()
        };
        let err = validate_with(&key_only, || {
            Ok((
                String::from("alice:x:1000:1000::/home/alice:/bin/bash"),
                |_: &Path| None,
            ))
        })
        .unwrap_err();
        assert!(err.to_string().contains("lock everyone out"));
    }

    #[test]
    fn ipv6_is_rendered_without_wildcards() {
        let config = SshConfig {
            ipv4: false,
            ..Default::default()
        };
        let conf = render(&config, &["2001:db8::1234".parse().unwrap()]);
        assert!(conf.contains("ListenAddress 2001:db8::1234"));
        assert!(!conf.contains("ListenAddress 127.0.0.1"));
        assert!(conf.contains("ListenAddress ::1"));
    }
}
