//! Dnsmasq service management and configuration application

use anyhow::{Context, Result};
use sqlx::SqlitePool;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{info, warn};

use super::config::{
    DNSMASQ_CONF_DIR, DNSMASQ_CONFIG_PATH, DNSMASQ_LEASE_FILE, DNSMASQ_MAIN_CONFIG_PATH,
    generate_dnsmasq_config,
};
use super::db::load_dnsmasq_state;

/// Ensure the dnsmasq configuration directory exists
pub fn ensure_dnsmasq_dir() -> Result<()> {
    let path = Path::new(DNSMASQ_CONF_DIR);
    if !path.exists() {
        fs::create_dir_all(path).with_context(|| {
            format!(
                "Failed to create dnsmasq config directory: {}",
                DNSMASQ_CONF_DIR
            )
        })?;
    }
    Ok(())
}

/// Ensure the dnsmasq lease file directory exists
pub fn ensure_lease_dir() -> Result<()> {
    if let Some(parent) = Path::new(DNSMASQ_LEASE_FILE).parent()
        && !parent.exists()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create lease directory: {:?}", parent))?;
    }
    Ok(())
}

/// Directory for staging candidate configs. `/var/lib/keystone` is writable
/// under the daemon's `ProtectSystem=strict` sandbox, whereas `/etc` (other than
/// the single bind-mounted `/etc/dnsmasq.conf`) is not.
const STAGING_DIR: &str = "/var/lib/keystone";

/// Validate a candidate dnsmasq configuration file using
/// `dnsmasq --test --conf-file=<path>`.
pub fn validate_dnsmasq_config_file(path: &Path) -> Result<()> {
    let output = Command::new("dnsmasq")
        .arg("--test")
        .arg(format!("--conf-file={}", path.display()))
        .output()
        .context("Failed to execute dnsmasq --test")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("dnsmasq configuration validation failed: {}", stderr.trim());
    }

    info!("dnsmasq configuration validated successfully");
    Ok(())
}

/// Previous contents of the Keystone-owned dnsmasq config, used for rollback.
struct DnsmasqConfigSnapshot {
    path: PathBuf,
    /// `None` when the file did not exist.
    content: Option<Vec<u8>>,
}

impl DnsmasqConfigSnapshot {
    fn capture(path: &Path) -> Result<Self> {
        let content = match fs::read(path) {
            Ok(content) => Some(content),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("Failed to snapshot dnsmasq config {:?}", path));
            }
        };
        Ok(Self {
            path: path.to_path_buf(),
            content,
        })
    }

    fn restore(&self) -> Result<()> {
        match &self.content {
            Some(content) => fs::write(&self.path, content)
                .with_context(|| format!("Failed to restore dnsmasq config {:?}", self.path)),
            None => match fs::remove_file(&self.path) {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error)
                    .with_context(|| format!("Failed to remove dnsmasq config {:?}", self.path)),
                _ => Ok(()),
            },
        }
    }
}

/// Write `content` to a staging file and validate it with `dnsmasq --test`
/// before anything touches the live configuration.
fn validate_candidate_config(content: &str) -> Result<()> {
    let staging = Path::new(STAGING_DIR).join("dnsmasq.conf.candidate");
    fs::write(&staging, content)
        .with_context(|| format!("Failed to write candidate dnsmasq config {:?}", staging))?;
    let result = validate_dnsmasq_config_file(&staging);
    let _ = fs::remove_file(&staging);
    result
}

/// Restart the dnsmasq service.
///
/// We intentionally prefer `restart` over `reload` here. In some environments
/// (notably the Arch unit using `Type=dbus`), `systemctl reload` can succeed
/// without dnsmasq re-reading updated config fragments under `/etc/dnsmasq.d/`,
/// leading to DNS working but DHCP (udp/67) not being activated.
pub fn restart_dnsmasq() -> Result<()> {
    let output = Command::new("systemctl")
        .args(["restart", "dnsmasq"])
        .output()
        .context("Failed to execute systemctl restart dnsmasq")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to restart dnsmasq: {}", stderr.trim());
    }

    info!("dnsmasq restarted successfully");
    Ok(())
}

/// Check if dnsmasq service is running
pub fn is_dnsmasq_running() -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", "dnsmasq"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Enable and start dnsmasq service
pub fn enable_dnsmasq() -> Result<()> {
    // Enable the service
    let output = Command::new("systemctl")
        .args(["enable", "dnsmasq"])
        .output()
        .context("Failed to enable dnsmasq service")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("Failed to enable dnsmasq: {}", stderr.trim());
    }

    // Start the service if not running
    if !is_dnsmasq_running() {
        let output = Command::new("systemctl")
            .args(["start", "dnsmasq"])
            .output()
            .context("Failed to start dnsmasq service")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to start dnsmasq: {}", stderr.trim());
        }
    }

    info!("dnsmasq service enabled and started");
    Ok(())
}

/// Disable and stop dnsmasq service
pub fn disable_dnsmasq() -> Result<()> {
    // Stop the service
    let _ = Command::new("systemctl").args(["stop", "dnsmasq"]).output();

    // Disable the service
    let output = Command::new("systemctl")
        .args(["disable", "dnsmasq"])
        .output()
        .context("Failed to disable dnsmasq service")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("Failed to disable dnsmasq: {}", stderr.trim());
    }

    info!("dnsmasq service disabled and stopped");
    Ok(())
}

/// Write dnsmasq configuration file
pub fn write_dnsmasq_config(content: &str) -> Result<()> {
    ensure_dnsmasq_dir()?;
    ensure_lease_dir()?;

    // Keystone owns the main config file. We intentionally do not rely on
    // distro-specific includes of `/etc/dnsmasq.d`.
    fs::write(DNSMASQ_MAIN_CONFIG_PATH, content).with_context(|| {
        format!(
            "Failed to write dnsmasq config to {}",
            DNSMASQ_MAIN_CONFIG_PATH
        )
    })?;

    // Remove legacy drop-in file if present.
    let legacy_path = Path::new(DNSMASQ_CONFIG_PATH);
    if legacy_path.exists() {
        fs::remove_file(legacy_path).with_context(|| {
            format!(
                "Failed to remove legacy dnsmasq config: {}",
                DNSMASQ_CONFIG_PATH
            )
        })?;
    }

    info!(
        "Wrote dnsmasq configuration to {}",
        DNSMASQ_MAIN_CONFIG_PATH
    );
    Ok(())
}

/// Remove Keystone-owned dnsmasq configuration
pub fn remove_dnsmasq_config() -> Result<()> {
    let path = Path::new(DNSMASQ_MAIN_CONFIG_PATH);
    if path.exists() {
        fs::remove_file(path).with_context(|| {
            format!(
                "Failed to remove dnsmasq config: {}",
                DNSMASQ_MAIN_CONFIG_PATH
            )
        })?;
        info!("Removed dnsmasq configuration file");
    }

    // Best-effort cleanup of legacy config file too.
    let legacy_path = Path::new(DNSMASQ_CONFIG_PATH);
    if legacy_path.exists() {
        let _ = fs::remove_file(legacy_path);
    }

    Ok(())
}

/// Apply dnsmasq configuration from database
///
/// This function:
/// 1. Loads configuration from database
/// 2. Generates config file content
/// 3. Validates a staged candidate with `dnsmasq --test --conf-file`
/// 4. Writes /etc/dnsmasq.conf (Keystone-owned), keeping a snapshot
/// 5. Restarts dnsmasq, restoring the snapshot if that fails
pub async fn apply_dnsmasq_config(pool: &SqlitePool) -> Result<()> {
    // Load complete state from database
    let state = load_dnsmasq_state(pool).await?;
    // Old database rows may predate API validation. Never write them into a
    // root-owned dnsmasq configuration without checking all fields again.
    keystone_core::validation::single_line_fields(&state).map_err(anyhow::Error::msg)?;
    for range in &state.dhcp_ranges {
        keystone_core::validation::interface_name(&range.interface).map_err(anyhow::Error::msg)?;
    }
    for name in state
        .config
        .listen_interfaces
        .iter()
        .chain(&state.config.except_interfaces)
        .chain(&state.config.no_dhcp_interfaces)
    {
        keystone_core::validation::interface_name(name).map_err(anyhow::Error::msg)?;
    }

    // Check if dnsmasq is enabled
    if !state.config.enabled {
        info!("dnsmasq is disabled, removing config and stopping service");
        remove_dnsmasq_config()?;
        disable_dnsmasq()?;
        return Ok(());
    }

    // Generate configuration and validate it before touching the live file.
    let content = generate_dnsmasq_config(&state);
    validate_candidate_config(&content)?;

    // Keep the previous config so a failed install or restart can be undone.
    // `/etc/dnsmasq.conf` is a bind-mounted single-file ReadWritePath in the
    // service sandbox, so it cannot be replaced by rename; it is rewritten in
    // place after the candidate has passed validation.
    let snapshot = DnsmasqConfigSnapshot::capture(Path::new(DNSMASQ_MAIN_CONFIG_PATH))?;

    let result = write_dnsmasq_config(&content)
        .and_then(|()| enable_dnsmasq())
        .and_then(|()| restart_dnsmasq());

    if let Err(error) = result {
        return match snapshot.restore().and_then(|()| restart_dnsmasq()) {
            Ok(()) => Err(anyhow::anyhow!(
                "dnsmasq failed to apply the new configuration and the previous config was restored: {error:#}"
            )),
            Err(restore_error) => Err(anyhow::anyhow!(
                "dnsmasq failed to apply the new configuration ({error:#}) and restoring the previous config also failed ({restore_error:#})"
            )),
        };
    }

    info!("dnsmasq configuration applied successfully");
    Ok(())
}

/// Generate a preview of the dnsmasq configuration without applying
pub async fn preview_dnsmasq_config(pool: &SqlitePool) -> Result<String> {
    let state = load_dnsmasq_state(pool).await?;
    Ok(generate_dnsmasq_config(&state))
}

/// Get the current dnsmasq service status
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsmasqServiceStatus {
    pub running: bool,
    pub enabled: bool,
    pub config_exists: bool,
}

/// Check the current status of the dnsmasq service
pub fn get_dnsmasq_status() -> DnsmasqServiceStatus {
    let running = is_dnsmasq_running();

    let enabled = Command::new("systemctl")
        .args(["is-enabled", "--quiet", "dnsmasq"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    let config_exists = Path::new(DNSMASQ_MAIN_CONFIG_PATH).exists();

    DnsmasqServiceStatus {
        running,
        enabled,
        config_exists,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("keystone-dnsmasq-{}-{name}", std::process::id()))
    }

    #[test]
    fn snapshot_restores_previous_content() {
        let path = temp_path("existing");
        fs::write(&path, b"old config").unwrap();
        let snapshot = DnsmasqConfigSnapshot::capture(&path).unwrap();
        fs::write(&path, b"broken").unwrap();
        snapshot.restore().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"old config");
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn snapshot_removes_file_that_did_not_exist() {
        let path = temp_path("missing");
        let _ = fs::remove_file(&path);
        let snapshot = DnsmasqConfigSnapshot::capture(&path).unwrap();
        fs::write(&path, b"new").unwrap();
        snapshot.restore().unwrap();
        assert!(!path.exists());
        // Restoring again when already absent is fine.
        snapshot.restore().unwrap();
    }
}
