//! Applying Blocky: `config.yml` and `keystone-blocky.service`.
//!
//! When DNS filtering is enabled the configuration is written and the service
//! is enabled and restarted. When it is disabled the service is stopped and
//! disabled and the configuration is removed. The caller records the snapshot.

use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use keystone_core::SystemdActiveState;
use keystone_core::blocky::{BlockyConfig, BlockyStatusResponse};
use tracing::{info, warn};

use super::api;
use super::config::{BLOCKY_BINARY_PATH, BLOCKY_CONFIG_PATH, render_config, validate_config};
use super::db::load_blocky_config;
use crate::db::Database;
use crate::systemd;

/// Directory holding `config.yml`. Created by `ConfigurationDirectory=`.
const BLOCKY_CONFIG_DIR: &str = "/etc/keystone-blocky";
/// The unit Keystone owns. It is shipped with Keystone, not with blocky-bin.
const SERVICE: &str = "keystone-blocky.service";
/// Blocky exits at once on a configuration it cannot load. systemd reports a
/// restart as done before that happens, so the service is checked again after
/// this delay.
const STARTUP_CHECK_DELAY: Duration = Duration::from_secs(2);

pub const BINARY_MISSING_MESSAGE: &str =
    "Blocky is not installed. Install blocky-bin from the AUR to use DNS filtering.";

/// Whether `/usr/bin/blocky` exists.
pub fn binary_installed() -> bool {
    Path::new(BLOCKY_BINARY_PATH).is_file()
}

pub fn binary_message(installed: bool) -> &'static str {
    if installed {
        "Blocky is installed."
    } else {
        BINARY_MISSING_MESSAGE
    }
}

/// Bring the system to the saved configuration. The caller records the
/// snapshot.
pub async fn apply_saved(db: &Database) -> Result<()> {
    let config = load_blocky_config(db.pool()).await?;
    validate_config(&config).map_err(|error| anyhow!(error))?;

    if config.enabled {
        apply_enabled(&config).await?;
    } else {
        disable().await?;
    }
    info!("Blocky applied: enabled={}", config.enabled);
    Ok(())
}

async fn apply_enabled(config: &BlockyConfig) -> Result<()> {
    if !binary_installed() {
        bail!("{BINARY_MISSING_MESSAGE}");
    }
    let content = render_config(config).map_err(|error| anyhow!(error))?;
    write_config(&content)?;

    systemd::enable_unit(SERVICE)
        .await
        .context("failed to enable keystone-blocky.service")?;
    systemd::restart_unit(SERVICE)
        .await
        .context("failed to restart keystone-blocky.service")?;

    tokio::time::sleep(STARTUP_CHECK_DELAY).await;
    if !service_active().await {
        bail!(
            "keystone-blocky.service is not running after the restart; see journalctl -u keystone-blocky"
        );
    }
    Ok(())
}

/// Stop Blocky and remove everything Keystone wrote for it. A Blocky that was
/// never installed or enabled is not an error.
async fn disable() -> Result<()> {
    if service_active().await
        && let Err(error) = systemd::stop_unit(SERVICE).await
    {
        warn!("Stopping keystone-blocky failed: {error:#}");
    }
    if let Err(error) = systemd::disable_unit(SERVICE).await {
        info!("keystone-blocky not disabled: {error:#}");
    }
    match fs::remove_file(BLOCKY_CONFIG_PATH) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to remove {BLOCKY_CONFIG_PATH}")),
    }
}

/// Write `config.yml` through a temporary file in the same directory, so the
/// service never reads a partial file. Blocky runs as a dynamic user, so the
/// file is world-readable, as UPnP's configuration is.
fn write_config(content: &str) -> Result<()> {
    fs::create_dir_all(BLOCKY_CONFIG_DIR)
        .with_context(|| format!("failed to create {BLOCKY_CONFIG_DIR}"))?;
    let temporary = Path::new(BLOCKY_CONFIG_DIR).join(".config.yml.tmp");
    fs::write(&temporary, content)
        .with_context(|| format!("failed to write {}", temporary.display()))?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o644))
        .with_context(|| format!("failed to set permissions on {}", temporary.display()))?;
    fs::rename(&temporary, BLOCKY_CONFIG_PATH)
        .with_context(|| format!("failed to install {BLOCKY_CONFIG_PATH}"))?;
    Ok(())
}

/// The `config.yml` text that apply would write, or empty when DNS filtering
/// is disabled. Used by the pending-changes diff, so it matches apply.
pub async fn preview_blocky_config(db: &Database) -> Result<String> {
    let config = load_blocky_config(db.pool()).await?;
    if !config.enabled {
        return Ok(String::new());
    }
    render_config(&config).map_err(|error| anyhow!(error))
}

/// Whether `keystone-blocky.service` is active, read from systemd over D-Bus.
pub async fn service_active() -> bool {
    match systemd::get_unit_detail(SERVICE).await {
        Ok(Some(detail)) => detail.unit.active_state == SystemdActiveState::Active,
        _ => false,
    }
}

/// True when dnsmasq can send its queries to Blocky: the binary exists and the
/// service is running. dnsmasq refuses to switch to Blocky mode otherwise.
pub async fn is_serving() -> bool {
    binary_installed() && service_active().await
}

/// Live state: the binary, the service and Blocky's own blocking state.
pub async fn read_status() -> BlockyStatusResponse {
    let installed = binary_installed();
    let service_active = service_active().await;
    let mut warnings = Vec::new();
    let mut blocking = None;
    let mut api_reachable = false;
    if service_active {
        match api::blocking_status().await {
            Ok(status) => {
                api_reachable = true;
                blocking = Some(status);
            }
            Err(error) => warnings.push(format!("{error:#}")),
        }
    }
    BlockyStatusResponse {
        installed,
        binary_message: binary_message(installed).to_string(),
        service_active,
        api_reachable,
        blocking,
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_binary_message_names_the_package() {
        assert!(binary_message(false).contains("blocky-bin"));
        assert!(!binary_message(true).contains("not installed"));
    }
}
