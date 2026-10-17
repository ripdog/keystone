//! Applying the access point: `/etc/hostapd/<interface>.conf` and
//! `hostapd@<interface>.service`.
//!
//! hostapd joins the bridge itself once the interface is in AP mode, so the
//! bridge (created by networkd) must exist first; the wireless component
//! therefore applies after the networkd component.

use std::fs;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use keystone_core::SystemdActiveState;
use keystone_core::validation;
use keystone_core::wireless::{WirelessConfig, WirelessStatusResponse};
use tokio::sync::Mutex;
use tracing::{info, warn};

use super::config::{HOSTAPD_CONF_DIR, conf_path, render_hostapd_conf, unit_name};
use super::db::{load_applied, load_wireless_config, save_applied};
use super::detect;
use crate::db::Database;
use crate::systemd;

/// How long hostapd gets to fail before the apply is judged successful. It
/// exits within a moment when the channel, country or bridge is unusable.
const STARTUP_GRACE: Duration = Duration::from_secs(2);

/// Serialises applies.
static APPLY_LOCK: Mutex<()> = Mutex::const_new(());

/// Names of the configured bridges an access point may join.
pub async fn bridge_candidates(db: &Database) -> Result<Vec<String>> {
    Ok(db
        .get_all_bridges()
        .await?
        .into_iter()
        .map(|bridge| bridge.name)
        .collect())
}

/// Bring the system to the saved configuration and record it as applied. The
/// caller records the snapshot.
pub async fn apply_saved(db: &Database) -> Result<()> {
    let _guard = APPLY_LOCK.lock().await;
    let pool = db.pool();
    let config = load_wireless_config(pool).await?;
    let bridges = bridge_candidates(db).await?;
    config.validate(&bridges).map_err(|error| anyhow!(error))?;

    // An access point left running on an interface that is no longer the
    // configured one would keep its radio and bridge port.
    if let Some(previous) = load_applied(pool).await?
        && !previous.interface.is_empty()
        && previous.interface != config.interface
    {
        remove_access_point(&previous.interface).await?;
    }

    if config.enabled {
        apply_enabled(&config).await?;
    } else if !config.interface.is_empty() {
        remove_access_point(&config.interface).await?;
    }

    save_applied(pool, &config).await?;
    info!(
        "Wireless applied: enabled={} interface={:?} bridge={:?}",
        config.enabled, config.interface, config.bridge
    );
    Ok(())
}

async fn apply_enabled(config: &WirelessConfig) -> Result<()> {
    if !detect::binary_installed("hostapd") {
        bail!("hostapd is not installed. Install it with: pacman -S hostapd");
    }
    let known = detect::list_interfaces().await;
    let Some(interface) = known.iter().find(|i| i.name == config.interface) else {
        bail!(
            "{} is not a wireless interface on this machine",
            config.interface
        );
    };
    if interface.ap_supported == Some(false) {
        bail!("{} cannot host an access point", config.interface);
    }

    let path = conf_path(&config.interface);
    let content = render_hostapd_conf(config);
    let changed = fs::read_to_string(&path).ok().as_deref() != Some(content.as_str());
    write_conf(Path::new(HOSTAPD_CONF_DIR), &config.interface, &content)?;

    let unit = unit_name(&config.interface);
    systemd::enable_unit(&unit)
        .await
        .with_context(|| format!("failed to enable {unit}"))?;
    if changed || !unit_active(&unit).await {
        systemd::restart_unit(&unit)
            .await
            .with_context(|| format!("failed to restart {unit}"))?;
        tokio::time::sleep(STARTUP_GRACE).await;
        if !unit_active(&unit).await {
            bail!(
                "{unit} stopped right after starting; check its log under Diagnostics, \
                 and that the channel, country and bridge are usable"
            );
        }
    }
    Ok(())
}

/// Stop the access point on `interface` and remove what Keystone wrote for it.
/// One that was never installed or started is not an error.
async fn remove_access_point(interface: &str) -> Result<()> {
    validation::interface_name(interface).map_err(|error| anyhow!(error))?;
    let unit = unit_name(interface);
    if unit_active(&unit).await
        && let Err(error) = systemd::stop_unit(&unit).await
    {
        warn!("Stopping {unit} failed: {error:#}");
    }
    if let Err(error) = systemd::disable_unit(&unit).await {
        // Disabling a unit that does not exist fails; that is the normal case
        // when hostapd is not installed.
        info!("{unit} not disabled: {error:#}");
    }
    let path = conf_path(interface);
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error).with_context(|| format!("failed to remove {path}")),
    }
    Ok(())
}

/// Write `<dir>/<interface>.conf` readable by root only: it holds the
/// passphrase. The file is created with its final mode and renamed into place.
fn write_conf(dir: &Path, interface: &str, content: &str) -> Result<()> {
    validation::interface_name(interface).map_err(|error| anyhow!(error))?;
    fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;
    let temporary = dir.join(format!(".{interface}.conf.tmp"));
    let target = dir.join(format!("{interface}.conf"));
    let _ = fs::remove_file(&temporary);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .with_context(|| format!("failed to create {}", temporary.display()))?;
    file.write_all(content.as_bytes())
        .and_then(|()| file.sync_all())
        .with_context(|| format!("failed to write {}", temporary.display()))?;
    fs::rename(&temporary, &target)
        .with_context(|| format!("failed to install {}", target.display()))?;
    Ok(())
}

/// The configuration that apply would write, or empty while the access point is
/// disabled. Used by the pending-changes diff, so it matches what apply writes.
pub async fn preview_wireless_config(db: &Database) -> Result<String> {
    let config = load_wireless_config(db.pool()).await?;
    if !config.enabled {
        return Ok(String::new());
    }
    let bridges = bridge_candidates(db).await?;
    config.validate(&bridges).map_err(|error| anyhow!(error))?;
    Ok(render_hostapd_conf(&config))
}

/// Whether `unit` is active, read from systemd over D-Bus.
async fn unit_active(unit: &str) -> bool {
    match systemd::get_unit_detail(unit).await {
        Ok(Some(detail)) => detail.unit.active_state == SystemdActiveState::Active,
        _ => false,
    }
}

/// Live state: the service and the associated stations.
pub async fn read_status(db: &Database) -> Result<WirelessStatusResponse> {
    let config = load_wireless_config(db.pool()).await?;
    if config.interface.is_empty() || validation::interface_name(&config.interface).is_err() {
        return Ok(WirelessStatusResponse {
            service_active: false,
            stations: Vec::new(),
            warnings: Vec::new(),
        });
    }
    let service_active = unit_active(&unit_name(&config.interface)).await;
    let mut warnings = Vec::new();
    let stations = if service_active {
        match detect::list_stations(&config.interface).await {
            Ok(stations) => stations,
            Err(error) => {
                warnings.push(error);
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    Ok(WirelessStatusResponse {
        service_active,
        stations,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("keystone-wireless-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn the_config_file_is_private_and_replaced_atomically() {
        let dir = temp_dir("write");
        write_conf(&dir, "wlan0", "wpa_passphrase=first\n").unwrap();
        let path = dir.join("wlan0.conf");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        // A second write replaces the content and leaves no temporary file.
        write_conf(&dir, "wlan0", "wpa_passphrase=second\n").unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "wpa_passphrase=second\n"
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_interface_name_cannot_write_outside_the_directory() {
        let dir = temp_dir("escape");
        for name in ["../evil", "a/b", ".."] {
            assert!(write_conf(&dir, name, "x").is_err(), "{name}");
        }
        assert!(!dir.exists() || fs::read_dir(&dir).unwrap().next().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_disabled_access_point_previews_as_nothing() {
        let db = Database::new_in_memory().await.unwrap();
        assert_eq!(preview_wireless_config(&db).await.unwrap(), "");
    }

    #[tokio::test]
    async fn an_enabled_access_point_on_a_missing_bridge_does_not_preview() {
        let db = Database::new_in_memory().await.unwrap();
        let config = WirelessConfig {
            enabled: true,
            interface: "wlan0".to_string(),
            bridge: "br-lan".to_string(),
            ssid: "x".to_string(),
            country_code: "NZ".to_string(),
            passphrase: "longenough1".to_string(),
            ..WirelessConfig::default()
        };
        super::super::db::save_wireless_config(db.pool(), &config)
            .await
            .unwrap();
        let error = preview_wireless_config(&db).await.unwrap_err();
        assert!(format!("{error:#}").contains("br-lan"));
    }

    #[test]
    fn the_packaged_daemon_can_write_the_hostapd_directory() {
        let unit = include_str!("../../../packaging/arch/keystone-daemon.service");
        let lists = |key: &str, path: &str| {
            unit.lines().any(|line| {
                line.strip_prefix(key)
                    .is_some_and(|paths| paths.split_whitespace().any(|p| p == path))
            })
        };
        assert!(lists("ReadWritePaths=", "/etc/hostapd"));
        // The directory must exist before the sandbox is built.
        assert!(lists("ConfigurationDirectory=", "hostapd"));
    }
}
