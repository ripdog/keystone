//! Applying UPnP: `miniupnpd.conf`, the nftables table and `miniupnpd.service`.
//!
//! Enabling requires the nftables build of miniupnpd. The table is created
//! before the service starts, because miniupnpd adds its rules at start and
//! does not create the table itself. A restart reloads the mappings from the
//! lease file, so the table is deleted and recreated before each restart to
//! avoid duplicate rules.

use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use keystone_core::InterfaceConfig;
use keystone_core::InterfaceRole;
use keystone_core::SystemdActiveState;
use keystone_core::upnp::{UpnpBinaryStatus, UpnpConfig, UpnpStatusResponse};
use tokio::sync::Mutex;
use tracing::{info, warn};

use super::config::{
    MINIUPNPD_CONF_PATH, UPNP_LEASE_FILE, render_miniupnpd_conf, resolve_client_subnets,
    uuid_from_machine_id, validate_config,
};
use super::db::{load_applied, load_upnp_config, save_applied};
use super::detect::detect_binary;
use super::leases::parse_lease_file;
use super::nft;
use crate::db::Database;
use crate::systemd;

/// Directory holding `miniupnpd.conf`. Created by `ConfigurationDirectory=`.
const MINIUPNPD_CONF_DIR: &str = "/etc/miniupnpd";
const MACHINE_ID_PATH: &str = "/etc/machine-id";
/// The packaged unit. Its name is fixed: Keystone never runs another daemon.
const SERVICE: &str = "miniupnpd.service";
/// Largest lease file read for the mapping list.
const MAX_LEASE_FILE_BYTES: u64 = 1024 * 1024;
/// How often the reconciler checks that the table still exists.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(15);

/// Serialises applies, so the reconciler never races a user-triggered apply.
static APPLY_LOCK: Mutex<()> = Mutex::const_new(());

/// Interface names of the configured LAN-role and WAN-role interfaces.
pub async fn interface_candidates(db: &Database) -> Result<(Vec<String>, Vec<String>)> {
    let interfaces = db.get_interface_configs().await?;
    Ok(candidates_from(&interfaces))
}

fn candidates_from(interfaces: &[InterfaceConfig]) -> (Vec<String>, Vec<String>) {
    let by_role = |role: InterfaceRole| {
        interfaces
            .iter()
            .filter(|iface| iface.role == role)
            .map(|iface| iface.name.clone())
            .collect()
    };
    (by_role(InterfaceRole::LAN), by_role(InterfaceRole::WAN))
}

/// Bring the system to the saved configuration and record it as applied. The
/// caller records the snapshot.
pub async fn apply_saved(db: &Database) -> Result<()> {
    let _guard = APPLY_LOCK.lock().await;
    let pool = db.pool();
    let config = load_upnp_config(pool).await?;
    let (lan, wan) = interface_candidates(db).await?;
    validate_config(&config, &lan, &wan).map_err(|error| anyhow!(error))?;

    if config.enabled {
        apply_enabled(db, &config).await?;
    } else {
        disable().await?;
    }

    save_applied(pool, &config).await?;
    info!(
        "UPnP applied: enabled={} lan={:?} wan={:?}",
        config.enabled, config.lan_interfaces, config.wan_interface
    );
    Ok(())
}

async fn apply_enabled(db: &Database, config: &UpnpConfig) -> Result<()> {
    let binary = detect_binary_async().await;
    if !binary.is_supported() {
        bail!("{}", binary.message());
    }

    let interfaces = db.get_interface_configs().await?;
    let subnets = resolve_client_subnets(config, &interfaces).map_err(|error| anyhow!(error))?;
    let content = render_for(config, &subnets)?;

    let previous = fs::read_to_string(MINIUPNPD_CONF_PATH).ok();
    let changed = previous.as_deref() != Some(content.as_str());
    write_config(&content)?;

    let running = service_active().await;
    let table = nft::table_exists().await;
    if changed || !running || !table {
        // Mapping rules live in the table. A restart re-adds them from the
        // lease file, so an old table must not be left in place.
        nft::delete_table().await?;
        nft::create_table().await?;
        systemd::enable_unit(SERVICE)
            .await
            .context("failed to enable miniupnpd.service")?;
        systemd::restart_unit(SERVICE)
            .await
            .context("failed to restart miniupnpd.service")?;
    }
    Ok(())
}

/// Stop UPnP and remove everything Keystone created for it. A miniupnpd that
/// was never installed or enabled is not an error.
async fn disable() -> Result<()> {
    if service_active().await
        && let Err(error) = systemd::stop_unit(SERVICE).await
    {
        warn!("Stopping miniupnpd failed: {error:#}");
    }
    if let Err(error) = systemd::disable_unit(SERVICE).await {
        // Disabling a unit that does not exist fails; that is the normal case
        // when miniupnpd is not installed.
        info!("miniupnpd not disabled: {error:#}");
    }
    nft::delete_table().await?;
    match fs::remove_file(MINIUPNPD_CONF_PATH) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("failed to remove {MINIUPNPD_CONF_PATH}"));
        }
    }
    Ok(())
}

/// The `miniupnpd.conf` text for `config`, with the UUID from the machine-id.
fn render_for(config: &UpnpConfig, subnets: &[String]) -> Result<String> {
    let machine_id = fs::read_to_string(MACHINE_ID_PATH)
        .with_context(|| format!("failed to read {MACHINE_ID_PATH} for the UPnP UUID"))?;
    let uuid = uuid_from_machine_id(&machine_id).map_err(|error| anyhow!(error))?;
    render_miniupnpd_conf(config, subnets, &uuid).map_err(|error| anyhow!(error))
}

/// The configuration that apply would write, or empty when UPnP is disabled.
/// Used by the pending-changes diff, so it matches what apply writes.
pub async fn preview_upnp_config(db: &Database) -> Result<String> {
    let config = load_upnp_config(db.pool()).await?;
    if !config.enabled {
        return Ok(String::new());
    }
    let interfaces = db.get_interface_configs().await?;
    let subnets = resolve_client_subnets(&config, &interfaces).map_err(|error| anyhow!(error))?;
    render_for(&config, &subnets)
}

fn write_config(content: &str) -> Result<()> {
    fs::create_dir_all(MINIUPNPD_CONF_DIR)
        .with_context(|| format!("failed to create {MINIUPNPD_CONF_DIR}"))?;
    let temporary = Path::new(MINIUPNPD_CONF_DIR).join(".miniupnpd.conf.tmp");
    fs::write(&temporary, content)
        .with_context(|| format!("failed to write {}", temporary.display()))?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o644))
        .with_context(|| format!("failed to set permissions on {}", temporary.display()))?;
    fs::rename(&temporary, MINIUPNPD_CONF_PATH)
        .with_context(|| format!("failed to install {MINIUPNPD_CONF_PATH}"))?;
    Ok(())
}

async fn detect_binary_async() -> UpnpBinaryStatus {
    tokio::task::spawn_blocking(detect_binary)
        .await
        .unwrap_or(UpnpBinaryStatus::Unknown)
}

/// Whether `miniupnpd.service` is active, read from systemd over D-Bus.
async fn service_active() -> bool {
    match systemd::get_unit_detail(SERVICE).await {
        Ok(Some(detail)) => detail.unit.active_state == SystemdActiveState::Active,
        _ => false,
    }
}

/// Live state: the binary, the service and the mappings in the lease file.
pub async fn read_status() -> UpnpStatusResponse {
    let binary = detect_binary_async().await;
    let service_active = service_active().await;
    let (mappings, mut warnings) = read_lease_file();
    if !mappings.is_empty() && !service_active {
        warnings.push("miniupnpd is not running, so these mappings are not active".to_string());
    }
    UpnpStatusResponse {
        binary,
        binary_message: binary.message().to_string(),
        service_active,
        mappings,
        warnings,
    }
}

fn read_lease_file() -> (Vec<keystone_core::upnp::UpnpMapping>, Vec<String>) {
    let path = Path::new(UPNP_LEASE_FILE);
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return (Vec::new(), Vec::new()),
        Err(error) => {
            return (
                Vec::new(),
                vec![format!(
                    "could not inspect the miniupnpd lease file: {error}"
                )],
            );
        }
    };
    if metadata.len() > MAX_LEASE_FILE_BYTES {
        return (
            Vec::new(),
            vec!["the miniupnpd lease file is too large to read".to_string()],
        );
    }
    match fs::read_to_string(path) {
        Ok(text) => parse_lease_file(&text),
        Err(error) => (
            Vec::new(),
            vec![format!("could not read the miniupnpd lease file: {error}")],
        ),
    }
}

/// Start the reconciler. After a reboot the table is gone while
/// `miniupnpd.service` may already be running, so the table is recreated and
/// the service restarted to reload its mappings.
pub fn start_reconciler(db: Database) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(RECONCILE_INTERVAL);
        loop {
            interval.tick().await;
            if let Err(error) = reconcile(&db).await {
                warn!("UPnP reconciliation: {error:#}");
            }
        }
    });
}

async fn reconcile(db: &Database) -> Result<()> {
    let _guard = APPLY_LOCK.lock().await;
    let Some(applied) = load_applied(db.pool()).await? else {
        return Ok(());
    };
    if !applied.enabled || nft::table_exists().await {
        return Ok(());
    }
    if !detect_binary_async().await.is_supported() {
        return Ok(());
    }
    warn!(
        "UPnP table {} is missing; recreating it and restarting miniupnpd",
        nft::UPNP_TABLE
    );
    nft::create_table().await?;
    systemd::restart_unit(SERVICE).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use keystone_core::{DhcpMode, StaticAddress};

    fn interface(name: &str, role: InterfaceRole) -> InterfaceConfig {
        InterfaceConfig {
            id: None,
            name: name.to_string(),
            role,
            enabled: true,
            description: None,
            dhcp_mode: DhcpMode::No,
            addresses: vec![StaticAddress {
                address: "192.168.1.1/24".to_string(),
                label: None,
                scope: Default::default(),
            }],
            routes: Vec::new(),
            dns_servers: Vec::new(),
            search_domains: Vec::new(),
            gateway: None,
            link_local: Default::default(),
            ..Default::default()
        }
    }

    #[test]
    fn candidates_split_by_role() {
        let interfaces = [
            interface("eth0", InterfaceRole::WAN),
            interface("eth1", InterfaceRole::LAN),
            interface("eth2", InterfaceRole::LAN),
        ];
        let (lan, wan) = candidates_from(&interfaces);
        assert_eq!(lan, vec!["eth1", "eth2"]);
        assert_eq!(wan, vec!["eth0"]);
    }
}
