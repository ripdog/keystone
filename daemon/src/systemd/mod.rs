//! Systemd unit management via D-Bus
//!
//! Uses zbus_systemd to interact with systemd via D-Bus for listing,
//! starting, stopping, enabling, and disabling units.

pub mod routes;

use anyhow::{Context, Result};
use keystone_core::{SystemdActiveState, SystemdLoadState, SystemdUnit, SystemdUnitDetail};
use tracing::debug;
use zbus::Connection;
use zbus_systemd::systemd1;

/// List systemd units, optionally filtering to keystone-related units
pub async fn list_units(keystone_only: bool) -> Result<Vec<SystemdUnit>> {
    let connection = Connection::system()
        .await
        .context("Failed to connect to system D-Bus")?;

    let manager = systemd1::ManagerProxy::new(&connection)
        .await
        .context("Failed to create systemd manager proxy")?;

    if keystone_only {
        return list_managed_units(&manager).await;
    }

    // ListUnits returns: (name, description, load_state, active_state, sub_state, following, unit_path, job_id, job_type, job_path)
    let units = manager
        .list_units()
        .await
        .context("Failed to list systemd units")?;

    // Get unit file states to determine enabled status
    let unit_files = manager
        .list_unit_files()
        .await
        .context("Failed to list unit files")?;

    // Build a map of unit name -> enabled status
    let enabled_map: std::collections::HashMap<String, bool> = unit_files
        .into_iter()
        .map(|(name, state)| {
            let is_enabled = state == "enabled" || state == "enabled-runtime" || state == "static";
            // Extract just the unit name from the path
            let unit_name = name.rsplit('/').next().unwrap_or(&name).to_string();
            (unit_name, is_enabled)
        })
        .collect();

    let mut result: Vec<SystemdUnit> = units
        .into_iter()
        .filter(|(name, _, _, _, _, _, _, _, _, _)| {
            // Only include .service units
            if !name.ends_with(".service") {
                return false;
            }
            // If keystone_only, filter to keystone-related units
            if keystone_only {
                is_keystone_related(name)
            } else {
                true
            }
        })
        .map(
            |(name, description, load_state, active_state, sub_state, _, _, _, _, _)| {
                let enabled = enabled_map.get(&name).copied().unwrap_or(false);
                SystemdUnit {
                    name: name.clone(),
                    description,
                    load_state: parse_load_state(&load_state),
                    active_state: parse_active_state(&active_state),
                    sub_state,
                    enabled,
                }
            },
        )
        .collect();

    result.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(result)
}

/// Fast path for the dashboard, which polls every few seconds: query only the
/// managed units. `ListUnits` + `ListUnitFiles` make PID 1 walk every unit
/// directory on disk, which showed up as sustained systemd CPU load.
async fn list_managed_units(manager: &systemd1::ManagerProxy<'_>) -> Result<Vec<SystemdUnit>> {
    let names: Vec<String> = MANAGED_UNITS.iter().map(|n| n.to_string()).collect();
    let units = manager
        .list_units_by_names(names)
        .await
        .context("Failed to list managed systemd units")?;

    let mut result = Vec::with_capacity(units.len());
    for (name, description, load_state, active_state, sub_state, _, _, _, _, _) in units {
        // Match `ListUnits`, which only reports units systemd has loaded.
        if load_state == "not-found" {
            continue;
        }
        let enabled = manager
            .get_unit_file_state(name.clone())
            .await
            .map(|state| matches!(state.as_str(), "enabled" | "enabled-runtime" | "static"))
            .unwrap_or(false);
        result.push(SystemdUnit {
            name,
            description,
            load_state: parse_load_state(&load_state),
            active_state: parse_active_state(&active_state),
            sub_state,
            enabled,
        });
    }
    result.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(result)
}

/// Services Keystone manages, and the only ones its API controls or reads logs
/// of. Filtering the displayed list is not a security boundary.
pub(crate) const MANAGED_UNITS: &[&str] = &[
    "keystone-daemon.service",
    "keystone-web-ui.service",
    "systemd-networkd.service",
    "nftables.service",
    "dnsmasq.service",
    "caddy.service",
    "miniupnpd.service",
    "keystone-blocky.service",
    "sshd.service",
];

pub(crate) fn is_keystone_related(name: &str) -> bool {
    MANAGED_UNITS.contains(&name)
}

fn ensure_managed_unit(name: &str) -> Result<()> {
    if !is_keystone_related(name) {
        anyhow::bail!("Service is not managed by Keystone: {name}");
    }
    Ok(())
}

/// Get detailed information about a specific unit
pub async fn get_unit_detail(unit_name: &str) -> Result<Option<SystemdUnitDetail>> {
    ensure_managed_unit(unit_name)?;
    let connection = Connection::system()
        .await
        .context("Failed to connect to system D-Bus")?;

    let manager = systemd1::ManagerProxy::new(&connection)
        .await
        .context("Failed to create systemd manager proxy")?;

    // Get the unit object path
    let unit_path = match manager.get_unit(unit_name.to_string()).await {
        Ok(path) => path,
        Err(e) => {
            debug!("Unit {} not found: {}", unit_name, e);
            return Ok(None);
        }
    };

    // Create a unit proxy
    let unit_proxy = systemd1::UnitProxy::builder(&connection)
        .path(unit_path.clone())
        .context("Invalid unit path")?
        .build()
        .await
        .context("Failed to create unit proxy")?;

    // Get basic properties
    let description = unit_proxy.description().await.unwrap_or_default();
    let load_state = unit_proxy.load_state().await.unwrap_or_default();
    let active_state = unit_proxy.active_state().await.unwrap_or_default();
    let sub_state = unit_proxy.sub_state().await.unwrap_or_default();
    let active_enter_timestamp = unit_proxy.active_enter_timestamp().await.ok();
    let inactive_enter_timestamp = unit_proxy.inactive_enter_timestamp().await.ok();

    // Get unit file state for enabled status
    let unit_file_state = manager
        .get_unit_file_state(unit_name.to_string())
        .await
        .unwrap_or_default();
    let enabled = unit_file_state == "enabled"
        || unit_file_state == "enabled-runtime"
        || unit_file_state == "static";

    // Try to get service-specific properties if this is a service
    let (main_pid, memory_bytes, result) = if unit_name.ends_with(".service") {
        let service_proxy = systemd1::ServiceProxy::builder(&connection)
            .path(unit_path)
            .context("Invalid service path")?
            .build()
            .await
            .ok();

        if let Some(svc) = service_proxy {
            let pid = svc.main_pid().await.ok().filter(|&p| p > 0);
            let mem = svc.memory_current().await.ok();
            let res = svc.result().await.ok();
            (pid, mem, res)
        } else {
            (None, None, None)
        }
    } else {
        (None, None, None)
    };

    Ok(Some(SystemdUnitDetail {
        unit: SystemdUnit {
            name: unit_name.to_string(),
            description,
            load_state: parse_load_state(&load_state),
            active_state: parse_active_state(&active_state),
            sub_state,
            enabled,
        },
        main_pid,
        memory_bytes,
        active_enter_timestamp,
        inactive_enter_timestamp,
        result,
    }))
}

/// Start a systemd unit
pub async fn start_unit(unit_name: &str) -> Result<()> {
    ensure_managed_unit(unit_name)?;
    let connection = Connection::system()
        .await
        .context("Failed to connect to system D-Bus")?;

    let manager = systemd1::ManagerProxy::new(&connection)
        .await
        .context("Failed to create systemd manager proxy")?;

    manager
        .start_unit(unit_name.to_string(), "replace".to_string())
        .await
        .context("Failed to start unit")?;

    Ok(())
}

/// Stop a systemd unit
pub async fn stop_unit(unit_name: &str) -> Result<()> {
    ensure_managed_unit(unit_name)?;
    let connection = Connection::system()
        .await
        .context("Failed to connect to system D-Bus")?;

    let manager = systemd1::ManagerProxy::new(&connection)
        .await
        .context("Failed to create systemd manager proxy")?;

    manager
        .stop_unit(unit_name.to_string(), "replace".to_string())
        .await
        .context("Failed to stop unit")?;

    Ok(())
}

/// Restart a systemd unit
pub async fn restart_unit(unit_name: &str) -> Result<()> {
    ensure_managed_unit(unit_name)?;
    let connection = Connection::system()
        .await
        .context("Failed to connect to system D-Bus")?;

    let manager = systemd1::ManagerProxy::new(&connection)
        .await
        .context("Failed to create systemd manager proxy")?;

    manager
        .restart_unit(unit_name.to_string(), "replace".to_string())
        .await
        .context("Failed to restart unit")?;

    Ok(())
}

/// Enable a systemd unit (start on boot)
pub async fn enable_unit(unit_name: &str) -> Result<()> {
    ensure_managed_unit(unit_name)?;
    let connection = Connection::system()
        .await
        .context("Failed to connect to system D-Bus")?;

    let manager = systemd1::ManagerProxy::new(&connection)
        .await
        .context("Failed to create systemd manager proxy")?;

    manager
        .enable_unit_files(vec![unit_name.to_string()], false, true)
        .await
        .context("Failed to enable unit")?;

    // Reload daemon to pick up the changes
    manager
        .reload()
        .await
        .context("Failed to reload systemd daemon")?;

    Ok(())
}

/// Disable a systemd unit (don't start on boot)
pub async fn disable_unit(unit_name: &str) -> Result<()> {
    ensure_managed_unit(unit_name)?;
    let connection = Connection::system()
        .await
        .context("Failed to connect to system D-Bus")?;

    let manager = systemd1::ManagerProxy::new(&connection)
        .await
        .context("Failed to create systemd manager proxy")?;

    manager
        .disable_unit_files(vec![unit_name.to_string()], false)
        .await
        .context("Failed to disable unit")?;

    // Reload daemon to pick up the changes
    manager
        .reload()
        .await
        .context("Failed to reload systemd daemon")?;

    Ok(())
}

fn parse_load_state(state: &str) -> SystemdLoadState {
    state.parse().unwrap_or(SystemdLoadState::Loaded)
}

fn parse_active_state(state: &str) -> SystemdActiveState {
    state.parse().unwrap_or(SystemdActiveState::Inactive)
}

#[cfg(test)]
mod security_tests {
    use super::*;
    #[test]
    fn cannot_control_unrelated_system_units() {
        assert!(ensure_managed_unit("systemd-networkd.service").is_ok());
        assert!(ensure_managed_unit("ssh.service").is_err());
        assert!(ensure_managed_unit("--user").is_err());
        assert!(ensure_managed_unit("malicious-keystone.service").is_err());
    }
}
