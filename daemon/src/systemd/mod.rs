//! Systemd unit management via D-Bus
//!
//! Uses zbus_systemd to interact with systemd via D-Bus for listing,
//! starting, stopping, enabling, and disabling units.

pub mod routes;

use anyhow::{Context, Result};
use keystone_core::{SystemdActiveState, SystemdLoadState, SystemdUnit, SystemdUnitDetail};
use std::process::Command;
use tracing::{debug, warn};
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
            let unit_name = name
                .rsplit('/')
                .next()
                .unwrap_or(&name)
                .to_string();
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

/// Check if a unit name is keystone-related
fn is_keystone_related(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.contains("keystone")
        || lower.contains("systemd-networkd")
        || lower.contains("nftables")
        || lower.contains("dnsmasq")
        || lower.contains("caddy")
}

/// Get detailed information about a specific unit
pub async fn get_unit_detail(unit_name: &str) -> Result<Option<SystemdUnitDetail>> {
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

    // Get recent logs using journalctl
    let recent_logs = get_recent_logs(unit_name, 50).await;

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
        recent_logs,
    }))
}

/// Start a systemd unit
pub async fn start_unit(unit_name: &str) -> Result<()> {
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

/// Get recent log lines for a unit using journalctl
async fn get_recent_logs(unit_name: &str, lines: usize) -> Vec<String> {
    let output = Command::new("journalctl")
        .args([
            "-u",
            unit_name,
            "-n",
            &lines.to_string(),
            "--no-pager",
            "-o",
            "short-iso",
        ])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            stdout.lines().map(|s| s.to_string()).collect()
        }
        Ok(o) => {
            warn!(
                "journalctl returned error: {}",
                String::from_utf8_lossy(&o.stderr)
            );
            Vec::new()
        }
        Err(e) => {
            warn!("Failed to run journalctl: {}", e);
            Vec::new()
        }
    }
}

fn parse_load_state(state: &str) -> SystemdLoadState {
    state.parse().unwrap_or(SystemdLoadState::Loaded)
}

fn parse_active_state(state: &str) -> SystemdActiveState {
    state.parse().unwrap_or(SystemdActiveState::Inactive)
}
