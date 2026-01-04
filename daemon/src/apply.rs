//! Unified configuration apply module
//!
//! This module provides a single function to apply all configuration changes
//! to the router at once, ensuring consistency across all services.

use std::sync::Arc;

use anyhow::{Context, Result};
use keystone_core::{ApplyComponentResults, ComponentResult};
use tracing::{error, info, warn};

use crate::caddy;
use crate::db::Database;
use crate::dnsmasq;
use crate::firewall::FirewallApplyManager;
use crate::networkd;

/// Re-export the result type for use by main.rs
pub use keystone_core::ApplyAllResponse as ApplyAllResult;

// Helper functions for creating ComponentResult values
fn component_success(message: impl Into<String>) -> ComponentResult {
    ComponentResult {
        success: true,
        message: message.into(),
        skipped: false,
    }
}

fn component_failure(message: impl Into<String>) -> ComponentResult {
    ComponentResult {
        success: false,
        message: message.into(),
        skipped: false,
    }
}

fn component_skipped(message: impl Into<String>) -> ComponentResult {
    ComponentResult {
        success: true,
        message: message.into(),
        skipped: true,
    }
}

/// Apply all configuration to the router
///
/// This function applies configuration in a specific order:
/// 1. First check if config changes are disabled
/// 2. Apply networkd configuration (interfaces, VLANs, bridges)
/// 3. Apply firewall configuration (with rollback protection)
/// 4. Apply dnsmasq configuration (DNS/DHCP)
/// 5. Apply Caddy configuration (web server)
///
/// If any component fails, subsequent components are still attempted to avoid
/// leaving the system in an inconsistent state.
pub async fn apply_all(
    db: &Database,
    firewall_manager: &Arc<FirewallApplyManager>,
    firewall_timeout_secs: Option<u64>,
) -> Result<ApplyAllResult> {
    info!("Starting unified configuration apply");

    // Check if configuration changes are disabled
    let global_settings = db.get_global_settings().await?;
    if global_settings.config_changes_disabled {
        return Ok(ApplyAllResult {
            success: false,
            message: "Configuration changes are disabled. Unlock in Settings to apply changes."
                .to_string(),
            components: ApplyComponentResults::default(),
            firewall_pending_confirmation: false,
            firewall_confirm_deadline: None,
            firewall_session_id: None,
        });
    }

    let mut components = ApplyComponentResults::default();
    let mut all_success = true;

    // 1. Apply networkd configuration
    info!("Applying networkd configuration...");
    components.networkd = match apply_networkd_config(db).await {
        Ok(msg) => {
            info!("Networkd: {}", msg);
            component_success(msg)
        }
        Err(e) => {
            error!("Networkd failed: {}", e);
            all_success = false;
            component_failure(e.to_string())
        }
    };

    // 2. Apply firewall configuration
    info!("Applying firewall configuration...");
    let firewall_result = firewall_manager.apply(firewall_timeout_secs).await;
    let (firewall_pending, firewall_deadline, firewall_session) = match &firewall_result {
        Ok(resp) if resp.success => {
            info!("Firewall: {}", resp.message);
            components.firewall = component_success(&resp.message);
            (
                resp.pending_confirmation,
                resp.confirm_deadline,
                resp.session_id.clone(),
            )
        }
        Ok(resp) => {
            // Apply returned success=false (e.g., another apply pending)
            warn!("Firewall: {}", resp.message);
            if resp.pending_confirmation {
                // There's already a pending apply, not a failure
                components.firewall = component_skipped(&resp.message);
            } else {
                all_success = false;
                components.firewall = component_failure(&resp.message);
            }
            (
                resp.pending_confirmation,
                resp.confirm_deadline,
                resp.session_id.clone(),
            )
        }
        Err(e) => {
            error!("Firewall failed: {}", e);
            all_success = false;
            components.firewall = component_failure(e.to_string());
            (false, None, None)
        }
    };

    // 3. Apply dnsmasq configuration
    info!("Applying dnsmasq configuration...");
    components.dnsmasq = match dnsmasq::apply_dnsmasq_config(db.pool()).await {
        Ok(()) => {
            info!("Dnsmasq: applied successfully");
            component_success("Applied successfully")
        }
        Err(e) => {
            error!("Dnsmasq failed: {}", e);
            all_success = false;
            component_failure(e.to_string())
        }
    };

    // 4. Apply Caddy configuration
    info!("Applying Caddy configuration...");
    components.caddy = match caddy::apply_caddy_config(db.pool()).await {
        Ok(()) => {
            info!("Caddy: applied successfully");
            component_success("Applied successfully")
        }
        Err(e) => {
            error!("Caddy failed: {}", e);
            all_success = false;
            component_failure(e.to_string())
        }
    };

    // Build summary message
    let message = if all_success {
        if firewall_pending {
            "Configuration applied. Firewall changes require confirmation.".to_string()
        } else {
            "All configuration applied successfully.".to_string()
        }
    } else {
        let failed: Vec<&str> = [
            (!components.networkd.success && !components.networkd.skipped).then_some("networkd"),
            (!components.firewall.success && !components.firewall.skipped).then_some("firewall"),
            (!components.dnsmasq.success && !components.dnsmasq.skipped).then_some("dnsmasq"),
            (!components.caddy.success && !components.caddy.skipped).then_some("caddy"),
        ]
        .into_iter()
        .flatten()
        .collect();

        format!("Some components failed: {}", failed.join(", "))
    };

    info!("Unified apply complete: {}", message);

    Ok(ApplyAllResult {
        success: all_success,
        message,
        components,
        firewall_pending_confirmation: firewall_pending,
        firewall_confirm_deadline: firewall_deadline,
        firewall_session_id: firewall_session,
    })
}

/// Apply networkd configuration (interfaces, VLANs, bridges)
async fn apply_networkd_config(db: &Database) -> Result<String> {
    // Get all interface configs from database
    let configs = db.get_interface_configs().await?;

    // Get all VLAN configs from database
    let vlans = db.get_all_vlans().await?;

    // Get all bridge configs from database
    let bridges = db.get_all_bridges().await?;

    // Ensure networkd directory exists
    networkd::ensure_networkd_dir()?;

    // Write all enabled configs to disk
    let mut written = Vec::new();
    let mut vlan_written = Vec::new();
    let mut bridge_written = Vec::new();
    let mut errors = Vec::new();

    for config in &configs {
        if config.enabled {
            match networkd::write_network_file(config) {
                Ok(()) => {
                    written.push(config.name.clone());
                }
                Err(e) => {
                    errors.push(format!("{}: {}", config.name, e));
                }
            }
        } else {
            // Remove disabled interface configs
            if let Err(e) = networkd::remove_network_file(&config.name) {
                warn!(
                    "Failed to remove network file for disabled interface {}: {}",
                    config.name, e
                );
            }
        }
    }

    // Write all VLAN .netdev files
    for vlan in &vlans {
        match networkd::write_vlan_netdev_file(vlan) {
            Ok(()) => {
                vlan_written.push(vlan.name.clone());
            }
            Err(e) => {
                errors.push(format!("VLAN {}: {}", vlan.name, e));
            }
        }
    }

    // Write all bridge .netdev files and member .network files
    for bridge in &bridges {
        match networkd::write_bridge_netdev_file(bridge) {
            Ok(()) => {
                bridge_written.push(bridge.name.clone());
            }
            Err(e) => {
                errors.push(format!("Bridge {}: {}", bridge.name, e));
            }
        }
        // Write bridge member .network files
        if let Err(e) = networkd::write_bridge_member_network_files(bridge) {
            errors.push(format!("Bridge {} members: {}", bridge.name, e));
        }
    }

    if !errors.is_empty() {
        anyhow::bail!("Failed to write config files: {}", errors.join("; "));
    }

    // Reload networkd to apply changes
    networkd::reload_networkd().context("Config files written but reload failed")?;

    Ok(format!(
        "Applied {} interfaces, {} VLANs, {} bridges",
        written.len(),
        vlan_written.len(),
        bridge_written.len()
    ))
}
