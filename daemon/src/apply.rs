//! Unified configuration apply module
//!
//! This module provides a single function to apply all configuration changes
//! to the router at once, ensuring consistency across all services.

use std::sync::Arc;

use anyhow::Result;
use keystone_core::{ApplyComponentResults, ComponentResult};
use tracing::{error, info, warn};

use crate::caddy;
use crate::db::Database;
use crate::dnsmasq;
use crate::firewall::DEFAULT_CONFIRM_TIMEOUT_SECS;
use crate::firewall::FirewallApplyManager;
use crate::networkd::NetworkdApplyManager;

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
            networkd_pending_confirmation: false,
        });
    }

    let mut components = ApplyComponentResults::default();
    let mut all_success = true;

    // 1. Apply networkd configuration
    info!("Applying networkd configuration...");
    let networkd_manager = firewall_manager.networkd();
    let mut networkd_pending = false;
    components.networkd = match apply_networkd_config(db, networkd_manager).await {
        Ok((msg, pending)) => {
            info!("Networkd: {}", msg);
            networkd_pending = pending;
            component_success(msg)
        }
        Err(e) => {
            error!("Networkd failed: {e:#}");
            all_success = false;
            component_failure(format!("{e:#}"))
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
            error!("Firewall failed: {e:#}");
            all_success = false;
            components.firewall = component_failure(format!("{e:#}"));
            (false, None, None)
        }
    };

    // Share the firewall's confirmation session so one confirm covers both.
    // If only networkd is pending, report its session in the same fields.
    let mut firewall_pending = firewall_pending;
    let mut firewall_deadline = firewall_deadline;
    let mut firewall_session = firewall_session;
    if networkd_pending {
        match (&firewall_session, firewall_deadline) {
            (Some(session), Some(deadline)) if firewall_pending => {
                networkd_manager.adopt(session, deadline).await;
            }
            _ => {
                if let Some(info) = networkd_manager.pending_info().await {
                    firewall_pending = true;
                    firewall_deadline = Some(info.deadline);
                    firewall_session = Some(info.session_id);
                }
            }
        }
    }

    // 3. Apply dnsmasq configuration
    info!("Applying dnsmasq configuration...");
    components.dnsmasq = match dnsmasq::apply_dnsmasq_config(db.pool()).await {
        Ok(()) => {
            info!("Dnsmasq: applied successfully");
            component_success("Applied successfully")
        }
        Err(e) => {
            error!("Dnsmasq failed: {e:#}");
            all_success = false;
            component_failure(format!("{e:#}"))
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
            error!("Caddy failed: {e:#}");
            all_success = false;
            component_failure(format!("{e:#}"))
        }
    };

    // Build summary message
    let message = if all_success {
        if firewall_pending {
            "Configuration applied. Changes require confirmation or they will be rolled back."
                .to_string()
        } else {
            "All configuration applied successfully.".to_string()
        }
    } else {
        format_failed_components(&components)
    };

    info!("Unified apply complete: {}", message);

    Ok(ApplyAllResult {
        success: all_success,
        message,
        components,
        firewall_pending_confirmation: firewall_pending,
        firewall_confirm_deadline: firewall_deadline,
        firewall_session_id: firewall_session,
        networkd_pending_confirmation: networkd_pending,
    })
}

/// Format the component-specific errors instead of discarding their diagnostics.
/// The CLI setup wizard displays this summary verbatim on activation failure.
fn format_failed_components(components: &ApplyComponentResults) -> String {
    let failures = [
        ("networkd", &components.networkd),
        ("firewall", &components.firewall),
        ("dnsmasq", &components.dnsmasq),
        ("caddy", &components.caddy),
    ]
    .into_iter()
    .filter(|(_, result)| !result.success && !result.skipped)
    .collect::<Vec<_>>();

    let names = failures.iter().map(|(name, _)| *name).collect::<Vec<_>>();
    let details = failures
        .iter()
        .map(|(name, result)| format!("  {name}: {}", result.message))
        .collect::<Vec<_>>();

    format!(
        "Some components failed: {}\n{}",
        names.join(", "),
        details.join("\n")
    )
}

/// Apply networkd configuration (interfaces, VLANs, bridges). The flag reports
/// whether the change now awaits confirmation.
async fn apply_networkd_config(
    db: &Database,
    manager: &NetworkdApplyManager,
) -> Result<(String, bool)> {
    let configs = db.get_interface_configs().await?;
    let vlans = db.get_all_vlans().await?;
    let bridges = db.get_all_bridges().await?;
    let applied = manager
        .apply(&configs, &vlans, &bridges, DEFAULT_CONFIRM_TIMEOUT_SECS)
        .await?;
    let summary = applied.summary;

    Ok((
        format!(
            "Applied {} interfaces, {} VLANs, {} bridges",
            summary.interfaces, summary.vlans, summary.bridges
        ),
        applied.pending.is_some(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_error_summary_includes_component_diagnostics() {
        let components = ApplyComponentResults {
            networkd: component_failure("systemctl reload failed"),
            firewall: component_success("applied"),
            dnsmasq: component_failure("address already in use"),
            caddy: component_skipped("not configured"),
        };
        assert_eq!(
            format_failed_components(&components),
            "Some components failed: networkd, dnsmasq\n  networkd: systemctl reload failed\n  dnsmasq: address already in use"
        );
    }
}
