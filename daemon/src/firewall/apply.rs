//! Firewall apply/confirm/rollback logic
//!
//! This module implements safe firewall application with automatic rollback:
//!
//! 1. User requests apply -> rules are staged and applied
//! 2. A rollback timer starts (default 60 seconds)
//! 3. User must confirm within the timeout or rules are automatically rolled back
//! 4. This prevents lockout from misconfigured firewall rules

use crate::db::Database;
use crate::firewall::generate::generate_ruleset;
use anyhow::{Context, Result};
use keystone_core::{
    FirewallApplyResponse, FirewallConfig, FirewallConfirmResponse, FirewallRollbackResponse,
    FirewallStatusResponse,
};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Default timeout for confirmation (60 seconds)
const DEFAULT_CONFIRM_TIMEOUT_SECS: u64 = 60;

/// Pending apply session state
#[derive(Debug, Clone)]
pub struct PendingApply {
    /// Unique session ID for this apply
    pub session_id: String,
    /// Unix timestamp when rollback will occur
    pub rollback_at: u64,
    /// Previous configuration to restore on rollback. `None` means Keystone
    /// owned no nftables tables before this apply.
    pub previous_config: Option<FirewallConfig>,
    /// Configuration that was applied and will become active on confirmation.
    pub applied_config: FirewallConfig,
}

/// Manager for firewall apply/confirm/rollback operations
pub struct FirewallApplyManager {
    /// Database for persistence
    db: Arc<Database>,
    /// Current pending apply session (if any)
    pending: Arc<RwLock<Option<PendingApply>>>,
}

impl FirewallApplyManager {
    /// Create a new FirewallApplyManager
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            pending: Arc::new(RwLock::new(None)),
        }
    }

    /// Initialize manager and recover any pending rollback from a prior run.
    pub async fn init(&self) -> Result<()> {
        if let Some((previous_config, rollback_at)) = self.db.get_rollback_state().await? {
            let now = current_unix_time();
            if now >= rollback_at as u64 {
                warn!("Found expired pending apply from previous run, rolling back");
                restore_firewall_config(previous_config.as_ref()).await?;
                persist_active_snapshot(&self.db, previous_config.as_ref()).await?;
                self.db.clear_rollback_state().await?;
            } else {
                let remaining = rollback_at as u64 - now;
                info!(
                    "Restoring pending apply state, {} seconds remaining",
                    remaining
                );

                let session_id = Uuid::new_v4().to_string();
                let applied_config = self.db.get_firewall_config().await?;
                *self.pending.write().await = Some(PendingApply {
                    session_id: session_id.clone(),
                    rollback_at: rollback_at as u64,
                    previous_config,
                    applied_config,
                });
                self.start_rollback_timer(session_id, Duration::from_secs(remaining));
                return Ok(());
            }
        }

        // Upgrade compatibility: older Keystone versions did not persist the
        // confirmed ruleset separately. If Keystone tables already exist, use
        // the current database configuration as the initial confirmed baseline.
        if self.db.get_active_firewall_config().await?.is_none() && keystone_tables_exist().await {
            let baseline = self.db.get_firewall_config().await?;
            self.db.save_active_firewall_config(&baseline).await?;
        }

        Ok(())
    }

    /// Apply firewall configuration with rollback protection.
    pub async fn apply(&self, timeout_secs: Option<u64>) -> Result<FirewallApplyResponse> {
        if self.pending.read().await.is_some() {
            return Ok(FirewallApplyResponse {
                success: false,
                message: "Another apply is pending confirmation. Confirm or wait for rollback."
                    .to_string(),
                pending_confirmation: true,
                confirm_deadline: None,
                session_id: None,
            });
        }

        let previous_config = self.db.get_active_firewall_config().await?;
        let new_config = self.db.get_firewall_config().await?;
        let timeout = timeout_secs.unwrap_or(DEFAULT_CONFIRM_TIMEOUT_SECS);
        let rollback_at = current_unix_time() + timeout;
        let session_id = Uuid::new_v4().to_string();

        // Persist recovery metadata before touching the kernel. A crash after
        // this point will be repaired by init() on the next daemon start.
        self.db
            .save_rollback_state(previous_config.as_ref(), rollback_at as i64)
            .await?;

        match apply_config_with_restore(&new_config, previous_config.as_ref()).await {
            Ok(()) => {
                *self.pending.write().await = Some(PendingApply {
                    session_id: session_id.clone(),
                    rollback_at,
                    previous_config,
                    applied_config: new_config,
                });

                self.start_rollback_timer(session_id.clone(), Duration::from_secs(timeout));

                info!(
                    "Firewall applied, awaiting confirmation (timeout: {}s)",
                    timeout
                );

                Ok(FirewallApplyResponse {
                    success: true,
                    message: format!(
                        "Firewall rules applied. Please confirm within {} seconds or rules will be rolled back.",
                        timeout
                    ),
                    pending_confirmation: true,
                    confirm_deadline: Some(rollback_at),
                    session_id: Some(session_id),
                })
            }
            Err(e) => {
                if let Err(clear_error) = self.db.clear_rollback_state().await {
                    error!(
                        "Failed to clear rollback metadata after restored apply failure: {}",
                        clear_error
                    );
                }
                error!("Failed to apply firewall rules: {}", e);
                Ok(FirewallApplyResponse {
                    success: false,
                    message: format!("Failed to apply firewall rules: {}", e),
                    pending_confirmation: false,
                    confirm_deadline: None,
                    session_id: None,
                })
            }
        }
    }

    /// Confirm the pending apply (cancels rollback).
    pub async fn confirm(&self, session_id: &str) -> Result<FirewallConfirmResponse> {
        let pending = {
            let mut guard = self.pending.write().await;
            match guard.as_ref() {
                Some(pending) if pending.session_id == session_id => guard.take(),
                Some(_) => {
                    return Ok(FirewallConfirmResponse {
                        success: false,
                        message: "Invalid session ID".to_string(),
                    });
                }
                None => {
                    return Ok(FirewallConfirmResponse {
                        success: false,
                        message: "No pending configuration to confirm".to_string(),
                    });
                }
            }
        }
        .expect("matching pending apply was present");

        if let Err(error) = async {
            self.db
                .save_active_firewall_config(&pending.applied_config)
                .await?;
            self.db.clear_rollback_state().await
        }
        .await
        {
            *self.pending.write().await = Some(pending);
            return Err(error);
        }

        info!("Firewall configuration confirmed");
        Ok(FirewallConfirmResponse {
            success: true,
            message: "Firewall configuration confirmed and saved.".to_string(),
        })
    }

    /// Force a rollback (manually triggered).
    pub async fn rollback(&self) -> Result<FirewallRollbackResponse> {
        let Some(pending) = self.pending.write().await.take() else {
            return Ok(FirewallRollbackResponse {
                success: false,
                message: "No pending configuration to rollback".to_string(),
            });
        };

        match restore_firewall_config(pending.previous_config.as_ref()).await {
            Ok(()) => {
                if let Err(error) = async {
                    persist_active_snapshot(&self.db, pending.previous_config.as_ref()).await?;
                    self.db.clear_rollback_state().await
                }
                .await
                {
                    *self.pending.write().await = Some(pending);
                    return Err(error);
                }

                info!("Firewall configuration rolled back");
                Ok(FirewallRollbackResponse {
                    success: true,
                    message: "Firewall configuration rolled back to previous state.".to_string(),
                })
            }
            Err(error) => {
                error!("Failed to rollback firewall: {}", error);
                *self.pending.write().await = Some(pending);
                Ok(FirewallRollbackResponse {
                    success: false,
                    message: format!("Failed to rollback: {}", error),
                })
            }
        }
    }

    /// Get current status of pending apply
    pub async fn status(&self) -> FirewallStatusResponse {
        let pending = self.pending.read().await;

        match &*pending {
            Some(p) => {
                let now = current_unix_time();
                let remaining = if p.rollback_at > now {
                    (p.rollback_at - now) as u32
                } else {
                    0
                };

                FirewallStatusResponse {
                    pending_confirmation: true,
                    seconds_remaining: Some(remaining),
                    session_id: Some(p.session_id.clone()),
                }
            }
            None => FirewallStatusResponse {
                pending_confirmation: false,
                seconds_remaining: None,
                session_id: None,
            },
        }
    }

    /// Start a background task that will trigger rollback if not confirmed.
    fn start_rollback_timer(&self, session_id: String, timeout: Duration) {
        let db = self.db.clone();
        let pending_state = self.pending.clone();

        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;

            let pending = {
                let mut guard = pending_state.write().await;
                match guard.as_ref() {
                    Some(pending) if pending.session_id == session_id => guard.take(),
                    _ => None,
                }
            };

            let Some(pending) = pending else {
                info!("Rollback timer expired but the apply was already resolved");
                return;
            };

            warn!(
                "Rollback timer expired for session {}, rolling back",
                session_id
            );

            if let Err(error) = restore_firewall_config(pending.previous_config.as_ref()).await {
                error!("Failed to apply automatic rollback: {}", error);
                *pending_state.write().await = Some(pending);
                return;
            }

            if let Err(error) = async {
                persist_active_snapshot(&db, pending.previous_config.as_ref()).await?;
                db.clear_rollback_state().await
            }
            .await
            {
                error!("Failed to persist automatic rollback state: {}", error);
                *pending_state.write().await = Some(pending);
                return;
            }

            info!("Automatic firewall rollback completed");
        });
    }
}

async fn persist_active_snapshot(db: &Database, config: Option<&FirewallConfig>) -> Result<()> {
    match config {
        Some(config) => db.save_active_firewall_config(config).await,
        None => db.clear_active_firewall_config().await,
    }
}

async fn apply_config_with_restore(
    new_config: &FirewallConfig,
    previous_config: Option<&FirewallConfig>,
) -> Result<()> {
    if let Err(apply_error) = apply_config_to_nftables(new_config).await {
        match restore_firewall_config(previous_config).await {
            Ok(()) => anyhow::bail!(
                "New ruleset was rejected; the previous firewall was restored: {}",
                apply_error
            ),
            Err(restore_error) => anyhow::bail!(
                "New ruleset failed ({}) and restoring the previous firewall also failed ({})",
                apply_error,
                restore_error
            ),
        }
    }
    Ok(())
}

async fn restore_firewall_config(config: Option<&FirewallConfig>) -> Result<()> {
    match config {
        Some(config) => apply_config_to_nftables(config).await,
        None => cleanup_existing_tables().await,
    }
}

async fn keystone_tables_exist() -> bool {
    use crate::firewall::generate::{FILTER_TABLE, NAT_TABLE};

    for table_name in [FILTER_TABLE, NAT_TABLE] {
        match Command::new("nft")
            .args(["list", "table", "inet", table_name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
        {
            Ok(status) if status.success() => return true,
            Ok(_) => {}
            Err(error) => {
                warn!("Unable to inspect existing nftables state: {}", error);
                return false;
            }
        }
    }
    false
}

/// Apply a firewall config to nftables.
async fn apply_config_to_nftables(config: &FirewallConfig) -> Result<()> {
    // nftables transactions cannot conditionally delete a table, so remove the
    // two Keystone-owned tables before loading the replacement JSON batch.
    cleanup_existing_tables().await?;

    // Generate the nftables JSON ruleset
    let ruleset = generate_ruleset(config);

    // Serialize to JSON
    let json = serde_json::to_string(&ruleset.nftables).context("Failed to serialize ruleset")?;

    info!("Applying nftables ruleset ({} bytes)", json.len());

    // Apply using nft -j -f -
    let mut child = Command::new("nft")
        .args(["-j", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to spawn nft command")?;

    // Write JSON to stdin
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(json.as_bytes())
            .await
            .context("Failed to write to nft stdin")?;
    }

    // Wait for completion
    let output = child
        .wait_with_output()
        .await
        .context("Failed to wait for nft command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        error!("nft command failed: stdout={}, stderr={}", stdout, stderr);
        anyhow::bail!("nft command failed: {}", stderr);
    }

    info!("nftables ruleset applied successfully");
    Ok(())
}

/// Clean up existing Keystone tables before applying a replacement ruleset.
async fn cleanup_existing_tables() -> Result<()> {
    use crate::firewall::generate::{FILTER_TABLE, NAT_TABLE};

    for table_name in [FILTER_TABLE, NAT_TABLE] {
        let output = Command::new("nft")
            .args(["delete", "table", "inet", table_name])
            .output()
            .await
            .with_context(|| format!("Failed to execute nft while deleting table {table_name}"))?;

        if output.status.success() {
            info!("Deleted existing table: inet {}", table_name);
            continue;
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("No such file or directory") {
            continue;
        }

        anyhow::bail!(
            "Failed to delete nftables table inet {}: {}",
            table_name,
            stderr
        );
    }

    Ok(())
}

/// Get current config as nftables JSON string (for preview)
pub async fn generate_preview(db: &Database) -> Result<String> {
    let config = db.get_firewall_config().await?;
    let ruleset = generate_ruleset(&config);
    Ok(ruleset.preview)
}

/// Get current config as raw nftables JSON (for debugging)
pub async fn generate_json(db: &Database) -> Result<String> {
    let config = db.get_firewall_config().await?;
    let ruleset = generate_ruleset(&config);
    serde_json::to_string_pretty(&ruleset.nftables).context("Failed to serialize ruleset")
}

/// Get current unix timestamp
fn current_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_unix_time() {
        let now = current_unix_time();
        // Should be after 2024-01-01
        assert!(now > 1704067200);
    }
}
