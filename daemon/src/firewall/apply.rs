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
    /// Previous configuration to restore on rollback
    pub previous_config: FirewallConfig,
}

/// Manager for firewall apply/confirm/rollback operations
pub struct FirewallApplyManager {
    /// Database for persistence
    db: Arc<Database>,
    /// Current pending apply session (if any)
    pending: RwLock<Option<PendingApply>>,
}

impl FirewallApplyManager {
    /// Create a new FirewallApplyManager
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            pending: RwLock::new(None),
        }
    }

    /// Initialize manager - check for any pending rollbacks from previous runs
    pub async fn init(&self) -> Result<()> {
        // Check if there's a pending rollback from a previous daemon run
        if let Some((config, rollback_at)) = self.db.get_rollback_state().await? {
            let now = current_unix_time();
            if now >= rollback_at as u64 {
                // Rollback time has passed, apply the rollback
                warn!("Found expired pending apply from previous run, rolling back");
                self.apply_config_internal(&config).await?;
                self.db.clear_rollback_state().await?;
            } else {
                // Still within timeout - restore state and start timer
                let remaining = rollback_at as u64 - now;
                info!(
                    "Restoring pending apply state, {} seconds remaining",
                    remaining
                );

                let session_id = Uuid::new_v4().to_string();
                *self.pending.write().await = Some(PendingApply {
                    session_id: session_id.clone(),
                    rollback_at: rollback_at as u64,
                    previous_config: config,
                });

                // Start rollback timer
                self.start_rollback_timer(session_id, Duration::from_secs(remaining));
            }
        }
        Ok(())
    }

    /// Apply firewall configuration with rollback protection
    pub async fn apply(&self, timeout_secs: Option<u64>) -> Result<FirewallApplyResponse> {
        // Check if there's already a pending apply
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

        // Get current config (will be our rollback point)
        let current_config = self.db.get_firewall_config().await?;

        // Generate new ruleset from current database config
        let new_config = self.db.get_firewall_config().await?;

        // Apply the new rules
        match self.apply_config_internal(&new_config).await {
            Ok(()) => {
                let timeout = timeout_secs.unwrap_or(DEFAULT_CONFIRM_TIMEOUT_SECS);
                let rollback_at = current_unix_time() + timeout;
                let session_id = Uuid::new_v4().to_string();

                // Save rollback state to database (survives daemon restart)
                self.db
                    .save_rollback_state(&current_config, rollback_at as i64)
                    .await?;

                // Store pending state
                *self.pending.write().await = Some(PendingApply {
                    session_id: session_id.clone(),
                    rollback_at,
                    previous_config: current_config,
                });

                // Start rollback timer
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

    /// Confirm the pending apply (cancels rollback)
    pub async fn confirm(&self, session_id: &str) -> Result<FirewallConfirmResponse> {
        let pending = self.pending.read().await;

        match &*pending {
            Some(p) if p.session_id == session_id => {
                drop(pending); // Release read lock

                // Clear pending state
                *self.pending.write().await = None;

                // Clear rollback state from database
                self.db.clear_rollback_state().await?;

                info!("Firewall configuration confirmed");

                Ok(FirewallConfirmResponse {
                    success: true,
                    message: "Firewall configuration confirmed and saved.".to_string(),
                })
            }
            Some(_) => Ok(FirewallConfirmResponse {
                success: false,
                message: "Invalid session ID".to_string(),
            }),
            None => Ok(FirewallConfirmResponse {
                success: false,
                message: "No pending configuration to confirm".to_string(),
            }),
        }
    }

    /// Force a rollback (manually triggered)
    pub async fn rollback(&self) -> Result<FirewallRollbackResponse> {
        let pending = self.pending.write().await.take();

        match pending {
            Some(p) => {
                // Apply the previous configuration
                match self.apply_config_internal(&p.previous_config).await {
                    Ok(()) => {
                        // Clear rollback state from database
                        self.db.clear_rollback_state().await?;

                        info!("Firewall configuration rolled back");

                        Ok(FirewallRollbackResponse {
                            success: true,
                            message: "Firewall configuration rolled back to previous state."
                                .to_string(),
                        })
                    }
                    Err(e) => {
                        error!("Failed to rollback firewall: {}", e);
                        Ok(FirewallRollbackResponse {
                            success: false,
                            message: format!("Failed to rollback: {}", e),
                        })
                    }
                }
            }
            None => Ok(FirewallRollbackResponse {
                success: false,
                message: "No pending configuration to rollback".to_string(),
            }),
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

    /// Start a background task that will trigger rollback if not confirmed
    fn start_rollback_timer(&self, session_id: String, timeout: Duration) {
        let db = self.db.clone();
        // We need to use a weak reference pattern here to avoid self-referential async
        // For now, we'll spawn a task that checks the database directly

        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;

            // Check if there's still a pending rollback in the database
            match db.get_rollback_state().await {
                Ok(Some((config, _))) => {
                    warn!(
                        "Rollback timer expired for session {}, rolling back",
                        session_id
                    );

                    // Apply the rollback
                    if let Err(e) = apply_config_to_nftables(&config).await {
                        error!("Failed to apply rollback: {}", e);
                    } else {
                        info!("Automatic rollback completed");
                    }

                    // Clear the rollback state
                    if let Err(e) = db.clear_rollback_state().await {
                        error!("Failed to clear rollback state: {}", e);
                    }
                }
                Ok(None) => {
                    // Already confirmed or rolled back, nothing to do
                    info!("Rollback timer expired but no pending state (already confirmed)");
                }
                Err(e) => {
                    error!("Failed to check rollback state: {}", e);
                }
            }
        });
    }

    /// Internal method to apply a config
    async fn apply_config_internal(&self, config: &FirewallConfig) -> Result<()> {
        apply_config_to_nftables(config).await
    }
}

/// Apply a firewall config to nftables
async fn apply_config_to_nftables(config: &FirewallConfig) -> Result<()> {
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
