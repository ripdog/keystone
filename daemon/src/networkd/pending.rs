//! Confirm-or-revert protection for networkd changes.
//!
//! Changing the LAN address or disabling the interface the administrator is
//! connected through can lock them out. After an apply that changed files, the
//! pre-apply snapshot is kept as "pending" and restored automatically unless
//! the change is confirmed before the deadline. The pending state is persisted
//! under `/var/lib/keystone` (the daemon's `StateDirectory`, writable under the
//! service sandbox) so a daemon restart cannot silently make it permanent.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use keystone_core::{BridgeConfig, InterfaceConfig, VlanConfig};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use uuid::Uuid;

use super::{NetworkdApplySummary, NetworkdConfigSnapshot};

/// Persisted pending state; lives in the daemon's writable state directory.
pub const PENDING_STATE_PATH: &str = "/var/lib/keystone/networkd-pending.json";

/// Side effects of rolling back, abstracted so tests never touch the system.
pub trait NetworkdRestorer: Send + Sync + 'static {
    /// Restore files, reload networkd and restore runtime forwarding.
    fn restore(&self, snapshot: &NetworkdConfigSnapshot) -> Result<()>;
}

/// Restores the real system state.
pub struct SystemRestorer;

impl NetworkdRestorer for SystemRestorer {
    fn restore(&self, snapshot: &NetworkdConfigSnapshot) -> Result<()> {
        snapshot.restore()?;
        super::reload_networkd()?;
        snapshot.restore_runtime_forwarding()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingNetworkd {
    session_id: String,
    /// Unix timestamp at which the change is rolled back.
    rollback_at: u64,
    snapshot: NetworkdConfigSnapshot,
}

/// Public description of a pending change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingInfo {
    pub session_id: String,
    pub deadline: u64,
}

/// Result of a managed apply.
#[derive(Debug)]
pub struct ManagedApply {
    pub summary: NetworkdApplySummary,
    pub pending: Option<PendingInfo>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConfirmOutcome {
    Confirmed,
    NoPending,
    WrongSession,
}

/// Told the session id whenever a timer rolls back an unconfirmed change.
pub type RollbackListener = Arc<dyn Fn(&str) + Send + Sync>;

pub struct NetworkdApplyManager {
    state_path: PathBuf,
    restorer: Arc<dyn NetworkdRestorer>,
    pending: Arc<Mutex<Option<PendingNetworkd>>>,
    rollback_listener: Option<RollbackListener>,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn persist(path: &Path, pending: &PendingNetworkd) -> Result<()> {
    let json = serde_json::to_vec(pending)?;
    super::atomic_write(path, json).context("Failed to persist pending networkd state")
}

fn clear_persisted(path: &Path) {
    if let Err(error) = std::fs::remove_file(path)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        error!("Failed to remove pending networkd state {path:?}: {error}");
    }
}

impl NetworkdApplyManager {
    pub fn system() -> Self {
        Self::new(PathBuf::from(PENDING_STATE_PATH), Arc::new(SystemRestorer))
    }

    pub fn new(state_path: PathBuf, restorer: Arc<dyn NetworkdRestorer>) -> Self {
        Self {
            state_path,
            restorer,
            pending: Arc::new(Mutex::new(None)),
            rollback_listener: None,
        }
    }

    /// Notify `listener` when the confirmation timer rolls back a change.
    pub fn with_rollback_listener(mut self, listener: RollbackListener) -> Self {
        self.rollback_listener = Some(listener);
        self
    }

    /// Recover a pending change persisted by a previous daemon run: roll back
    /// if its deadline has passed, otherwise re-arm the timer.
    pub async fn init(&self) -> Result<()> {
        let bytes = match std::fs::read(&self.state_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error).context("Failed to read pending networkd state"),
        };
        let pending: PendingNetworkd = match serde_json::from_slice(&bytes) {
            Ok(pending) => pending,
            Err(error) => {
                error!("Discarding unreadable pending networkd state: {error}");
                clear_persisted(&self.state_path);
                return Ok(());
            }
        };

        let now = now_secs();
        if now >= pending.rollback_at {
            warn!("Found expired pending networkd change from previous run, rolling back");
            self.restorer
                .restore(&pending.snapshot)
                .context("Failed to roll back expired networkd change")?;
            clear_persisted(&self.state_path);
        } else {
            let remaining = pending.rollback_at - now;
            info!("Restoring pending networkd change, {remaining} seconds remaining");
            let session_id = pending.session_id.clone();
            *self.pending.lock().await = Some(pending);
            self.arm_timer(session_id, Duration::from_secs(remaining));
        }
        Ok(())
    }

    pub async fn pending_info(&self) -> Option<PendingInfo> {
        self.pending.lock().await.as_ref().map(|p| PendingInfo {
            session_id: p.session_id.clone(),
            deadline: p.rollback_at,
        })
    }

    /// Fail with a clear message while an earlier change awaits confirmation.
    pub async fn ensure_idle(&self) -> Result<()> {
        if self.pending.lock().await.is_some() {
            anyhow::bail!(
                "A networkd change is pending confirmation. Confirm or wait for rollback first."
            );
        }
        Ok(())
    }

    /// Apply networkd configuration and start the rollback timer when files changed.
    pub async fn apply(
        &self,
        configs: &[InterfaceConfig],
        vlans: &[VlanConfig],
        bridges: &[BridgeConfig],
        timeout_secs: u64,
    ) -> Result<ManagedApply> {
        self.ensure_idle().await?;
        let outcome = super::apply_configuration(configs, vlans, bridges)?;
        let pending = self
            .register(outcome.previous, Duration::from_secs(timeout_secs))
            .await;
        Ok(ManagedApply {
            summary: outcome.summary,
            pending,
        })
    }

    /// Keep `previous` as pending (if the apply changed anything) and arm the timer.
    async fn register(
        &self,
        previous: Option<NetworkdConfigSnapshot>,
        timeout: Duration,
    ) -> Option<PendingInfo> {
        let snapshot = previous?;
        let pending = PendingNetworkd {
            session_id: Uuid::new_v4().to_string(),
            rollback_at: now_secs() + timeout.as_secs(),
            snapshot,
        };
        if let Err(error) = persist(&self.state_path, &pending) {
            warn!("{error:#}; rollback will not survive a daemon restart");
        }
        let info = PendingInfo {
            session_id: pending.session_id.clone(),
            deadline: pending.rollback_at,
        };
        *self.pending.lock().await = Some(pending);
        self.arm_timer(info.session_id.clone(), timeout);
        info!(
            "Networkd change applied, awaiting confirmation (timeout: {}s)",
            timeout.as_secs()
        );
        Some(info)
    }

    /// Share another confirmation session (the firewall's) so one confirm
    /// covers both. The rollback deadline moves to the shared deadline.
    pub async fn adopt(&self, session_id: &str, deadline: u64) {
        let delay = {
            let mut guard = self.pending.lock().await;
            let Some(pending) = guard.as_mut() else {
                return;
            };
            pending.session_id = session_id.to_string();
            pending.rollback_at = deadline;
            if let Err(error) = persist(&self.state_path, pending) {
                warn!("{error:#}; rollback will not survive a daemon restart");
            }
            Duration::from_secs(deadline.saturating_sub(now_secs()))
        };
        self.arm_timer(session_id.to_string(), delay);
    }

    pub async fn confirm(&self, session_id: &str) -> ConfirmOutcome {
        let mut guard = self.pending.lock().await;
        match guard.as_ref() {
            None => ConfirmOutcome::NoPending,
            Some(p) if p.session_id != session_id => ConfirmOutcome::WrongSession,
            Some(_) => {
                *guard = None;
                clear_persisted(&self.state_path);
                info!("Networkd configuration confirmed");
                ConfirmOutcome::Confirmed
            }
        }
    }

    /// Roll back immediately. `Ok(false)` means nothing was pending.
    pub async fn rollback(&self) -> Result<bool> {
        let mut guard = self.pending.lock().await;
        let Some(pending) = guard.as_ref() else {
            return Ok(false);
        };
        self.restorer.restore(&pending.snapshot)?;
        *guard = None;
        clear_persisted(&self.state_path);
        info!("Networkd configuration rolled back");
        Ok(true)
    }

    fn arm_timer(&self, session_id: String, delay: Duration) {
        let pending_state = self.pending.clone();
        let restorer = self.restorer.clone();
        let state_path = self.state_path.clone();
        let rollback_listener = self.rollback_listener.clone();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let mut guard = pending_state.lock().await;
            let Some(pending) = guard.as_ref().filter(|p| p.session_id == session_id) else {
                // Confirmed, rolled back or re-keyed to a newer timer.
                return;
            };
            error!(
                "Networkd change was not confirmed in time; rolling back to the previous configuration"
            );
            match restorer.restore(&pending.snapshot) {
                Ok(()) => {
                    *guard = None;
                    clear_persisted(&state_path);
                    warn!("Automatic networkd rollback completed");
                    if let Some(listener) = &rollback_listener {
                        listener(&session_id);
                    }
                }
                Err(error) => {
                    error!("Automatic networkd rollback FAILED: {error:#}");
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct FakeRestorer {
        restores: AtomicUsize,
    }

    impl NetworkdRestorer for FakeRestorer {
        fn restore(&self, _: &NetworkdConfigSnapshot) -> Result<()> {
            self.restores.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn snapshot() -> NetworkdConfigSnapshot {
        NetworkdConfigSnapshot {
            files: vec![(PathBuf::from("/etc/systemd/network/50-keystone-x"), vec![1])],
            ipv4_forwarding: "1\n".into(),
            ipv6_forwarding: "0\n".into(),
        }
    }

    fn manager() -> (NetworkdApplyManager, Arc<FakeRestorer>, PathBuf) {
        let restorer = Arc::new(FakeRestorer::default());
        let path = std::env::temp_dir().join(format!("keystone-nw-{}.json", Uuid::new_v4()));
        (
            NetworkdApplyManager::new(path.clone(), restorer.clone()),
            restorer,
            path,
        )
    }

    #[tokio::test]
    async fn unchanged_apply_starts_no_timer() {
        let (manager, restorer, path) = manager();
        assert!(manager.register(None, Duration::ZERO).await.is_none());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(manager.pending_info().await.is_none());
        assert_eq!(restorer.restores.load(Ordering::SeqCst), 0);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn unconfirmed_change_is_restored_on_timeout() {
        let (manager, restorer, path) = manager();
        let info = manager
            .register(Some(snapshot()), Duration::ZERO)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(restorer.restores.load(Ordering::SeqCst), 1);
        assert!(manager.pending_info().await.is_none());
        assert!(!path.exists());
        assert_eq!(
            manager.confirm(&info.session_id).await,
            ConfirmOutcome::NoPending
        );
    }

    #[tokio::test]
    async fn timer_rollback_notifies_listener_with_the_session() {
        let (manager, _restorer, path) = manager();
        let seen = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let sink = seen.clone();
        let manager = manager.with_rollback_listener(Arc::new(move |session: &str| {
            sink.lock().unwrap().push(session.to_owned());
        }));
        let info = manager
            .register(Some(snapshot()), Duration::ZERO)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(*seen.lock().unwrap(), vec![info.session_id]);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn confirmed_change_does_not_notify_listener() {
        let (manager, _restorer, path) = manager();
        let seen = Arc::new(std::sync::Mutex::new(0usize));
        let counter = seen.clone();
        let manager = manager.with_rollback_listener(Arc::new(move |_: &str| {
            *counter.lock().unwrap() += 1;
        }));
        let info = manager
            .register(Some(snapshot()), Duration::from_millis(200))
            .await
            .unwrap();
        assert_eq!(
            manager.confirm(&info.session_id).await,
            ConfirmOutcome::Confirmed
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(*seen.lock().unwrap(), 0);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn confirm_discards_snapshot_and_prevents_restore() {
        let (manager, restorer, path) = manager();
        let info = manager
            .register(Some(snapshot()), Duration::from_secs(1))
            .await
            .unwrap();
        assert!(path.exists());
        assert!(manager.ensure_idle().await.is_err());
        assert_eq!(manager.confirm("wrong").await, ConfirmOutcome::WrongSession);
        assert_eq!(
            manager.confirm(&info.session_id).await,
            ConfirmOutcome::Confirmed
        );
        assert!(!path.exists());
        assert!(manager.ensure_idle().await.is_ok());
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert_eq!(restorer.restores.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn adopted_session_confirms_with_shared_id() {
        let (manager, restorer, _path) = manager();
        manager
            .register(Some(snapshot()), Duration::from_secs(30))
            .await
            .unwrap();
        let deadline = now_secs() + 60;
        manager.adopt("shared", deadline).await;
        let info = manager.pending_info().await.unwrap();
        assert_eq!(info.session_id, "shared");
        assert_eq!(info.deadline, deadline);
        assert_eq!(manager.confirm("shared").await, ConfirmOutcome::Confirmed);
        assert_eq!(restorer.restores.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn manual_rollback_restores_and_clears() {
        let (manager, restorer, path) = manager();
        assert!(!manager.rollback().await.unwrap());
        manager
            .register(Some(snapshot()), Duration::from_secs(30))
            .await
            .unwrap();
        assert!(manager.rollback().await.unwrap());
        assert_eq!(restorer.restores.load(Ordering::SeqCst), 1);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn init_restores_expired_persisted_state() {
        let (manager, restorer, path) = manager();
        let expired = PendingNetworkd {
            session_id: "old".into(),
            rollback_at: now_secs().saturating_sub(5),
            snapshot: snapshot(),
        };
        persist(&path, &expired).unwrap();
        manager.init().await.unwrap();
        assert_eq!(restorer.restores.load(Ordering::SeqCst), 1);
        assert!(!path.exists());
        assert!(manager.pending_info().await.is_none());
    }

    #[tokio::test]
    async fn init_rearms_unexpired_persisted_state() {
        let (manager, restorer, path) = manager();
        let live = PendingNetworkd {
            session_id: "live".into(),
            rollback_at: now_secs() + 30,
            snapshot: snapshot(),
        };
        persist(&path, &live).unwrap();
        manager.init().await.unwrap();
        assert_eq!(restorer.restores.load(Ordering::SeqCst), 0);
        let info = manager.pending_info().await.unwrap();
        assert_eq!(info.session_id, "live");
        assert_eq!(manager.confirm("live").await, ConfirmOutcome::Confirmed);
        assert!(!path.exists());
    }

    #[test]
    fn same_files_ignores_order() {
        let a = NetworkdConfigSnapshot {
            files: vec![
                (PathBuf::from("/b"), vec![2]),
                (PathBuf::from("/a"), vec![1]),
            ],
            ipv4_forwarding: String::new(),
            ipv6_forwarding: String::new(),
        };
        let mut b = a.clone();
        b.files.reverse();
        assert!(a.same_files(&b));
        b.files[0].1 = vec![9];
        assert!(!a.same_files(&b));
    }
}
