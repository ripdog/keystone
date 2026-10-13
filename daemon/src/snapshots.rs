//! Configuration snapshots.
//!
//! Every successful apply records a point-in-time copy of the router
//! configuration, so an administrator can list earlier configurations and
//! restore one into the live database.
//!
//! A snapshot is a `VACUUM INTO` copy of the live database in which every
//! table that is not configuration (accounts, the JWT key, runtime rollback
//! state, setup flags, and the snapshot index itself) has been emptied. Only
//! the tables in [`CONFIG_TABLES`] are ever restored. Snapshot files live in a
//! `snapshots/` directory beside the database file; the directory is mode 0700
//! and the files are mode 0600.
//!
//! Restoring replaces configuration rows in the database only. It does not
//! apply anything to the system; applying the restored configuration is a
//! separate step.

// Read and restore entry points are consumed by the HTTP layer in a later phase.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use sqlx::migrate::Migrator;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow};
use sqlx::{Row, SqliteConnection, SqlitePool};
use tracing::{info, warn};
use uuid::Uuid;

use crate::db::Database;

/// Newest snapshots kept. Older ones, and their files, are pruned after each
/// new snapshot.
pub const RETENTION: usize = 50;

const SNAPSHOT_DIR_NAME: &str = "snapshots";

/// Schema migrations compiled into this daemon. Snapshot copies are migrated
/// with the same set, so they always end at this daemon's schema.
static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Tables holding router configuration. Snapshots capture these and restore
/// exactly these, nothing else.
pub const CONFIG_TABLES: &[&str] = &[
    "managed_interfaces",
    "interface_config",
    "interface_addresses",
    "interface_routes",
    "interface_dns",
    "interface_domains",
    "dhcpv4_client_config",
    "dhcpv6_client_config",
    "dhcp_server_config",
    "dhcp_server_dns",
    "dhcp_server_ntp",
    "dhcp_static_leases",
    "ipv6_ra_config",
    "ipv6_ra_dns",
    "ipv6_ra_search_domains",
    "ipv6_ra_prefixes",
    "ipv6_accept_ra_config",
    "vlan_config",
    "bridge_config",
    "firewall_zones",
    "firewall_zone_interfaces",
    "firewall_zone_forwards",
    "firewall_port_forwards",
    "firewall_input_rules",
    "firewall_forward_rules",
    "firewall_global_settings",
    "dnsmasq_config",
    "dnsmasq_listen_interfaces",
    "dnsmasq_except_interfaces",
    "dnsmasq_no_dhcp_interfaces",
    "dnsmasq_upstream_servers",
    "dnsmasq_dhcp_ranges",
    "dnsmasq_static_leases",
    "dnsmasq_static_lease_tags",
    "dnsmasq_dhcp_options",
    "dnsmasq_dhcp_option_tags",
    "dnsmasq_host_records",
    "dnsmasq_host_record_names",
    "dnsmasq_cname_records",
    "dnsmasq_address_overrides",
    "caddy_config",
];

/// Tables that are never captured into or restored from a snapshot: accounts
/// and secrets, runtime state, the setup/lock flags, and bookkeeping.
pub const NON_CONFIG_TABLES: &[&str] = &[
    // Migration history. Kept in snapshots so the copy records its schema version.
    "_sqlx_migrations",
    // Snapshot index. A copy must not contain the index of other copies.
    "config_snapshots",
    // SQLite's AUTOINCREMENT bookkeeping.
    "sqlite_sequence",
    // Accounts and password hashes.
    "users",
    // Token signing secret.
    "jwt_key",
    // Pending rollback bookkeeping for the live firewall.
    "firewall_rollback_state",
    // Last confirmed ruleset: describes what is live, not what is configured.
    "firewall_active_config",
    // Setup and wizard progress, plus the configuration-changes lock.
    "global_settings",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotKind {
    Applied,
    PreRestore,
    Imported,
    Manual,
}

impl SnapshotKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::PreRestore => "pre_restore",
            Self::Imported => "imported",
            Self::Manual => "manual",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "applied" => Self::Applied,
            "pre_restore" => Self::PreRestore,
            "imported" => Self::Imported,
            "manual" => Self::Manual,
            other => bail!("unknown snapshot kind {other:?}"),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotStatus {
    Active,
    PendingConfirmation,
    RolledBack,
}

impl SnapshotStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::PendingConfirmation => "pending_confirmation",
            Self::RolledBack => "rolled_back",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "active" => Self::Active,
            "pending_confirmation" => Self::PendingConfirmation,
            "rolled_back" => Self::RolledBack,
            other => bail!("unknown snapshot status {other:?}"),
        })
    }
}

/// Metadata for one snapshot row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SnapshotInfo {
    pub id: i64,
    pub created_at: i64,
    pub kind: SnapshotKind,
    pub status: SnapshotStatus,
    pub actor: Option<String>,
    pub note: Option<String>,
    pub file_name: String,
    pub schema_version: i64,
    pub session_id: Option<String>,
}

/// Parameters for recording a new snapshot.
pub struct NewSnapshot<'a> {
    pub kind: SnapshotKind,
    pub status: SnapshotStatus,
    /// Apply session that must be confirmed; set only for pending snapshots.
    pub session_id: Option<&'a str>,
    pub actor: Option<&'a str>,
    pub note: Option<&'a str>,
}

/// Result of restoring a snapshot.
#[derive(Debug)]
pub struct RestoreOutcome {
    pub restored: SnapshotInfo,
    /// The automatic backup of the configuration that was replaced.
    pub pre_restore: SnapshotInfo,
}

/// A snapshot opened read-only for previewing generated configuration. The
/// working copy is deleted when this value is dropped.
pub struct OpenedSnapshot {
    db: Database,
    path: PathBuf,
}

impl OpenedSnapshot {
    pub fn database(&self) -> &Database {
        &self.db
    }
}

impl Drop for OpenedSnapshot {
    fn drop(&mut self) {
        remove_snapshot_files(&self.path);
    }
}

// ============================================================================
// Classification
// ============================================================================

fn is_safe_identifier(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Fails when any table is neither configuration nor excluded. A migration that
/// adds a table therefore cannot silently enter or escape snapshots.
fn check_classified<'a>(tables: impl IntoIterator<Item = &'a str>) -> Result<()> {
    let unknown: Vec<&str> = tables
        .into_iter()
        .filter(|table| !CONFIG_TABLES.contains(table) && !NON_CONFIG_TABLES.contains(table))
        .collect();
    ensure!(
        unknown.is_empty(),
        "tables not classified as configuration or excluded from snapshots: {}",
        unknown.join(", ")
    );
    Ok(())
}

async fn table_names(pool: &SqlitePool) -> Result<Vec<String>> {
    Ok(
        sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type = 'table'")
            .fetch_all(pool)
            .await?,
    )
}

async fn schema_version(pool: &SqlitePool) -> Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT COALESCE(MAX(version), 0) FROM _sqlx_migrations WHERE success")
            .fetch_one(pool)
            .await?,
    )
}

// ============================================================================
// Paths, permissions and files
// ============================================================================

/// `snapshots/` beside the live database file.
async fn snapshot_dir(db: &Database) -> Result<PathBuf> {
    let file: String =
        sqlx::query_scalar("SELECT file FROM pragma_database_list WHERE name = 'main'")
            .fetch_one(db.pool())
            .await
            .context("Failed to locate the database file")?;
    ensure!(
        !file.is_empty(),
        "configuration snapshots need a file-backed database"
    );
    let parent = Path::new(&file)
        .parent()
        .context("database path has no parent directory")?;
    Ok(parent.join(SNAPSHOT_DIR_NAME))
}

/// Resolve a stored file name inside `dir`. Names come from the database, so
/// they are still checked before they become paths.
fn snapshot_file_path(dir: &Path, file_name: &str) -> Result<PathBuf> {
    let valid = file_name.len() <= 128
        && file_name.ends_with(".db")
        && file_name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    ensure!(valid, "invalid snapshot file name {file_name:?}");
    Ok(dir.join(file_name))
}

fn ensure_private_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir).with_context(|| format!("Failed to create {}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("Failed to restrict {}", dir.display()))?;
    Ok(())
}

fn restrict_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("Failed to restrict {}", path.display()))
}

/// Remove a snapshot file and any SQLite sidecar files. Missing files are fine.
fn remove_snapshot_files(path: &Path) {
    for suffix in ["", "-journal", "-wal", "-shm"] {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        if let Err(error) = std::fs::remove_file(&name)
            && error.kind() != ErrorKind::NotFound
        {
            warn!("Failed to remove snapshot file {}: {error}", name.display());
        }
    }
}

fn unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Open a standalone SQLite file. Snapshot files use rollback-journal mode so
/// each one is a single self-contained file.
async fn open_sqlite(path: &Path, read_only: bool) -> Result<SqlitePool> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(false)
        .read_only(read_only)
        .journal_mode(SqliteJournalMode::Delete);
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .with_context(|| format!("Failed to open {}", path.display()))
}

/// Copy a stored snapshot to a fresh private working file inside `dir`.
async fn working_copy(db: &Database, id: i64, purpose: &str) -> Result<(SnapshotInfo, PathBuf)> {
    let snapshot = get_snapshot(db, id)
        .await?
        .with_context(|| format!("snapshot {id} does not exist"))?;
    let dir = snapshot_dir(db).await?;
    let source = snapshot_file_path(&dir, &snapshot.file_name)?;
    ensure!(source.is_file(), "snapshot {id} has no file on disk");

    let work = dir.join(format!("{purpose}-{}.db", Uuid::new_v4().simple()));
    if let Err(error) = std::fs::copy(&source, &work)
        .with_context(|| format!("Failed to copy snapshot {id}"))
        .and_then(|_| restrict_file(&work))
    {
        remove_snapshot_files(&work);
        return Err(error);
    }
    Ok((snapshot, work))
}

// ============================================================================
// Querying
// ============================================================================

const SNAPSHOT_COLUMNS: &str =
    "id, created_at, kind, status, actor, note, file_name, schema_version, session_id";

fn info_from_row(row: &SqliteRow) -> Result<SnapshotInfo> {
    Ok(SnapshotInfo {
        id: row.try_get("id")?,
        created_at: row.try_get("created_at")?,
        kind: SnapshotKind::parse(&row.try_get::<String, _>("kind")?)?,
        status: SnapshotStatus::parse(&row.try_get::<String, _>("status")?)?,
        actor: row.try_get("actor")?,
        note: row.try_get("note")?,
        file_name: row.try_get("file_name")?,
        schema_version: row.try_get("schema_version")?,
        session_id: row.try_get("session_id")?,
    })
}

/// All snapshots, newest first.
pub async fn list_snapshots(db: &Database) -> Result<Vec<SnapshotInfo>> {
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {SNAPSHOT_COLUMNS} FROM config_snapshots ORDER BY id DESC"
    )))
    .fetch_all(db.pool())
    .await?;
    rows.iter().map(info_from_row).collect()
}

pub async fn get_snapshot(db: &Database, id: i64) -> Result<Option<SnapshotInfo>> {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {SNAPSHOT_COLUMNS} FROM config_snapshots WHERE id = ?"
    )))
    .bind(id)
    .fetch_optional(db.pool())
    .await?
    .as_ref()
    .map(info_from_row)
    .transpose()
}

/// The newest snapshot still marked active, if any.
pub async fn latest_active_snapshot(db: &Database) -> Result<Option<SnapshotInfo>> {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {SNAPSHOT_COLUMNS} FROM config_snapshots
         WHERE status = 'active' ORDER BY id DESC LIMIT 1"
    )))
    .fetch_optional(db.pool())
    .await?
    .as_ref()
    .map(info_from_row)
    .transpose()
}

/// Absolute path of a snapshot's file.
pub async fn snapshot_path(db: &Database, id: i64) -> Result<PathBuf> {
    let snapshot = get_snapshot(db, id)
        .await?
        .with_context(|| format!("snapshot {id} does not exist"))?;
    snapshot_file_path(&snapshot_dir(db).await?, &snapshot.file_name)
}

pub async fn mark_status(db: &Database, id: i64, status: SnapshotStatus) -> Result<bool> {
    let result = sqlx::query("UPDATE config_snapshots SET status = ? WHERE id = ?")
        .bind(status.as_str())
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(result.rows_affected() > 0)
}

// ============================================================================
// Recording
// ============================================================================

/// Create a snapshot of the current configuration, then prune old ones.
pub async fn create_snapshot(db: &Database, new: NewSnapshot<'_>) -> Result<SnapshotInfo> {
    let dir = snapshot_dir(db).await?;
    ensure_private_dir(&dir)?;

    let names = table_names(db.pool()).await?;
    check_classified(names.iter().map(String::as_str))?;
    let schema = schema_version(db.pool()).await?;

    let file_name = format!("{}-{}.db", unix_millis(), Uuid::new_v4().simple());
    let path = snapshot_file_path(&dir, &file_name)?;

    let written: Result<SnapshotInfo> = async {
        vacuum_into(db.pool(), &path).await?;
        restrict_file(&path)?;
        strip_to_configuration(&path).await?;
        let id = sqlx::query(
            "INSERT INTO config_snapshots
                (created_at, kind, status, actor, note, file_name, schema_version, session_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(unix_secs())
        .bind(new.kind.as_str())
        .bind(new.status.as_str())
        .bind(new.actor)
        .bind(new.note)
        .bind(file_name.as_str())
        .bind(schema)
        .bind(new.session_id)
        .execute(db.pool())
        .await?
        .last_insert_rowid();
        get_snapshot(db, id)
            .await?
            .context("snapshot row disappeared after insert")
    }
    .await;

    match written {
        Ok(info) => {
            if let Err(error) = prune_snapshots(db, RETENTION).await {
                warn!("Failed to prune old configuration snapshots: {error:#}");
            }
            info!(
                "Recorded configuration snapshot {} ({})",
                info.id,
                info.kind.as_str()
            );
            Ok(info)
        }
        Err(error) => {
            remove_snapshot_files(&path);
            Err(error)
        }
    }
}

async fn vacuum_into(pool: &SqlitePool, path: &Path) -> Result<()> {
    let target = path.to_str().context("snapshot path is not valid UTF-8")?;
    sqlx::query("VACUUM INTO ?")
        .bind(target)
        .execute(pool)
        .await
        .context("VACUUM INTO failed")?;
    Ok(())
}

/// Empty every non-configuration table in a fresh copy, then compact it.
async fn strip_to_configuration(path: &Path) -> Result<()> {
    let pool = open_sqlite(path, false).await?;
    let result: Result<()> = async {
        // _sqlx_migrations records the schema version and sqlite_sequence is
        // SQLite's own bookkeeping; both stay.
        for table in NON_CONFIG_TABLES
            .iter()
            .filter(|table| !matches!(**table, "_sqlx_migrations" | "sqlite_sequence"))
        {
            ensure!(
                is_safe_identifier(table),
                "unsupported table name {table:?}"
            );
            sqlx::query(sqlx::AssertSqlSafe(format!("DELETE FROM {table}")))
                .execute(&pool)
                .await?;
        }
        sqlx::query("VACUUM").execute(&pool).await?;
        Ok(())
    }
    .await;
    pool.close().await;
    result
}

/// Delete the oldest snapshots beyond `keep`, with their files. The newest
/// active snapshot and any snapshot awaiting confirmation are always kept.
pub async fn prune_snapshots(db: &Database, keep: usize) -> Result<usize> {
    let dir = snapshot_dir(db).await?;
    let keep = i64::try_from(keep).context("retention count is too large")?;
    let victims: Vec<(i64, String)> = sqlx::query_as(
        "SELECT id, file_name FROM config_snapshots
         WHERE id NOT IN (SELECT id FROM config_snapshots ORDER BY id DESC LIMIT ?)
           AND status <> 'pending_confirmation'
           AND id IS NOT (SELECT MAX(id) FROM config_snapshots WHERE status = 'active')
         ORDER BY id",
    )
    .bind(keep)
    .fetch_all(db.pool())
    .await?;

    let mut removed = 0;
    for (id, file_name) in victims {
        let path = snapshot_file_path(&dir, &file_name)?;
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                // Keep the row: it still describes a file that exists.
                warn!("Failed to delete snapshot {id}: {error}");
                continue;
            }
        }
        sqlx::query("DELETE FROM config_snapshots WHERE id = ?")
            .bind(id)
            .execute(db.pool())
            .await?;
        removed += 1;
    }
    Ok(removed)
}

/// Record the configuration after a successful apply. Snapshot failures are
/// logged and never fail the apply that was already carried out.
pub async fn record_applied(
    db: &Database,
    actor: Option<&str>,
    pending_session: Option<&str>,
    note: &str,
) {
    let status = if pending_session.is_some() {
        SnapshotStatus::PendingConfirmation
    } else {
        SnapshotStatus::Active
    };
    let new = NewSnapshot {
        kind: SnapshotKind::Applied,
        status,
        session_id: pending_session,
        actor,
        note: Some(note),
    };
    if let Err(error) = create_snapshot(db, new).await {
        warn!("Failed to record configuration snapshot ({note}): {error:#}");
    }
}

/// Settle the pending snapshot of an apply session. Only pending rows change,
/// so repeated or stale calls are harmless.
pub async fn resolve_session(
    db: &Database,
    session_id: &str,
    status: SnapshotStatus,
) -> Result<u64> {
    ensure!(
        status != SnapshotStatus::PendingConfirmation,
        "a session cannot be settled back to pending"
    );
    let result = sqlx::query(
        "UPDATE config_snapshots SET status = ?
         WHERE session_id = ? AND status = 'pending_confirmation'",
    )
    .bind(status.as_str())
    .bind(session_id)
    .execute(db.pool())
    .await?;
    Ok(result.rows_affected())
}

/// Settle a session from a confirmation or rollback path, where a bookkeeping
/// failure must not change the outcome that already happened. Failures are
/// logged.
pub async fn settle_session(db: &Database, session_id: &str, status: SnapshotStatus) {
    if let Err(error) = resolve_session(db, session_id, status).await {
        warn!(
            "Failed to mark configuration snapshot for session {session_id} as {}: {error:#}",
            status.as_str()
        );
    }
}

/// Reconcile snapshot rows with the apply sessions restored at daemon startup,
/// and create the baseline snapshot when none exist yet.
///
/// Firewall restore issues a new session id, so a pending row is re-linked to
/// an unclaimed live session when its own id is gone. A pending row with no
/// live session was resolved while the daemon was down and is marked rolled
/// back, because its rollback has already happened.
pub async fn reconcile_on_startup(db: &Database, live_sessions: &[String]) -> Result<()> {
    let pending: Vec<SnapshotInfo> = list_snapshots(db)
        .await?
        .into_iter()
        .filter(|snapshot| snapshot.status == SnapshotStatus::PendingConfirmation)
        .collect();

    let mut unclaimed: Vec<&str> = live_sessions
        .iter()
        .map(String::as_str)
        .filter(|live| {
            !pending
                .iter()
                .any(|snapshot| snapshot.session_id.as_deref() == Some(*live))
        })
        .collect();

    for snapshot in &pending {
        let still_live = snapshot
            .session_id
            .as_deref()
            .is_some_and(|session| live_sessions.iter().any(|live| live == session));
        if still_live {
            continue;
        }
        match unclaimed.pop() {
            Some(session) => {
                sqlx::query("UPDATE config_snapshots SET session_id = ? WHERE id = ?")
                    .bind(session)
                    .bind(snapshot.id)
                    .execute(db.pool())
                    .await?;
            }
            None => {
                mark_status(db, snapshot.id, SnapshotStatus::RolledBack).await?;
            }
        }
    }

    if list_snapshots(db).await?.is_empty() {
        let (status, session_id) = match live_sessions.first() {
            Some(session) => (SnapshotStatus::PendingConfirmation, Some(session.as_str())),
            None => (SnapshotStatus::Active, None),
        };
        create_snapshot(
            db,
            NewSnapshot {
                kind: SnapshotKind::Applied,
                status,
                session_id,
                actor: None,
                note: Some("Daemon startup baseline"),
            },
        )
        .await?;
    }
    Ok(())
}

// ============================================================================
// Restoring and previewing
// ============================================================================

/// Replace the live configuration with a snapshot's. The current configuration
/// is first saved as a `pre_restore` snapshot, so the restore can be undone.
pub async fn restore_snapshot(
    db: &Database,
    id: i64,
    actor: Option<&str>,
) -> Result<RestoreOutcome> {
    let (snapshot, work) = working_copy(db, id, "restore").await?;

    let result: Result<SnapshotInfo> = async {
        // Validate and migrate before anything is saved or changed.
        prepare_copy(&work).await?;
        let note = format!("Automatic backup before restoring snapshot {id}");
        let pre_restore = create_snapshot(
            db,
            NewSnapshot {
                kind: SnapshotKind::PreRestore,
                status: SnapshotStatus::Active,
                session_id: None,
                actor,
                note: Some(&note),
            },
        )
        .await?;
        replace_configuration(db.pool(), &work).await?;
        Ok(pre_restore)
    }
    .await;

    remove_snapshot_files(&work);
    let pre_restore = result?;
    info!("Restored configuration snapshot {id}");
    Ok(RestoreOutcome {
        restored: snapshot,
        pre_restore,
    })
}

/// Open a snapshot read-only, so preview generators can run against the
/// configuration it captured.
pub async fn open_snapshot(db: &Database, id: i64) -> Result<OpenedSnapshot> {
    let (_, work) = working_copy(db, id, "preview").await?;
    if let Err(error) = prepare_copy(&work).await {
        remove_snapshot_files(&work);
        return Err(error);
    }
    match open_sqlite(&work, true).await {
        Ok(pool) => Ok(OpenedSnapshot {
            db: Database::from_pool(pool),
            path: work,
        }),
        Err(error) => {
            remove_snapshot_files(&work);
            Err(error)
        }
    }
}

/// Validate a snapshot copy and migrate it to this daemon's schema. Snapshots
/// from a newer schema are refused, since this daemon cannot interpret them.
async fn prepare_copy(path: &Path) -> Result<()> {
    let pool = open_sqlite(path, false).await?;
    let result: Result<()> = async {
        let integrity: Vec<String> =
            sqlx::query_scalar("SELECT integrity_check FROM pragma_integrity_check")
                .fetch_all(&pool)
                .await?;
        ensure!(
            integrity == ["ok"],
            "snapshot failed the integrity check: {}",
            integrity.join("; ")
        );

        let newest_known = MIGRATOR.iter().map(|m| m.version).max().unwrap_or(0);
        let applied = schema_version(&pool).await?;
        ensure!(
            applied <= newest_known,
            "snapshot uses schema version {applied}, newer than this daemon's {newest_known}"
        );

        MIGRATOR
            .run(&pool)
            .await
            .context("Failed to migrate the snapshot to the current schema")?;

        let names = table_names(&pool).await?;
        check_classified(names.iter().map(String::as_str))?;
        Ok(())
    }
    .await;
    pool.close().await;
    result
}

/// Replace configuration rows in the live database with those of a validated
/// snapshot copy at `snapshot`, in one transaction.
async fn replace_configuration(live: &SqlitePool, snapshot: &Path) -> Result<()> {
    let names = table_names(live).await?;
    check_classified(names.iter().map(String::as_str))?;

    let mut conn = live.acquire().await?;
    // Foreign-key enforcement cannot change inside a transaction, so turn it
    // off for the bulk replace and check the result explicitly afterwards.
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut *conn)
        .await?;

    let outcome = restore_tables(&mut conn, snapshot).await;

    if let Err(error) = sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&mut *conn)
        .await
    {
        // Never return a connection with enforcement disabled to the pool.
        drop(conn.detach());
        return Err(error.into());
    }
    outcome
}

async fn restore_tables(conn: &mut SqliteConnection, snapshot: &Path) -> Result<()> {
    let path = snapshot
        .to_str()
        .context("snapshot path is not valid UTF-8")?;
    // ATTACH cannot run inside a transaction, so it happens first.
    sqlx::query("ATTACH DATABASE ? AS restore_source")
        .bind(path)
        .execute(&mut *conn)
        .await
        .context("Failed to attach the snapshot")?;

    let result = replace_rows(conn).await;
    if result.is_err() {
        // Nothing to roll back if BEGIN itself never ran.
        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
    }
    let detach = sqlx::query("DETACH DATABASE restore_source")
        .execute(&mut *conn)
        .await;

    result?;
    detach?;
    Ok(())
}

async fn replace_rows(conn: &mut SqliteConnection) -> Result<()> {
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

    for table in CONFIG_TABLES {
        ensure!(
            is_safe_identifier(table),
            "unsupported table name {table:?}"
        );
        let live_columns = column_names(conn, "main", table).await?;
        let snapshot_columns = column_names(conn, "restore_source", table).await?;
        ensure!(
            live_columns.iter().collect::<BTreeSet<_>>()
                == snapshot_columns.iter().collect::<BTreeSet<_>>(),
            "snapshot columns for {table} do not match the live schema"
        );

        // Explicit, identical column lists: column order cannot shift data.
        let columns = live_columns
            .iter()
            .map(|column| format!("\"{column}\""))
            .collect::<Vec<_>>()
            .join(", ");
        sqlx::query(sqlx::AssertSqlSafe(format!("DELETE FROM main.{table}")))
            .execute(&mut *conn)
            .await?;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT INTO main.{table} ({columns}) SELECT {columns} FROM restore_source.{table}"
        )))
        .execute(&mut *conn)
        .await?;
    }

    let violations = sqlx::query("PRAGMA main.foreign_key_check")
        .fetch_all(&mut *conn)
        .await?;
    ensure!(
        violations.is_empty(),
        "restored configuration violates {} foreign key constraint(s); nothing was changed",
        violations.len()
    );

    sqlx::query("COMMIT").execute(&mut *conn).await?;
    Ok(())
}

async fn column_names(
    conn: &mut SqliteConnection,
    schema: &str,
    table: &str,
) -> Result<Vec<String>> {
    let names: Vec<String> = sqlx::query_scalar("SELECT name FROM pragma_table_info(?, ?)")
        .bind(table)
        .bind(schema)
        .fetch_all(&mut *conn)
        .await?;
    for name in &names {
        ensure!(
            is_safe_identifier(name),
            "unsupported column name {name:?} in {table}"
        );
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch directory holding a file-backed database, so the snapshot
    /// directory is derived exactly as it is in production.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "keystone-snapshot-test-{}",
                Uuid::new_v4().simple()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn db_path(&self) -> PathBuf {
            self.0.join("keystone.db")
        }

        fn snapshot_dir(&self) -> PathBuf {
            self.0.join(SNAPSHOT_DIR_NAME)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    async fn open(scratch: &Scratch) -> Database {
        Database::open_at(&scratch.db_path()).await.unwrap()
    }

    fn applied_now() -> NewSnapshot<'static> {
        NewSnapshot {
            kind: SnapshotKind::Applied,
            status: SnapshotStatus::Active,
            session_id: None,
            actor: Some("admin"),
            note: Some("test"),
        }
    }

    async fn insert_zone(db: &Database, name: &str) {
        sqlx::query("INSERT INTO firewall_zones (name, created_at, updated_at) VALUES (?, 0, 0)")
            .bind(name)
            .execute(db.pool())
            .await
            .unwrap();
    }

    async fn zone_exists(db: &Database, name: &str) -> bool {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM firewall_zones WHERE name = ?")
            .bind(name)
            .fetch_one(db.pool())
            .await
            .unwrap()
            > 0
    }

    async fn usernames(db: &Database) -> Vec<String> {
        sqlx::query_scalar("SELECT username FROM users ORDER BY username")
            .fetch_all(db.pool())
            .await
            .unwrap()
    }

    async fn status_of(db: &Database, id: i64) -> SnapshotStatus {
        get_snapshot(db, id).await.unwrap().unwrap().status
    }

    #[tokio::test]
    async fn every_migrated_table_is_classified() {
        let db = Database::new_in_memory().await.unwrap();
        let names = table_names(db.pool()).await.unwrap();
        check_classified(names.iter().map(String::as_str))
            .expect("every table created by a migration must be classified");

        // Every listed name must exist, so a renamed or misspelled table fails here.
        for table in CONFIG_TABLES.iter().chain(NON_CONFIG_TABLES) {
            assert!(
                names.iter().any(|name| name.as_str() == *table),
                "{table} is listed but no migration creates it"
            );
        }
        for table in CONFIG_TABLES {
            assert!(
                !NON_CONFIG_TABLES.contains(table),
                "{table} is listed as both configuration and excluded"
            );
        }
    }

    #[tokio::test]
    async fn unclassified_table_is_rejected() {
        let db = Database::new_in_memory().await.unwrap();
        sqlx::query("CREATE TABLE mystery (id INTEGER PRIMARY KEY)")
            .execute(db.pool())
            .await
            .unwrap();

        let names = table_names(db.pool()).await.unwrap();
        let error = check_classified(names.iter().map(String::as_str)).unwrap_err();
        assert!(error.to_string().contains("mystery"), "{error}");
    }

    #[tokio::test]
    async fn restore_reverts_configuration_but_not_accounts() {
        let scratch = Scratch::new();
        let db = open(&scratch).await;
        db.create_user("admin", None, "hash-admin").await.unwrap();
        insert_zone(&db, "office").await;
        let snapshot = create_snapshot(&db, applied_now()).await.unwrap();

        insert_zone(&db, "guest").await;
        db.create_user("later", None, "hash-later").await.unwrap();
        assert!(zone_exists(&db, "guest").await);

        let outcome = restore_snapshot(&db, snapshot.id, Some("admin"))
            .await
            .unwrap();

        assert_eq!(outcome.restored.id, snapshot.id);
        assert!(zone_exists(&db, "office").await);
        assert!(
            !zone_exists(&db, "guest").await,
            "post-snapshot change survived restore"
        );
        // Accounts are not configuration: the account created after the snapshot stays.
        assert_eq!(usernames(&db).await, vec!["admin", "later"]);
    }

    #[tokio::test]
    async fn snapshot_file_holds_configuration_but_no_accounts_or_secrets() {
        let scratch = Scratch::new();
        let db = open(&scratch).await;
        db.create_user("admin", None, "hash-admin").await.unwrap();
        db.get_or_create_jwt_key().await.unwrap();
        insert_zone(&db, "office").await;
        let snapshot = create_snapshot(&db, applied_now()).await.unwrap();

        let path = snapshot_path(&db, snapshot.id).await.unwrap();
        let copy = open_sqlite(&path, true).await.unwrap();
        for table in ["users", "jwt_key", "config_snapshots", "global_settings"] {
            let rows: i64 =
                sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT COUNT(*) FROM {table}")))
                    .fetch_one(&copy)
                    .await
                    .unwrap();
            assert_eq!(rows, 0, "{table} must not be captured");
        }
        let zones: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM firewall_zones WHERE name = 'office'")
                .fetch_one(&copy)
                .await
                .unwrap();
        assert_eq!(zones, 1, "configuration must be captured");
        copy.close().await;
    }

    #[tokio::test]
    async fn snapshot_directory_and_files_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let scratch = Scratch::new();
        let db = open(&scratch).await;
        let snapshot = create_snapshot(&db, applied_now()).await.unwrap();

        let dir_mode = std::fs::metadata(scratch.snapshot_dir())
            .unwrap()
            .permissions()
            .mode();
        let file_mode = std::fs::metadata(snapshot_path(&db, snapshot.id).await.unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700);
        assert_eq!(file_mode & 0o777, 0o600);
    }

    #[tokio::test]
    async fn restore_records_pre_restore_snapshot_that_can_undo_it() {
        let scratch = Scratch::new();
        let db = open(&scratch).await;
        insert_zone(&db, "office").await;
        let snapshot = create_snapshot(&db, applied_now()).await.unwrap();
        insert_zone(&db, "guest").await;

        let outcome = restore_snapshot(&db, snapshot.id, Some("admin"))
            .await
            .unwrap();

        assert_eq!(outcome.pre_restore.kind, SnapshotKind::PreRestore);
        assert_eq!(outcome.pre_restore.status, SnapshotStatus::Active);
        assert_eq!(outcome.pre_restore.actor.as_deref(), Some("admin"));
        assert!(!zone_exists(&db, "guest").await);

        // Restoring the automatic backup brings back the replaced change.
        restore_snapshot(&db, outcome.pre_restore.id, Some("admin"))
            .await
            .unwrap();
        assert!(zone_exists(&db, "guest").await);
    }

    #[tokio::test]
    async fn restore_is_refused_and_changes_nothing_when_foreign_keys_fail() {
        let scratch = Scratch::new();
        let db = open(&scratch).await;
        insert_zone(&db, "office").await;
        let snapshot = create_snapshot(&db, applied_now()).await.unwrap();

        // Corrupt the stored copy: a forward policy pointing at zones that do not exist.
        let path = snapshot_path(&db, snapshot.id).await.unwrap();
        let copy = open_sqlite(&path, false).await.unwrap();
        sqlx::query("PRAGMA foreign_keys = OFF")
            .execute(&copy)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO firewall_zone_forwards
                (source_zone_id, dest_zone_id, policy, enabled, created_at, updated_at)
             VALUES (9998, 9999, 'accept', 1, 0, 0)",
        )
        .execute(&copy)
        .await
        .unwrap();
        copy.close().await;

        insert_zone(&db, "guest").await;
        let forwards_before: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM firewall_zone_forwards")
                .fetch_one(db.pool())
                .await
                .unwrap();

        let error = restore_snapshot(&db, snapshot.id, None).await.unwrap_err();
        assert!(error.to_string().contains("foreign key"), "{error:#}");

        assert!(
            zone_exists(&db, "guest").await,
            "failed restore must not change live data"
        );
        let forwards_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM firewall_zone_forwards")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(forwards_before, forwards_after);
        // Foreign-key enforcement must be back on for the pool.
        let fk: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(fk, 1);
    }

    #[tokio::test]
    async fn snapshot_from_newer_schema_is_refused() {
        let scratch = Scratch::new();
        let db = open(&scratch).await;
        insert_zone(&db, "office").await;
        let snapshot = create_snapshot(&db, applied_now()).await.unwrap();

        let path = snapshot_path(&db, snapshot.id).await.unwrap();
        let copy = open_sqlite(&path, false).await.unwrap();
        sqlx::query(
            "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time)
             VALUES (99991231000000, 'from the future', 1, X'00', 0)",
        )
        .execute(&copy)
        .await
        .unwrap();
        copy.close().await;

        insert_zone(&db, "guest").await;
        let error = restore_snapshot(&db, snapshot.id, None).await.unwrap_err();
        assert!(error.to_string().contains("newer"), "{error:#}");
        assert!(zone_exists(&db, "guest").await);
        // Refusal happens before the automatic backup, so no extra snapshot appears.
        assert_eq!(list_snapshots(&db).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn open_snapshot_previews_captured_configuration_read_only() {
        let scratch = Scratch::new();
        let db = open(&scratch).await;
        insert_zone(&db, "office").await;
        let snapshot = create_snapshot(&db, applied_now()).await.unwrap();
        insert_zone(&db, "guest").await;

        let preview = open_snapshot(&db, snapshot.id).await.unwrap();
        assert!(zone_exists(preview.database(), "office").await);
        assert!(!zone_exists(preview.database(), "guest").await);
        assert!(
            sqlx::query("DELETE FROM firewall_zones")
                .execute(preview.database().pool())
                .await
                .is_err(),
            "preview must be read-only"
        );
    }

    #[tokio::test]
    async fn retention_keeps_newest_active_and_pending_snapshots() {
        let scratch = Scratch::new();
        let db = open(&scratch).await;

        // 1 active, 2 pending, 3-5 rolled back.
        let statuses = [
            SnapshotStatus::Active,
            SnapshotStatus::PendingConfirmation,
            SnapshotStatus::RolledBack,
            SnapshotStatus::RolledBack,
            SnapshotStatus::RolledBack,
        ];
        let mut infos = Vec::new();
        for status in statuses {
            let session = (status == SnapshotStatus::PendingConfirmation).then_some("s1");
            infos.push(
                create_snapshot(
                    &db,
                    NewSnapshot {
                        kind: SnapshotKind::Applied,
                        status,
                        session_id: session,
                        actor: None,
                        note: None,
                    },
                )
                .await
                .unwrap(),
            );
        }

        let removed = prune_snapshots(&db, 1).await.unwrap();

        assert_eq!(
            removed, 2,
            "only the two oldest rolled-back snapshots may go"
        );
        let remaining: Vec<i64> = list_snapshots(&db)
            .await
            .unwrap()
            .iter()
            .map(|s| s.id)
            .collect();
        assert_eq!(remaining, vec![infos[4].id, infos[1].id, infos[0].id]);
        assert!(!scratch.snapshot_dir().join(&infos[2].file_name).exists());
        assert!(!scratch.snapshot_dir().join(&infos[3].file_name).exists());
        assert!(scratch.snapshot_dir().join(&infos[0].file_name).exists());
    }

    #[tokio::test]
    async fn pending_snapshot_settles_once_and_reconciles_after_restart() {
        let scratch = Scratch::new();
        let db = open(&scratch).await;
        let pending = create_snapshot(
            &db,
            NewSnapshot {
                kind: SnapshotKind::Applied,
                status: SnapshotStatus::PendingConfirmation,
                session_id: Some("session-a"),
                actor: None,
                note: None,
            },
        )
        .await
        .unwrap();

        settle_session(&db, "session-a", SnapshotStatus::Active).await;
        assert_eq!(status_of(&db, pending.id).await, SnapshotStatus::Active);
        // A second settle finds nothing pending and changes nothing.
        assert_eq!(
            resolve_session(&db, "session-a", SnapshotStatus::RolledBack)
                .await
                .unwrap(),
            0
        );
        assert_eq!(status_of(&db, pending.id).await, SnapshotStatus::Active);

        let restart = create_snapshot(
            &db,
            NewSnapshot {
                kind: SnapshotKind::Applied,
                status: SnapshotStatus::PendingConfirmation,
                session_id: Some("old-session"),
                actor: None,
                note: None,
            },
        )
        .await
        .unwrap();
        // Firewall restore issues a new session id; the row must follow it.
        reconcile_on_startup(&db, &["new-session".to_string()])
            .await
            .unwrap();
        let relinked = get_snapshot(&db, restart.id).await.unwrap().unwrap();
        assert_eq!(relinked.status, SnapshotStatus::PendingConfirmation);
        assert_eq!(relinked.session_id.as_deref(), Some("new-session"));

        // With nothing live, the expired pending change has been rolled back.
        reconcile_on_startup(&db, &[]).await.unwrap();
        assert_eq!(status_of(&db, restart.id).await, SnapshotStatus::RolledBack);
    }

    #[tokio::test]
    async fn startup_creates_baseline_only_when_no_snapshots_exist() {
        let scratch = Scratch::new();
        let db = open(&scratch).await;

        reconcile_on_startup(&db, &[]).await.unwrap();
        let first = list_snapshots(&db).await.unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].kind, SnapshotKind::Applied);
        assert_eq!(first[0].status, SnapshotStatus::Active);

        reconcile_on_startup(&db, &[]).await.unwrap();
        assert_eq!(list_snapshots(&db).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn latest_active_snapshot_ignores_pending_and_rolled_back() {
        let scratch = Scratch::new();
        let db = open(&scratch).await;
        let active = create_snapshot(&db, applied_now()).await.unwrap();
        let rolled = create_snapshot(
            &db,
            NewSnapshot {
                status: SnapshotStatus::RolledBack,
                ..applied_now()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            latest_active_snapshot(&db).await.unwrap().map(|s| s.id),
            Some(active.id)
        );
        assert!(
            mark_status(&db, active.id, SnapshotStatus::RolledBack)
                .await
                .unwrap()
        );
        assert!(latest_active_snapshot(&db).await.unwrap().is_none());
        assert_eq!(status_of(&db, rolled.id).await, SnapshotStatus::RolledBack);
    }
}
