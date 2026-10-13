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

use std::collections::{BTreeMap, BTreeSet};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sqlx::migrate::Migrator;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow};
use sqlx::{Row, SqliteConnection, SqlitePool};
use tracing::{info, warn};
use uuid::Uuid;

pub use keystone_core::changes::{Component, SnapshotKind, SnapshotStatus};

use crate::db::Database;
use crate::snapshot_validation::validate_configuration;

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
    "ipv6_accept_ra_config",
    "vlan_config",
    "bridge_config",
    "firewall_zones",
    "firewall_zone_interfaces",
    "firewall_zone_forwards",
    "firewall_address_groups",
    "firewall_address_group_entries",
    "firewall_port_groups",
    "firewall_port_group_entries",
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
    "sqm_config",
    "upnp_config",
    "upnp_lan_interfaces",
    "upnp_allowed_subnets",
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
    // Shaping rules last applied with tc. Runtime state that the SQM
    // reconciler re-applies, not configuration.
    "sqm_applied",
    // UPnP configuration last applied. Runtime state, like sqm_applied: the
    // reconciler uses it to recreate the miniupnpd table after a reboot.
    "upnp_applied",
];

/// Tables that an earlier migration created and a later migration drops. A
/// snapshot written before the drop still holds them. Migrating a copy removes
/// them, so they are accepted only while an uploaded file is checked, which
/// happens before that migration runs.
pub const RETIRED_TABLES: &[&str] = &[
    "dhcp_server_config",
    "dhcp_server_dns",
    "dhcp_server_ntp",
    "dhcp_static_leases",
    "ipv6_ra_config",
    "ipv6_ra_dns",
    "ipv6_ra_search_domains",
    "ipv6_ra_prefixes",
];

/// The component whose generated files depend on a configuration table.
/// Every table in [`CONFIG_TABLES`] maps to exactly one component, so a
/// component's rows can be restored without touching the others.
pub fn component_of(table: &str) -> Option<Component> {
    use Component::{Caddy, Dnsmasq, Firewall, Networkd, Sqm, Upnp};
    Some(match table {
        "managed_interfaces"
        | "interface_config"
        | "interface_addresses"
        | "interface_routes"
        | "interface_dns"
        | "interface_domains"
        | "dhcpv4_client_config"
        | "dhcpv6_client_config"
        | "ipv6_accept_ra_config"
        | "vlan_config"
        | "bridge_config" => Networkd,
        "firewall_zones"
        | "firewall_zone_interfaces"
        | "firewall_zone_forwards"
        | "firewall_address_groups"
        | "firewall_address_group_entries"
        | "firewall_port_groups"
        | "firewall_port_group_entries"
        | "firewall_port_forwards"
        | "firewall_input_rules"
        | "firewall_forward_rules"
        | "firewall_global_settings" => Firewall,
        "dnsmasq_config"
        | "dnsmasq_listen_interfaces"
        | "dnsmasq_except_interfaces"
        | "dnsmasq_no_dhcp_interfaces"
        | "dnsmasq_upstream_servers"
        | "dnsmasq_dhcp_ranges"
        | "dnsmasq_static_leases"
        | "dnsmasq_static_lease_tags"
        | "dnsmasq_dhcp_options"
        | "dnsmasq_dhcp_option_tags"
        | "dnsmasq_host_records"
        | "dnsmasq_host_record_names"
        | "dnsmasq_cname_records"
        | "dnsmasq_address_overrides" => Dnsmasq,
        "sqm_config" => Sqm,
        "upnp_config" | "upnp_lan_interfaces" | "upnp_allowed_subnets" => Upnp,
        "caddy_config" => Caddy,
        _ => return None,
    })
}

/// Comma list stored in `config_snapshots.components`. Sorted and de-duplicated.
fn encode_components(components: &[Component]) -> String {
    let mut sorted = components.to_vec();
    sorted.sort();
    sorted.dedup();
    sorted
        .iter()
        .map(|component| component.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

fn decode_components(value: &str) -> Result<Vec<Component>> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    value
        .split(',')
        .map(|name| {
            Component::parse(name)
                .with_context(|| format!("unknown component {name:?} in snapshot record"))
        })
        .collect()
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
    /// Components this snapshot is the applied baseline for.
    pub components: Vec<Component>,
}

/// Parameters for recording a new snapshot.
pub struct NewSnapshot<'a> {
    pub kind: SnapshotKind,
    pub status: SnapshotStatus,
    /// Apply session that must be confirmed; set only for pending snapshots.
    pub session_id: Option<&'a str>,
    /// Components this snapshot is the applied baseline for. Empty means the
    /// snapshot is never a baseline.
    pub components: &'a [Component],
    pub actor: Option<&'a str>,
    pub note: Option<&'a str>,
}

/// Result of restoring snapshots into the live database.
#[derive(Debug)]
pub struct RestoreOutcome {
    /// The snapshots the configuration was taken from, in id order.
    pub restored: Vec<SnapshotInfo>,
    /// Components whose tables were replaced, in component order.
    pub components: Vec<Component>,
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

const SNAPSHOT_COLUMNS: &str = "id, created_at, kind, status, actor, note, file_name, \
     schema_version, session_id, components";

fn parse_known<T>(value: &str, parse: fn(&str) -> Option<T>, what: &str) -> Result<T> {
    parse(value).with_context(|| format!("unknown {what} {value:?}"))
}

fn info_from_row(row: &SqliteRow) -> Result<SnapshotInfo> {
    Ok(SnapshotInfo {
        id: row.try_get("id")?,
        created_at: row.try_get("created_at")?,
        kind: parse_known(
            &row.try_get::<String, _>("kind")?,
            SnapshotKind::parse,
            "snapshot kind",
        )?,
        status: parse_known(
            &row.try_get::<String, _>("status")?,
            SnapshotStatus::parse,
            "snapshot status",
        )?,
        actor: row.try_get("actor")?,
        note: row.try_get("note")?,
        file_name: row.try_get("file_name")?,
        schema_version: row.try_get("schema_version")?,
        session_id: row.try_get("session_id")?,
        components: decode_components(&row.try_get::<String, _>("components")?)?,
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

/// The newest active snapshot that is the applied baseline for `component`.
/// Pending, rolled-back, manual, imported and pre-restore snapshots never
/// qualify, and neither does a snapshot taken for other components only.
pub async fn latest_applied_for(
    db: &Database,
    component: Component,
) -> Result<Option<SnapshotInfo>> {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {SNAPSHOT_COLUMNS} FROM config_snapshots
         WHERE status = 'active'
           AND instr(',' || components || ',', ',' || ? || ',') > 0
         ORDER BY id DESC LIMIT 1"
    )))
    .bind(component.as_str())
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
                (created_at, kind, status, actor, note, file_name, schema_version, session_id,
                 components)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(unix_secs())
        .bind(new.kind.as_str())
        .bind(new.status.as_str())
        .bind(new.actor)
        .bind(new.note)
        .bind(file_name.as_str())
        .bind(schema)
        .bind(new.session_id)
        .bind(encode_components(new.components))
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

/// Snapshot ids that retention must keep regardless of age: the newest active
/// snapshot, and the newest active baseline of each component.
fn protected_snapshot_ids(newest_first: &[SnapshotInfo]) -> BTreeSet<i64> {
    let mut protected = BTreeSet::new();
    let active = || {
        newest_first
            .iter()
            .filter(|snapshot| snapshot.status == SnapshotStatus::Active)
    };
    if let Some(newest) = active().next() {
        protected.insert(newest.id);
    }
    for component in Component::ALL {
        if let Some(baseline) = active().find(|s| s.components.contains(&component)) {
            protected.insert(baseline.id);
        }
    }
    protected
}

/// Delete the oldest snapshots beyond `keep`, with their files. Pending
/// snapshots and the snapshots protected by [`protected_snapshot_ids`] are
/// always kept.
pub async fn prune_snapshots(db: &Database, keep: usize) -> Result<usize> {
    let dir = snapshot_dir(db).await?;
    let newest_first = list_snapshots(db).await?;
    let protected = protected_snapshot_ids(&newest_first);

    let mut victims: Vec<(i64, String)> = newest_first
        .iter()
        .skip(keep)
        .filter(|snapshot| snapshot.status != SnapshotStatus::PendingConfirmation)
        .filter(|snapshot| !protected.contains(&snapshot.id))
        .map(|snapshot| (snapshot.id, snapshot.file_name.clone()))
        .collect();
    victims.reverse();

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

/// Record the configuration after a successful apply of `components`. Snapshot
/// failures are logged and never fail the apply that was already carried out.
///
/// Only the listed components become applied baselines. The database holds
/// every component, but the other components' generated files were not
/// written by this apply.
pub async fn record_applied(
    db: &Database,
    actor: Option<&str>,
    pending_session: Option<&str>,
    components: &[Component],
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
        components,
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
                components: &Component::ALL,
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

/// Replace the live configuration with a snapshot's, or with the chosen
/// components of it. The current configuration is first saved as a
/// `pre_restore` snapshot, so the restore can be undone. Nothing is applied to
/// the system; the restored configuration becomes pending changes.
pub async fn restore_snapshot(
    db: &Database,
    id: i64,
    actor: Option<&str>,
    components: Option<&[Component]>,
) -> Result<RestoreOutcome> {
    let components = components.map_or_else(|| Component::ALL.to_vec(), <[Component]>::to_vec);
    restore_components(db, &[(id, components)], actor).await
}

/// Replace configuration tables from several snapshots at once. Each plan entry
/// pairs a snapshot id with the components to take from it, and a component may
/// appear only once. The whole plan is one transaction: either every selected
/// table is replaced or none is.
pub async fn restore_components(
    db: &Database,
    plan: &[(i64, Vec<Component>)],
    actor: Option<&str>,
) -> Result<RestoreOutcome> {
    ensure!(!plan.is_empty(), "no snapshot was selected for restore");

    let mut by_snapshot: BTreeMap<i64, Vec<Component>> = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for (id, components) in plan {
        ensure!(
            !components.is_empty(),
            "no components selected from snapshot {id}"
        );
        for component in components {
            ensure!(
                seen.insert(*component),
                "component {component} is selected from more than one snapshot"
            );
        }
        by_snapshot
            .entry(*id)
            .or_default()
            .extend(components.iter().copied());
    }

    // Working copies are removed on every path, including refusals.
    let mut copies: Vec<(SnapshotInfo, PathBuf)> = Vec::new();
    let outcome = restore_from_copies(db, &by_snapshot, actor, &mut copies).await;
    for (_, work) in &copies {
        remove_snapshot_files(work);
    }
    let outcome = outcome?;
    info!(
        "Restored configuration components {:?} from snapshots {:?}",
        outcome.components,
        outcome.restored.iter().map(|s| s.id).collect::<Vec<_>>()
    );
    Ok(outcome)
}

async fn restore_from_copies(
    db: &Database,
    by_snapshot: &BTreeMap<i64, Vec<Component>>,
    actor: Option<&str>,
    copies: &mut Vec<(SnapshotInfo, PathBuf)>,
) -> Result<RestoreOutcome> {
    for id in by_snapshot.keys() {
        copies.push(working_copy(db, *id, "restore").await?);
    }
    // Validate and migrate every source before anything is saved or changed.
    for (_, work) in copies.iter() {
        prepare_copy(work).await?;
    }

    let sources: Vec<(String, PathBuf, Vec<Component>)> = copies
        .iter()
        .zip(by_snapshot.values())
        .enumerate()
        .map(|(index, ((_, work), components))| {
            (source_alias(index), work.clone(), components.clone())
        })
        .collect();
    // Refuse before the backup is taken or any live row is replaced.
    validate_restored_configuration(db, &sources).await?;

    let ids: Vec<String> = by_snapshot.keys().map(i64::to_string).collect();
    let note = format!(
        "Automatic backup before restoring snapshot {}",
        ids.join(", ")
    );
    let pre_restore = create_snapshot(
        db,
        NewSnapshot {
            kind: SnapshotKind::PreRestore,
            status: SnapshotStatus::Active,
            session_id: None,
            // The replaced state was not necessarily applied, so it never
            // becomes an applied baseline.
            components: &[],
            actor,
            note: Some(&note),
        },
    )
    .await?;

    replace_configuration(db.pool(), &sources).await?;

    let mut components: Vec<Component> = by_snapshot.values().flatten().copied().collect();
    components.sort();
    let restored = copies.iter().map(|(info, _)| info.clone()).collect();
    Ok(RestoreOutcome {
        restored,
        components,
        pre_restore,
    })
}

/// Check the configuration a restore would produce, before anything live is
/// changed. The merged result is built in a scratch copy of the live database
/// with the same replacement the restore runs, then validated there.
async fn validate_restored_configuration(
    db: &Database,
    sources: &[(String, PathBuf, Vec<Component>)],
) -> Result<()> {
    let dir = snapshot_dir(db).await?;
    let scratch = dir.join(format!("restore-check-{}.db", Uuid::new_v4().simple()));
    let result: Result<()> = async {
        vacuum_into(db.pool(), &scratch).await?;
        strip_to_configuration(&scratch).await?;
        let pool = open_sqlite(&scratch, false).await?;
        let outcome: Result<()> = async {
            replace_configuration(&pool, sources).await?;
            let errors = validate_configuration(&Database::from_pool(pool.clone())).await;
            ensure!(
                errors.is_empty(),
                "restored configuration is invalid: {}",
                errors.join("; ")
            );
            Ok(())
        }
        .await;
        pool.close().await;
        outcome
    }
    .await;
    remove_snapshot_files(&scratch);
    result
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

/// Largest uploaded snapshot accepted. Configuration snapshots are small, so
/// this only bounds the work done on an untrusted file.
pub const MAX_IMPORT_BYTES: usize = keystone_core::changes::MAX_SNAPSHOT_UPLOAD_BYTES;

const SQLITE_HEADER: &[u8] = b"SQLite format 3\0";

/// Store an uploaded configuration snapshot as an `imported` snapshot.
///
/// The upload is never attached to the live database. It is written to a
/// private file, checked read-only, migrated and stripped to configuration
/// there, and only then registered. An imported snapshot has no components, so
/// it never becomes an applied baseline. Restoring it is a separate step.
pub async fn import_snapshot(
    db: &Database,
    bytes: &[u8],
    actor: Option<&str>,
) -> Result<SnapshotInfo> {
    ensure!(
        bytes.len() <= MAX_IMPORT_BYTES,
        "snapshot upload is larger than the {MAX_IMPORT_BYTES}-byte limit"
    );
    ensure!(
        bytes.starts_with(SQLITE_HEADER),
        "uploaded file is not an SQLite database"
    );
    let dir = snapshot_dir(db).await?;
    ensure_private_dir(&dir)?;

    let staged = dir.join(format!("import-{}.db", Uuid::new_v4().simple()));
    let file_name = format!("{}-{}.db", unix_millis(), Uuid::new_v4().simple());
    let final_path = snapshot_file_path(&dir, &file_name)?;

    let result: Result<SnapshotInfo> = async {
        write_private_file(&staged, bytes)?;
        precheck_read_only(&staged).await?;
        prepare_copy(&staged).await?;
        strip_to_configuration(&staged).await?;
        let (schema, errors) = {
            let pool = open_sqlite(&staged, true).await?;
            let staged_db = Database::from_pool(pool);
            let errors = validate_configuration(&staged_db).await;
            let version = schema_version(staged_db.pool()).await;
            staged_db.pool().close().await;
            (version?, errors)
        };
        ensure!(
            errors.is_empty(),
            "uploaded snapshot holds invalid configuration: {}",
            errors.join("; ")
        );

        std::fs::rename(&staged, &final_path).context("Failed to store the imported snapshot")?;
        restrict_file(&final_path)?;
        let id = sqlx::query(
            "INSERT INTO config_snapshots
                (created_at, kind, status, actor, note, file_name, schema_version, session_id,
                 components)
             VALUES (?, ?, ?, ?, ?, ?, ?, NULL, '')",
        )
        .bind(unix_secs())
        .bind(SnapshotKind::Imported.as_str())
        .bind(SnapshotStatus::Active.as_str())
        .bind(actor)
        .bind("Imported from an uploaded file")
        .bind(file_name.as_str())
        .bind(schema)
        .execute(db.pool())
        .await?
        .last_insert_rowid();
        get_snapshot(db, id)
            .await?
            .context("snapshot row disappeared after insert")
    }
    .await;

    remove_snapshot_files(&staged);
    match result {
        Ok(info) => {
            info!("Imported configuration snapshot {}", info.id);
            Ok(info)
        }
        Err(error) => {
            remove_snapshot_files(&final_path);
            Err(error)
        }
    }
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("Failed to create {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("Failed to write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("Failed to flush {}", path.display()))?;
    Ok(())
}

/// Validate an untrusted file without writing to it: integrity, schema version
/// and table classification. Runs before any migration or stripping.
async fn precheck_read_only(path: &Path) -> Result<()> {
    let pool = open_sqlite(path, true).await?;
    let result: Result<()> = async {
        let integrity: Vec<String> =
            sqlx::query_scalar("SELECT integrity_check FROM pragma_integrity_check")
                .fetch_all(&pool)
                .await
                .context("uploaded file is not a readable SQLite database")?;
        ensure!(
            integrity == ["ok"],
            "uploaded snapshot failed the integrity check: {}",
            integrity.join("; ")
        );

        let newest_known = MIGRATOR.iter().map(|m| m.version).max().unwrap_or(0);
        let applied = schema_version(&pool)
            .await
            .context("uploaded file has no migration history")?;
        ensure!(
            applied <= newest_known,
            "uploaded snapshot uses schema version {applied}, newer than this daemon's {newest_known}"
        );

        // Retired tables are dropped when the file is migrated, which happens
        // after this check, so an older snapshot may still hold them here.
        let names = table_names(&pool).await?;
        check_classified(
            names
                .iter()
                .map(String::as_str)
                .filter(|name| !RETIRED_TABLES.contains(name)),
        )?;
        // Snapshots hold tables and their indexes only. Triggers and views
        // have no place in an upload, so they are refused outright.
        let other_objects: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type NOT IN ('table', 'index')",
        )
        .fetch_one(&pool)
        .await?;
        ensure!(
            other_objects == 0,
            "uploaded snapshot contains triggers or views, which snapshots never use"
        );
        Ok(())
    }
    .await;
    pool.close().await;
    result
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

fn source_alias(index: usize) -> String {
    format!("restore_source_{index}")
}

/// Replace configuration rows in the live database with those of validated
/// snapshot copies. Each source contributes the tables of its components.
async fn replace_configuration(
    live: &SqlitePool,
    sources: &[(String, PathBuf, Vec<Component>)],
) -> Result<()> {
    let names = table_names(live).await?;
    check_classified(names.iter().map(String::as_str))?;

    let mut conn = live.acquire().await?;
    // Foreign-key enforcement cannot change inside a transaction, so turn it
    // off for the bulk replace and check the result explicitly afterwards.
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut *conn)
        .await?;

    let outcome = restore_tables(&mut conn, sources).await;

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

async fn restore_tables(
    conn: &mut SqliteConnection,
    sources: &[(String, PathBuf, Vec<Component>)],
) -> Result<()> {
    // ATTACH cannot run inside a transaction, so every source is attached first.
    let mut attached = Vec::new();
    let mut result: Result<()> = Ok(());
    for (alias, path, _) in sources {
        let attach = async {
            let path = path.to_str().context("snapshot path is not valid UTF-8")?;
            sqlx::query(sqlx::AssertSqlSafe(format!("ATTACH DATABASE ? AS {alias}")))
                .bind(path)
                .execute(&mut *conn)
                .await
                .context("Failed to attach the snapshot")?;
            anyhow::Ok(())
        }
        .await;
        match attach {
            Ok(()) => attached.push(alias.clone()),
            Err(error) => {
                result = Err(error);
                break;
            }
        }
    }

    if result.is_ok() {
        result = replace_rows(conn, sources).await;
    }
    if result.is_err() {
        // Nothing to roll back if BEGIN itself never ran.
        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
    }

    let mut detach_result: Result<()> = Ok(());
    for alias in &attached {
        if let Err(error) = sqlx::query(sqlx::AssertSqlSafe(format!("DETACH DATABASE {alias}")))
            .execute(&mut *conn)
            .await
        {
            detach_result = Err(error.into());
        }
    }

    result?;
    detach_result?;
    Ok(())
}

async fn replace_rows(
    conn: &mut SqliteConnection,
    sources: &[(String, PathBuf, Vec<Component>)],
) -> Result<()> {
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

    for table in CONFIG_TABLES {
        ensure!(
            is_safe_identifier(table),
            "unsupported table name {table:?}"
        );
        let component =
            component_of(table).with_context(|| format!("{table} has no owning component"))?;
        let Some((alias, _, _)) = sources
            .iter()
            .find(|(_, _, components)| components.contains(&component))
        else {
            continue;
        };

        let live_columns = column_names(conn, "main", table).await?;
        let snapshot_columns = column_names(conn, alias, table).await?;
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
            "INSERT INTO main.{table} ({columns}) SELECT {columns} FROM {alias}.{table}"
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
pub(crate) mod tests {
    use super::*;

    /// A scratch directory holding a file-backed database, so the snapshot
    /// directory is derived exactly as it is in production.
    pub(crate) struct Scratch(PathBuf);

    impl Scratch {
        pub(crate) fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "keystone-snapshot-test-{}",
                Uuid::new_v4().simple()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        pub(crate) fn db_path(&self) -> PathBuf {
            self.0.join("keystone.db")
        }

        pub(crate) fn snapshot_dir(&self) -> PathBuf {
            self.0.join(SNAPSHOT_DIR_NAME)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    pub(crate) async fn open(scratch: &Scratch) -> Database {
        Database::open_at(&scratch.db_path()).await.unwrap()
    }

    fn applied_now() -> NewSnapshot<'static> {
        NewSnapshot {
            kind: SnapshotKind::Applied,
            status: SnapshotStatus::Active,
            session_id: None,
            components: &Component::ALL,
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
        // Retired tables are dropped by a migration, so a migrated database
        // must not contain them, and they must not be listed anywhere else.
        for table in RETIRED_TABLES {
            assert!(
                !names.iter().any(|name| name.as_str() == *table),
                "{table} is retired but a migration still creates it"
            );
            assert!(
                !CONFIG_TABLES.contains(table) && !NON_CONFIG_TABLES.contains(table),
                "{table} is retired but still listed as configuration or excluded"
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

        let outcome = restore_snapshot(&db, snapshot.id, Some("admin"), None)
            .await
            .unwrap();

        assert_eq!(outcome.restored[0].id, snapshot.id);
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

        let outcome = restore_snapshot(&db, snapshot.id, Some("admin"), None)
            .await
            .unwrap();

        assert_eq!(outcome.pre_restore.kind, SnapshotKind::PreRestore);
        assert_eq!(outcome.pre_restore.status, SnapshotStatus::Active);
        assert_eq!(outcome.pre_restore.actor.as_deref(), Some("admin"));
        assert!(!zone_exists(&db, "guest").await);

        // Restoring the automatic backup brings back the replaced change.
        restore_snapshot(&db, outcome.pre_restore.id, Some("admin"), None)
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

        let error = restore_snapshot(&db, snapshot.id, None, None)
            .await
            .unwrap_err();
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
        let error = restore_snapshot(&db, snapshot.id, None, None)
            .await
            .unwrap_err();
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
                        components: &Component::ALL,
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
                components: &Component::ALL,
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
                components: &Component::ALL,
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
    async fn latest_applied_ignores_pending_and_rolled_back() {
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
            latest_applied_for(&db, Component::Firewall)
                .await
                .unwrap()
                .map(|s| s.id),
            Some(active.id)
        );
        assert!(
            mark_status(&db, active.id, SnapshotStatus::RolledBack)
                .await
                .unwrap()
        );
        assert!(
            latest_applied_for(&db, Component::Firewall)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(status_of(&db, rolled.id).await, SnapshotStatus::RolledBack);
    }

    async fn count_rows(pool: &SqlitePool, table: &str) -> i64 {
        sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT COUNT(*) FROM {table}")))
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn dnsmasq_cache_size(db: &Database) -> i64 {
        sqlx::query_scalar("SELECT cache_size FROM dnsmasq_config WHERE id = 1")
            .fetch_one(db.pool())
            .await
            .unwrap()
    }

    async fn set_dnsmasq_cache_size(db: &Database, size: i64) {
        sqlx::query("UPDATE dnsmasq_config SET cache_size = ? WHERE id = 1")
            .bind(size)
            .execute(db.pool())
            .await
            .unwrap();
    }

    fn applied_for(components: &'static [Component]) -> NewSnapshot<'static> {
        NewSnapshot {
            kind: SnapshotKind::Applied,
            status: SnapshotStatus::Active,
            session_id: None,
            components,
            actor: None,
            note: None,
        }
    }

    #[test]
    fn every_config_table_belongs_to_exactly_one_component() {
        let owners: Vec<(&str, Component)> = CONFIG_TABLES
            .iter()
            .map(|table| {
                let owner = component_of(table)
                    .unwrap_or_else(|| panic!("{table} has no owning component"));
                (*table, owner)
            })
            .collect();
        assert_eq!(owners.len(), CONFIG_TABLES.len());
        for component in Component::ALL {
            assert!(
                owners.iter().any(|(_, owner)| *owner == component),
                "{component} owns no configuration table"
            );
        }
        assert_eq!(component_of("users"), None);
        assert_eq!(component_of("config_snapshots"), None);
        assert_eq!(component_of("mystery"), None);
    }

    #[test]
    fn component_lists_round_trip_and_reject_unknown_names() {
        let encoded = encode_components(&[Component::Caddy, Component::Networkd, Component::Caddy]);
        assert_eq!(encoded, "networkd,caddy");
        assert_eq!(
            decode_components(&encoded).unwrap(),
            vec![Component::Networkd, Component::Caddy]
        );
        assert_eq!(encode_components(&[]), "");
        assert!(decode_components("").unwrap().is_empty());
        assert!(decode_components("networkd,mystery").is_err());
    }

    #[tokio::test]
    async fn migration_gives_existing_rows_every_component() {
        let db = Database::new_in_memory().await.unwrap();
        let components: String = sqlx::query_scalar(
            "SELECT dflt_value FROM pragma_table_info('config_snapshots') WHERE name = 'components'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(components, "'networkd,firewall,dnsmasq,caddy'");
    }

    #[tokio::test]
    async fn per_subsystem_apply_does_not_make_other_components_look_applied() {
        let scratch = Scratch::new();
        let db = open(&scratch).await;
        record_applied(
            &db,
            Some("admin"),
            None,
            &[Component::Dnsmasq],
            "dnsmasq apply",
        )
        .await;

        let dnsmasq = latest_applied_for(&db, Component::Dnsmasq)
            .await
            .unwrap()
            .expect("dnsmasq baseline");
        assert_eq!(dnsmasq.components, vec![Component::Dnsmasq]);
        for other in [Component::Networkd, Component::Firewall, Component::Caddy] {
            assert!(
                latest_applied_for(&db, other).await.unwrap().is_none(),
                "{other} must not be marked applied by a dnsmasq apply"
            );
        }
    }

    #[tokio::test]
    async fn only_active_snapshots_covering_a_component_are_its_baseline() {
        let scratch = Scratch::new();
        let db = open(&scratch).await;

        let firewall = create_snapshot(&db, applied_for(&[Component::Firewall]))
            .await
            .unwrap();
        // Manual, imported and pre-restore snapshots carry no components, so
        // they are never a baseline even though they are active.
        for kind in [
            SnapshotKind::Manual,
            SnapshotKind::Imported,
            SnapshotKind::PreRestore,
        ] {
            create_snapshot(
                &db,
                NewSnapshot {
                    kind,
                    components: &[],
                    ..applied_for(&[])
                },
            )
            .await
            .unwrap();
        }
        assert_eq!(
            latest_applied_for(&db, Component::Firewall)
                .await
                .unwrap()
                .map(|s| s.id),
            Some(firewall.id)
        );
        assert!(
            latest_applied_for(&db, Component::Dnsmasq)
                .await
                .unwrap()
                .is_none()
        );

        // A pending apply is not applied until it is confirmed, and a rolled
        // back one never is.
        record_applied(
            &db,
            None,
            Some("session-pending"),
            &[Component::Firewall],
            "firewall apply",
        )
        .await;
        let pending = list_snapshots(&db).await.unwrap()[0].id;
        assert_eq!(
            latest_applied_for(&db, Component::Firewall)
                .await
                .unwrap()
                .map(|s| s.id),
            Some(firewall.id),
            "a pending apply must not replace the baseline"
        );
        settle_session(&db, "session-pending", SnapshotStatus::Active).await;
        assert_eq!(
            latest_applied_for(&db, Component::Firewall)
                .await
                .unwrap()
                .map(|s| s.id),
            Some(pending)
        );
        settle_session(&db, "session-pending", SnapshotStatus::RolledBack).await;
    }

    #[tokio::test]
    async fn restoring_one_component_leaves_the_others_alone() {
        let scratch = Scratch::new();
        let db = open(&scratch).await;
        insert_zone(&db, "office").await;
        set_dnsmasq_cache_size(&db, 1000).await;
        let snapshot = create_snapshot(&db, applied_now()).await.unwrap();

        insert_zone(&db, "guest").await;
        set_dnsmasq_cache_size(&db, 4321).await;

        restore_snapshot(&db, snapshot.id, None, Some(&[Component::Dnsmasq]))
            .await
            .unwrap();

        assert_eq!(dnsmasq_cache_size(&db).await, 1000);
        assert!(
            zone_exists(&db, "guest").await,
            "firewall rows must not change when only dnsmasq is restored"
        );
    }

    #[tokio::test]
    async fn restore_plan_takes_each_component_from_its_own_snapshot() {
        let scratch = Scratch::new();
        let db = open(&scratch).await;
        insert_zone(&db, "firewall-a").await;
        set_dnsmasq_cache_size(&db, 100).await;
        let a = create_snapshot(&db, applied_now()).await.unwrap();

        sqlx::query("DELETE FROM firewall_zones")
            .execute(db.pool())
            .await
            .unwrap();
        insert_zone(&db, "firewall-b").await;
        set_dnsmasq_cache_size(&db, 200).await;
        let b = create_snapshot(&db, applied_now()).await.unwrap();

        sqlx::query("DELETE FROM firewall_zones")
            .execute(db.pool())
            .await
            .unwrap();
        insert_zone(&db, "live").await;
        set_dnsmasq_cache_size(&db, 300).await;

        let outcome = restore_components(
            &db,
            &[
                (a.id, vec![Component::Firewall]),
                (b.id, vec![Component::Dnsmasq]),
            ],
            None,
        )
        .await
        .unwrap();

        assert_eq!(
            outcome.components,
            vec![Component::Firewall, Component::Dnsmasq]
        );
        assert!(zone_exists(&db, "firewall-a").await);
        assert!(!zone_exists(&db, "firewall-b").await);
        assert!(!zone_exists(&db, "live").await);
        assert_eq!(dnsmasq_cache_size(&db).await, 200);
        // The replaced state is saved, and never counts as an applied baseline.
        assert!(outcome.pre_restore.components.is_empty());
    }

    #[tokio::test]
    async fn restore_plan_refuses_a_component_from_two_snapshots() {
        let scratch = Scratch::new();
        let db = open(&scratch).await;
        insert_zone(&db, "office").await;
        let snapshot = create_snapshot(&db, applied_now()).await.unwrap();
        insert_zone(&db, "guest").await;

        let error = restore_components(
            &db,
            &[
                (snapshot.id, vec![Component::Firewall]),
                (snapshot.id, vec![Component::Firewall]),
            ],
            None,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("more than one"), "{error:#}");
        assert!(zone_exists(&db, "guest").await);
        assert_eq!(list_snapshots(&db).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn retention_keeps_each_components_newest_baseline() {
        let scratch = Scratch::new();
        let db = open(&scratch).await;

        let networkd = create_snapshot(&db, applied_for(&[Component::Networkd]))
            .await
            .unwrap();
        for _ in 0..3 {
            create_snapshot(
                &db,
                NewSnapshot {
                    status: SnapshotStatus::RolledBack,
                    ..applied_for(&Component::ALL)
                },
            )
            .await
            .unwrap();
        }
        // The newest snapshot is a manual one: it must not push the networkd
        // baseline out of retention.
        let manual = create_snapshot(
            &db,
            NewSnapshot {
                kind: SnapshotKind::Manual,
                components: &[],
                ..applied_for(&[])
            },
        )
        .await
        .unwrap();

        let removed = prune_snapshots(&db, 1).await.unwrap();
        assert_eq!(removed, 3);
        let remaining: Vec<i64> = list_snapshots(&db)
            .await
            .unwrap()
            .iter()
            .map(|s| s.id)
            .collect();
        assert_eq!(remaining, vec![manual.id, networkd.id]);
        assert_eq!(
            latest_applied_for(&db, Component::Networkd)
                .await
                .unwrap()
                .map(|s| s.id),
            Some(networkd.id)
        );
    }

    #[tokio::test]
    async fn import_strips_accounts_and_is_never_a_baseline() {
        let scratch = Scratch::new();
        let db = open(&scratch).await;
        db.create_user("admin", None, "hash-admin").await.unwrap();
        insert_zone(&db, "office").await;

        // A full copy of the live database, accounts included.
        let full = scratch.snapshot_dir().join("full-copy.db");
        std::fs::create_dir_all(scratch.snapshot_dir()).unwrap();
        sqlx::query("VACUUM INTO ?")
            .bind(full.to_str().unwrap())
            .execute(db.pool())
            .await
            .unwrap();
        let bytes = std::fs::read(&full).unwrap();
        std::fs::remove_file(&full).unwrap();

        let imported = import_snapshot(&db, &bytes, Some("admin")).await.unwrap();
        assert_eq!(imported.kind, SnapshotKind::Imported);
        assert_eq!(imported.status, SnapshotStatus::Active);
        assert!(imported.components.is_empty());
        for component in Component::ALL {
            assert!(latest_applied_for(&db, component).await.unwrap().is_none());
        }

        let copy = open_sqlite(&snapshot_path(&db, imported.id).await.unwrap(), true)
            .await
            .unwrap();
        assert_eq!(
            count_rows(&copy, "users").await,
            0,
            "accounts must be stripped"
        );
        assert_eq!(count_rows(&copy, "jwt_key").await, 0);
        let office: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM firewall_zones WHERE name = 'office'")
                .fetch_one(&copy)
                .await
                .unwrap();
        assert_eq!(office, 1, "configuration must survive the import");
        copy.close().await;

        // The upload restores like any other snapshot.
        insert_zone(&db, "guest").await;
        restore_snapshot(&db, imported.id, None, None)
            .await
            .unwrap();
        assert!(zone_exists(&db, "office").await);
        assert!(!zone_exists(&db, "guest").await);
    }

    #[tokio::test]
    async fn import_rejects_non_sqlite_bytes_and_leaves_no_files() {
        let scratch = Scratch::new();
        let db = open(&scratch).await;
        create_snapshot(&db, applied_now()).await.unwrap();
        let before = std::fs::read_dir(scratch.snapshot_dir()).unwrap().count();

        let error = import_snapshot(&db, b"#!/bin/sh\necho nope\n", None)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("not an SQLite"), "{error:#}");
        assert_eq!(
            std::fs::read_dir(scratch.snapshot_dir()).unwrap().count(),
            before
        );
        assert_eq!(list_snapshots(&db).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn import_rejects_triggers_and_leaves_no_files() {
        let scratch = Scratch::new();
        let db = open(&scratch).await;
        std::fs::create_dir_all(scratch.snapshot_dir()).unwrap();
        let copy_path = scratch.snapshot_dir().join("trigger-copy.db");
        sqlx::query("VACUUM INTO ?")
            .bind(copy_path.to_str().unwrap())
            .execute(db.pool())
            .await
            .unwrap();
        let copy = open_sqlite(&copy_path, false).await.unwrap();
        sqlx::query(
            "CREATE TRIGGER exfiltrate AFTER DELETE ON users BEGIN
                 INSERT INTO firewall_zones (name, created_at, updated_at) VALUES ('x', 0, 0);
             END",
        )
        .execute(&copy)
        .await
        .unwrap();
        copy.close().await;
        let bytes = std::fs::read(&copy_path).unwrap();
        std::fs::remove_file(&copy_path).unwrap();
        let before = std::fs::read_dir(scratch.snapshot_dir()).unwrap().count();

        let error = import_snapshot(&db, &bytes, None).await.unwrap_err();
        assert!(error.to_string().contains("triggers"), "{error:#}");
        assert_eq!(
            std::fs::read_dir(scratch.snapshot_dir()).unwrap().count(),
            before
        );
        assert!(list_snapshots(&db).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn import_rejects_a_newer_schema_and_leaves_no_files() {
        let scratch = Scratch::new();
        let db = open(&scratch).await;
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
        let bytes = std::fs::read(&path).unwrap();
        let before = std::fs::read_dir(scratch.snapshot_dir()).unwrap().count();

        let error = import_snapshot(&db, &bytes, None).await.unwrap_err();
        assert!(error.to_string().contains("newer"), "{error:#}");
        assert_eq!(
            std::fs::read_dir(scratch.snapshot_dir()).unwrap().count(),
            before
        );
        assert_eq!(list_snapshots(&db).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn import_rejects_invalid_configuration_and_registers_nothing() {
        use crate::snapshot_validation::tests::populate_valid_configuration;

        let scratch = Scratch::new();
        let db = open(&scratch).await;
        populate_valid_configuration(&db).await;

        // An upload whose host record name would inject a dnsmasq directive.
        std::fs::create_dir_all(scratch.snapshot_dir()).unwrap();
        let copy_path = scratch.snapshot_dir().join("tampered-copy.db");
        sqlx::query("VACUUM INTO ?")
            .bind(copy_path.to_str().unwrap())
            .execute(db.pool())
            .await
            .unwrap();
        let copy = open_sqlite(&copy_path, false).await.unwrap();
        sqlx::query(
            "UPDATE dnsmasq_host_record_names
             SET hostname = 'nas.example' || char(10) || 'dhcp-script=/bin/sh'",
        )
        .execute(&copy)
        .await
        .unwrap();
        copy.close().await;
        let bytes = std::fs::read(&copy_path).unwrap();
        std::fs::remove_file(&copy_path).unwrap();
        let before = std::fs::read_dir(scratch.snapshot_dir()).unwrap().count();

        let error = import_snapshot(&db, &bytes, Some("admin"))
            .await
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("invalid configuration"), "{message}");
        assert!(message.contains("dnsmasq:"), "{message}");
        assert!(list_snapshots(&db).await.unwrap().is_empty());
        assert_eq!(
            std::fs::read_dir(scratch.snapshot_dir()).unwrap().count(),
            before,
            "a refused upload must leave no files behind"
        );
    }

    #[tokio::test]
    async fn restore_refuses_invalid_snapshot_and_keeps_live_configuration() {
        use crate::snapshot_validation::tests::populate_valid_configuration;

        let scratch = Scratch::new();
        let db = open(&scratch).await;
        populate_valid_configuration(&db).await;
        let snapshot = create_snapshot(&db, applied_now()).await.unwrap();

        // Tamper with the stored copy: an interface description that would
        // write a second directive into the generated networkd file.
        let path = snapshot_path(&db, snapshot.id).await.unwrap();
        let copy = open_sqlite(&path, false).await.unwrap();
        sqlx::query(
            "UPDATE interface_config
             SET description = 'uplink' || char(10) || 'Table=1'
             WHERE interface_name = 'wan0'",
        )
        .execute(&copy)
        .await
        .unwrap();
        copy.close().await;

        insert_zone(&db, "guest").await;
        let snapshots_before = list_snapshots(&db).await.unwrap().len();
        let files_before = std::fs::read_dir(scratch.snapshot_dir()).unwrap().count();

        let error = restore_snapshot(&db, snapshot.id, None, None)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("networkd:"), "{error:#}");

        assert!(
            zone_exists(&db, "guest").await,
            "refused restore must not change live data"
        );
        assert_eq!(db.get_interface_configs().await.unwrap().len(), 2);
        assert_eq!(
            list_snapshots(&db).await.unwrap().len(),
            snapshots_before,
            "no pre-restore backup should be taken for a refused restore"
        );
        assert_eq!(
            std::fs::read_dir(scratch.snapshot_dir()).unwrap().count(),
            files_before,
            "the scratch copy must be removed"
        );
    }

    #[tokio::test]
    async fn valid_configuration_round_trips_through_import_and_restore() {
        use crate::snapshot_validation::tests::populate_valid_configuration;

        let scratch = Scratch::new();
        let db = open(&scratch).await;
        populate_valid_configuration(&db).await;
        let snapshot = create_snapshot(&db, applied_now()).await.unwrap();
        let bytes = std::fs::read(snapshot_path(&db, snapshot.id).await.unwrap()).unwrap();

        insert_zone(&db, "guest").await;
        restore_snapshot(&db, snapshot.id, None, None)
            .await
            .expect("a snapshot the daemon created must restore");
        assert!(!zone_exists(&db, "guest").await);
        assert!(zone_exists(&db, "office").await);

        let imported = import_snapshot(&db, &bytes, None)
            .await
            .expect("a valid upload must be accepted");
        insert_zone(&db, "guest").await;
        restore_snapshot(&db, imported.id, None, None)
            .await
            .expect("an imported valid snapshot must restore");
        assert!(!zone_exists(&db, "guest").await);
        assert_eq!(db.get_interface_configs().await.unwrap().len(), 2);
    }

    /// Write a snapshot file as a daemon from before the drop migration would
    /// have: the current configuration plus the retired DHCP server and IPv6 RA
    /// tables, with rows in each, and migration history that stops before the
    /// drop.
    async fn write_pre_drop_snapshot(db: &Database, path: &Path) {
        vacuum_into(db.pool(), path).await.unwrap();
        let pool = open_sqlite(path, false).await.unwrap();

        for sql in [
            include_str!("../migrations/20241228000007_dhcp_server_config.sql"),
            include_str!("../migrations/20241228000008_ipv6_ra_config.sql"),
        ] {
            sqlx::raw_sql(sql).execute(&pool).await.unwrap();
        }
        // The ipv6 tables reference `interface_configs`, a table that never
        // existed, so enforcement stays off while the legacy rows are written.
        sqlx::query("PRAGMA foreign_keys = OFF")
            .execute(&pool)
            .await
            .unwrap();
        let interface: i64 = sqlx::query_scalar("SELECT MIN(id) FROM interface_config")
            .fetch_one(&pool)
            .await
            .unwrap();
        for sql in [
            "INSERT INTO dhcp_server_config (interface_config_id, enabled, pool_offset, pool_size)
             VALUES (?1, 1, 10, 100)",
            "INSERT INTO dhcp_server_dns (dhcp_server_id, server) VALUES (?1, '192.168.50.2')",
            "INSERT INTO dhcp_server_ntp (dhcp_server_id, server) VALUES (?1, 'pool.ntp.org')",
            "INSERT INTO dhcp_static_leases (dhcp_server_id, mac_address, ip_address, hostname)
             VALUES (?1, '00:11:22:33:44:55', '192.168.50.20', 'nas')",
            "INSERT INTO ipv6_ra_config (interface_config_id, enabled) VALUES (?1, 1)",
            "INSERT INTO ipv6_ra_dns (ipv6_ra_config_id, server) VALUES (?1, '2001:db8::53')",
            "INSERT INTO ipv6_ra_search_domains (ipv6_ra_config_id, domain)
             VALUES (?1, 'lan.example')",
            "INSERT INTO ipv6_ra_prefixes (ipv6_ra_config_id, prefix) VALUES (?1, '2001:db8:1::/64')",
        ] {
            sqlx::query(sql)
                .bind(interface)
                .execute(&pool)
                .await
                .unwrap();
        }
        // The copy as an older daemon left it: the drop was not yet applied.
        // Only the drop's history row is removed; later migrations (which add
        // columns and cannot run twice) stay recorded, and sqlx applies the
        // missing drop when the copy is migrated.
        sqlx::query("DELETE FROM _sqlx_migrations WHERE version = 20261015000001")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        strip_to_configuration(path).await.unwrap();

        let pool = open_sqlite(path, true).await.unwrap();
        let names = table_names(&pool).await.unwrap();
        pool.close().await;
        for table in RETIRED_TABLES {
            assert!(
                names.iter().any(|name| name.as_str() == *table),
                "the pre-drop snapshot must still hold {table}"
            );
        }
    }

    #[tokio::test]
    async fn snapshot_from_before_the_drop_migration_restores() {
        use crate::snapshot_validation::tests::populate_valid_configuration;

        let scratch = Scratch::new();
        let db = open(&scratch).await;
        populate_valid_configuration(&db).await;
        ensure_private_dir(&scratch.snapshot_dir()).unwrap();

        // Stored as a snapshot on disk, the way an older daemon left it.
        let file_name = format!("{}-{}.db", unix_millis(), Uuid::new_v4().simple());
        let path = snapshot_file_path(&scratch.snapshot_dir(), &file_name).unwrap();
        write_pre_drop_snapshot(&db, &path).await;
        let id = sqlx::query(
            "INSERT INTO config_snapshots
                (created_at, kind, status, actor, note, file_name, schema_version, session_id,
                 components)
             VALUES (?, ?, ?, NULL, 'pre-drop', ?, 20261014000003, NULL, '')",
        )
        .bind(unix_secs())
        .bind(SnapshotKind::Manual.as_str())
        .bind(SnapshotStatus::Active.as_str())
        .bind(file_name.as_str())
        .execute(db.pool())
        .await
        .unwrap()
        .last_insert_rowid();

        insert_zone(&db, "guest").await;
        restore_snapshot(&db, id, None, None)
            .await
            .expect("a snapshot taken before the drop migration must restore");
        assert!(!zone_exists(&db, "guest").await);
        assert!(zone_exists(&db, "office").await);
        assert_eq!(db.get_interface_configs().await.unwrap().len(), 2);
        let names = table_names(db.pool()).await.unwrap();
        for table in RETIRED_TABLES {
            assert!(!names.iter().any(|name| name.as_str() == *table));
        }
    }

    #[tokio::test]
    async fn snapshot_from_before_the_drop_migration_imports_and_restores() {
        use crate::snapshot_validation::tests::populate_valid_configuration;

        let scratch = Scratch::new();
        let db = open(&scratch).await;
        populate_valid_configuration(&db).await;
        ensure_private_dir(&scratch.snapshot_dir()).unwrap();
        let path = scratch.snapshot_dir().join("pre-drop-upload.db");
        write_pre_drop_snapshot(&db, &path).await;
        let bytes = std::fs::read(&path).unwrap();

        let imported = import_snapshot(&db, &bytes, None)
            .await
            .expect("an upload from before the drop migration must be accepted");
        insert_zone(&db, "guest").await;
        restore_snapshot(&db, imported.id, None, None)
            .await
            .expect("the imported copy must restore");
        assert!(!zone_exists(&db, "guest").await);
        assert!(zone_exists(&db, "office").await);
    }

    /// Write a snapshot file as a daemon from before the zone default forward
    /// policy was dropped would have: the current configuration with the
    /// retired `default_forward_policy` column put back, holding values, and
    /// migration history that stops before the drop.
    async fn write_pre_zone_forward_drop_snapshot(db: &Database, path: &Path) {
        vacuum_into(db.pool(), path).await.unwrap();
        let pool = open_sqlite(path, false).await.unwrap();
        sqlx::query(
            "ALTER TABLE firewall_zones
             ADD COLUMN default_forward_policy TEXT NOT NULL DEFAULT 'drop'",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE firewall_zones SET default_forward_policy = 'accept' WHERE name = 'lan'",
        )
        .execute(&pool)
        .await
        .unwrap();
        // Only the drop's history row is removed; sqlx applies the missing
        // drop when the copy is migrated.
        sqlx::query("DELETE FROM _sqlx_migrations WHERE version = 20261015000400")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        strip_to_configuration(path).await.unwrap();
    }

    async fn zone_forward_policy_column_exists(pool: &SqlitePool) -> bool {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pragma_table_info('firewall_zones')
             WHERE name = 'default_forward_policy'",
        )
        .fetch_one(pool)
        .await
        .unwrap();
        count > 0
    }

    #[tokio::test]
    async fn snapshot_from_before_the_zone_forward_policy_drop_restores() {
        use crate::snapshot_validation::tests::populate_valid_configuration;

        let scratch = Scratch::new();
        let db = open(&scratch).await;
        populate_valid_configuration(&db).await;
        ensure_private_dir(&scratch.snapshot_dir()).unwrap();

        let file_name = format!("{}-{}.db", unix_millis(), Uuid::new_v4().simple());
        let path = snapshot_file_path(&scratch.snapshot_dir(), &file_name).unwrap();
        write_pre_zone_forward_drop_snapshot(&db, &path).await;
        let id = sqlx::query(
            "INSERT INTO config_snapshots
                (created_at, kind, status, actor, note, file_name, schema_version, session_id,
                 components)
             VALUES (?, ?, ?, NULL, 'pre-forward-drop', ?, 20261015000200, NULL, '')",
        )
        .bind(unix_secs())
        .bind(SnapshotKind::Manual.as_str())
        .bind(SnapshotStatus::Active.as_str())
        .bind(file_name.as_str())
        .execute(db.pool())
        .await
        .unwrap()
        .last_insert_rowid();

        insert_zone(&db, "guest").await;
        restore_snapshot(&db, id, None, None)
            .await
            .expect("a snapshot holding the retired column must restore");
        assert!(!zone_exists(&db, "guest").await);
        assert!(zone_exists(&db, "office").await);
        assert!(!zone_forward_policy_column_exists(db.pool()).await);
    }

    #[tokio::test]
    async fn snapshot_from_before_the_zone_forward_policy_drop_imports_and_restores() {
        use crate::snapshot_validation::tests::populate_valid_configuration;

        let scratch = Scratch::new();
        let db = open(&scratch).await;
        populate_valid_configuration(&db).await;
        ensure_private_dir(&scratch.snapshot_dir()).unwrap();
        let path = scratch.snapshot_dir().join("pre-forward-drop-upload.db");
        write_pre_zone_forward_drop_snapshot(&db, &path).await;
        let bytes = std::fs::read(&path).unwrap();

        let imported = import_snapshot(&db, &bytes, None)
            .await
            .expect("an upload holding the retired column must be accepted");
        insert_zone(&db, "guest").await;
        restore_snapshot(&db, imported.id, None, None)
            .await
            .expect("the imported copy must restore");
        assert!(!zone_exists(&db, "guest").await);
        assert!(zone_exists(&db, "office").await);
    }
}
