//! Pending configuration changes, discarding them, and the snapshot API.
//!
//! Configuration edits are saved to the database at once, and an apply turns
//! the database into system files. A change is therefore pending when the files
//! generated from the live database differ from the files generated from the
//! newest applied snapshot of the same component.
//!
//! Both sides are generated with the same functions the apply uses, so the diff
//! shows what the next apply would write.

use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use keystone_core::api::{CreateSnapshot, DiscardChanges, Endpoint, Req, Res, RestoreSnapshot};
use keystone_core::changes::{
    AwaitingConfirmation, Component, ComponentBaselines, ComponentDiff, DiscardChangesResponse,
    FileChangeStatus, FileDiff, PendingChangesResponse, RestoreSnapshotResponse,
    SnapshotListResponse, SnapshotResponse, SnapshotSummary,
};
use similar::TextDiff;
use tracing::info;

use crate::db::Database;
use crate::firewall::FirewallApplyManager;
use crate::networkd::PendingInfo;
use crate::snapshots::{self, NewSnapshot, SnapshotInfo, SnapshotKind, SnapshotStatus};
use crate::{Actor, AppError, networkd_preview_files};

/// Generated files of one component, keyed by the path they are written to.
type Generated = BTreeMap<String, String>;

/// Label for the nftables ruleset. The firewall is loaded with `nft` and has no
/// file on disk, so the ruleset is compared under this name.
const FIREWALL_RULESET_LABEL: &str = "keystone.nft";

/// Label for the traffic-shaping commands, which `tc` and `ip` apply instead of
/// writing a file.
const SQM_PLAN_LABEL: &str = "tc:sqm";

/// Longest note accepted on a manual snapshot.
const MAX_NOTE_BYTES: usize = 500;

#[derive(Clone)]
pub struct ChangesState {
    pub db: Database,
    pub firewall: Arc<FirewallApplyManager>,
}

// ============================================================================
// Generated configuration
// ============================================================================

/// The files `component` would write for the configuration in `db`.
async fn generate(component: Component, db: &Database) -> Result<Generated> {
    Ok(match component {
        Component::Networkd => networkd_preview_files(db)
            .await?
            .into_iter()
            .map(|file| (file.filename, file.content))
            .collect(),
        Component::Firewall => BTreeMap::from([(
            FIREWALL_RULESET_LABEL.to_string(),
            without_generation_time(crate::firewall::generate_preview(db).await?),
        )]),
        // The planned tc/ip commands. Nothing is generated while shaping is off.
        Component::Sqm => {
            let plan = crate::sqm::preview_sqm(db.pool()).await?;
            if plan.is_empty() {
                BTreeMap::new()
            } else {
                BTreeMap::from([(SQM_PLAN_LABEL.to_string(), plan)])
            }
        }
        // The miniupnpd configuration, or nothing while UPnP is disabled.
        Component::Upnp => {
            let config = crate::upnp::preview_upnp_config(db).await?;
            if config.is_empty() {
                BTreeMap::new()
            } else {
                BTreeMap::from([(crate::upnp::config::MINIUPNPD_CONF_PATH.to_string(), config)])
            }
        }
        Component::Dnsmasq => BTreeMap::from([(
            crate::dnsmasq::DNSMASQ_CONFIG_PATH.to_string(),
            crate::dnsmasq::preview_dnsmasq_config(db.pool()).await?,
        )]),
        Component::Caddy => BTreeMap::from([(
            crate::caddy::CADDYFILE_PATH.to_string(),
            crate::caddy::preview_caddyfile(db.pool()).await?,
        )]),
    })
}

/// The ruleset preview begins with the time it was generated. Two sides
/// generated a second apart would then always differ, so that header line is
/// dropped before comparing.
fn without_generation_time(ruleset: String) -> String {
    ruleset
        .split_inclusive('\n')
        .filter(|line| !line.starts_with("# Generated:"))
        .collect()
}

/// Generate for one side of a comparison. Errors are kept as text so that they
/// can be reported per component.
async fn generate_side(component: Component, db: &Database) -> Result<Generated, String> {
    generate(component, db)
        .await
        .map_err(|error| format!("{error:#}"))
}

/// Build the diff of one component. `old` is the baseline side and `new` the
/// side being compared against it. Labels name each side in the unified diff.
fn component_diff(
    component: Component,
    old: Result<Generated, String>,
    new: Result<Generated, String>,
    old_label: &str,
    new_label: &str,
) -> ComponentDiff {
    match (old, new) {
        (Ok(old), Ok(new)) => {
            let files = compare_files(&old, &new, old_label, new_label);
            ComponentDiff {
                component,
                changed: !files.is_empty(),
                files,
                error: None,
            }
        }
        (old, new) => {
            // A side that cannot be generated is a difference, unless both
            // sides fail the same way and nothing else is known.
            let message = match (&old, &new) {
                (Err(old), Err(new)) if old == new => old.clone(),
                (old, new) => [
                    old.as_ref().err().map(|e| format!("{old_label}: {e}")),
                    new.as_ref().err().map(|e| format!("{new_label}: {e}")),
                ]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join("; "),
            };
            let changed = match (&old, &new) {
                (Err(old), Err(new)) => old != new,
                _ => true,
            };
            ComponentDiff {
                component,
                changed,
                files: Vec::new(),
                error: Some(message),
            }
        }
    }
}

fn compare_files(
    old: &Generated,
    new: &Generated,
    old_label: &str,
    new_label: &str,
) -> Vec<FileDiff> {
    let mut files = Vec::new();
    for (path, new_content) in new {
        match old.get(path) {
            None => files.push(file_diff(
                path,
                FileChangeStatus::Added,
                "",
                new_content,
                old_label,
                new_label,
            )),
            Some(old_content) if old_content != new_content => files.push(file_diff(
                path,
                FileChangeStatus::Modified,
                old_content,
                new_content,
                old_label,
                new_label,
            )),
            Some(_) => {}
        }
    }
    for (path, old_content) in old {
        if !new.contains_key(path) {
            files.push(file_diff(
                path,
                FileChangeStatus::Removed,
                old_content,
                "",
                old_label,
                new_label,
            ));
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    files
}

fn file_diff(
    path: &str,
    status: FileChangeStatus,
    old: &str,
    new: &str,
    old_label: &str,
    new_label: &str,
) -> FileDiff {
    let unified_diff = TextDiff::from_lines(old, new)
        .unified_diff()
        .context_radius(3)
        .header(
            &format!("{old_label}/{path}"),
            &format!("{new_label}/{path}"),
        )
        .to_string();
    FileDiff {
        path: path.to_string(),
        status,
        unified_diff,
    }
}

// ============================================================================
// Pending changes and snapshot diffs
// ============================================================================

/// Current Unix time in seconds, as the daemon's clock reads it.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// Session ids of the live applies that await confirmation.
fn session_ids(live: &[PendingInfo]) -> Vec<&str> {
    live.iter().map(|info| info.session_id.as_str()).collect()
}

/// The apply awaiting confirmation, if any. It is the newest pending snapshot
/// whose session is live. The deadline comes from the live session, so it is
/// reported even when no snapshot could be recorded for the apply.
async fn awaiting_confirmation(
    db: &Database,
    live: &[PendingInfo],
) -> Result<Option<AwaitingConfirmation>> {
    let Some(first) = live.first() else {
        return Ok(None);
    };
    let snapshot = snapshots::pending_for_sessions(db, &session_ids(live)).await?;
    Ok(Some(match snapshot {
        Some(snapshot) => {
            let session = snapshot.session_id.as_deref().unwrap_or_default();
            let info = live
                .iter()
                .find(|info| info.session_id == session)
                .unwrap_or(first);
            AwaitingConfirmation {
                session_id: info.session_id.clone(),
                deadline: info.deadline,
                components: snapshot.components,
            }
        }
        None => AwaitingConfirmation {
            session_id: first.session_id.clone(),
            deadline: first.deadline,
            components: Vec::new(),
        },
    }))
}

/// Compare the live configuration with the baseline of each component: the
/// snapshot the running system matches (see [`snapshots::baseline_for`]). A
/// component with no baseline is compared with nothing, so every file it
/// generates counts as added. `live` lists the applies awaiting confirmation.
pub(crate) async fn pending_changes(
    db: &Database,
    live: &[PendingInfo],
) -> Result<PendingChangesResponse> {
    let mut opened: HashMap<i64, Result<snapshots::OpenedSnapshot, String>> = HashMap::new();
    let mut baselines = ComponentBaselines::default();
    let mut components = Vec::with_capacity(Component::ALL.len());
    let live_ids = session_ids(live);

    for component in Component::ALL {
        let baseline = snapshots::baseline_for(db, component, &live_ids)
            .await?
            .map(|snapshot| snapshot.id);
        baselines.set(component, baseline);

        let old = match baseline {
            None => Ok(Generated::new()),
            Some(id) => baseline_generated(&mut opened, db, id, component).await,
        };
        let new = generate_side(component, db).await;
        components.push(component_diff(component, old, new, "applied", "live"));
    }

    Ok(PendingChangesResponse {
        components,
        baseline_ids: baselines,
        awaiting_confirmation: awaiting_confirmation(db, live).await?,
        server_time: now_secs(),
    })
}

/// Generate `component` from snapshot `id`. Each snapshot is opened once per
/// request, however many components use it.
async fn baseline_generated(
    opened: &mut HashMap<i64, Result<snapshots::OpenedSnapshot, String>>,
    db: &Database,
    id: i64,
    component: Component,
) -> Result<Generated, String> {
    let entry = match opened.entry(id) {
        Entry::Occupied(entry) => entry.into_mut(),
        Entry::Vacant(entry) => {
            let result = snapshots::open_snapshot(db, id)
                .await
                .map_err(|error| format!("{error:#}"));
            entry.insert(result)
        }
    };
    match entry {
        Ok(snapshot) => generate_side(component, snapshot.database()).await,
        Err(error) => Err(format!("snapshot {id} could not be opened: {error}")),
    }
}

/// What restoring snapshot `id` would change in the live configuration. The
/// live configuration is the old side and the snapshot the new side.
pub(crate) async fn snapshot_diff(db: &Database, id: i64) -> Result<PendingChangesResponse> {
    let snapshot = snapshots::open_snapshot(db, id).await?;
    let label = format!("snapshot-{id}");
    let mut components = Vec::with_capacity(Component::ALL.len());
    for component in Component::ALL {
        let old = generate_side(component, db).await;
        let new = generate_side(component, snapshot.database()).await;
        components.push(component_diff(component, old, new, "live", &label));
    }

    let mut baselines = ComponentBaselines::default();
    for component in Component::ALL {
        baselines.set(component, Some(id));
    }
    Ok(PendingChangesResponse {
        components,
        baseline_ids: baselines,
        awaiting_confirmation: None,
        server_time: now_secs(),
    })
}

// ============================================================================
// Discard and restore
// ============================================================================

/// Normalise a requested component list. Omitting it selects every component.
fn selected_components(requested: Option<Vec<Component>>) -> Result<Vec<Component>> {
    let Some(mut components) = requested else {
        return Ok(Component::ALL.to_vec());
    };
    ensure!(!components.is_empty(), "choose at least one component");
    components.sort();
    components.dedup();
    Ok(components)
}

/// Revert the selected components (default: every changed one) to their newest
/// applied snapshot. Nothing is applied to the system. Each affected snapshot
/// is read once, and the whole change is one transaction.
pub(crate) async fn discard_changes(
    db: &Database,
    live: &[PendingInfo],
    requested: Option<Vec<Component>>,
    actor: Option<&str>,
) -> Result<DiscardChangesResponse> {
    let components = match requested {
        Some(list) => selected_components(Some(list))?,
        None => pending_changes(db, live)
            .await?
            .components
            .iter()
            .filter(|diff| diff.changed)
            .map(|diff| diff.component)
            .collect(),
    };
    if components.is_empty() {
        return Ok(DiscardChangesResponse {
            success: true,
            message: "There are no pending changes to discard.".to_string(),
            pre_restore_snapshot_id: None,
            components,
        });
    }

    let live_ids = session_ids(live);
    let mut by_snapshot: BTreeMap<i64, Vec<Component>> = BTreeMap::new();
    for component in &components {
        let baseline = snapshots::baseline_for(db, *component, &live_ids)
            .await?
            .with_context(|| {
                format!(
                    "{component} has no applied configuration to discard back to; nothing was changed"
                )
            })?;
        by_snapshot.entry(baseline.id).or_default().push(*component);
    }
    let plan: Vec<(i64, Vec<Component>)> = by_snapshot.into_iter().collect();
    let outcome = snapshots::restore_components(db, &plan, actor).await?;

    Ok(DiscardChangesResponse {
        success: true,
        message: format!(
            "Discarded pending changes for {}. The live configuration matches the last applied state; nothing was applied to the system. The replaced configuration was saved as snapshot {}.",
            join_components(&outcome.components),
            outcome.pre_restore.id
        ),
        pre_restore_snapshot_id: Some(outcome.pre_restore.id),
        components: outcome.components,
    })
}

fn join_components(components: &[Component]) -> String {
    components
        .iter()
        .map(|component| component.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Fails when a change is awaiting confirmation or configuration changes are
/// locked. Discarding or restoring then would race with the pending apply.
async fn ensure_changes_allowed(state: &ChangesState) -> Result<()> {
    if state
        .db
        .get_global_settings()
        .await?
        .config_changes_disabled
    {
        bail!(
            "Configuration changes are disabled. Unlock in Settings to change the configuration."
        );
    }
    if state.firewall.status().await.pending_confirmation {
        bail!(
            "A configuration change is awaiting confirmation. Confirm or roll it back before discarding or restoring."
        );
    }
    Ok(())
}

// ============================================================================
// Snapshot listing, creation and export
// ============================================================================

async fn summarize(db: &Database, info: &SnapshotInfo) -> SnapshotSummary {
    // A missing file reports zero bytes rather than failing the whole listing.
    let size_bytes = match snapshots::snapshot_path(db, info.id).await {
        Ok(path) => std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0),
        Err(_) => 0,
    };
    SnapshotSummary {
        id: info.id,
        created_at: info.created_at,
        kind: info.kind,
        status: info.status,
        actor: info.actor.clone(),
        note: info.note.clone(),
        components: info.components.clone(),
        size_bytes,
    }
}

// ============================================================================
// HTTP routes
// ============================================================================

pub(crate) fn changes_routes(state: ChangesState) -> Router<Arc<crate::AppState>> {
    Router::new()
        .route("/changes/pending", get(get_pending_changes))
        .route(DiscardChanges::PATH, post(discard_changes_route))
        .route("/snapshots", get(list_snapshots_route))
        .route(CreateSnapshot::PATH, post(create_snapshot_route))
        .route(
            "/snapshots/import",
            post(import_snapshot_route).layer(DefaultBodyLimit::max(snapshots::MAX_IMPORT_BYTES)),
        )
        .route("/snapshots/{id}/diff", get(snapshot_diff_route))
        .route("/snapshots/{id}/export", get(export_snapshot_route))
        .route(RestoreSnapshot::PATH, post(restore_snapshot_route))
        .with_state(state)
}

fn actor_name(actor: &Option<Extension<Actor>>) -> Option<&str> {
    actor.as_ref().map(|Extension(actor)| actor.0.as_str())
}

async fn get_pending_changes(
    State(state): State<ChangesState>,
) -> Result<Json<PendingChangesResponse>, AppError> {
    info!("Computing pending configuration changes");
    let live = state.firewall.awaiting_confirmation().await;
    Ok(Json(pending_changes(&state.db, &live).await?))
}

async fn discard_changes_route(
    State(state): State<ChangesState>,
    actor: Option<Extension<Actor>>,
    Json(request): Json<Req<DiscardChanges>>,
) -> Result<Json<Res<DiscardChanges>>, AppError> {
    info!("Discarding pending configuration changes");
    ensure_changes_allowed(&state).await?;
    let live = state.firewall.awaiting_confirmation().await;
    let response =
        discard_changes(&state.db, &live, request.components, actor_name(&actor)).await?;
    Ok(Json(response))
}

async fn list_snapshots_route(
    State(state): State<ChangesState>,
) -> Result<Json<SnapshotListResponse>, AppError> {
    let infos = snapshots::list_snapshots(&state.db).await?;
    let mut summaries = Vec::with_capacity(infos.len());
    for info in &infos {
        summaries.push(summarize(&state.db, info).await);
    }
    Ok(Json(SnapshotListResponse {
        snapshots: summaries,
    }))
}

async fn create_snapshot_route(
    State(state): State<ChangesState>,
    actor: Option<Extension<Actor>>,
    Json(request): Json<Req<CreateSnapshot>>,
) -> Result<Json<Res<CreateSnapshot>>, AppError> {
    let note = request
        .note
        .map(|note| note.trim().to_string())
        .filter(|note| !note.is_empty());
    if note
        .as_ref()
        .is_some_and(|note| note.len() > MAX_NOTE_BYTES)
    {
        return Err(anyhow::anyhow!("note must be at most {MAX_NOTE_BYTES} bytes").into());
    }
    // A manual snapshot may capture unapplied edits, so it has no components
    // and never becomes an applied baseline.
    let info = snapshots::create_snapshot(
        &state.db,
        NewSnapshot {
            kind: SnapshotKind::Manual,
            status: SnapshotStatus::Active,
            session_id: None,
            components: &[],
            actor: actor_name(&actor),
            note: note.as_deref(),
        },
    )
    .await?;
    Ok(Json(SnapshotResponse {
        success: true,
        message: format!(
            "Saved snapshot {} of the current configuration. It is not an applied baseline.",
            info.id
        ),
        snapshot: summarize(&state.db, &info).await,
    }))
}

async fn import_snapshot_route(
    State(state): State<ChangesState>,
    actor: Option<Extension<Actor>>,
    body: Bytes,
) -> Result<Json<SnapshotResponse>, AppError> {
    info!("Importing configuration snapshot ({} bytes)", body.len());
    let info = snapshots::import_snapshot(&state.db, &body, actor_name(&actor)).await?;
    Ok(Json(SnapshotResponse {
        success: true,
        message: format!(
            "Imported snapshot {}. It is stored for restore only and is not an applied configuration.",
            info.id
        ),
        snapshot: summarize(&state.db, &info).await,
    }))
}

async fn snapshot_diff_route(
    State(state): State<ChangesState>,
    Path(id): Path<i64>,
) -> Result<Json<PendingChangesResponse>, AppError> {
    Ok(Json(snapshot_diff(&state.db, id).await?))
}

async fn restore_snapshot_route(
    State(state): State<ChangesState>,
    actor: Option<Extension<Actor>>,
    Path(id): Path<i64>,
    Json(request): Json<Req<RestoreSnapshot>>,
) -> Result<Json<Res<RestoreSnapshot>>, AppError> {
    info!("Restoring configuration snapshot {id}");
    ensure_changes_allowed(&state).await?;
    let components = selected_components(request.components)?;
    let outcome =
        snapshots::restore_snapshot(&state.db, id, actor_name(&actor), Some(&components)).await?;
    Ok(Json(RestoreSnapshotResponse {
        success: true,
        message: format!(
            "Restored {} from snapshot {id} into the live configuration. The restored configuration is pending until it is applied. The replaced configuration was saved as snapshot {}.",
            join_components(&outcome.components),
            outcome.pre_restore.id
        ),
        pre_restore_snapshot_id: Some(outcome.pre_restore.id),
        components: outcome.components,
    }))
}

async fn export_snapshot_route(
    State(state): State<ChangesState>,
    Path(id): Path<i64>,
) -> Result<Response, AppError> {
    let info = snapshots::get_snapshot(&state.db, id)
        .await?
        .with_context(|| format!("snapshot {id} does not exist"))?;
    let path = snapshots::snapshot_path(&state.db, id).await?;
    let bytes = tokio::fs::read(&path)
        .await
        .with_context(|| format!("snapshot {id} has no file on disk"))?;
    let date = keystone_core::changes::format_utc_date(info.created_at).replace('-', "");
    let filename = format!("keystone-config-{id}-{date}.db");
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/vnd.sqlite3")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .body(Body::from(bytes))
        .context("Failed to build the export response")?;
    Ok(response.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AppState;
    use crate::auth::AuthManager;
    use crate::db::Database;
    use crate::networkd::NetworkdApplyManager;
    use crate::snapshots::tests::{Scratch, open};
    use axum::http::Request;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn generated(files: &[(&str, &str)]) -> Generated {
        files
            .iter()
            .map(|(path, content)| (path.to_string(), content.to_string()))
            .collect()
    }

    #[test]
    fn compare_reports_added_modified_and_removed_files() {
        let old = generated(&[("a.conf", "one\n"), ("gone.conf", "x\n")]);
        let new = generated(&[("a.conf", "two\n"), ("new.conf", "y\n")]);
        let files = compare_files(&old, &new, "applied", "live");

        let summary: Vec<(&str, FileChangeStatus)> = files
            .iter()
            .map(|file| (file.path.as_str(), file.status))
            .collect();
        assert_eq!(
            summary,
            vec![
                ("a.conf", FileChangeStatus::Modified),
                ("gone.conf", FileChangeStatus::Removed),
                ("new.conf", FileChangeStatus::Added),
            ]
        );
        assert!(files[0].unified_diff.contains("-one"));
        assert!(files[0].unified_diff.contains("+two"));
        assert!(files[0].unified_diff.contains("applied/a.conf"));
        assert!(compare_files(&new, &new, "applied", "live").is_empty());
    }

    #[test]
    fn firewall_generation_time_is_not_a_change() {
        let at = |secs: &str| {
            format!(
                "# Keystone\n# Generated: Unix timestamp: {secs}\n\ntable inet keystone {{\n}}\n"
            )
        };
        assert_eq!(
            without_generation_time(at("100")),
            without_generation_time(at("101"))
        );
        let edited = at("101").replace("table inet keystone", "table inet other");
        assert_ne!(
            without_generation_time(at("100")),
            without_generation_time(edited)
        );
        assert!(without_generation_time(at("100")).ends_with("}\n"));
    }

    #[test]
    fn component_diff_treats_unreadable_sides_as_changes() {
        let same = Generated::new();
        let both_failing_alike = component_diff(
            Component::Caddy,
            Err("bad bind".into()),
            Err("bad bind".into()),
            "applied",
            "live",
        );
        assert!(!both_failing_alike.changed);
        assert_eq!(both_failing_alike.error.as_deref(), Some("bad bind"));

        let live_only_fails = component_diff(
            Component::Caddy,
            Ok(same.clone()),
            Err("bad bind".into()),
            "applied",
            "live",
        );
        assert!(live_only_fails.changed);
        assert_eq!(live_only_fails.error.as_deref(), Some("live: bad bind"));
    }

    #[test]
    fn selection_defaults_to_every_component_and_rejects_empty_lists() {
        assert_eq!(selected_components(None).unwrap(), Component::ALL.to_vec());
        assert!(selected_components(Some(vec![])).is_err());
        assert_eq!(
            selected_components(Some(vec![Component::Caddy, Component::Caddy])).unwrap(),
            vec![Component::Caddy]
        );
    }

    /// Database with a dnsmasq baseline and no other edits.
    async fn applied_baseline(scratch: &Scratch) -> Database {
        let db = open(scratch).await;
        snapshots::record_applied(&db, Some("admin"), None, &Component::ALL, "test apply").await;
        db
    }

    async fn set_dnsmasq_cache_size(db: &Database, size: i64) {
        sqlx::query("UPDATE dnsmasq_config SET cache_size = ? WHERE id = 1")
            .bind(size)
            .execute(db.pool())
            .await
            .unwrap();
    }

    fn changed(response: &PendingChangesResponse, component: Component) -> bool {
        response
            .components
            .iter()
            .find(|diff| diff.component == component)
            .unwrap()
            .changed
    }

    #[tokio::test]
    async fn a_dnsmasq_edit_is_pending_only_for_dnsmasq_until_discarded() {
        let scratch = Scratch::new();
        let db = applied_baseline(&scratch).await;

        let clean = pending_changes(&db, &[]).await.unwrap();
        for component in Component::ALL {
            assert!(
                !changed(&clean, component),
                "{component} changed with no edits: {clean:?}"
            );
        }
        assert!(clean.baseline_ids.get(Component::Dnsmasq).is_some());

        set_dnsmasq_cache_size(&db, 4321).await;
        let pending = pending_changes(&db, &[]).await.unwrap();
        assert!(changed(&pending, Component::Dnsmasq));
        assert!(!changed(&pending, Component::Firewall));
        assert!(!changed(&pending, Component::Networkd));
        let dnsmasq = pending
            .components
            .iter()
            .find(|diff| diff.component == Component::Dnsmasq)
            .unwrap();
        assert_eq!(dnsmasq.files.len(), 1);
        assert_eq!(dnsmasq.files[0].status, FileChangeStatus::Modified);
        assert!(dnsmasq.files[0].unified_diff.contains("+cache-size=4321"));

        let outcome = discard_changes(&db, &[], Some(vec![Component::Dnsmasq]), Some("admin"))
            .await
            .unwrap();
        assert_eq!(outcome.components, vec![Component::Dnsmasq]);
        assert!(outcome.pre_restore_snapshot_id.is_some());

        let after = pending_changes(&db, &[]).await.unwrap();
        assert!(!changed(&after, Component::Dnsmasq));
    }

    #[tokio::test]
    async fn a_upnp_edit_is_pending_for_upnp_and_the_firewall_accept_until_discarded() {
        let scratch = Scratch::new();
        let db = applied_baseline(&scratch).await;

        sqlx::query("UPDATE upnp_config SET enabled = 1, wan_interface = 'eth0' WHERE id = 1")
            .execute(db.pool())
            .await
            .unwrap();
        sqlx::query("INSERT INTO upnp_lan_interfaces (interface) VALUES ('eth1')")
            .execute(db.pool())
            .await
            .unwrap();
        sqlx::query("INSERT INTO upnp_allowed_subnets (subnet) VALUES ('192.168.1.0/24')")
            .execute(db.pool())
            .await
            .unwrap();

        let pending = pending_changes(&db, &[]).await.unwrap();
        assert!(changed(&pending, Component::Upnp));
        // The forward accept for DNATed mappings is part of the firewall ruleset.
        assert!(changed(&pending, Component::Firewall));
        assert!(!changed(&pending, Component::Dnsmasq));
        assert!(!changed(&pending, Component::Sqm));

        let upnp = pending
            .components
            .iter()
            .find(|diff| diff.component == Component::Upnp)
            .unwrap();
        let conf = upnp
            .files
            .iter()
            .find(|file| file.path == crate::upnp::config::MINIUPNPD_CONF_PATH)
            .expect("miniupnpd.conf is in the UPnP diff");
        assert_eq!(conf.status, FileChangeStatus::Added);
        assert!(
            conf.unified_diff
                .contains("+allow 1024-65535 192.168.1.0/24 1024-65535")
        );
        let firewall = pending
            .components
            .iter()
            .find(|diff| diff.component == Component::Firewall)
            .unwrap();
        assert!(firewall.files[0].unified_diff.contains("ks:upnp"));

        let outcome = discard_changes(
            &db,
            &[],
            Some(vec![Component::Upnp, Component::Firewall]),
            Some("admin"),
        )
        .await
        .unwrap();
        assert_eq!(
            outcome.components,
            vec![Component::Firewall, Component::Upnp]
        );

        let after = pending_changes(&db, &[]).await.unwrap();
        assert!(!changed(&after, Component::Upnp));
        assert!(!changed(&after, Component::Firewall));
    }

    #[tokio::test]
    async fn an_sqm_edit_is_pending_only_for_sqm_and_lists_the_tc_commands() {
        let scratch = Scratch::new();
        let db = applied_baseline(&scratch).await;

        sqlx::query(
            "UPDATE sqm_config SET enabled = 1, interface = 'eth0', download_kbit = 90000, upload_kbit = 18000 WHERE id = 1",
        )
        .execute(db.pool())
        .await
        .unwrap();

        let pending = pending_changes(&db, &[]).await.unwrap();
        assert!(changed(&pending, Component::Sqm));
        assert!(!changed(&pending, Component::Dnsmasq));
        assert!(!changed(&pending, Component::Firewall));
        let sqm = pending
            .components
            .iter()
            .find(|diff| diff.component == Component::Sqm)
            .unwrap();
        assert_eq!(sqm.files.len(), 1);
        assert_eq!(sqm.files[0].path, "tc:sqm");
        assert_eq!(sqm.files[0].status, FileChangeStatus::Added);
        assert!(
            sqm.files[0]
                .unified_diff
                .contains("+tc qdisc replace dev eth0 root cake bandwidth 18000kbit")
        );
        assert!(
            sqm.files[0]
                .unified_diff
                .contains("+tc qdisc replace dev ifb4eth0 root cake bandwidth 90000kbit")
        );

        let outcome = discard_changes(&db, &[], Some(vec![Component::Sqm]), None)
            .await
            .unwrap();
        assert_eq!(outcome.components, vec![Component::Sqm]);
        assert!(!changed(
            &pending_changes(&db, &[]).await.unwrap(),
            Component::Sqm
        ));
    }

    #[tokio::test]
    async fn discard_without_components_reverts_only_changed_components() {
        let scratch = Scratch::new();
        let db = applied_baseline(&scratch).await;
        set_dnsmasq_cache_size(&db, 7).await;

        let outcome = discard_changes(&db, &[], None, None).await.unwrap();
        assert_eq!(outcome.components, vec![Component::Dnsmasq]);
        assert!(!changed(
            &pending_changes(&db, &[]).await.unwrap(),
            Component::Dnsmasq
        ));

        let nothing = discard_changes(&db, &[], None, None).await.unwrap();
        assert!(nothing.pre_restore_snapshot_id.is_none());
        assert!(nothing.components.is_empty());
    }

    #[tokio::test]
    async fn discard_refuses_a_component_that_was_never_applied() {
        let scratch = Scratch::new();
        let db = open(&scratch).await;
        set_dnsmasq_cache_size(&db, 7).await;
        let error = discard_changes(&db, &[], Some(vec![Component::Dnsmasq]), None)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("no applied configuration"),
            "{error:#}"
        );
        assert_eq!(snapshots::list_snapshots(&db).await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn snapshot_diff_shows_what_restoring_would_change() {
        let scratch = Scratch::new();
        let db = applied_baseline(&scratch).await;
        let baseline = snapshots::baseline_for(&db, Component::Dnsmasq, &[])
            .await
            .unwrap()
            .unwrap();
        set_dnsmasq_cache_size(&db, 99).await;

        let diff = snapshot_diff(&db, baseline.id).await.unwrap();
        assert!(changed(&diff, Component::Dnsmasq));
        assert!(!changed(&diff, Component::Caddy));
        assert_eq!(diff.baseline_ids.get(Component::Caddy), Some(baseline.id));
        let dnsmasq = diff
            .components
            .iter()
            .find(|d| d.component == Component::Dnsmasq)
            .unwrap();
        // Live is the old side here, so the snapshot's value is the addition.
        assert!(dnsmasq.files[0].unified_diff.contains("+cache-size=1000"));
    }

    /// Apply a dnsmasq edit the way apply-all does: the live configuration is
    /// recorded as a snapshot pending on `session`. Returns that snapshot's id.
    async fn dnsmasq_change_awaiting(db: &Database, session: &str) -> i64 {
        set_dnsmasq_cache_size(db, 5).await;
        snapshots::record_applied(
            db,
            Some("admin"),
            Some(session),
            &[Component::Dnsmasq],
            "test apply",
        )
        .await;
        snapshots::pending_for_sessions(db, &[session])
            .await
            .unwrap()
            .expect("the pending apply is recorded")
            .id
    }

    fn live(session: &str, deadline: u64) -> PendingInfo {
        PendingInfo {
            session_id: session.to_string(),
            deadline,
        }
    }

    #[tokio::test]
    async fn a_live_apply_awaiting_confirmation_is_the_baseline_and_not_a_pending_change() {
        let scratch = Scratch::new();
        let db = applied_baseline(&scratch).await;
        let pending_id = dnsmasq_change_awaiting(&db, "s1").await;

        let waiting = pending_changes(&db, &[live("s1", 1_000)]).await.unwrap();
        assert!(!changed(&waiting, Component::Dnsmasq), "{waiting:?}");
        assert_eq!(
            waiting.baseline_ids.get(Component::Dnsmasq),
            Some(pending_id)
        );
        assert_eq!(
            waiting.awaiting_confirmation,
            Some(AwaitingConfirmation {
                session_id: "s1".to_string(),
                deadline: 1_000,
                components: vec![Component::Dnsmasq],
            })
        );

        // An edit made after the apply is still pending, and confirmation waits.
        set_dnsmasq_cache_size(&db, 6).await;
        let edited = pending_changes(&db, &[live("s1", 1_000)]).await.unwrap();
        assert!(changed(&edited, Component::Dnsmasq));
        assert!(edited.awaiting_confirmation.is_some());
    }

    #[tokio::test]
    async fn a_confirmed_apply_stays_the_baseline_and_nothing_awaits() {
        let scratch = Scratch::new();
        let db = applied_baseline(&scratch).await;
        let pending_id = dnsmasq_change_awaiting(&db, "s1").await;

        snapshots::settle_session(&db, "s1", SnapshotStatus::Active).await;
        let confirmed = pending_changes(&db, &[]).await.unwrap();
        assert!(!changed(&confirmed, Component::Dnsmasq));
        assert_eq!(
            confirmed.baseline_ids.get(Component::Dnsmasq),
            Some(pending_id)
        );
        assert_eq!(confirmed.awaiting_confirmation, None);
    }

    #[tokio::test]
    async fn a_rolled_back_apply_stops_being_the_baseline_and_its_changes_are_pending_again() {
        let scratch = Scratch::new();
        let db = applied_baseline(&scratch).await;
        let earlier = snapshots::baseline_for(&db, Component::Dnsmasq, &[])
            .await
            .unwrap()
            .unwrap()
            .id;
        dnsmasq_change_awaiting(&db, "s1").await;

        // The rollback timer restores the previous configuration and settles the session.
        snapshots::settle_session(&db, "s1", SnapshotStatus::RolledBack).await;
        set_dnsmasq_cache_size(&db, 1000).await;
        let rolled_back = pending_changes(&db, &[]).await.unwrap();
        assert_eq!(
            rolled_back.baseline_ids.get(Component::Dnsmasq),
            Some(earlier)
        );
        assert_eq!(rolled_back.awaiting_confirmation, None);
        assert!(!changed(&rolled_back, Component::Dnsmasq));

        // The configuration that was rolled back is no longer the baseline, so
        // the same edit shows as pending against the earlier applied state.
        set_dnsmasq_cache_size(&db, 5).await;
        let again = pending_changes(&db, &[]).await.unwrap();
        assert!(changed(&again, Component::Dnsmasq));
        assert_eq!(again.baseline_ids.get(Component::Dnsmasq), Some(earlier));
    }

    #[tokio::test]
    async fn a_live_session_without_a_snapshot_still_reports_its_deadline() {
        let scratch = Scratch::new();
        let db = applied_baseline(&scratch).await;
        let response = pending_changes(&db, &[live("orphan", 42)]).await.unwrap();
        assert_eq!(
            response.awaiting_confirmation,
            Some(AwaitingConfirmation {
                session_id: "orphan".to_string(),
                deadline: 42,
                components: Vec::new(),
            })
        );
    }

    #[tokio::test]
    async fn apply_all_refuses_while_a_confirmation_is_pending() {
        let scratch = Scratch::new();
        let db = applied_baseline(&scratch).await;
        let firewall = manager(&db);
        firewall.seed_pending_for_test("s1", u64::MAX / 2).await;
        let result = crate::apply::apply_all(&db, &firewall, None, Some("admin"))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(
            result
                .message
                .contains("Confirm or roll back the previous change first"),
            "{}",
            result.message
        );
        // Nothing was applied, so no component reports an outcome.
        assert!(result.components.networkd.message.is_empty());
        assert!(result.components.dnsmasq.message.is_empty());
        assert_eq!(snapshots::list_snapshots(&db).await.unwrap().len(), 1);
    }

    fn app(db: &Database, firewall: Arc<FirewallApplyManager>) -> Router {
        let state = Arc::new(AppState::new(
            Arc::new(AuthManager::new(vec![7; 32])),
            db.clone(),
            firewall.clone(),
        ));
        changes_routes(ChangesState {
            db: db.clone(),
            firewall,
        })
        .with_state(state)
    }

    fn manager(db: &Database) -> Arc<FirewallApplyManager> {
        Arc::new(FirewallApplyManager::new(
            Arc::new(db.clone()),
            Arc::new(NetworkdApplyManager::system()),
        ))
    }

    async fn send(
        app: &Router,
        request: Request<Body>,
    ) -> (StatusCode, Vec<u8>, axum::http::HeaderMap) {
        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024 * 1024)
            .await
            .unwrap()
            .to_vec();
        (status, body, headers)
    }

    #[tokio::test]
    async fn routes_create_list_and_export_manual_snapshots() {
        let scratch = Scratch::new();
        let db = applied_baseline(&scratch).await;
        let app = app(&db, manager(&db));

        let create = Request::builder()
            .method("POST")
            .uri("/snapshots")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"note":"before the trip"}"#))
            .unwrap();
        let (status, body, _) = send(&app, create).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let created: SnapshotResponse = serde_json::from_slice(&body).unwrap();
        assert!(
            created.snapshot.components.is_empty(),
            "manual snapshots are never baselines"
        );
        assert_eq!(created.snapshot.kind, SnapshotKind::Manual);
        assert_eq!(created.snapshot.note.as_deref(), Some("before the trip"));
        assert!(created.snapshot.size_bytes > 0);

        let (status, body, _) = send(
            &app,
            Request::builder()
                .uri("/snapshots")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let listed: SnapshotListResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(listed.snapshots.len(), 2);

        let (status, bytes, headers) = send(
            &app,
            Request::builder()
                .uri(format!("/snapshots/{}/export", created.snapshot.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[header::CONTENT_TYPE], "application/vnd.sqlite3");
        let disposition = headers[header::CONTENT_DISPOSITION].to_str().unwrap();
        assert!(
            disposition.starts_with("attachment; filename=\"keystone-config-"),
            "{disposition}"
        );
        assert!(bytes.starts_with(b"SQLite format 3\0"));
    }

    #[tokio::test]
    async fn import_route_rejects_garbage_with_an_error_message() {
        let scratch = Scratch::new();
        let db = applied_baseline(&scratch).await;
        let app = app(&db, manager(&db));

        let (status, body, _) = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/snapshots/import")
                .body(Body::from("definitely not sqlite"))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["error"].as_str().unwrap().contains("not an SQLite"));
    }

    #[tokio::test]
    async fn restore_and_discard_are_refused_while_changes_are_locked() {
        let scratch = Scratch::new();
        let db = applied_baseline(&scratch).await;
        let app = app(&db, manager(&db));
        let mut settings = db.get_global_settings().await.unwrap();
        settings.config_changes_disabled = true;
        db.save_global_settings(&settings).await.unwrap();

        let (status, body, _) = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/changes/discard")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["error"].as_str().unwrap().contains("disabled"));
    }

    #[tokio::test]
    async fn restore_route_reports_the_components_it_restored() {
        let scratch = Scratch::new();
        let db = applied_baseline(&scratch).await;
        let baseline = snapshots::baseline_for(&db, Component::Dnsmasq, &[])
            .await
            .unwrap()
            .unwrap();
        set_dnsmasq_cache_size(&db, 5).await;
        let app = app(&db, manager(&db));

        let (status, body, _) = send(
            &app,
            Request::builder()
                .method("POST")
                .uri(format!("/snapshots/{}/restore", baseline.id))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"components":["dnsmasq"]}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let restored: RestoreSnapshotResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(restored.components, vec![Component::Dnsmasq]);
        assert!(restored.message.contains("pending until it is applied"));
        assert!(!changed(
            &pending_changes(&db, &[]).await.unwrap(),
            Component::Dnsmasq
        ));
    }
}
