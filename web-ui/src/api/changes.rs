//! Configuration changes, snapshot history and apply API functions

use keystone_core::ApplyAllResponse;
use keystone_core::api::{CreateSnapshot, DiscardChanges, RestoreSnapshot};
use keystone_core::changes::{
    Component, ComponentSelectionRequest, CreateSnapshotRequest, DiscardChangesResponse,
    PendingChangesResponse, RestoreSnapshotResponse, SnapshotListResponse, SnapshotResponse,
    SnapshotSummary,
};

use super::client::{call, call_with, get, get_bytes, post_empty, post_raw};

/// Generated configuration that differs from the last applied state
pub async fn fetch_pending_changes(token: &str) -> Result<PendingChangesResponse, String> {
    get("/api/changes/pending", token).await
}

/// Apply every component that has pending changes, in one request
pub async fn apply_all(token: &str) -> Result<ApplyAllResponse, String> {
    post_empty("/api/apply-all", token).await
}

/// Revert the given components (or every changed component when `None`) to
/// their last applied state
pub async fn discard_changes(
    token: &str,
    components: Option<Vec<Component>>,
) -> Result<DiscardChangesResponse, String> {
    call::<DiscardChanges>(token, &ComponentSelectionRequest { components }).await
}

/// Fetch the snapshot history, newest first as the daemon returns it
pub async fn fetch_snapshots(token: &str) -> Result<Vec<SnapshotSummary>, String> {
    let response: SnapshotListResponse = get("/api/snapshots", token).await?;
    Ok(response.snapshots)
}

/// Save the current configuration as a manual snapshot
pub async fn create_snapshot(
    token: &str,
    note: Option<String>,
) -> Result<SnapshotResponse, String> {
    call::<CreateSnapshot>(token, &CreateSnapshotRequest { note }).await
}

/// Compare a snapshot with the live configuration. The live side is the old
/// side and the snapshot the new side, so the diff shows what a restore changes.
pub async fn fetch_snapshot_diff(token: &str, id: i64) -> Result<PendingChangesResponse, String> {
    get(&format!("/api/snapshots/{id}/diff"), token).await
}

/// Copy a snapshot into the live configuration for the given components (all
/// components when `None`). The result is pending until it is applied.
pub async fn restore_snapshot(
    token: &str,
    id: i64,
    components: Option<Vec<Component>>,
) -> Result<RestoreSnapshotResponse, String> {
    call_with::<RestoreSnapshot>(
        token,
        &[("id", &id.to_string())],
        &ComponentSelectionRequest { components },
    )
    .await
}

/// Download a snapshot's database file
pub async fn export_snapshot(token: &str, id: i64) -> Result<Vec<u8>, String> {
    get_bytes(&format!("/api/snapshots/{id}/export"), token).await
}

/// Upload a snapshot database file previously exported from Keystone
pub async fn import_snapshot(token: &str, file: web_sys::File) -> Result<SnapshotResponse, String> {
    post_raw("/api/snapshots/import", token, file).await
}
