//! Configuration changes, snapshot history and apply API functions

use keystone_core::ApplyAllResponse;
use keystone_core::api::DiscardChanges;
use keystone_core::changes::{
    Component, ComponentSelectionRequest, DiscardChangesResponse, PendingChangesResponse,
};

use super::client::{call, get, post_empty};

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
