//! Network diagnostics (ping, traceroute, DNS lookup, TCP check).
use crate::api::client;
use keystone_core::api::{StartDiagnostic, StopDiagnostic};
use keystone_core::diagnostics::{
    DiagnosticNoRequest, DiagnosticProgress, DiagnosticRequest, DiagnosticStarted,
};

/// Start a diagnostic; its output is read with [`fetch_diagnostic`].
pub async fn start_diagnostic(
    token: &str,
    request: &DiagnosticRequest,
) -> Result<DiagnosticStarted, String> {
    client::call::<StartDiagnostic>(token, request).await
}

/// Output of diagnostic `id` from byte offset `after` on.
pub async fn fetch_diagnostic(
    token: &str,
    id: &str,
    after: u64,
) -> Result<DiagnosticProgress, String> {
    client::get(&format!("/api/diagnostics/jobs/{id}?after={after}"), token).await
}

/// End a running diagnostic early.
pub async fn stop_diagnostic(token: &str, id: &str) -> Result<DiagnosticProgress, String> {
    client::call_with::<StopDiagnostic>(token, &[("id", id)], &DiagnosticNoRequest {}).await
}
