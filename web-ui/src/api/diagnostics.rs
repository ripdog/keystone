//! Network diagnostics (ping, traceroute, DNS lookup, TCP check).
use crate::api::client;
use keystone_core::api::RunDiagnostic;
use keystone_core::diagnostics::{DiagnosticRequest, DiagnosticResponse};

pub async fn run_diagnostic(
    token: &str,
    request: &DiagnosticRequest,
) -> Result<DiagnosticResponse, String> {
    client::call::<RunDiagnostic>(token, request).await
}
