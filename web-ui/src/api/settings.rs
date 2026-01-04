//! Global settings API functions

use keystone_core::{
    ApplyAllResponse, CompleteSetupResponse, GlobalSettings, GlobalSettingsResponse,
    SaveGlobalSettingsRequest, SaveGlobalSettingsResponse, SystemStatusResponse,
};

use super::client::{get, get_public, post, post_empty};

/// Fetch global settings from the API
pub async fn fetch_global_settings(token: &str) -> Result<GlobalSettings, String> {
    let response: GlobalSettingsResponse = get("/api/settings", token).await?;
    Ok(response.settings)
}

/// Save global settings
pub async fn save_global_settings(
    token: &str,
    settings: GlobalSettings,
) -> Result<SaveGlobalSettingsResponse, String> {
    let request = SaveGlobalSettingsRequest { settings };
    post("/api/settings", token, &request).await
}

// ============================================================================
// System Status
// ============================================================================

/// Fetch system status checks (public endpoint - no auth required)
pub async fn fetch_system_status() -> Result<SystemStatusResponse, String> {
    get_public("/api/system-status").await
}

/// Complete initial setup (requires all checks to pass)
pub async fn complete_setup(token: &str) -> Result<CompleteSetupResponse, String> {
    post_empty("/api/complete-setup", token).await
}

// ============================================================================
// Unified Apply
// ============================================================================

/// Apply all configuration (networkd, firewall, dnsmasq, caddy)
///
/// This applies all pending configuration changes at once. If firewall changes
/// are included, the response will indicate that confirmation is needed within
/// the timeout period, otherwise the firewall changes will automatically roll back.
pub async fn apply_all_config(token: &str) -> Result<ApplyAllResponse, String> {
    post_empty("/api/apply-all", token).await
}
