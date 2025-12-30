//! Global settings API functions

use keystone_core::{
    ApplyAllResponse, GlobalSettings, GlobalSettingsResponse, SaveGlobalSettingsRequest,
    SaveGlobalSettingsResponse,
};

use super::client::{get, post, post_empty};

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
