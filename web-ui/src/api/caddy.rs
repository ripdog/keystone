//! Caddy reverse proxy configuration API functions

use keystone_core::api::SaveCaddyConfig;
use keystone_core::{
    CaddyApplyResponse, CaddyConfig, CaddyPreviewResponse, CaddyStateResponse,
    CaddyValidateResponse, SaveCaddyConfigRequest,
};

use super::client::{call, get, post_empty};

// ============================================================================
// State
// ============================================================================

/// Fetch complete Caddy state including available interfaces
pub async fn fetch_caddy_state(token: &str) -> Result<CaddyStateResponse, String> {
    get("/api/caddy", token).await
}

// ============================================================================
// Config
// ============================================================================

/// Save Caddy configuration
pub async fn save_caddy_config(token: &str, config: CaddyConfig) -> Result<(), String> {
    let response = call::<SaveCaddyConfig>(token, &SaveCaddyConfigRequest { config }).await?;
    if response.success {
        Ok(())
    } else {
        Err(response.message)
    }
}

// ============================================================================
// Preview, Validate & Apply
// ============================================================================

/// Fetch generated Caddyfile preview
pub async fn fetch_caddy_preview(token: &str) -> Result<String, String> {
    let response: CaddyPreviewResponse = get("/api/caddy/preview", token).await?;
    Ok(response.caddyfile)
}

/// Validate Caddy configuration
pub async fn validate_caddy(token: &str) -> Result<CaddyValidateResponse, String> {
    post_empty("/api/caddy/validate", token).await
}

/// Apply Caddy configuration
pub async fn apply_caddy(token: &str) -> Result<CaddyApplyResponse, String> {
    post_empty("/api/caddy/apply", token).await
}

/// Caddy service status
#[derive(Debug, Clone, serde::Deserialize)]
pub struct CaddyServiceStatus {
    pub running: bool,
    pub enabled: bool,
    pub config_exists: bool,
}

/// Fetch Caddy service status
pub async fn fetch_caddy_status(token: &str) -> Result<CaddyServiceStatus, String> {
    get("/api/caddy/status", token).await
}
