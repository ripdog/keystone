//! Caddy API routes
//!
//! REST endpoints for managing Caddy reverse proxy configuration:
//! - Global configuration
//! - Preview/Validate
//! - Apply

use crate::caddy::{self};
use crate::db::Database;
use axum::{
    Json, Router,
    extract::State,
    routing::{get, post, put},
};
use keystone_core::api::{Endpoint, Req, Res, SaveCaddyConfig};
use keystone_core::{
    CaddyApplyResponse, CaddyConfig, CaddyPreviewResponse, CaddyStateResponse,
    CaddyValidateResponse, SaveCaddyConfigResponse,
};
use std::sync::Arc;
use tracing::info;

use crate::AppError;

/// State shared with Caddy routes
#[derive(Clone)]
pub struct CaddyState {
    pub db: Database,
}

/// Create Caddy router with all routes
pub fn caddy_routes(state: CaddyState) -> Router<Arc<crate::AppState>> {
    Router::new()
        // State and config
        .route("/caddy", get(get_caddy_state))
        .route("/caddy/config", get(get_config))
        .route(SaveCaddyConfig::PATH, put(save_config))
        // Preview, validate, and apply
        .route("/caddy/preview", get(preview_caddy))
        .route("/caddy/validate", post(validate_caddy))
        .route("/caddy/apply", post(apply_caddy))
        .route("/caddy/status", get(get_caddy_status))
        .with_state(state)
}

// ============================================================================
// State & Config
// ============================================================================

/// GET /caddy - Get complete Caddy state including available interfaces
async fn get_caddy_state(
    State(state): State<CaddyState>,
) -> Result<Json<CaddyStateResponse>, AppError> {
    info!("Getting Caddy state");
    let pool = state.db.pool();
    let config = caddy::load_caddy_config(pool).await?;
    let available_interfaces = state
        .db
        .get_interface_configs()
        .await?
        .into_iter()
        .filter(|iface| iface.enabled && iface.role == keystone_core::InterfaceRole::LAN)
        .map(|iface| iface.name)
        .collect();

    Ok(Json(CaddyStateResponse {
        config,
        available_interfaces,
    }))
}

/// GET /caddy/config - Get Caddy configuration
async fn get_config(State(state): State<CaddyState>) -> Result<Json<CaddyConfig>, AppError> {
    info!("Getting Caddy config");
    let pool = state.db.pool();
    let config = caddy::load_caddy_config(pool).await?;
    Ok(Json(config))
}

/// PUT /caddy/config - Save Caddy configuration
async fn save_config(
    State(state): State<CaddyState>,
    Json(request): Json<Req<SaveCaddyConfig>>,
) -> Result<Json<Res<SaveCaddyConfig>>, AppError> {
    info!("Saving Caddy config");

    // Validate required fields if enabled
    if request.config.enabled && request.config.server_address.is_empty() {
        return Ok(Json(SaveCaddyConfigResponse {
            success: false,
            message: "Server address is required when Caddy is enabled".to_string(),
        }));
    }

    let pool = state.db.pool();
    caddy::save_caddy_config(pool, &request.config).await?;

    Ok(Json(SaveCaddyConfigResponse {
        success: true,
        message: "Configuration saved".to_string(),
    }))
}

// ============================================================================
// Preview, Validate & Apply
// ============================================================================

/// GET /caddy/preview - Preview generated Caddyfile
async fn preview_caddy(
    State(state): State<CaddyState>,
) -> Result<Json<CaddyPreviewResponse>, AppError> {
    info!("Generating Caddyfile preview");
    let pool = state.db.pool();
    let caddyfile = caddy::preview_caddyfile(pool).await?;
    Ok(Json(CaddyPreviewResponse { caddyfile }))
}

/// POST /caddy/validate - Validate current configuration
async fn validate_caddy(
    State(state): State<CaddyState>,
) -> Result<Json<CaddyValidateResponse>, AppError> {
    info!("Validating Caddy configuration");
    let pool = state.db.pool();

    match caddy::validate_caddy_config(pool).await {
        Ok((valid, output)) => Ok(Json(CaddyValidateResponse {
            valid,
            message: if valid {
                "Configuration is valid".to_string()
            } else {
                "Validation failed".to_string()
            },
            output,
        })),
        Err(e) => Ok(Json(CaddyValidateResponse {
            valid: false,
            message: format!("Validation error: {e:#}"),
            output: String::new(),
        })),
    }
}

/// POST /caddy/apply - Apply Caddy configuration
async fn apply_caddy(
    State(state): State<CaddyState>,
) -> Result<Json<CaddyApplyResponse>, AppError> {
    info!("Applying Caddy configuration");

    // Check if configuration changes are disabled
    let global_settings = state.db.get_global_settings().await?;
    if global_settings.config_changes_disabled {
        return Ok(Json(CaddyApplyResponse {
            success: false,
            message: "Configuration changes are disabled. Unlock in Settings to apply changes."
                .to_string(),
        }));
    }

    let pool = state.db.pool();

    match caddy::apply_caddy_config(pool).await {
        Ok(()) => Ok(Json(CaddyApplyResponse {
            success: true,
            message: "Caddy configuration applied successfully".to_string(),
        })),
        Err(e) => Ok(Json(CaddyApplyResponse {
            success: false,
            message: format!("Failed to apply Caddy configuration: {e:#}"),
        })),
    }
}

/// GET /caddy/status - Get Caddy service status
async fn get_caddy_status(
    State(_state): State<CaddyState>,
) -> Result<Json<caddy::CaddyServiceStatus>, AppError> {
    info!("Getting Caddy status");
    let status = caddy::get_caddy_status();
    Ok(Json(status))
}
