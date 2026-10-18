//! HTTP routes for systemd unit management

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use keystone_core::{SystemdUnitControlResponse, SystemdUnitDetailResponse, SystemdUnitsResponse};
use serde::Deserialize;
use std::sync::Arc;
use tracing::{debug, info};

use crate::AppError;

async fn check_control_allowed(
    state: &Arc<crate::AppState>,
) -> Result<Option<Json<SystemdUnitControlResponse>>, AppError> {
    if state
        .db
        .get_global_settings()
        .await?
        .config_changes_disabled
    {
        return Ok(Some(Json(SystemdUnitControlResponse {
            success: false,
            message: "Configuration changes are locked".to_string(),
        })));
    }
    Ok(None)
}

/// Query parameters for listing units
#[derive(Debug, Deserialize)]
pub struct ListUnitsQuery {
    /// If true, only show keystone-related units
    #[serde(default = "default_true")]
    pub keystone_only: bool,
}

fn default_true() -> bool {
    true
}

/// GET /systemd/units - List systemd units
async fn list_units(
    Query(query): Query<ListUnitsQuery>,
) -> Result<Json<SystemdUnitsResponse>, AppError> {
    debug!(
        "Listing systemd units (keystone_only={})",
        query.keystone_only
    );

    let units = super::list_units(query.keystone_only).await?;

    Ok(Json(SystemdUnitsResponse { units }))
}

/// GET /systemd/units/:name - Get detailed unit info
async fn get_unit_detail(
    Path(name): Path<String>,
) -> Result<Json<SystemdUnitDetailResponse>, AppError> {
    debug!("Getting detail for unit: {}", name);

    let unit = super::get_unit_detail(&name).await?;

    Ok(Json(SystemdUnitDetailResponse { unit }))
}

/// POST /systemd/units/:name/start - Start a unit
async fn start_unit(
    State(state): State<Arc<crate::AppState>>,
    Path(name): Path<String>,
) -> Result<Json<SystemdUnitControlResponse>, AppError> {
    info!("Starting unit: {}", name);
    if let Some(response) = check_control_allowed(&state).await? {
        return Ok(response);
    }

    match super::start_unit(&name).await {
        Ok(()) => Ok(Json(SystemdUnitControlResponse {
            success: true,
            message: format!("Unit {} started", name),
        })),
        Err(e) => Ok(Json(SystemdUnitControlResponse {
            success: false,
            message: format!("Failed to start {}: {}", name, e),
        })),
    }
}

/// POST /systemd/units/:name/stop - Stop a unit
async fn stop_unit(
    State(state): State<Arc<crate::AppState>>,
    Path(name): Path<String>,
) -> Result<Json<SystemdUnitControlResponse>, AppError> {
    info!("Stopping unit: {}", name);
    if let Some(response) = check_control_allowed(&state).await? {
        return Ok(response);
    }

    match super::stop_unit(&name).await {
        Ok(()) => Ok(Json(SystemdUnitControlResponse {
            success: true,
            message: format!("Unit {} stopped", name),
        })),
        Err(e) => Ok(Json(SystemdUnitControlResponse {
            success: false,
            message: format!("Failed to stop {}: {}", name, e),
        })),
    }
}

/// POST /systemd/units/:name/restart - Restart a unit
async fn restart_unit(
    State(state): State<Arc<crate::AppState>>,
    Path(name): Path<String>,
) -> Result<Json<SystemdUnitControlResponse>, AppError> {
    info!("Restarting unit: {}", name);
    if let Some(response) = check_control_allowed(&state).await? {
        return Ok(response);
    }

    match super::restart_unit(&name).await {
        Ok(()) => Ok(Json(SystemdUnitControlResponse {
            success: true,
            message: format!("Unit {} restarted", name),
        })),
        Err(e) => Ok(Json(SystemdUnitControlResponse {
            success: false,
            message: format!("Failed to restart {}: {}", name, e),
        })),
    }
}

/// POST /systemd/units/:name/enable - Enable a unit (start on boot)
async fn enable_unit(
    State(state): State<Arc<crate::AppState>>,
    Path(name): Path<String>,
) -> Result<Json<SystemdUnitControlResponse>, AppError> {
    info!("Enabling unit: {}", name);
    if let Some(response) = check_control_allowed(&state).await? {
        return Ok(response);
    }

    match super::enable_unit(&name).await {
        Ok(()) => Ok(Json(SystemdUnitControlResponse {
            success: true,
            message: format!("Unit {} enabled", name),
        })),
        Err(e) => Ok(Json(SystemdUnitControlResponse {
            success: false,
            message: format!("Failed to enable {}: {}", name, e),
        })),
    }
}

/// POST /systemd/units/:name/disable - Disable a unit (don't start on boot)
async fn disable_unit(
    State(state): State<Arc<crate::AppState>>,
    Path(name): Path<String>,
) -> Result<Json<SystemdUnitControlResponse>, AppError> {
    info!("Disabling unit: {}", name);
    if let Some(response) = check_control_allowed(&state).await? {
        return Ok(response);
    }

    match super::disable_unit(&name).await {
        Ok(()) => Ok(Json(SystemdUnitControlResponse {
            success: true,
            message: format!("Unit {} disabled", name),
        })),
        Err(e) => Ok(Json(SystemdUnitControlResponse {
            success: false,
            message: format!("Failed to disable {}: {}", name, e),
        })),
    }
}

/// Create the router for systemd routes
pub fn systemd_routes() -> Router<Arc<crate::AppState>> {
    Router::new()
        .route("/systemd/units", get(list_units))
        .route("/systemd/units/{name}", get(get_unit_detail))
        .route("/systemd/units/{name}/start", post(start_unit))
        .route("/systemd/units/{name}/stop", post(stop_unit))
        .route("/systemd/units/{name}/restart", post(restart_unit))
        .route("/systemd/units/{name}/enable", post(enable_unit))
        .route("/systemd/units/{name}/disable", post(disable_unit))
}
