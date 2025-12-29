//! Firewall API routes
//!
//! REST endpoints for managing firewall configuration:
//! - Zones (CRUD)
//! - Zone-to-zone forwarding policies
//! - Input rules (traffic to router)
//! - Forward rules (traffic through router)
//! - Port forwards (DNAT)
//! - Apply/Confirm/Rollback workflow
//! - Preview generated nftables rules

use crate::db::Database;
use crate::firewall::{generate_json, generate_preview, FirewallApplyManager};
use axum::{
    extract::{Path, State},
    routing::{delete, get, post},
    Json, Router,
};
use keystone_core::{
    DeleteResponse, FirewallApplyResponse, FirewallConfirmRequest, FirewallConfirmResponse,
    FirewallConfigResponse, FirewallPreviewResponse, FirewallRollbackResponse,
    FirewallStatusResponse, FirewallZone, FirewallZonesResponse, ForwardRule, InputRule,
    PortForward, ReorderRulesRequest, ReorderRulesResponse, ZoneForwardPolicy,
};
use std::sync::Arc;
use tracing::info;

use crate::AppError;

/// State shared with firewall routes
#[derive(Clone)]
pub struct FirewallState {
    pub db: Database,
    pub apply_manager: Arc<FirewallApplyManager>,
}

/// Create firewall router with all routes
pub fn firewall_routes(state: FirewallState) -> Router<Arc<crate::AppState>> {
    Router::new()
        // Zones
        .route("/firewall/zones", get(get_zones))
        .route("/firewall/zones/{id}", get(get_zone))
        .route("/firewall/zones", post(save_zone))
        .route("/firewall/zones/{id}", delete(delete_zone))
        // Zone forwards
        .route("/firewall/zone-forwards", get(get_zone_forwards))
        .route("/firewall/zone-forwards", post(save_zone_forward))
        .route("/firewall/zone-forwards/{id}", delete(delete_zone_forward))
        // Input rules
        .route("/firewall/input-rules", get(get_input_rules))
        .route("/firewall/input-rules", post(save_input_rule))
        .route("/firewall/input-rules/{id}", delete(delete_input_rule))
        .route("/firewall/input-rules/reorder", post(reorder_input_rules))
        // Forward rules
        .route("/firewall/forward-rules", get(get_forward_rules))
        .route("/firewall/forward-rules", post(save_forward_rule))
        .route("/firewall/forward-rules/{id}", delete(delete_forward_rule))
        .route(
            "/firewall/forward-rules/reorder",
            post(reorder_forward_rules),
        )
        // Port forwards
        .route("/firewall/port-forwards", get(get_port_forwards))
        .route("/firewall/port-forwards", post(save_port_forward))
        .route("/firewall/port-forwards/{id}", delete(delete_port_forward))
        // Config overview
        .route("/firewall/config", get(get_firewall_config))
        // Preview and Apply
        .route("/firewall/preview", get(preview_firewall))
        .route("/firewall/preview/json", get(preview_firewall_json))
        .route("/firewall/apply", post(apply_firewall))
        .route("/firewall/confirm", post(confirm_firewall))
        .route("/firewall/rollback", post(rollback_firewall))
        .route("/firewall/status", get(firewall_status))
        .with_state(state)
}

// ============================================================================
// Zone Endpoints
// ============================================================================

/// GET /firewall/zones - Get all firewall zones
async fn get_zones(State(state): State<FirewallState>) -> Result<Json<FirewallZonesResponse>, AppError> {
    info!("Getting firewall zones");
    let zones = state.db.get_firewall_zones().await?;
    Ok(Json(FirewallZonesResponse { zones }))
}

/// GET /firewall/zones/:id - Get a single zone
async fn get_zone(
    State(state): State<FirewallState>,
    Path(id): Path<i64>,
) -> Result<Json<Option<FirewallZone>>, AppError> {
    info!("Getting firewall zone id: {}", id);
    let zone = state.db.get_firewall_zone(id).await?;
    Ok(Json(zone))
}

/// POST /firewall/zones - Create or update a zone
async fn save_zone(
    State(state): State<FirewallState>,
    Json(zone): Json<FirewallZone>,
) -> Result<Json<SaveResponse>, AppError> {
    info!("Saving firewall zone: {}", zone.name);

    // Validate zone name
    if zone.name.is_empty() {
        return Ok(Json(SaveResponse {
            success: false,
            message: "Zone name is required".to_string(),
            id: None,
        }));
    }

    // Reserved zone names
    if zone.name == "any" || zone.name == "local" {
        return Ok(Json(SaveResponse {
            success: false,
            message: format!("Zone name '{}' is reserved", zone.name),
            id: None,
        }));
    }

    let id = state.db.save_firewall_zone(&zone).await?;
    Ok(Json(SaveResponse {
        success: true,
        message: "Zone saved".to_string(),
        id: Some(id),
    }))
}

/// DELETE /firewall/zones/:id - Delete a zone
async fn delete_zone(
    State(state): State<FirewallState>,
    Path(id): Path<i64>,
) -> Result<Json<DeleteResponse>, AppError> {
    info!("Deleting firewall zone id: {}", id);
    let deleted = state.db.delete_firewall_zone(id).await?;
    Ok(Json(DeleteResponse {
        success: deleted,
        message: if deleted {
            "Zone deleted".to_string()
        } else {
            "Zone not found".to_string()
        },
    }))
}

// ============================================================================
// Zone Forward Endpoints
// ============================================================================

/// GET /firewall/zone-forwards - Get all zone-to-zone forward policies
async fn get_zone_forwards(
    State(state): State<FirewallState>,
) -> Result<Json<Vec<ZoneForwardPolicy>>, AppError> {
    info!("Getting zone forwards");
    let forwards = state.db.get_zone_forwards().await?;
    Ok(Json(forwards))
}

/// POST /firewall/zone-forwards - Create or update a zone forward policy
async fn save_zone_forward(
    State(state): State<FirewallState>,
    Json(forward): Json<ZoneForwardPolicy>,
) -> Result<Json<SaveResponse>, AppError> {
    info!(
        "Saving zone forward: {} -> {}",
        forward.source_zone, forward.dest_zone
    );

    let id = state.db.save_zone_forward(&forward).await?;
    Ok(Json(SaveResponse {
        success: true,
        message: "Zone forward saved".to_string(),
        id: Some(id),
    }))
}

/// DELETE /firewall/zone-forwards/:id - Delete a zone forward policy
async fn delete_zone_forward(
    State(state): State<FirewallState>,
    Path(id): Path<i64>,
) -> Result<Json<DeleteResponse>, AppError> {
    info!("Deleting zone forward id: {}", id);
    let deleted = state.db.delete_zone_forward(id).await?;
    Ok(Json(DeleteResponse {
        success: deleted,
        message: if deleted {
            "Zone forward deleted".to_string()
        } else {
            "Zone forward not found".to_string()
        },
    }))
}

// ============================================================================
// Input Rule Endpoints
// ============================================================================

/// GET /firewall/input-rules - Get all input rules
async fn get_input_rules(State(state): State<FirewallState>) -> Result<Json<Vec<InputRule>>, AppError> {
    info!("Getting input rules");
    let rules = state.db.get_input_rules().await?;
    Ok(Json(rules))
}

/// POST /firewall/input-rules - Create or update an input rule
async fn save_input_rule(
    State(state): State<FirewallState>,
    Json(rule): Json<InputRule>,
) -> Result<Json<SaveResponse>, AppError> {
    info!("Saving input rule: {}", rule.name);

    if rule.name.is_empty() {
        return Ok(Json(SaveResponse {
            success: false,
            message: "Rule name is required".to_string(),
            id: None,
        }));
    }

    let id = state.db.save_input_rule(&rule).await?;
    Ok(Json(SaveResponse {
        success: true,
        message: "Input rule saved".to_string(),
        id: Some(id),
    }))
}

/// DELETE /firewall/input-rules/:id - Delete an input rule
async fn delete_input_rule(
    State(state): State<FirewallState>,
    Path(id): Path<i64>,
) -> Result<Json<DeleteResponse>, AppError> {
    info!("Deleting input rule id: {}", id);
    let deleted = state.db.delete_input_rule(id).await?;
    Ok(Json(DeleteResponse {
        success: deleted,
        message: if deleted {
            "Input rule deleted".to_string()
        } else {
            "Input rule not found".to_string()
        },
    }))
}

/// POST /firewall/input-rules/reorder - Reorder input rules
async fn reorder_input_rules(
    State(state): State<FirewallState>,
    Json(request): Json<ReorderRulesRequest>,
) -> Result<Json<ReorderRulesResponse>, AppError> {
    info!("Reordering {} input rules", request.rule_ids.len());

    // Update positions based on array order
    for (position, id) in request.rule_ids.iter().enumerate() {
        // Fetch, update position, save
        if let Some(mut rule) = state.db.get_input_rule(*id).await? {
            rule.position = position as i32;
            state.db.save_input_rule(&rule).await?;
        }
    }

    Ok(Json(ReorderRulesResponse {
        success: true,
        message: "Input rules reordered".to_string(),
    }))
}

// ============================================================================
// Forward Rule Endpoints
// ============================================================================

/// GET /firewall/forward-rules - Get all forward rules
async fn get_forward_rules(
    State(state): State<FirewallState>,
) -> Result<Json<Vec<ForwardRule>>, AppError> {
    info!("Getting forward rules");
    let rules = state.db.get_forward_rules().await?;
    Ok(Json(rules))
}

/// POST /firewall/forward-rules - Create or update a forward rule
async fn save_forward_rule(
    State(state): State<FirewallState>,
    Json(rule): Json<ForwardRule>,
) -> Result<Json<SaveResponse>, AppError> {
    info!("Saving forward rule: {}", rule.name);

    if rule.name.is_empty() {
        return Ok(Json(SaveResponse {
            success: false,
            message: "Rule name is required".to_string(),
            id: None,
        }));
    }

    let id = state.db.save_forward_rule(&rule).await?;
    Ok(Json(SaveResponse {
        success: true,
        message: "Forward rule saved".to_string(),
        id: Some(id),
    }))
}

/// DELETE /firewall/forward-rules/:id - Delete a forward rule
async fn delete_forward_rule(
    State(state): State<FirewallState>,
    Path(id): Path<i64>,
) -> Result<Json<DeleteResponse>, AppError> {
    info!("Deleting forward rule id: {}", id);
    let deleted = state.db.delete_forward_rule(id).await?;
    Ok(Json(DeleteResponse {
        success: deleted,
        message: if deleted {
            "Forward rule deleted".to_string()
        } else {
            "Forward rule not found".to_string()
        },
    }))
}

/// POST /firewall/forward-rules/reorder - Reorder forward rules
async fn reorder_forward_rules(
    State(state): State<FirewallState>,
    Json(request): Json<ReorderRulesRequest>,
) -> Result<Json<ReorderRulesResponse>, AppError> {
    info!("Reordering {} forward rules", request.rule_ids.len());

    for (position, id) in request.rule_ids.iter().enumerate() {
        if let Some(mut rule) = state.db.get_forward_rule(*id).await? {
            rule.position = position as i32;
            state.db.save_forward_rule(&rule).await?;
        }
    }

    Ok(Json(ReorderRulesResponse {
        success: true,
        message: "Forward rules reordered".to_string(),
    }))
}

// ============================================================================
// Port Forward Endpoints
// ============================================================================

/// GET /firewall/port-forwards - Get all port forwards
async fn get_port_forwards(
    State(state): State<FirewallState>,
) -> Result<Json<Vec<PortForward>>, AppError> {
    info!("Getting port forwards");
    let pfs = state.db.get_port_forwards().await?;
    Ok(Json(pfs))
}

/// POST /firewall/port-forwards - Create or update a port forward
async fn save_port_forward(
    State(state): State<FirewallState>,
    Json(pf): Json<PortForward>,
) -> Result<Json<SaveResponse>, AppError> {
    info!("Saving port forward: {}", pf.name);

    if pf.name.is_empty() {
        return Ok(Json(SaveResponse {
            success: false,
            message: "Port forward name is required".to_string(),
            id: None,
        }));
    }

    if pf.dest_ip.is_empty() {
        return Ok(Json(SaveResponse {
            success: false,
            message: "Destination IP is required".to_string(),
            id: None,
        }));
    }

    let id = state.db.save_port_forward(&pf).await?;
    Ok(Json(SaveResponse {
        success: true,
        message: "Port forward saved".to_string(),
        id: Some(id),
    }))
}

/// DELETE /firewall/port-forwards/:id - Delete a port forward
async fn delete_port_forward(
    State(state): State<FirewallState>,
    Path(id): Path<i64>,
) -> Result<Json<DeleteResponse>, AppError> {
    info!("Deleting port forward id: {}", id);
    let deleted = state.db.delete_port_forward(id).await?;
    Ok(Json(DeleteResponse {
        success: deleted,
        message: if deleted {
            "Port forward deleted".to_string()
        } else {
            "Port forward not found".to_string()
        },
    }))
}

// ============================================================================
// Config & Preview Endpoints
// ============================================================================

/// GET /firewall/config - Get complete firewall config
async fn get_firewall_config(
    State(state): State<FirewallState>,
) -> Result<Json<FirewallConfigResponse>, AppError> {
    info!("Getting firewall config");
    let config = state.db.get_firewall_config().await?;
    Ok(Json(FirewallConfigResponse { config }))
}

/// GET /firewall/preview - Preview generated nftables rules (human-readable)
async fn preview_firewall(
    State(state): State<FirewallState>,
) -> Result<Json<FirewallPreviewResponse>, AppError> {
    info!("Generating firewall preview");
    let ruleset = generate_preview(&state.db).await?;
    Ok(Json(FirewallPreviewResponse { ruleset }))
}

/// GET /firewall/preview/json - Preview generated nftables rules (raw JSON)
async fn preview_firewall_json(State(state): State<FirewallState>) -> Result<String, AppError> {
    info!("Generating firewall JSON preview");
    let json = generate_json(&state.db).await?;
    Ok(json)
}

// ============================================================================
// Apply/Confirm/Rollback Endpoints
// ============================================================================

/// POST /firewall/apply - Apply firewall configuration
async fn apply_firewall(
    State(state): State<FirewallState>,
) -> Result<Json<FirewallApplyResponse>, AppError> {
    info!("Applying firewall configuration");
    let response = state.apply_manager.apply(None).await?;
    Ok(Json(response))
}

/// POST /firewall/confirm - Confirm pending firewall changes
async fn confirm_firewall(
    State(state): State<FirewallState>,
    Json(request): Json<FirewallConfirmRequest>,
) -> Result<Json<FirewallConfirmResponse>, AppError> {
    info!("Confirming firewall changes");
    let response = state.apply_manager.confirm(&request.session_id).await?;
    Ok(Json(response))
}

/// POST /firewall/rollback - Force rollback of pending changes
async fn rollback_firewall(
    State(state): State<FirewallState>,
) -> Result<Json<FirewallRollbackResponse>, AppError> {
    info!("Rolling back firewall changes");
    let response = state.apply_manager.rollback().await?;
    Ok(Json(response))
}

/// GET /firewall/status - Get status of pending apply
async fn firewall_status(
    State(state): State<FirewallState>,
) -> Result<Json<FirewallStatusResponse>, AppError> {
    let status = state.apply_manager.status().await;
    Ok(Json(status))
}

// ============================================================================
// Helper Types
// ============================================================================

/// Generic save response
#[derive(serde::Serialize)]
struct SaveResponse {
    success: bool,
    message: String,
    id: Option<i64>,
}
