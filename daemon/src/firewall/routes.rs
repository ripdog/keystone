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

use crate::Actor;
use crate::db::Database;
use crate::firewall::groups::{
    GroupIndex, validate_address_group, validate_group_names, validate_port_group,
};
use crate::firewall::validate::{
    validate_forward_rule, validate_input_rule, validate_port_forward, validate_zone,
    validate_zone_forward,
};
use crate::firewall::{FirewallApplyManager, generate_json, generate_preview};
use crate::snapshots::{self, Component};
use axum::{
    Json, Router,
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post, put},
};
use keystone_core::api::{
    ConfirmFirewall, CreateSimpleForward, Endpoint, ReorderForwardRules, ReorderInputRules, Req,
    Res, SaveAddressGroup, SaveFirewallGlobalSettings, SaveFirewallZone, SaveForwardRule,
    SaveInputRule, SavePortForward, SavePortGroup, SaveZoneForward, TestFirewallPacket,
    UpdateSimpleForward,
};
use keystone_core::{
    AddressGroup, AddressGroupsResponse, DeleteResponse, FirewallApplyResponse,
    FirewallConfigResponse, FirewallCountersResponse, FirewallGlobalSettingsResponse,
    FirewallPreviewResponse, FirewallRollbackResponse, FirewallStatusResponse, FirewallZone,
    FirewallZonesResponse, ForwardRulesResponse, InputRulesResponse, PortForwardsResponse,
    PortGroup, PortGroupsResponse, ReorderRulesResponse, SaveAddressGroupResponse,
    SaveFirewallGlobalSettingsResponse, SaveFirewallZoneResponse, SaveForwardRuleResponse,
    SaveInputRuleResponse, SavePortForwardResponse, SavePortGroupResponse, SaveZoneForwardResponse,
    ZoneForwardsResponse,
};
use serde::Deserialize;
use serde_json::json;
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
        .route(SaveFirewallZone::PATH, post(save_zone))
        .route("/firewall/zones/{id}", delete(delete_zone))
        // Zone forwards
        .route("/firewall/zone-forwards", get(get_zone_forwards))
        .route(SaveZoneForward::PATH, post(save_zone_forward))
        .route("/firewall/zone-forwards/{id}", delete(delete_zone_forward))
        // Input rules
        .route("/firewall/input-rules", get(get_input_rules))
        .route(SaveInputRule::PATH, post(save_input_rule))
        .route("/firewall/input-rules/{id}", delete(delete_input_rule))
        .route(ReorderInputRules::PATH, post(reorder_input_rules))
        // Forward rules
        .route("/firewall/forward-rules", get(get_forward_rules))
        .route(SaveForwardRule::PATH, post(save_forward_rule))
        .route("/firewall/forward-rules/{id}", delete(delete_forward_rule))
        .route(ReorderForwardRules::PATH, post(reorder_forward_rules))
        // Convenience WAN forwards, derived from regular forward/NAT rules
        .route("/firewall/simple-forwards", get(super::simple::list))
        .route(CreateSimpleForward::PATH, post(super::simple::create))
        .route(
            "/firewall/simple-forwards/{id}",
            delete(super::simple::remove),
        )
        .route(UpdateSimpleForward::PATH, put(super::simple::update))
        .route("/firewall/lan-devices", get(super::simple::devices))
        // Legacy DNAT-only endpoints (advanced clients)
        .route("/firewall/port-forwards", get(get_port_forwards))
        .route(SavePortForward::PATH, post(save_port_forward))
        .route("/firewall/port-forwards/{id}", delete(delete_port_forward))
        // Global settings
        .route("/firewall/settings", get(get_global_settings))
        .route(SaveFirewallGlobalSettings::PATH, post(save_global_settings))
        // Address and port groups
        .route("/firewall/address-groups", get(get_address_groups))
        .route(SaveAddressGroup::PATH, post(save_address_group))
        .route(
            "/firewall/address-groups/{id}",
            delete(delete_address_group),
        )
        .route("/firewall/port-groups", get(get_port_groups))
        .route(SavePortGroup::PATH, post(save_port_group))
        .route("/firewall/port-groups/{id}", delete(delete_port_group))
        // Config overview
        .route("/firewall/config", get(get_firewall_config))
        // Hit counters for user rules
        .route("/firewall/counters", get(get_rule_counters))
        // Trace one packet through the saved (or applied) configuration
        .route(TestFirewallPacket::PATH, post(test_firewall_packet))
        // Preview and Apply
        .route("/firewall/preview", get(preview_firewall))
        .route("/firewall/preview/json", get(preview_firewall_json))
        .route("/firewall/apply", post(apply_firewall))
        .route(ConfirmFirewall::PATH, post(confirm_firewall))
        .route("/firewall/rollback", post(rollback_firewall))
        .route("/firewall/status", get(firewall_status))
        .with_state(state)
}

// ============================================================================
// Group Endpoints
// ============================================================================

/// Groups as stored, owned here so that a [`GroupIndex`] can borrow them.
struct StoredGroups {
    address: Vec<AddressGroup>,
    port: Vec<PortGroup>,
}

impl StoredGroups {
    async fn load(db: &Database) -> Result<Self, AppError> {
        Ok(Self {
            address: db.get_address_groups().await?,
            port: db.get_port_groups().await?,
        })
    }

    fn index(&self) -> GroupIndex<'_> {
        GroupIndex::new(&self.address, &self.port)
    }
}

/// Trim entries and descriptions from the form and drop blank entry lines.
fn tidy_group(entries: Vec<String>, description: Option<String>) -> (Vec<String>, Option<String>) {
    let entries = entries
        .into_iter()
        .map(|entry| entry.trim().to_string())
        .filter(|entry| !entry.is_empty())
        .collect();
    let description = description
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty());
    (entries, description)
}

/// GET /firewall/address-groups - Get all address groups
async fn get_address_groups(
    State(state): State<FirewallState>,
) -> Result<Json<AddressGroupsResponse>, AppError> {
    info!("Getting address groups");
    let groups = state.db.get_address_groups().await?;
    Ok(Json(AddressGroupsResponse { groups }))
}

/// POST /firewall/address-groups - Create or update an address group
async fn save_address_group(
    State(state): State<FirewallState>,
    Json(request): Json<Req<SaveAddressGroup>>,
) -> Result<Json<Res<SaveAddressGroup>>, AppError> {
    let mut group = request.group;
    info!("Saving address group: {}", group.name);
    (group.entries, group.description) = tidy_group(group.entries, group.description);

    let stored = StoredGroups::load(&state.db).await?;
    let mut errors = validate_address_group(&group);
    // The group's own stored row may keep its name; any other row may not.
    let mut addresses: Vec<AddressGroup> = stored
        .address
        .into_iter()
        .filter(|other| other.id != group.id)
        .collect();
    addresses.push(group.clone());
    errors.extend(validate_group_names(&addresses, &stored.port));
    if !errors.is_empty() {
        return Ok(Json(SaveAddressGroupResponse {
            success: false,
            message: errors.join("; "),
            group_id: None,
        }));
    }

    let id = state.db.save_address_group(&group).await?;
    Ok(Json(SaveAddressGroupResponse {
        success: true,
        message: "Address group saved".to_string(),
        group_id: Some(id),
    }))
}

/// DELETE /firewall/address-groups/:id - Delete an address group
async fn delete_address_group(
    State(state): State<FirewallState>,
    Path(id): Path<i64>,
) -> Result<Json<DeleteResponse>, AppError> {
    info!("Deleting address group id: {}", id);
    let deleted = state.db.delete_address_group(id).await?;
    Ok(Json(DeleteResponse {
        success: deleted,
        message: if deleted {
            "Address group deleted".to_string()
        } else {
            "Address group not found".to_string()
        },
    }))
}

/// GET /firewall/port-groups - Get all port groups
async fn get_port_groups(
    State(state): State<FirewallState>,
) -> Result<Json<PortGroupsResponse>, AppError> {
    info!("Getting port groups");
    let groups = state.db.get_port_groups().await?;
    Ok(Json(PortGroupsResponse { groups }))
}

/// POST /firewall/port-groups - Create or update a port group
async fn save_port_group(
    State(state): State<FirewallState>,
    Json(request): Json<Req<SavePortGroup>>,
) -> Result<Json<Res<SavePortGroup>>, AppError> {
    let mut group = request.group;
    info!("Saving port group: {}", group.name);
    (group.entries, group.description) = tidy_group(group.entries, group.description);

    let stored = StoredGroups::load(&state.db).await?;
    let mut errors = validate_port_group(&group);
    let mut ports: Vec<PortGroup> = stored
        .port
        .into_iter()
        .filter(|other| other.id != group.id)
        .collect();
    ports.push(group.clone());
    errors.extend(validate_group_names(&stored.address, &ports));
    if !errors.is_empty() {
        return Ok(Json(SavePortGroupResponse {
            success: false,
            message: errors.join("; "),
            group_id: None,
        }));
    }

    let id = state.db.save_port_group(&group).await?;
    Ok(Json(SavePortGroupResponse {
        success: true,
        message: "Port group saved".to_string(),
        group_id: Some(id),
    }))
}

/// DELETE /firewall/port-groups/:id - Delete a port group
async fn delete_port_group(
    State(state): State<FirewallState>,
    Path(id): Path<i64>,
) -> Result<Json<DeleteResponse>, AppError> {
    info!("Deleting port group id: {}", id);
    let deleted = state.db.delete_port_group(id).await?;
    Ok(Json(DeleteResponse {
        success: deleted,
        message: if deleted {
            "Port group deleted".to_string()
        } else {
            "Port group not found".to_string()
        },
    }))
}

// ============================================================================
// Zone Endpoints
// ============================================================================

/// GET /firewall/zones - Get all firewall zones
async fn get_zones(
    State(state): State<FirewallState>,
) -> Result<Json<FirewallZonesResponse>, AppError> {
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
    Json(request): Json<Req<SaveFirewallZone>>,
) -> Result<Json<Res<SaveFirewallZone>>, AppError> {
    let zone = request.zone;
    info!("Saving firewall zone: {}", zone.name);

    // Validate zone name
    if zone.name.is_empty() {
        return Ok(Json(SaveFirewallZoneResponse {
            success: false,
            message: "Zone name is required".to_string(),
            zone_id: None,
        }));
    }

    // Reserved zone names
    if zone.name == "any" || zone.name == "local" {
        return Ok(Json(SaveFirewallZoneResponse {
            success: false,
            message: format!("Zone name '{}' is reserved", zone.name),
            zone_id: None,
        }));
    }

    let mut errors = validate_zone(&zone);
    let zones = state.db.get_firewall_zones().await?;
    errors.extend(crate::config_validation::zone_interface_conflicts(
        &zone, &zones,
    ));
    if !errors.is_empty() {
        return Ok(Json(SaveFirewallZoneResponse {
            success: false,
            message: errors.join("; "),
            zone_id: None,
        }));
    }

    let id = state.db.save_firewall_zone(&zone).await?;
    Ok(Json(SaveFirewallZoneResponse {
        success: true,
        message: "Zone saved".to_string(),
        zone_id: Some(id),
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
) -> Result<Json<ZoneForwardsResponse>, AppError> {
    info!("Getting zone forwards");
    let forwards = state.db.get_zone_forwards().await?;
    Ok(Json(ZoneForwardsResponse { forwards }))
}

/// POST /firewall/zone-forwards - Create or update a zone forward policy
async fn save_zone_forward(
    State(state): State<FirewallState>,
    Json(request): Json<Req<SaveZoneForward>>,
) -> Result<Json<Res<SaveZoneForward>>, AppError> {
    let forward = request.forward;
    info!(
        "Saving zone forward: {} -> {}",
        forward.source_zone, forward.dest_zone
    );

    let errors = validate_zone_forward(&forward);
    if !errors.is_empty() {
        return Ok(Json(SaveZoneForwardResponse {
            success: false,
            message: errors.join("; "),
            forward_id: None,
        }));
    }

    let id = state.db.save_zone_forward(&forward).await?;
    Ok(Json(SaveZoneForwardResponse {
        success: true,
        message: "Zone forward saved".to_string(),
        forward_id: Some(id),
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
async fn get_input_rules(
    State(state): State<FirewallState>,
) -> Result<Json<InputRulesResponse>, AppError> {
    info!("Getting input rules");
    let rules = state.db.get_input_rules().await?;
    Ok(Json(InputRulesResponse { rules }))
}

/// POST /firewall/input-rules - Create or update an input rule
async fn save_input_rule(
    State(state): State<FirewallState>,
    Json(request): Json<Req<SaveInputRule>>,
) -> Result<Json<Res<SaveInputRule>>, AppError> {
    let rule = request.rule;
    info!("Saving input rule: {}", rule.name);

    if rule.name.is_empty() {
        return Ok(Json(SaveInputRuleResponse {
            success: false,
            message: "Rule name is required".to_string(),
            rule_id: None,
        }));
    }

    let stored = StoredGroups::load(&state.db).await?;
    let errors = validate_input_rule(&rule, &stored.index());
    if !errors.is_empty() {
        return Ok(Json(SaveInputRuleResponse {
            success: false,
            message: errors.join("; "),
            rule_id: None,
        }));
    }

    let id = state.db.save_input_rule(&rule).await?;
    Ok(Json(SaveInputRuleResponse {
        success: true,
        message: "Input rule saved".to_string(),
        rule_id: Some(id),
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
    Json(request): Json<Req<ReorderInputRules>>,
) -> Result<Json<Res<ReorderInputRules>>, AppError> {
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
) -> Result<Json<ForwardRulesResponse>, AppError> {
    info!("Getting forward rules");
    let rules = state.db.get_forward_rules().await?;
    Ok(Json(ForwardRulesResponse { rules }))
}

/// POST /firewall/forward-rules - Create or update a forward rule
async fn save_forward_rule(
    State(state): State<FirewallState>,
    Json(request): Json<Req<SaveForwardRule>>,
) -> Result<Json<Res<SaveForwardRule>>, AppError> {
    let rule = request.rule;
    info!("Saving forward rule: {}", rule.name);

    if rule.name.is_empty() {
        return Ok(Json(SaveForwardRuleResponse {
            success: false,
            message: "Rule name is required".to_string(),
            rule_id: None,
        }));
    }

    let stored = StoredGroups::load(&state.db).await?;
    let errors = validate_forward_rule(&rule, &stored.index());
    if !errors.is_empty() {
        return Ok(Json(SaveForwardRuleResponse {
            success: false,
            message: errors.join("; "),
            rule_id: None,
        }));
    }

    let id = state.db.save_forward_rule(&rule).await?;
    Ok(Json(SaveForwardRuleResponse {
        success: true,
        message: "Forward rule saved".to_string(),
        rule_id: Some(id),
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
    Json(request): Json<Req<ReorderForwardRules>>,
) -> Result<Json<Res<ReorderForwardRules>>, AppError> {
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
) -> Result<Json<PortForwardsResponse>, AppError> {
    info!("Getting port forwards");
    let port_forwards = state.db.get_port_forwards().await?;
    Ok(Json(PortForwardsResponse { port_forwards }))
}

/// POST /firewall/port-forwards - Create or update a port forward
async fn save_port_forward(
    State(state): State<FirewallState>,
    Json(request): Json<Req<SavePortForward>>,
) -> Result<Json<Res<SavePortForward>>, AppError> {
    let pf = request.port_forward;
    info!("Saving port forward: {}", pf.name);

    if pf.name.is_empty() {
        return Ok(Json(SavePortForwardResponse {
            success: false,
            message: "Port forward name is required".to_string(),
            port_forward_id: None,
        }));
    }

    if pf.dest_ip.is_empty() {
        return Ok(Json(SavePortForwardResponse {
            success: false,
            message: "Destination IP is required".to_string(),
            port_forward_id: None,
        }));
    }

    let stored = StoredGroups::load(&state.db).await?;
    let errors = validate_port_forward(&pf, &stored.index());
    if !errors.is_empty() {
        return Ok(Json(SavePortForwardResponse {
            success: false,
            message: errors.join("; "),
            port_forward_id: None,
        }));
    }

    let id = state.db.save_port_forward(&pf).await?;
    Ok(Json(SavePortForwardResponse {
        success: true,
        message: "Port forward saved".to_string(),
        port_forward_id: Some(id),
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
// Global Settings Endpoints
// ============================================================================

/// GET /firewall/settings - Get global firewall settings
async fn get_global_settings(
    State(state): State<FirewallState>,
) -> Result<Json<FirewallGlobalSettingsResponse>, AppError> {
    info!("Getting firewall global settings");
    let settings = state.db.get_firewall_global_settings().await?;
    Ok(Json(FirewallGlobalSettingsResponse { settings }))
}

/// POST /firewall/settings - Save global firewall settings
async fn save_global_settings(
    State(state): State<FirewallState>,
    Json(request): Json<Req<SaveFirewallGlobalSettings>>,
) -> Result<Json<Res<SaveFirewallGlobalSettings>>, AppError> {
    info!("Saving firewall global settings");
    state
        .db
        .save_firewall_global_settings(&request.settings)
        .await?;
    Ok(Json(SaveFirewallGlobalSettingsResponse {
        success: true,
        message: "Settings saved".to_string(),
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

/// GET /firewall/counters - Hit counters of the applied user rules
async fn get_rule_counters() -> Result<Json<FirewallCountersResponse>, AppError> {
    let counters = super::counters::read_rule_counters().await?;
    Ok(Json(FirewallCountersResponse { counters }))
}

/// Query of `POST /firewall/test-packet`.
#[derive(Debug, Deserialize)]
struct TestPacketQuery {
    /// `saved` (default) traces the configuration as edited; `applied` traces
    /// the last applied configuration.
    #[serde(default)]
    baseline: Option<String>,
}

/// Error response with a status and a message the client can show.
fn error_response(
    status: StatusCode,
    message: impl Into<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(json!({ "error": message.into() })))
}

/// POST /firewall/test-packet - Trace one packet through the firewall
async fn test_firewall_packet(
    State(state): State<FirewallState>,
    Query(query): Query<TestPacketQuery>,
    Json(request): Json<Req<TestFirewallPacket>>,
) -> Result<Json<Res<TestFirewallPacket>>, (StatusCode, Json<serde_json::Value>)> {
    let internal = |error: anyhow::Error| {
        error_response(StatusCode::INTERNAL_SERVER_ERROR, format!("{error:#}"))
    };
    let (config, baseline, snapshot_id) = match query.baseline.as_deref() {
        None | Some("saved") => {
            let config = state.db.get_firewall_config().await.map_err(internal)?;
            (config, "saved", None)
        }
        Some("applied") => {
            let applied = snapshots::latest_applied_for(&state.db, Component::Firewall)
                .await
                .map_err(internal)?
                .ok_or_else(|| {
                    error_response(
                        StatusCode::NOT_FOUND,
                        "no applied firewall configuration to trace",
                    )
                })?;
            let opened = snapshots::open_snapshot(&state.db, applied.id)
                .await
                .map_err(internal)?;
            let config = opened
                .database()
                .get_firewall_config()
                .await
                .map_err(internal)?;
            (config, "applied", Some(applied.id))
        }
        Some(other) => {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                format!("baseline must be 'saved' or 'applied', not '{other}'"),
            ));
        }
    };

    let view = super::trace::live_view().await.map_err(internal)?;
    let packet = super::trace::packet_from_request(&request, &config)
        .map_err(|message| error_response(StatusCode::BAD_REQUEST, message))?;
    let mut response = super::trace::trace(&config, &view, &packet);
    response.baseline = baseline.to_string();
    response.applied_snapshot_id = snapshot_id;
    if request.egress_interface.is_none() && response.path == keystone_core::TraceStage::Forward {
        response.notes.push(match &response.egress {
            Some(egress) => {
                format!("The outgoing interface {egress} is taken from the live routing table.")
            }
            None => "No route to the destination is known in the live routing table.".to_string(),
        });
    }
    Ok(Json(response))
}

/// POST /firewall/apply - Apply firewall configuration
async fn apply_firewall(
    State(state): State<FirewallState>,
    actor: Option<Extension<Actor>>,
) -> Result<Json<FirewallApplyResponse>, AppError> {
    info!("Applying firewall configuration");

    // Check if configuration changes are disabled
    let global_settings = state.db.get_global_settings().await?;
    if global_settings.config_changes_disabled {
        return Ok(Json(FirewallApplyResponse {
            success: false,
            message: "Configuration changes are disabled. Unlock in Settings to apply changes."
                .to_string(),
            pending_confirmation: false,
            confirm_deadline: None,
            session_id: None,
        }));
    }

    let response = state.apply_manager.apply(None).await?;
    if response.success {
        let actor = actor.as_ref().map(|Extension(actor)| actor.0.as_str());
        let pending = if response.pending_confirmation {
            response.session_id.as_deref()
        } else {
            None
        };
        snapshots::record_applied(
            &state.db,
            actor,
            pending,
            &[keystone_core::changes::Component::Firewall],
            "firewall apply",
        )
        .await;
    }
    Ok(Json(response))
}

/// POST /firewall/confirm - Confirm pending firewall changes
async fn confirm_firewall(
    State(state): State<FirewallState>,
    Json(request): Json<Req<ConfirmFirewall>>,
) -> Result<Json<Res<ConfirmFirewall>>, AppError> {
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
