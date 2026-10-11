//! Firewall configuration API functions

use keystone_core::{
    CreateSimplePortForwardRequest, DeleteResponse, FirewallApplyResponse, FirewallConfirmRequest,
    FirewallConfirmResponse, FirewallGlobalSettings, FirewallGlobalSettingsResponse,
    FirewallPreviewResponse, FirewallRollbackResponse, FirewallZone, FirewallZonesResponse,
    ForwardRule, InputRule, LanDevice, LanDevicesResponse, SaveFirewallGlobalSettingsRequest,
    SaveFirewallGlobalSettingsResponse, SimplePortForward, SimplePortForwardsResponse,
    ZoneForwardPolicy,
};

use super::client::{SaveIdResponse, delete, extract_id, get, post, post_empty, put_no_response};

// ============================================================================
// Zones
// ============================================================================

/// Fetch all firewall zones
pub async fn fetch_firewall_zones(token: &str) -> Result<Vec<FirewallZone>, String> {
    let response: FirewallZonesResponse = get("/api/firewall/zones", token).await?;
    Ok(response.zones)
}

/// Save a firewall zone
pub async fn save_firewall_zone(token: &str, zone: FirewallZone) -> Result<i64, String> {
    let response: SaveIdResponse = post("/api/firewall/zones", token, &zone).await?;
    extract_id(response)
}

/// Delete a firewall zone
pub async fn delete_firewall_zone(token: &str, id: i64) -> Result<DeleteResponse, String> {
    delete(&format!("/api/firewall/zones/{}", id), token).await
}

// ============================================================================
// Zone Forwards
// ============================================================================

/// Fetch zone-to-zone forward policies
pub async fn fetch_zone_forwards(token: &str) -> Result<Vec<ZoneForwardPolicy>, String> {
    get("/api/firewall/zone-forwards", token).await
}

/// Save a zone forward policy
pub async fn save_zone_forward(token: &str, forward: ZoneForwardPolicy) -> Result<i64, String> {
    let response: SaveIdResponse = post("/api/firewall/zone-forwards", token, &forward).await?;
    extract_id(response)
}

/// Delete a zone forward policy
pub async fn delete_zone_forward(token: &str, id: i64) -> Result<DeleteResponse, String> {
    delete(&format!("/api/firewall/zone-forwards/{}", id), token).await
}

// ============================================================================
// Input Rules
// ============================================================================

/// Fetch input rules
pub async fn fetch_input_rules(token: &str) -> Result<Vec<InputRule>, String> {
    get("/api/firewall/input-rules", token).await
}

/// Save an input rule
pub async fn save_input_rule(token: &str, rule: InputRule) -> Result<i64, String> {
    let response: SaveIdResponse = post("/api/firewall/input-rules", token, &rule).await?;
    extract_id(response)
}

/// Delete an input rule
pub async fn delete_input_rule(token: &str, id: i64) -> Result<DeleteResponse, String> {
    delete(&format!("/api/firewall/input-rules/{}", id), token).await
}

// ============================================================================
// Forward Rules
// ============================================================================

/// Fetch forward rules
pub async fn fetch_forward_rules(token: &str) -> Result<Vec<ForwardRule>, String> {
    get("/api/firewall/forward-rules", token).await
}

/// Save a forward rule
pub async fn save_forward_rule(token: &str, rule: ForwardRule) -> Result<i64, String> {
    let response: SaveIdResponse = post("/api/firewall/forward-rules", token, &rule).await?;
    extract_id(response)
}

/// Delete a forward rule
pub async fn delete_forward_rule(token: &str, id: i64) -> Result<DeleteResponse, String> {
    delete(&format!("/api/firewall/forward-rules/{}", id), token).await
}

// ============================================================================
// Port Forwards
// ============================================================================

/// Effective WAN exposures, reconstructed from allow and NAT rules.
pub async fn fetch_simple_forwards(token: &str) -> Result<Vec<SimplePortForward>, String> {
    let response: SimplePortForwardsResponse = get("/api/firewall/simple-forwards", token).await?;
    Ok(response.forwards)
}

pub async fn fetch_lan_devices(token: &str) -> Result<Vec<LanDevice>, String> {
    let response: LanDevicesResponse = get("/api/firewall/lan-devices", token).await?;
    Ok(response.devices)
}

pub async fn create_simple_forward(
    token: &str,
    req: CreateSimplePortForwardRequest,
) -> Result<(), String> {
    let _: SimplePortForwardsResponse = post("/api/firewall/simple-forwards", token, &req).await?;
    Ok(())
}

pub async fn update_simple_forward(
    token: &str,
    rule_id: i64,
    req: CreateSimplePortForwardRequest,
) -> Result<(), String> {
    put_no_response(
        &format!("/api/firewall/simple-forwards/{rule_id}"),
        token,
        &req,
    )
    .await
}

pub async fn delete_simple_forward(token: &str, rule_id: i64) -> Result<DeleteResponse, String> {
    delete(&format!("/api/firewall/simple-forwards/{rule_id}"), token).await
}

// ============================================================================
// Global Settings
// ============================================================================

/// Fetch firewall global settings
pub async fn fetch_firewall_global_settings(token: &str) -> Result<FirewallGlobalSettings, String> {
    let response: FirewallGlobalSettingsResponse = get("/api/firewall/settings", token).await?;
    Ok(response.settings)
}

/// Save firewall global settings
pub async fn save_firewall_global_settings(
    token: &str,
    settings: FirewallGlobalSettings,
) -> Result<SaveFirewallGlobalSettingsResponse, String> {
    let request = SaveFirewallGlobalSettingsRequest { settings };
    post("/api/firewall/settings", token, &request).await
}

// ============================================================================
// Apply / Confirm / Rollback
// ============================================================================

/// Get firewall preview (human-readable nftables rules)
pub async fn fetch_firewall_preview(token: &str) -> Result<String, String> {
    let response: FirewallPreviewResponse = get("/api/firewall/preview", token).await?;
    Ok(response.ruleset)
}

/// Apply firewall configuration
pub async fn apply_firewall(token: &str) -> Result<FirewallApplyResponse, String> {
    post_empty("/api/firewall/apply", token).await
}

/// Confirm firewall changes
pub async fn confirm_firewall(
    token: &str,
    session_id: &str,
) -> Result<FirewallConfirmResponse, String> {
    let request = FirewallConfirmRequest {
        session_id: session_id.to_string(),
    };
    post("/api/firewall/confirm", token, &request).await
}

/// Rollback firewall changes
pub async fn rollback_firewall(token: &str) -> Result<FirewallRollbackResponse, String> {
    post_empty("/api/firewall/rollback", token).await
}
