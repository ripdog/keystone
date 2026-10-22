//! Firewall configuration API functions

use keystone_core::api::{
    ConfirmFirewall, CreateSimpleForward, Endpoint, ReorderForwardRules, ReorderInputRules,
    SaveAddressGroup, SaveFirewallGlobalSettings, SaveFirewallZone, SaveForwardRule, SaveInputRule,
    SavePortForward, SavePortGroup, SaveZoneForward, TestFirewallPacket, UpdateSimpleForward,
};
use keystone_core::{
    AddressGroup, AddressGroupsResponse, ConnectionsResponse, CreateSimplePortForwardRequest,
    DeleteResponse, FirewallConfirmRequest, FirewallConfirmResponse, FirewallCountersResponse,
    FirewallGlobalSettings, FirewallGlobalSettingsResponse, FirewallLogResponse,
    FirewallPreviewResponse, FirewallRollbackResponse, FirewallRuleCounter, FirewallZone,
    FirewallZonesResponse, ForwardRule, ForwardRulesResponse, InputRule, InputRulesResponse,
    LanDevice, LanDevicesResponse, PortForward, PortGroup, PortGroupsResponse, ReorderRulesRequest,
    SaveAddressGroupRequest, SaveFirewallGlobalSettingsRequest, SaveFirewallGlobalSettingsResponse,
    SaveFirewallZoneRequest, SaveForwardRuleRequest, SaveInputRuleRequest, SavePortForwardRequest,
    SavePortGroupRequest, SaveZoneForwardRequest, SimplePortForward, SimplePortForwardsResponse,
    TestPacketRequest, TestPacketResponse, ZoneForwardPolicy, ZoneForwardsResponse,
};

use super::client::{call, call_at, call_with, delete, get, post_empty};

/// Turn a `{success, message, id}` save response into the saved id.
fn saved_id(success: bool, message: String, id: Option<i64>) -> Result<i64, String> {
    if success {
        Ok(id.unwrap_or(0))
    } else {
        Err(message)
    }
}

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
    let response = call::<SaveFirewallZone>(token, &SaveFirewallZoneRequest { zone }).await?;
    saved_id(response.success, response.message, response.zone_id)
}

/// Delete a firewall zone
pub async fn delete_firewall_zone(token: &str, id: i64) -> Result<DeleteResponse, String> {
    delete(&format!("/api/firewall/zones/{}", id), token).await
}

// ============================================================================
// Address and Port Groups
// ============================================================================

/// Fetch all address groups
pub async fn fetch_address_groups(token: &str) -> Result<Vec<AddressGroup>, String> {
    let response: AddressGroupsResponse = get("/api/firewall/address-groups", token).await?;
    Ok(response.groups)
}

/// Save an address group
pub async fn save_address_group(token: &str, group: AddressGroup) -> Result<i64, String> {
    let response = call::<SaveAddressGroup>(token, &SaveAddressGroupRequest { group }).await?;
    saved_id(response.success, response.message, response.group_id)
}

/// Delete an address group. The daemon refuses while a rule references it.
pub async fn delete_address_group(token: &str, id: i64) -> Result<DeleteResponse, String> {
    delete(&format!("/api/firewall/address-groups/{id}"), token).await
}

/// Fetch all port groups
pub async fn fetch_port_groups(token: &str) -> Result<Vec<PortGroup>, String> {
    let response: PortGroupsResponse = get("/api/firewall/port-groups", token).await?;
    Ok(response.groups)
}

/// Save a port group
pub async fn save_port_group(token: &str, group: PortGroup) -> Result<i64, String> {
    let response = call::<SavePortGroup>(token, &SavePortGroupRequest { group }).await?;
    saved_id(response.success, response.message, response.group_id)
}

/// Delete a port group. The daemon refuses while a rule references it.
pub async fn delete_port_group(token: &str, id: i64) -> Result<DeleteResponse, String> {
    delete(&format!("/api/firewall/port-groups/{id}"), token).await
}

// ============================================================================
// Rule Hit Counters and Ordering
// ============================================================================

/// Hit counters of the applied user rules (one entry per rule that has hits)
pub async fn fetch_rule_counters(token: &str) -> Result<Vec<FirewallRuleCounter>, String> {
    let response: FirewallCountersResponse = get("/api/firewall/counters", token).await?;
    Ok(response.counters)
}

/// Save the order of input rules: positions follow the order of `rule_ids`
pub async fn reorder_input_rules(token: &str, rule_ids: Vec<i64>) -> Result<(), String> {
    let response = call::<ReorderInputRules>(token, &ReorderRulesRequest { rule_ids }).await?;
    if response.success {
        Ok(())
    } else {
        Err(response.message)
    }
}

/// Save the order of forward rules: positions follow the order of `rule_ids`
pub async fn reorder_forward_rules(token: &str, rule_ids: Vec<i64>) -> Result<(), String> {
    let response = call::<ReorderForwardRules>(token, &ReorderRulesRequest { rule_ids }).await?;
    if response.success {
        Ok(())
    } else {
        Err(response.message)
    }
}

// ============================================================================
// Zone Forwards
// ============================================================================

/// Fetch zone-to-zone forward policies
pub async fn fetch_zone_forwards(token: &str) -> Result<Vec<ZoneForwardPolicy>, String> {
    let response: ZoneForwardsResponse = get("/api/firewall/zone-forwards", token).await?;
    Ok(response.forwards)
}

/// Save a zone forward policy
pub async fn save_zone_forward(token: &str, forward: ZoneForwardPolicy) -> Result<i64, String> {
    let response = call::<SaveZoneForward>(token, &SaveZoneForwardRequest { forward }).await?;
    saved_id(response.success, response.message, response.forward_id)
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
    let response: InputRulesResponse = get("/api/firewall/input-rules", token).await?;
    Ok(response.rules)
}

/// Save an input rule
pub async fn save_input_rule(token: &str, rule: InputRule) -> Result<i64, String> {
    let response = call::<SaveInputRule>(token, &SaveInputRuleRequest { rule }).await?;
    saved_id(response.success, response.message, response.rule_id)
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
    let response: ForwardRulesResponse = get("/api/firewall/forward-rules", token).await?;
    Ok(response.rules)
}

/// Save a forward rule
pub async fn save_forward_rule(token: &str, rule: ForwardRule) -> Result<i64, String> {
    let response = call::<SaveForwardRule>(token, &SaveForwardRuleRequest { rule }).await?;
    saved_id(response.success, response.message, response.rule_id)
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

/// Port forwards that are not part of any simple forward (e.g. created via CLI/API).
pub async fn fetch_other_port_forwards(token: &str) -> Result<Vec<PortForward>, String> {
    let response: SimplePortForwardsResponse = get("/api/firewall/simple-forwards", token).await?;
    Ok(response.other_port_forwards)
}

/// Save a raw port forward (DNAT) row
pub async fn save_port_forward(token: &str, port_forward: PortForward) -> Result<i64, String> {
    let response = call::<SavePortForward>(token, &SavePortForwardRequest { port_forward }).await?;
    saved_id(response.success, response.message, response.port_forward_id)
}

/// Delete a raw port forward (DNAT) row
pub async fn delete_port_forward(token: &str, id: i64) -> Result<DeleteResponse, String> {
    delete(&format!("/api/firewall/port-forwards/{id}"), token).await
}

pub async fn fetch_lan_devices(token: &str) -> Result<Vec<LanDevice>, String> {
    let response: LanDevicesResponse = get("/api/firewall/lan-devices", token).await?;
    Ok(response.devices)
}

pub async fn create_simple_forward(
    token: &str,
    req: CreateSimplePortForwardRequest,
) -> Result<(), String> {
    call::<CreateSimpleForward>(token, &req).await?;
    Ok(())
}

pub async fn update_simple_forward(
    token: &str,
    rule_id: i64,
    req: CreateSimplePortForwardRequest,
) -> Result<(), String> {
    call_with::<UpdateSimpleForward>(token, &[("id", &rule_id.to_string())], &req).await?;
    Ok(())
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
    call::<SaveFirewallGlobalSettings>(token, &request).await
}

// ============================================================================
// Apply / Confirm / Rollback
// ============================================================================

/// Get firewall preview (human-readable nftables rules)
pub async fn fetch_firewall_preview(token: &str) -> Result<String, String> {
    let response: FirewallPreviewResponse = get("/api/firewall/preview", token).await?;
    Ok(response.ruleset)
}

/// Confirm firewall changes
pub async fn confirm_firewall(
    token: &str,
    session_id: &str,
) -> Result<FirewallConfirmResponse, String> {
    let request = FirewallConfirmRequest {
        session_id: session_id.to_string(),
    };
    call::<ConfirmFirewall>(token, &request).await
}

/// Rollback firewall changes
pub async fn rollback_firewall(token: &str) -> Result<FirewallRollbackResponse, String> {
    post_empty("/api/firewall/rollback", token).await
}

// ============================================================================
// Packet Tester, Live Log and Connections
// ============================================================================

/// Trace one packet. With `applied`, the last applied configuration is traced
/// instead of the saved one.
pub async fn run_packet_trace(
    token: &str,
    request: &TestPacketRequest,
    applied: bool,
) -> Result<TestPacketResponse, String> {
    let path = if applied {
        format!("{}?baseline=applied", TestFirewallPacket::PATH)
    } else {
        TestFirewallPacket::PATH.to_string()
    };
    call_at::<TestFirewallPacket>(token, &path, request).await
}

/// Kernel log lines logged by firewall rules, after `cursor` when given.
///
/// The daemon validates the cursor. `;` and `=` are percent-encoded here so
/// they cannot split the query string.
pub async fn fetch_firewall_log(
    token: &str,
    cursor: Option<&str>,
    limit: usize,
) -> Result<FirewallLogResponse, String> {
    let mut url = format!("/api/firewall/log?limit={limit}");
    if let Some(cursor) = cursor {
        url.push_str("&cursor=");
        url.push_str(&cursor.replace(';', "%3B").replace('=', "%3D"));
    }
    get(&url, token).await
}

/// Connections in the kernel's connection tracking table.
pub async fn fetch_connections(token: &str) -> Result<ConnectionsResponse, String> {
    get("/api/firewall/connections", token).await
}
