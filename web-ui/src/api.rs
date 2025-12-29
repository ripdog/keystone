//! API client functions for communicating with the Keystone daemon

use keystone_core::{
    ApplyConfigResponse, BridgeConfig, BridgeConfigResponse, BridgeConfigsResponse,
    DashboardResponse, DeleteBridgeResponse, DeleteUserRequest, DeleteUserResponse,
    DeleteVlanResponse, InterfaceConfig, InterfaceConfigResponse, InterfaceConfigsResponse,
    LoginRequest, LoginResponse, ManagedInterface, ManagedInterfacesResponse,
    NetworkdPreviewResponse, SaveBridgeConfigRequest, SaveBridgeConfigResponse,
    SaveInterfaceConfigRequest, SaveInterfaceConfigResponse, SaveManagedInterfacesRequest,
    SaveManagedInterfacesResponse, SaveUserRequest, SaveUserResponse, SaveVlanConfigRequest,
    SaveVlanConfigResponse, UserInfo, UsersResponse, VlanConfig, VlanConfigResponse,
    VlanConfigsResponse,
};

/// Login to the API and get a JWT token
pub async fn login(username: &str, password: &str) -> Result<LoginResponse, String> {
    let request = LoginRequest {
        username: username.to_string(),
        password: password.to_string(),
    };

    let response = gloo_net::http::Request::post("/api/login")
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&request).unwrap())
        .map_err(|e| format!("Failed to build request: {}", e))?
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.ok() {
        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Fetch dashboard data (state + interface counters)
pub async fn fetch_dashboard(token: &str) -> Result<DashboardResponse, String> {
    let response = gloo_net::http::Request::get("/api/dashboard")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Fetch managed interfaces from the API
pub async fn fetch_managed_interfaces(token: &str) -> Result<Vec<ManagedInterface>, String> {
    let response = gloo_net::http::Request::get("/api/managed-interfaces")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        let data: ManagedInterfacesResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;
        Ok(data.interfaces)
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Save managed interfaces to the API
pub async fn save_managed_interfaces(
    token: &str,
    interfaces: Vec<ManagedInterface>,
) -> Result<SaveManagedInterfacesResponse, String> {
    let request = SaveManagedInterfacesRequest { interfaces };

    let response = gloo_net::http::Request::post("/api/managed-interfaces")
        .header("Authorization", &format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&request).unwrap())
        .map_err(|e| format!("Failed to build request: {}", e))?
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Fetch users from the API
pub async fn fetch_users(token: &str) -> Result<Vec<UserInfo>, String> {
    let response = gloo_net::http::Request::get("/api/users")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        let data: UsersResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;
        Ok(data.users)
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Save a user (create or update)
pub async fn save_user(
    token: &str,
    user: SaveUserRequest,
) -> Result<SaveUserResponse, String> {
    let response = gloo_net::http::Request::post("/api/users")
        .header("Authorization", &format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&user).unwrap())
        .map_err(|e| format!("Failed to build request: {}", e))?
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Delete a user
pub async fn delete_user(token: &str, user_id: i64) -> Result<DeleteUserResponse, String> {
    let request = DeleteUserRequest { id: user_id };

    let response = gloo_net::http::Request::delete("/api/users")
        .header("Authorization", &format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&request).unwrap())
        .map_err(|e| format!("Failed to build request: {}", e))?
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

// ============================================================================
// Interface Configuration API
// ============================================================================

/// Fetch all interface configurations
#[allow(dead_code)]
pub async fn fetch_interface_configs(token: &str) -> Result<Vec<InterfaceConfig>, String> {
    let response = gloo_net::http::Request::get("/api/interface-config")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        let data: InterfaceConfigsResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;
        Ok(data.configs)
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Fetch a single interface configuration by name
pub async fn fetch_interface_config(
    token: &str,
    name: &str,
) -> Result<Option<InterfaceConfig>, String> {
    let response = gloo_net::http::Request::get(&format!("/api/interface-config/{}", name))
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        let data: InterfaceConfigResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;
        Ok(data.config)
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Save an interface configuration
pub async fn save_interface_config(
    token: &str,
    config: InterfaceConfig,
) -> Result<SaveInterfaceConfigResponse, String> {
    let request = SaveInterfaceConfigRequest { config };

    let response = gloo_net::http::Request::post("/api/interface-config")
        .header("Authorization", &format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&request).unwrap())
        .map_err(|e| format!("Failed to build request: {}", e))?
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Delete an interface configuration
#[allow(dead_code)]
pub async fn delete_interface_config(
    token: &str,
    name: &str,
) -> Result<SaveInterfaceConfigResponse, String> {
    let response = gloo_net::http::Request::delete(&format!("/api/interface-config/{}", name))
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Apply networkd configuration - writes .network files and reloads systemd-networkd
pub async fn apply_networkd(token: &str) -> Result<ApplyConfigResponse, String> {
    let response = gloo_net::http::Request::post("/api/apply-networkd")
        .header("Authorization", &format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body("{}")
        .map_err(|e| format!("Failed to build request: {}", e))?
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Get networkd configuration preview without writing to disk
pub async fn get_networkd_preview(token: &str) -> Result<NetworkdPreviewResponse, String> {
    let response = gloo_net::http::Request::get("/api/networkd-preview")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

// ============================================================================
// VLAN Configuration API
// ============================================================================

/// Fetch all VLAN configurations
pub async fn fetch_vlans(token: &str) -> Result<Vec<VlanConfig>, String> {
    let response = gloo_net::http::Request::get("/api/vlans")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        let data: VlanConfigsResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;
        Ok(data.configs)
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Fetch a single VLAN configuration by ID
#[allow(dead_code)]
pub async fn fetch_vlan(token: &str, id: i64) -> Result<Option<VlanConfig>, String> {
    let response = gloo_net::http::Request::get(&format!("/api/vlans/{}", id))
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        let data: VlanConfigResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;
        Ok(data.config)
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Save a VLAN configuration (create or update)
pub async fn save_vlan(token: &str, config: VlanConfig) -> Result<SaveVlanConfigResponse, String> {
    let request = SaveVlanConfigRequest { config };

    let response = gloo_net::http::Request::post("/api/vlans")
        .header("Authorization", &format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&request).unwrap())
        .map_err(|e| format!("Failed to build request: {}", e))?
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Delete a VLAN configuration
pub async fn delete_vlan(token: &str, id: i64) -> Result<DeleteVlanResponse, String> {
    let response = gloo_net::http::Request::delete(&format!("/api/vlans/{}", id))
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

// ============================================================================
// Bridge Configuration API
// ============================================================================

/// Fetch all bridge configurations
pub async fn fetch_bridges(token: &str) -> Result<Vec<BridgeConfig>, String> {
    let response = gloo_net::http::Request::get("/api/bridges")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        let data: BridgeConfigsResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;
        Ok(data.configs)
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Fetch a single bridge configuration by ID
pub async fn fetch_bridge(token: &str, id: i64) -> Result<Option<BridgeConfig>, String> {
    let response = gloo_net::http::Request::get(&format!("/api/bridges/{}", id))
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        let data: BridgeConfigResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;
        Ok(data.config)
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Save a bridge configuration (create or update)
pub async fn save_bridge(token: &str, config: BridgeConfig) -> Result<SaveBridgeConfigResponse, String> {
    let request = SaveBridgeConfigRequest { config };

    let response = gloo_net::http::Request::post("/api/bridges")
        .header("Authorization", &format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&request).unwrap())
        .map_err(|e| format!("Failed to build request: {}", e))?
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Delete a bridge configuration
pub async fn delete_bridge(token: &str, id: i64) -> Result<DeleteBridgeResponse, String> {
    let response = gloo_net::http::Request::delete(&format!("/api/bridges/{}", id))
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

// ============================================================================
// Firewall API
// ============================================================================

use keystone_core::{
    DeleteResponse, FirewallApplyResponse, FirewallConfirmRequest, FirewallConfirmResponse,
    FirewallConfig, FirewallConfigResponse, FirewallPreviewResponse, FirewallRollbackResponse,
    FirewallStatusResponse, FirewallZone, FirewallZonesResponse, ForwardRule, InputRule,
    PortForward, ZoneForwardPolicy,
};

/// Fetch complete firewall configuration
pub async fn fetch_firewall_config(token: &str) -> Result<FirewallConfig, String> {
    let response = gloo_net::http::Request::get("/api/firewall/config")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        let data: FirewallConfigResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;
        Ok(data.config)
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Fetch all firewall zones
pub async fn fetch_firewall_zones(token: &str) -> Result<Vec<FirewallZone>, String> {
    let response = gloo_net::http::Request::get("/api/firewall/zones")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        let data: FirewallZonesResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;
        Ok(data.zones)
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Save a firewall zone
pub async fn save_firewall_zone(token: &str, zone: FirewallZone) -> Result<i64, String> {
    let response = gloo_net::http::Request::post("/api/firewall/zones")
        .header("Authorization", &format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&zone).unwrap())
        .map_err(|e| format!("Failed to build request: {}", e))?
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        #[derive(serde::Deserialize)]
        struct SaveResponse {
            success: bool,
            message: String,
            id: Option<i64>,
        }
        let data: SaveResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;
        if data.success {
            Ok(data.id.unwrap_or(0))
        } else {
            Err(data.message)
        }
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Delete a firewall zone
pub async fn delete_firewall_zone(token: &str, id: i64) -> Result<DeleteResponse, String> {
    let response = gloo_net::http::Request::delete(&format!("/api/firewall/zones/{}", id))
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Fetch zone-to-zone forward policies
pub async fn fetch_zone_forwards(token: &str) -> Result<Vec<ZoneForwardPolicy>, String> {
    let response = gloo_net::http::Request::get("/api/firewall/zone-forwards")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Save a zone forward policy
pub async fn save_zone_forward(token: &str, forward: ZoneForwardPolicy) -> Result<i64, String> {
    let response = gloo_net::http::Request::post("/api/firewall/zone-forwards")
        .header("Authorization", &format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&forward).unwrap())
        .map_err(|e| format!("Failed to build request: {}", e))?
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        #[derive(serde::Deserialize)]
        struct SaveResponse {
            success: bool,
            message: String,
            id: Option<i64>,
        }
        let data: SaveResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;
        if data.success {
            Ok(data.id.unwrap_or(0))
        } else {
            Err(data.message)
        }
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Delete a zone forward policy
pub async fn delete_zone_forward(token: &str, id: i64) -> Result<DeleteResponse, String> {
    let response = gloo_net::http::Request::delete(&format!("/api/firewall/zone-forwards/{}", id))
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Fetch input rules
pub async fn fetch_input_rules(token: &str) -> Result<Vec<InputRule>, String> {
    let response = gloo_net::http::Request::get("/api/firewall/input-rules")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Save an input rule
pub async fn save_input_rule(token: &str, rule: InputRule) -> Result<i64, String> {
    let response = gloo_net::http::Request::post("/api/firewall/input-rules")
        .header("Authorization", &format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&rule).unwrap())
        .map_err(|e| format!("Failed to build request: {}", e))?
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        #[derive(serde::Deserialize)]
        struct SaveResponse {
            success: bool,
            message: String,
            id: Option<i64>,
        }
        let data: SaveResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;
        if data.success {
            Ok(data.id.unwrap_or(0))
        } else {
            Err(data.message)
        }
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Delete an input rule
pub async fn delete_input_rule(token: &str, id: i64) -> Result<DeleteResponse, String> {
    let response = gloo_net::http::Request::delete(&format!("/api/firewall/input-rules/{}", id))
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Fetch forward rules
pub async fn fetch_forward_rules(token: &str) -> Result<Vec<ForwardRule>, String> {
    let response = gloo_net::http::Request::get("/api/firewall/forward-rules")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Save a forward rule
pub async fn save_forward_rule(token: &str, rule: ForwardRule) -> Result<i64, String> {
    let response = gloo_net::http::Request::post("/api/firewall/forward-rules")
        .header("Authorization", &format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&rule).unwrap())
        .map_err(|e| format!("Failed to build request: {}", e))?
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        #[derive(serde::Deserialize)]
        struct SaveResponse {
            success: bool,
            message: String,
            id: Option<i64>,
        }
        let data: SaveResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;
        if data.success {
            Ok(data.id.unwrap_or(0))
        } else {
            Err(data.message)
        }
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Delete a forward rule
pub async fn delete_forward_rule(token: &str, id: i64) -> Result<DeleteResponse, String> {
    let response = gloo_net::http::Request::delete(&format!("/api/firewall/forward-rules/{}", id))
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Fetch port forwards
pub async fn fetch_port_forwards(token: &str) -> Result<Vec<PortForward>, String> {
    let response = gloo_net::http::Request::get("/api/firewall/port-forwards")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Save a port forward
pub async fn save_port_forward(token: &str, pf: PortForward) -> Result<i64, String> {
    let response = gloo_net::http::Request::post("/api/firewall/port-forwards")
        .header("Authorization", &format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&pf).unwrap())
        .map_err(|e| format!("Failed to build request: {}", e))?
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        #[derive(serde::Deserialize)]
        struct SaveResponse {
            success: bool,
            message: String,
            id: Option<i64>,
        }
        let data: SaveResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;
        if data.success {
            Ok(data.id.unwrap_or(0))
        } else {
            Err(data.message)
        }
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Delete a port forward
pub async fn delete_port_forward(token: &str, id: i64) -> Result<DeleteResponse, String> {
    let response = gloo_net::http::Request::delete(&format!("/api/firewall/port-forwards/{}", id))
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Get firewall preview (human-readable nftables rules)
pub async fn fetch_firewall_preview(token: &str) -> Result<String, String> {
    let response = gloo_net::http::Request::get("/api/firewall/preview")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        let data: FirewallPreviewResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;
        Ok(data.ruleset)
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Apply firewall configuration
pub async fn apply_firewall(token: &str) -> Result<FirewallApplyResponse, String> {
    let response = gloo_net::http::Request::post("/api/firewall/apply")
        .header("Authorization", &format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body("{}")
        .map_err(|e| format!("Failed to build request: {}", e))?
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Confirm firewall changes
pub async fn confirm_firewall(token: &str, session_id: &str) -> Result<FirewallConfirmResponse, String> {
    let request = FirewallConfirmRequest {
        session_id: session_id.to_string(),
    };

    let response = gloo_net::http::Request::post("/api/firewall/confirm")
        .header("Authorization", &format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&request).unwrap())
        .map_err(|e| format!("Failed to build request: {}", e))?
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Rollback firewall changes
pub async fn rollback_firewall(token: &str) -> Result<FirewallRollbackResponse, String> {
    let response = gloo_net::http::Request::post("/api/firewall/rollback")
        .header("Authorization", &format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body("{}")
        .map_err(|e| format!("Failed to build request: {}", e))?
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Get firewall apply status
pub async fn fetch_firewall_status(token: &str) -> Result<FirewallStatusResponse, String> {
    let response = gloo_net::http::Request::get("/api/firewall/status")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}
