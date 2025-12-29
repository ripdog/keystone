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
