//! API client functions for communicating with the Keystone daemon

use keystone_core::{
    DashboardResponse, DeleteUserRequest, DeleteUserResponse, InterfaceConfig,
    InterfaceConfigResponse, InterfaceConfigsResponse, LoginRequest, LoginResponse,
    ManagedInterface, ManagedInterfacesResponse, SaveInterfaceConfigRequest,
    SaveInterfaceConfigResponse, SaveManagedInterfacesRequest, SaveManagedInterfacesResponse,
    SaveUserRequest, SaveUserResponse, UserInfo, UsersResponse,
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
