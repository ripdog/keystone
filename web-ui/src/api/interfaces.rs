//! Interface configuration API functions

use keystone_core::{
    ApplyConfigResponse, InterfaceConfig, InterfaceConfigResponse, InterfaceConfigsResponse,
    ManagedInterface, ManagedInterfacesResponse, NetworkdPreviewResponse,
    SaveInterfaceConfigRequest, SaveInterfaceConfigResponse, SaveManagedInterfacesRequest,
    SaveManagedInterfacesResponse,
};

use super::client::{delete, get, post, post_empty};

// ============================================================================
// Managed Interfaces
// ============================================================================

/// Fetch managed interfaces from the API
pub async fn fetch_managed_interfaces(token: &str) -> Result<Vec<ManagedInterface>, String> {
    let response: ManagedInterfacesResponse = get("/api/managed-interfaces", token).await?;
    Ok(response.interfaces)
}

/// Save managed interfaces to the API
pub async fn save_managed_interfaces(
    token: &str,
    interfaces: Vec<ManagedInterface>,
) -> Result<SaveManagedInterfacesResponse, String> {
    let request = SaveManagedInterfacesRequest { interfaces };
    post("/api/managed-interfaces", token, &request).await
}

// ============================================================================
// Interface Configuration
// ============================================================================

/// Fetch all interface configurations
#[allow(dead_code)]
pub async fn fetch_interface_configs(token: &str) -> Result<Vec<InterfaceConfig>, String> {
    let response: InterfaceConfigsResponse = get("/api/interface-config", token).await?;
    Ok(response.configs)
}

/// Fetch a single interface configuration by name
pub async fn fetch_interface_config(
    token: &str,
    name: &str,
) -> Result<Option<InterfaceConfig>, String> {
    let response: InterfaceConfigResponse =
        get(&format!("/api/interface-config/{}", name), token).await?;
    Ok(response.config)
}

/// Save an interface configuration
pub async fn save_interface_config(
    token: &str,
    config: InterfaceConfig,
) -> Result<SaveInterfaceConfigResponse, String> {
    let request = SaveInterfaceConfigRequest { config };
    post("/api/interface-config", token, &request).await
}

/// Delete an interface configuration
#[allow(dead_code)]
pub async fn delete_interface_config(
    token: &str,
    name: &str,
) -> Result<SaveInterfaceConfigResponse, String> {
    delete(&format!("/api/interface-config/{}", name), token).await
}

// ============================================================================
// Networkd Operations
// ============================================================================

/// Apply networkd configuration - writes .network files and reloads systemd-networkd
pub async fn apply_networkd(token: &str) -> Result<ApplyConfigResponse, String> {
    post_empty("/api/apply-networkd", token).await
}

/// Get networkd configuration preview without writing to disk
pub async fn get_networkd_preview(token: &str) -> Result<NetworkdPreviewResponse, String> {
    get("/api/networkd-preview", token).await
}
