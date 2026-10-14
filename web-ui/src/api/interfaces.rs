//! Interface configuration API functions

use keystone_core::api::{RenameInterface, SaveInterfaceConfig, SaveManagedInterfaces};
use keystone_core::{
    InterfaceConfig, InterfaceConfigResponse, ManagedInterface, ManagedInterfacesResponse,
    NetworkdPreviewResponse, RenameInterfaceRequest, RenameInterfaceResponse,
    RenewInterfaceResponse, SaveInterfaceConfigRequest, SaveInterfaceConfigResponse,
    SaveManagedInterfacesRequest, SaveManagedInterfacesResponse, SystemState,
};

use super::client::{call, call_with, get, post_empty};

// ============================================================================
// Runtime interface discovery
// ============================================================================

/// Fetch basic system state, including discovered network interfaces.
pub async fn fetch_system_state(token: &str) -> Result<SystemState, String> {
    get("/api/state", token).await
}

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
    call::<SaveManagedInterfaces>(token, &request).await
}

// ============================================================================
// Interface Configuration
// ============================================================================

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
    call::<SaveInterfaceConfig>(token, &request).await
}

// ============================================================================
// Networkd Operations
// ============================================================================

/// Request networkd to renew the dynamic configuration of one managed link.
pub async fn renew_interface(token: &str, name: &str) -> Result<RenewInterfaceResponse, String> {
    post_empty(&format!("/api/interfaces/{name}/renew"), token).await
}

/// Ask networkd to re-read and re-apply one managed link's `.network` file.
pub async fn reconfigure_interface(
    token: &str,
    name: &str,
) -> Result<RenewInterfaceResponse, String> {
    post_empty(&format!("/api/interfaces/{name}/reconfigure"), token).await
}

/// Get networkd configuration preview without writing to disk
pub async fn get_networkd_preview(token: &str) -> Result<NetworkdPreviewResponse, String> {
    get("/api/networkd-preview", token).await
}

/// Give a physical interface a persistent custom name and apply the result.
pub async fn rename_interface(
    token: &str,
    name: &str,
    new_name: &str,
) -> Result<RenameInterfaceResponse, String> {
    let request = RenameInterfaceRequest {
        new_name: new_name.to_string(),
    };
    call_with::<RenameInterface>(token, &[("name", name)], &request).await
}
