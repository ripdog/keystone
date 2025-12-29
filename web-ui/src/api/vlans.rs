//! VLAN configuration API functions

use keystone_core::{
    DeleteVlanResponse, SaveVlanConfigRequest, SaveVlanConfigResponse, VlanConfig,
    VlanConfigResponse, VlanConfigsResponse,
};

use super::client::{delete, get, post};

/// Fetch all VLAN configurations
pub async fn fetch_vlans(token: &str) -> Result<Vec<VlanConfig>, String> {
    let response: VlanConfigsResponse = get("/api/vlans", token).await?;
    Ok(response.configs)
}

/// Fetch a single VLAN configuration by ID
#[allow(dead_code)]
pub async fn fetch_vlan(token: &str, id: i64) -> Result<Option<VlanConfig>, String> {
    let response: VlanConfigResponse = get(&format!("/api/vlans/{}", id), token).await?;
    Ok(response.config)
}

/// Save a VLAN configuration (create or update)
pub async fn save_vlan(token: &str, config: VlanConfig) -> Result<SaveVlanConfigResponse, String> {
    let request = SaveVlanConfigRequest { config };
    post("/api/vlans", token, &request).await
}

/// Delete a VLAN configuration
pub async fn delete_vlan(token: &str, id: i64) -> Result<DeleteVlanResponse, String> {
    delete(&format!("/api/vlans/{}", id), token).await
}
