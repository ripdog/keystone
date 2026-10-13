//! VLAN configuration API functions

use keystone_core::api::SaveVlan;
use keystone_core::{
    DeleteVlanResponse, SaveVlanConfigRequest, SaveVlanConfigResponse, VlanConfig,
    VlanConfigsResponse,
};

use super::client::{call, delete, get};

/// Fetch all VLAN configurations
pub async fn fetch_vlans(token: &str) -> Result<Vec<VlanConfig>, String> {
    let response: VlanConfigsResponse = get("/api/vlans", token).await?;
    Ok(response.configs)
}

/// Save a VLAN configuration (create or update)
pub async fn save_vlan(token: &str, config: VlanConfig) -> Result<SaveVlanConfigResponse, String> {
    let request = SaveVlanConfigRequest { config };
    call::<SaveVlan>(token, &request).await
}

/// Delete a VLAN configuration
pub async fn delete_vlan(token: &str, id: i64) -> Result<DeleteVlanResponse, String> {
    delete(&format!("/api/vlans/{}", id), token).await
}
