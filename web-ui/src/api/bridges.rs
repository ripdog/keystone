//! Bridge configuration API functions

use keystone_core::api::SaveBridge;
use keystone_core::{
    BridgeConfig, BridgeConfigsResponse, DeleteBridgeResponse, SaveBridgeConfigRequest,
    SaveBridgeConfigResponse,
};

use super::client::{call, delete, get};

/// Fetch all bridge configurations
pub async fn fetch_bridges(token: &str) -> Result<Vec<BridgeConfig>, String> {
    let response: BridgeConfigsResponse = get("/api/bridges", token).await?;
    Ok(response.configs)
}

/// Save a bridge configuration (create or update)
pub async fn save_bridge(
    token: &str,
    config: BridgeConfig,
) -> Result<SaveBridgeConfigResponse, String> {
    let request = SaveBridgeConfigRequest { config };
    call::<SaveBridge>(token, &request).await
}

/// Delete a bridge configuration
pub async fn delete_bridge(token: &str, id: i64) -> Result<DeleteBridgeResponse, String> {
    delete(&format!("/api/bridges/{}", id), token).await
}
