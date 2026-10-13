//! UPnP / NAT-PMP API functions

use keystone_core::api::SaveUpnpConfig;
use keystone_core::upnp::{
    SaveUpnpConfigRequest, UpnpConfig, UpnpStateResponse, UpnpStatusResponse,
};

use super::client::{call, get};

/// Fetch the saved UPnP configuration, the interfaces and the binary check
pub async fn fetch_upnp_state(token: &str) -> Result<UpnpStateResponse, String> {
    get("/api/upnp", token).await
}

/// Save the UPnP configuration. Nothing is applied until configuration is applied.
pub async fn save_upnp_config(token: &str, config: UpnpConfig) -> Result<(), String> {
    let response = call::<SaveUpnpConfig>(token, &SaveUpnpConfigRequest { config }).await?;
    if response.success {
        Ok(())
    } else {
        Err(response.message)
    }
}

/// Fetch the service state and the live port mappings
pub async fn fetch_upnp_status(token: &str) -> Result<UpnpStatusResponse, String> {
    get("/api/upnp/status", token).await
}
