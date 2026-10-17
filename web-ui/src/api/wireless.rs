//! Wi-Fi access point API functions

use keystone_core::api::SaveWirelessConfig;
use keystone_core::wireless::{
    SaveWirelessConfigRequest, WirelessConfig, WirelessStateResponse, WirelessStatusResponse,
};

use super::client::{call, get};

/// Fetch the saved access point configuration, the interfaces and the tool checks
pub async fn fetch_wireless_state(token: &str) -> Result<WirelessStateResponse, String> {
    get("/api/wireless", token).await
}

/// Save the access point configuration. Nothing is applied until configuration is applied.
pub async fn save_wireless_config(token: &str, config: WirelessConfig) -> Result<(), String> {
    let response = call::<SaveWirelessConfig>(token, &SaveWirelessConfigRequest { config }).await?;
    if response.success {
        Ok(())
    } else {
        Err(response.message)
    }
}

/// Fetch the service state and the associated stations
pub async fn fetch_wireless_status(token: &str) -> Result<WirelessStatusResponse, String> {
    get("/api/wireless/status", token).await
}
