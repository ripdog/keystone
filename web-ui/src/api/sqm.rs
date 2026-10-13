//! Traffic shaping (SQM) API functions

use keystone_core::api::SaveSqmConfig;
use keystone_core::sqm::{SaveSqmConfigRequest, SqmConfig, SqmStateResponse, SqmStatusResponse};

use super::client::{call, get};

/// Fetch the saved SQM configuration and the interfaces to choose from
pub async fn fetch_sqm_state(token: &str) -> Result<SqmStateResponse, String> {
    get("/api/sqm", token).await
}

/// Save the SQM configuration. Nothing is applied until configuration is applied.
pub async fn save_sqm_config(token: &str, config: SqmConfig) -> Result<(), String> {
    let response = call::<SaveSqmConfig>(token, &SaveSqmConfigRequest { config }).await?;
    if response.success {
        Ok(())
    } else {
        Err(response.message)
    }
}

/// Fetch live shaper counters for the applied configuration
pub async fn fetch_sqm_status(token: &str) -> Result<SqmStatusResponse, String> {
    get("/api/sqm/status", token).await
}
