//! Host resource information API

use keystone_core::SystemInfo;

use super::client::get;

/// Fetch CPU, memory, disk and uptime figures for the dashboard
pub async fn fetch_system_info(token: &str) -> Result<SystemInfo, String> {
    get("/api/system/info", token).await
}
