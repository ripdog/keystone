//! API client functions for systemd service management

use crate::api::client;
use keystone_core::{
    SystemdUnit, SystemdUnitControlResponse, SystemdUnitDetail, SystemdUnitDetailResponse,
    SystemdUnitsResponse,
};

/// Fetch list of systemd units
pub async fn fetch_units(token: &str, keystone_only: bool) -> Result<Vec<SystemdUnit>, String> {
    let url = format!("/api/systemd/units?keystone_only={}", keystone_only);
    let response: SystemdUnitsResponse = client::get(&url, token).await?;
    Ok(response.units)
}

/// Fetch detailed info for a specific unit
pub async fn fetch_unit_detail(
    token: &str,
    unit_name: &str,
) -> Result<Option<SystemdUnitDetail>, String> {
    let url = format!("/api/systemd/units/{}", urlencoding::encode(unit_name));
    let response: SystemdUnitDetailResponse = client::get(&url, token).await?;
    Ok(response.unit)
}

/// Start a systemd unit
pub async fn start_unit(token: &str, unit_name: &str) -> Result<SystemdUnitControlResponse, String> {
    let url = format!("/api/systemd/units/{}/start", urlencoding::encode(unit_name));
    client::post_empty(&url, token).await
}

/// Stop a systemd unit
pub async fn stop_unit(token: &str, unit_name: &str) -> Result<SystemdUnitControlResponse, String> {
    let url = format!("/api/systemd/units/{}/stop", urlencoding::encode(unit_name));
    client::post_empty(&url, token).await
}

/// Restart a systemd unit
pub async fn restart_unit(
    token: &str,
    unit_name: &str,
) -> Result<SystemdUnitControlResponse, String> {
    let url = format!(
        "/api/systemd/units/{}/restart",
        urlencoding::encode(unit_name)
    );
    client::post_empty(&url, token).await
}

/// Enable a systemd unit (start on boot)
pub async fn enable_unit(
    token: &str,
    unit_name: &str,
) -> Result<SystemdUnitControlResponse, String> {
    let url = format!(
        "/api/systemd/units/{}/enable",
        urlencoding::encode(unit_name)
    );
    client::post_empty(&url, token).await
}

/// Disable a systemd unit (don't start on boot)
pub async fn disable_unit(
    token: &str,
    unit_name: &str,
) -> Result<SystemdUnitControlResponse, String> {
    let url = format!(
        "/api/systemd/units/{}/disable",
        urlencoding::encode(unit_name)
    );
    client::post_empty(&url, token).await
}
