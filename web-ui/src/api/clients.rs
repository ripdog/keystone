//! LAN client inventory API functions

use keystone_core::{Client, ClientTraffic, ClientTrafficResponse, ClientsResponse};

use super::client::get;

/// Fetch every device seen on the LAN, one record per MAC address
pub async fn fetch_clients(token: &str) -> Result<Vec<Client>, String> {
    let response: ClientsResponse = get("/api/clients", token).await?;
    Ok(response.clients)
}

/// Fetch the last minute of WAN throughput for the given devices (by MAC).
pub async fn fetch_client_traffic(
    token: &str,
    macs: &[String],
) -> Result<Vec<ClientTraffic>, String> {
    // MACs are hex digits and colons, so they are safe in a query string as is.
    let url = format!("/api/clients/traffic?macs={}", macs.join(","));
    let response: ClientTrafficResponse = get(&url, token).await?;
    Ok(response.clients)
}
