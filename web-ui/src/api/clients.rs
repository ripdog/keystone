//! LAN client inventory API functions

use keystone_core::{Client, ClientsResponse};

use super::client::get;

/// Fetch every device seen on the LAN, one record per MAC address
pub async fn fetch_clients(token: &str) -> Result<Vec<Client>, String> {
    let response: ClientsResponse = get("/api/clients", token).await?;
    Ok(response.clients)
}
