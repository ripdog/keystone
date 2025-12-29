//! Dashboard API functions

use keystone_core::DashboardResponse;

use super::client::get;

/// Fetch dashboard data (state + interface counters)
pub async fn fetch_dashboard(token: &str) -> Result<DashboardResponse, String> {
    get("/api/dashboard", token).await
}
