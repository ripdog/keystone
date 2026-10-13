//! Dnsmasq (DNS/DHCP) configuration API functions

use keystone_core::{
    DhcpLease, DhcpLeasesResponse, DnsmasqAddressOverride, DnsmasqApplyResponse,
    DnsmasqCnameRecord, DnsmasqConfig, DnsmasqDhcpOption, DnsmasqDhcpRange, DnsmasqHostRecord,
    DnsmasqPreviewResponse, DnsmasqStateResponse, DnsmasqStaticLease, SaveStaticLeaseRequest,
};

use super::client::{delete_no_response, get, post, post_empty, put_no_response};

// ============================================================================
// State
// ============================================================================

/// Fetch complete dnsmasq state
pub async fn fetch_dnsmasq_state(token: &str) -> Result<DnsmasqStateResponse, String> {
    get("/api/dnsmasq", token).await
}

// ============================================================================
// Global Config
// ============================================================================

/// Save global dnsmasq configuration
pub async fn save_dnsmasq_config(token: &str, config: DnsmasqConfig) -> Result<(), String> {
    put_no_response("/api/dnsmasq/config", token, &config).await
}

// ============================================================================
// DHCP Ranges
// ============================================================================

/// Response type for saving DHCP ranges
#[derive(serde::Deserialize)]
struct SaveRangeResponse {
    success: bool,
    message: String,
    range_id: Option<i64>,
}

/// Save a DHCP range
pub async fn save_dhcp_range(token: &str, range: DnsmasqDhcpRange) -> Result<i64, String> {
    let response: SaveRangeResponse = post("/api/dnsmasq/ranges", token, &range).await?;
    if response.success {
        Ok(response.range_id.unwrap_or(0))
    } else {
        Err(response.message)
    }
}

/// Delete a DHCP range
pub async fn delete_dhcp_range(token: &str, id: i64) -> Result<(), String> {
    delete_no_response(&format!("/api/dnsmasq/ranges/{}", id), token).await
}

// ============================================================================
// Static Leases
// ============================================================================

/// Response type for saving static leases
#[derive(serde::Deserialize)]
struct SaveLeaseResponse {
    success: bool,
    message: String,
    lease_id: Option<i64>,
}

/// Save a static lease
pub async fn save_static_lease(token: &str, lease: DnsmasqStaticLease) -> Result<i64, String> {
    let request = SaveStaticLeaseRequest { lease };
    let response: SaveLeaseResponse = post("/api/dnsmasq/leases", token, &request).await?;
    if response.success {
        Ok(response.lease_id.unwrap_or(0))
    } else {
        Err(response.message)
    }
}

/// Delete a static lease
pub async fn delete_static_lease(token: &str, id: i64) -> Result<(), String> {
    delete_no_response(&format!("/api/dnsmasq/leases/{}", id), token).await
}

/// Fetch active DHCP leases
pub async fn fetch_active_leases(token: &str) -> Result<Vec<DhcpLease>, String> {
    let response: DhcpLeasesResponse = get("/api/dnsmasq/active-leases", token).await?;
    Ok(response.leases)
}

// ============================================================================
// DHCP Options
// ============================================================================

/// Response type for saving DHCP options
#[derive(serde::Deserialize)]
struct SaveOptionResponse {
    success: bool,
    message: String,
    option_id: Option<i64>,
}

/// Save a DHCP option
pub async fn save_dhcp_option(token: &str, option: DnsmasqDhcpOption) -> Result<i64, String> {
    let response: SaveOptionResponse = post("/api/dnsmasq/options", token, &option).await?;
    if response.success {
        Ok(response.option_id.unwrap_or(0))
    } else {
        Err(response.message)
    }
}

/// Delete a DHCP option
pub async fn delete_dhcp_option(token: &str, id: i64) -> Result<(), String> {
    delete_no_response(&format!("/api/dnsmasq/options/{}", id), token).await
}

// ============================================================================
// Host Records
// ============================================================================

/// Response type for saving host records
#[derive(serde::Deserialize)]
struct SaveHostRecordResponse {
    success: bool,
    message: String,
    record_id: Option<i64>,
}

/// Save a host record
pub async fn save_host_record(token: &str, record: DnsmasqHostRecord) -> Result<i64, String> {
    let response: SaveHostRecordResponse = post("/api/dnsmasq/hosts", token, &record).await?;
    if response.success {
        Ok(response.record_id.unwrap_or(0))
    } else {
        Err(response.message)
    }
}

/// Delete a host record
pub async fn delete_host_record(token: &str, id: i64) -> Result<(), String> {
    delete_no_response(&format!("/api/dnsmasq/hosts/{}", id), token).await
}

// ============================================================================
// CNAME Records
// ============================================================================

/// Response type for saving CNAME records
#[derive(serde::Deserialize)]
struct SaveCnameResponse {
    success: bool,
    message: String,
    record_id: Option<i64>,
}

/// Save a CNAME record
pub async fn save_cname_record(token: &str, record: DnsmasqCnameRecord) -> Result<i64, String> {
    let response: SaveCnameResponse = post("/api/dnsmasq/cnames", token, &record).await?;
    if response.success {
        Ok(response.record_id.unwrap_or(0))
    } else {
        Err(response.message)
    }
}

/// Delete a CNAME record
pub async fn delete_cname_record(token: &str, id: i64) -> Result<(), String> {
    delete_no_response(&format!("/api/dnsmasq/cnames/{}", id), token).await
}

// ============================================================================
// Address Overrides
// ============================================================================

/// Response type for saving address overrides
#[derive(serde::Deserialize)]
struct SaveOverrideResponse {
    success: bool,
    message: String,
    override_id: Option<i64>,
}

/// Save an address override
pub async fn save_address_override(
    token: &str,
    override_entry: DnsmasqAddressOverride,
) -> Result<i64, String> {
    let response: SaveOverrideResponse =
        post("/api/dnsmasq/overrides", token, &override_entry).await?;
    if response.success {
        Ok(response.override_id.unwrap_or(0))
    } else {
        Err(response.message)
    }
}

/// Delete an address override
pub async fn delete_address_override(token: &str, id: i64) -> Result<(), String> {
    delete_no_response(&format!("/api/dnsmasq/overrides/{}", id), token).await
}

// ============================================================================
// Preview / Apply
// ============================================================================

/// Fetch dnsmasq config preview
pub async fn fetch_dnsmasq_preview(token: &str) -> Result<String, String> {
    let response: DnsmasqPreviewResponse = get("/api/dnsmasq/preview", token).await?;
    Ok(response.config_content)
}

/// Apply dnsmasq configuration
pub async fn apply_dnsmasq(token: &str) -> Result<DnsmasqApplyResponse, String> {
    post_empty("/api/dnsmasq/apply", token).await
}
