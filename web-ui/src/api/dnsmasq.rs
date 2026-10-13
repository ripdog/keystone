//! Dnsmasq (DNS/DHCP) configuration API functions

use keystone_core::api::{
    SaveAddressOverride, SaveCnameRecord, SaveDhcpOption, SaveDhcpRange, SaveDnsmasqConfig,
    SaveHostRecord, SaveStaticLease,
};
use keystone_core::{
    DhcpLease, DhcpLeasesResponse, DnsmasqAddressOverride, DnsmasqCnameRecord, DnsmasqConfig,
    DnsmasqDhcpOption, DnsmasqDhcpRange, DnsmasqHostRecord, DnsmasqPreviewResponse,
    DnsmasqStateResponse, DnsmasqStaticLease, SaveAddressOverrideRequest, SaveCnameRecordRequest,
    SaveDhcpOptionRequest, SaveDhcpRangeRequest, SaveDnsmasqConfigRequest, SaveHostRecordRequest,
    SaveStaticLeaseRequest,
};

use super::client::{call, delete_no_response, get};

/// Turn a `{success, message, id}` save response into the saved id.
fn saved_id(success: bool, message: String, id: Option<i64>) -> Result<i64, String> {
    if success {
        Ok(id.unwrap_or(0))
    } else {
        Err(message)
    }
}

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
    let response = call::<SaveDnsmasqConfig>(token, &SaveDnsmasqConfigRequest { config }).await?;
    if response.success {
        Ok(())
    } else {
        Err(response.message)
    }
}

// ============================================================================
// DHCP Ranges
// ============================================================================

/// Save a DHCP range
pub async fn save_dhcp_range(token: &str, range: DnsmasqDhcpRange) -> Result<i64, String> {
    let response = call::<SaveDhcpRange>(token, &SaveDhcpRangeRequest { range }).await?;
    saved_id(response.success, response.message, response.range_id)
}

/// Delete a DHCP range
pub async fn delete_dhcp_range(token: &str, id: i64) -> Result<(), String> {
    delete_no_response(&format!("/api/dnsmasq/ranges/{}", id), token).await
}

// ============================================================================
// Static Leases
// ============================================================================

/// Save a static lease
pub async fn save_static_lease(token: &str, lease: DnsmasqStaticLease) -> Result<i64, String> {
    let response = call::<SaveStaticLease>(token, &SaveStaticLeaseRequest { lease }).await?;
    saved_id(response.success, response.message, response.lease_id)
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

/// Save a DHCP option
pub async fn save_dhcp_option(token: &str, option: DnsmasqDhcpOption) -> Result<i64, String> {
    let response = call::<SaveDhcpOption>(token, &SaveDhcpOptionRequest { option }).await?;
    saved_id(response.success, response.message, response.option_id)
}

/// Delete a DHCP option
pub async fn delete_dhcp_option(token: &str, id: i64) -> Result<(), String> {
    delete_no_response(&format!("/api/dnsmasq/options/{}", id), token).await
}

// ============================================================================
// Host Records
// ============================================================================

/// Save a host record
pub async fn save_host_record(token: &str, record: DnsmasqHostRecord) -> Result<i64, String> {
    let response = call::<SaveHostRecord>(token, &SaveHostRecordRequest { record }).await?;
    saved_id(response.success, response.message, response.record_id)
}

/// Delete a host record
pub async fn delete_host_record(token: &str, id: i64) -> Result<(), String> {
    delete_no_response(&format!("/api/dnsmasq/hosts/{}", id), token).await
}

// ============================================================================
// CNAME Records
// ============================================================================

/// Save a CNAME record
pub async fn save_cname_record(token: &str, record: DnsmasqCnameRecord) -> Result<i64, String> {
    let response = call::<SaveCnameRecord>(token, &SaveCnameRecordRequest { record }).await?;
    saved_id(response.success, response.message, response.record_id)
}

/// Delete a CNAME record
pub async fn delete_cname_record(token: &str, id: i64) -> Result<(), String> {
    delete_no_response(&format!("/api/dnsmasq/cnames/{}", id), token).await
}

// ============================================================================
// Address Overrides
// ============================================================================

/// Save an address override
pub async fn save_address_override(
    token: &str,
    override_entry: DnsmasqAddressOverride,
) -> Result<i64, String> {
    let response =
        call::<SaveAddressOverride>(token, &SaveAddressOverrideRequest { override_entry }).await?;
    saved_id(response.success, response.message, response.override_id)
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
