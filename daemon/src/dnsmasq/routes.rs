//! Dnsmasq API routes
//!
//! REST endpoints for managing dnsmasq DNS/DHCP configuration:
//! - Global configuration
//! - DHCP ranges
//! - Static leases
//! - DHCP options
//! - Host records
//! - CNAME records
//! - Address overrides
//! - Active leases (from lease file)
//! - Apply/Preview

use crate::Actor;
use crate::db::Database;
use crate::dnsmasq::{self, get_active_leases};
use crate::snapshots;
use axum::{
    Json, Router,
    extract::{Extension, Path, State},
    routing::{delete, get, post, put},
};
use keystone_core::api::{
    Endpoint, Req, Res, SaveAddressOverride, SaveCnameRecord, SaveDhcpOption, SaveDhcpRange,
    SaveDnsmasqConfig, SaveHostRecord, SaveStaticLease,
};
use keystone_core::{
    AddressOverridesResponse, CnameRecordsResponse, DeleteResponse, DhcpLeasesResponse,
    DhcpOptionsResponse, DhcpRangesResponse, DnsmasqApplyResponse, DnsmasqConfig,
    DnsmasqPreviewResponse, DnsmasqStateResponse, HostRecordsResponse, SaveAddressOverrideResponse,
    SaveCnameRecordResponse, SaveDhcpOptionResponse, SaveDhcpRangeResponse,
    SaveDnsmasqConfigResponse, SaveHostRecordResponse, SaveStaticLeaseResponse,
    StaticLeasesResponse,
};
use std::sync::Arc;
use tracing::info;

use crate::AppError;

/// State shared with dnsmasq routes
#[derive(Clone)]
pub struct DnsmasqState {
    pub db: Database,
}

/// Create dnsmasq router with all routes
pub fn dnsmasq_routes(state: DnsmasqState) -> Router<Arc<crate::AppState>> {
    Router::new()
        // Global state
        .route("/dnsmasq", get(get_dnsmasq_state))
        .route("/dnsmasq/config", get(get_config))
        .route(SaveDnsmasqConfig::PATH, put(save_config))
        // DHCP ranges
        .route("/dnsmasq/ranges", get(get_ranges))
        .route(SaveDhcpRange::PATH, post(save_range))
        .route("/dnsmasq/ranges/{id}", delete(delete_range))
        // Static leases
        .route("/dnsmasq/leases", get(get_static_leases))
        .route(SaveStaticLease::PATH, post(save_static_lease))
        .route("/dnsmasq/leases/{id}", delete(delete_static_lease))
        // DHCP options
        .route("/dnsmasq/options", get(get_options))
        .route(SaveDhcpOption::PATH, post(save_option))
        .route("/dnsmasq/options/{id}", delete(delete_option))
        // Host records
        .route("/dnsmasq/hosts", get(get_hosts))
        .route(SaveHostRecord::PATH, post(save_host))
        .route("/dnsmasq/hosts/{id}", delete(delete_host))
        // CNAME records
        .route("/dnsmasq/cnames", get(get_cnames))
        .route(SaveCnameRecord::PATH, post(save_cname))
        .route("/dnsmasq/cnames/{id}", delete(delete_cname))
        // Address overrides
        .route("/dnsmasq/overrides", get(get_overrides))
        .route(SaveAddressOverride::PATH, post(save_override))
        .route("/dnsmasq/overrides/{id}", delete(delete_override))
        // Active leases (from lease file)
        .route("/dnsmasq/active-leases", get(get_active_leases_endpoint))
        // Preview and Apply
        .route("/dnsmasq/preview", get(preview_dnsmasq))
        .route("/dnsmasq/apply", post(apply_dnsmasq))
        .route("/dnsmasq/status", get(get_dnsmasq_status))
        .with_state(state)
}

// ============================================================================
// Global State & Config
// ============================================================================

/// GET /dnsmasq - Get complete dnsmasq state
async fn get_dnsmasq_state(
    State(state): State<DnsmasqState>,
) -> Result<Json<DnsmasqStateResponse>, AppError> {
    info!("Getting dnsmasq state");
    let pool = state.db.pool();
    let dnsmasq_state = dnsmasq::load_dnsmasq_state(pool).await?;
    Ok(Json(dnsmasq_state))
}

/// GET /dnsmasq/config - Get global dnsmasq config
async fn get_config(State(state): State<DnsmasqState>) -> Result<Json<DnsmasqConfig>, AppError> {
    info!("Getting dnsmasq config");
    let pool = state.db.pool();
    let config = dnsmasq::load_dnsmasq_config(pool).await?;
    Ok(Json(config))
}

/// PUT /dnsmasq/config - Save global dnsmasq config
async fn save_config(
    State(state): State<DnsmasqState>,
    Json(request): Json<Req<SaveDnsmasqConfig>>,
) -> Result<Json<Res<SaveDnsmasqConfig>>, AppError> {
    info!("Saving dnsmasq config");
    let pool = state.db.pool();
    dnsmasq::save_dnsmasq_config(pool, &request.config).await?;
    Ok(Json(SaveDnsmasqConfigResponse {
        success: true,
        message: "Configuration saved".to_string(),
    }))
}

// ============================================================================
// DHCP Ranges
// ============================================================================

/// GET /dnsmasq/ranges - Get all DHCP ranges
async fn get_ranges(
    State(state): State<DnsmasqState>,
) -> Result<Json<DhcpRangesResponse>, AppError> {
    info!("Getting DHCP ranges");
    let pool = state.db.pool();
    let ranges = dnsmasq::load_dhcp_ranges(pool).await?;
    Ok(Json(DhcpRangesResponse { ranges }))
}

/// POST /dnsmasq/ranges - Create or update a DHCP range
async fn save_range(
    State(state): State<DnsmasqState>,
    Json(request): Json<Req<SaveDhcpRange>>,
) -> Result<Json<Res<SaveDhcpRange>>, AppError> {
    info!("Saving DHCP range: {}", request.range.name);

    // Validate
    if request.range.name.is_empty() {
        return Ok(Json(SaveDhcpRangeResponse {
            success: false,
            message: "Range name is required".to_string(),
            range_id: None,
        }));
    }
    if request.range.interface.is_empty() {
        return Ok(Json(SaveDhcpRangeResponse {
            success: false,
            message: "Interface is required".to_string(),
            range_id: None,
        }));
    }
    if request.range.start_address.is_empty() || request.range.end_address.is_empty() {
        return Ok(Json(SaveDhcpRangeResponse {
            success: false,
            message: "Start and end addresses are required".to_string(),
            range_id: None,
        }));
    }

    let configs = state.db.get_interface_configs().await?;
    let errors = crate::config_validation::validate_dhcp_range(&request.range, &configs);
    if !errors.is_empty() {
        return Ok(Json(SaveDhcpRangeResponse {
            success: false,
            message: errors.join("; "),
            range_id: None,
        }));
    }

    let pool = state.db.pool();
    let id = dnsmasq::save_dhcp_range(pool, &request.range).await?;
    Ok(Json(SaveDhcpRangeResponse {
        success: true,
        message: "DHCP range saved".to_string(),
        range_id: Some(id),
    }))
}

/// DELETE /dnsmasq/ranges/:id - Delete a DHCP range
async fn delete_range(
    State(state): State<DnsmasqState>,
    Path(id): Path<i64>,
) -> Result<Json<DeleteResponse>, AppError> {
    info!("Deleting DHCP range id: {}", id);
    let pool = state.db.pool();
    let deleted = dnsmasq::delete_dhcp_range(pool, id).await?;
    Ok(Json(DeleteResponse {
        success: deleted,
        message: if deleted {
            "DHCP range deleted".to_string()
        } else {
            "DHCP range not found".to_string()
        },
    }))
}

// ============================================================================
// Static Leases
// ============================================================================

/// GET /dnsmasq/leases - Get all static leases
async fn get_static_leases(
    State(state): State<DnsmasqState>,
) -> Result<Json<StaticLeasesResponse>, AppError> {
    info!("Getting static leases");
    let pool = state.db.pool();
    let leases = dnsmasq::load_static_leases(pool).await?;
    Ok(Json(StaticLeasesResponse { leases }))
}

/// POST /dnsmasq/leases - Create or update a static lease
async fn save_static_lease(
    State(state): State<DnsmasqState>,
    Json(request): Json<Req<SaveStaticLease>>,
) -> Result<Json<Res<SaveStaticLease>>, AppError> {
    info!("Saving static lease: {}", request.lease.mac_address);

    // Validate
    if request.lease.mac_address.is_empty() && request.lease.client_id.is_none() {
        return Ok(Json(SaveStaticLeaseResponse {
            success: false,
            message: "MAC address or client ID is required".to_string(),
            lease_id: None,
        }));
    }
    if request.lease.ip_address.is_empty() {
        return Ok(Json(SaveStaticLeaseResponse {
            success: false,
            message: "IP address is required".to_string(),
            lease_id: None,
        }));
    }

    let pool = state.db.pool();
    let configs = state.db.get_interface_configs().await?;
    let existing = dnsmasq::load_static_leases(pool).await?;
    let errors =
        crate::config_validation::validate_static_lease(&request.lease, &existing, &configs);
    if !errors.is_empty() {
        return Ok(Json(SaveStaticLeaseResponse {
            success: false,
            message: errors.join("; "),
            lease_id: None,
        }));
    }
    let id = dnsmasq::save_static_lease(pool, &request.lease).await?;
    Ok(Json(SaveStaticLeaseResponse {
        success: true,
        message: "Static lease saved".to_string(),
        lease_id: Some(id),
    }))
}

/// DELETE /dnsmasq/leases/:id - Delete a static lease
async fn delete_static_lease(
    State(state): State<DnsmasqState>,
    Path(id): Path<i64>,
) -> Result<Json<DeleteResponse>, AppError> {
    info!("Deleting static lease id: {}", id);
    let pool = state.db.pool();
    let deleted = dnsmasq::delete_static_lease(pool, id).await?;
    Ok(Json(DeleteResponse {
        success: deleted,
        message: if deleted {
            "Static lease deleted".to_string()
        } else {
            "Static lease not found".to_string()
        },
    }))
}

// ============================================================================
// DHCP Options
// ============================================================================

/// GET /dnsmasq/options - Get all DHCP options
async fn get_options(
    State(state): State<DnsmasqState>,
) -> Result<Json<DhcpOptionsResponse>, AppError> {
    info!("Getting DHCP options");
    let pool = state.db.pool();
    let options = dnsmasq::load_dhcp_options(pool).await?;
    Ok(Json(DhcpOptionsResponse { options }))
}

/// POST /dnsmasq/options - Create or update a DHCP option
async fn save_option(
    State(state): State<DnsmasqState>,
    Json(request): Json<Req<SaveDhcpOption>>,
) -> Result<Json<Res<SaveDhcpOption>>, AppError> {
    info!("Saving DHCP option: {}", request.option.option);

    // Validate
    if request.option.option.is_empty() {
        return Ok(Json(SaveDhcpOptionResponse {
            success: false,
            message: "Option name/number is required".to_string(),
            option_id: None,
        }));
    }
    if request.option.value.is_empty() {
        return Ok(Json(SaveDhcpOptionResponse {
            success: false,
            message: "Option value is required".to_string(),
            option_id: None,
        }));
    }

    let pool = state.db.pool();
    let id = dnsmasq::save_dhcp_option(pool, &request.option).await?;
    Ok(Json(SaveDhcpOptionResponse {
        success: true,
        message: "DHCP option saved".to_string(),
        option_id: Some(id),
    }))
}

/// DELETE /dnsmasq/options/:id - Delete a DHCP option
async fn delete_option(
    State(state): State<DnsmasqState>,
    Path(id): Path<i64>,
) -> Result<Json<DeleteResponse>, AppError> {
    info!("Deleting DHCP option id: {}", id);
    let pool = state.db.pool();
    let deleted = dnsmasq::delete_dhcp_option(pool, id).await?;
    Ok(Json(DeleteResponse {
        success: deleted,
        message: if deleted {
            "DHCP option deleted".to_string()
        } else {
            "DHCP option not found".to_string()
        },
    }))
}

// ============================================================================
// Host Records
// ============================================================================

/// GET /dnsmasq/hosts - Get all host records
async fn get_hosts(
    State(state): State<DnsmasqState>,
) -> Result<Json<HostRecordsResponse>, AppError> {
    info!("Getting host records");
    let pool = state.db.pool();
    let records = dnsmasq::load_host_records(pool).await?;
    Ok(Json(HostRecordsResponse { records }))
}

/// POST /dnsmasq/hosts - Create or update a host record
async fn save_host(
    State(state): State<DnsmasqState>,
    Json(request): Json<Req<SaveHostRecord>>,
) -> Result<Json<Res<SaveHostRecord>>, AppError> {
    info!("Saving host record");

    // Validate
    if request.record.hostnames.is_empty() {
        return Ok(Json(SaveHostRecordResponse {
            success: false,
            message: "At least one hostname is required".to_string(),
            record_id: None,
        }));
    }
    if request.record.ipv4_address.is_none() && request.record.ipv6_address.is_none() {
        return Ok(Json(SaveHostRecordResponse {
            success: false,
            message: "At least one IP address (IPv4 or IPv6) is required".to_string(),
            record_id: None,
        }));
    }

    let pool = state.db.pool();
    let id = dnsmasq::save_host_record(pool, &request.record).await?;
    Ok(Json(SaveHostRecordResponse {
        success: true,
        message: "Host record saved".to_string(),
        record_id: Some(id),
    }))
}

/// DELETE /dnsmasq/hosts/:id - Delete a host record
async fn delete_host(
    State(state): State<DnsmasqState>,
    Path(id): Path<i64>,
) -> Result<Json<DeleteResponse>, AppError> {
    info!("Deleting host record id: {}", id);
    let pool = state.db.pool();
    let deleted = dnsmasq::delete_host_record(pool, id).await?;
    Ok(Json(DeleteResponse {
        success: deleted,
        message: if deleted {
            "Host record deleted".to_string()
        } else {
            "Host record not found".to_string()
        },
    }))
}

// ============================================================================
// CNAME Records
// ============================================================================

/// GET /dnsmasq/cnames - Get all CNAME records
async fn get_cnames(
    State(state): State<DnsmasqState>,
) -> Result<Json<CnameRecordsResponse>, AppError> {
    info!("Getting CNAME records");
    let pool = state.db.pool();
    let records = dnsmasq::load_cname_records(pool).await?;
    Ok(Json(CnameRecordsResponse { records }))
}

/// POST /dnsmasq/cnames - Create or update a CNAME record
async fn save_cname(
    State(state): State<DnsmasqState>,
    Json(request): Json<Req<SaveCnameRecord>>,
) -> Result<Json<Res<SaveCnameRecord>>, AppError> {
    info!(
        "Saving CNAME record: {} -> {}",
        request.record.alias, request.record.target
    );

    // Validate
    if request.record.alias.is_empty() {
        return Ok(Json(SaveCnameRecordResponse {
            success: false,
            message: "Alias is required".to_string(),
            record_id: None,
        }));
    }
    if request.record.target.is_empty() {
        return Ok(Json(SaveCnameRecordResponse {
            success: false,
            message: "Target is required".to_string(),
            record_id: None,
        }));
    }

    let pool = state.db.pool();
    let id = dnsmasq::save_cname_record(pool, &request.record).await?;
    Ok(Json(SaveCnameRecordResponse {
        success: true,
        message: "CNAME record saved".to_string(),
        record_id: Some(id),
    }))
}

/// DELETE /dnsmasq/cnames/:id - Delete a CNAME record
async fn delete_cname(
    State(state): State<DnsmasqState>,
    Path(id): Path<i64>,
) -> Result<Json<DeleteResponse>, AppError> {
    info!("Deleting CNAME record id: {}", id);
    let pool = state.db.pool();
    let deleted = dnsmasq::delete_cname_record(pool, id).await?;
    Ok(Json(DeleteResponse {
        success: deleted,
        message: if deleted {
            "CNAME record deleted".to_string()
        } else {
            "CNAME record not found".to_string()
        },
    }))
}

// ============================================================================
// Address Overrides
// ============================================================================

/// GET /dnsmasq/overrides - Get all address overrides
async fn get_overrides(
    State(state): State<DnsmasqState>,
) -> Result<Json<AddressOverridesResponse>, AppError> {
    info!("Getting address overrides");
    let pool = state.db.pool();
    let overrides = dnsmasq::load_address_overrides(pool).await?;
    Ok(Json(AddressOverridesResponse { overrides }))
}

/// POST /dnsmasq/overrides - Create or update an address override
async fn save_override(
    State(state): State<DnsmasqState>,
    Json(request): Json<Req<SaveAddressOverride>>,
) -> Result<Json<Res<SaveAddressOverride>>, AppError> {
    info!("Saving address override: {}", request.override_entry.domain);

    // Validate
    if request.override_entry.domain.is_empty() {
        return Ok(Json(SaveAddressOverrideResponse {
            success: false,
            message: "Domain is required".to_string(),
            override_id: None,
        }));
    }

    let pool = state.db.pool();
    let id = dnsmasq::save_address_override(pool, &request.override_entry).await?;
    Ok(Json(SaveAddressOverrideResponse {
        success: true,
        message: "Address override saved".to_string(),
        override_id: Some(id),
    }))
}

/// DELETE /dnsmasq/overrides/:id - Delete an address override
async fn delete_override(
    State(state): State<DnsmasqState>,
    Path(id): Path<i64>,
) -> Result<Json<DeleteResponse>, AppError> {
    info!("Deleting address override id: {}", id);
    let pool = state.db.pool();
    let deleted = dnsmasq::delete_address_override(pool, id).await?;
    Ok(Json(DeleteResponse {
        success: deleted,
        message: if deleted {
            "Address override deleted".to_string()
        } else {
            "Address override not found".to_string()
        },
    }))
}

// ============================================================================
// Active Leases
// ============================================================================

/// GET /dnsmasq/active-leases - Get current active DHCP leases from lease file
async fn get_active_leases_endpoint(
    State(_state): State<DnsmasqState>,
) -> Result<Json<DhcpLeasesResponse>, AppError> {
    info!("Getting active DHCP leases");
    let leases = get_active_leases()?;
    Ok(Json(DhcpLeasesResponse { leases }))
}

// ============================================================================
// Preview & Apply
// ============================================================================

/// GET /dnsmasq/preview - Preview generated dnsmasq config file
async fn preview_dnsmasq(
    State(state): State<DnsmasqState>,
) -> Result<Json<DnsmasqPreviewResponse>, AppError> {
    info!("Generating dnsmasq config preview");
    let pool = state.db.pool();
    let config_content = dnsmasq::preview_dnsmasq_config(pool).await?;
    Ok(Json(DnsmasqPreviewResponse { config_content }))
}

/// POST /dnsmasq/apply - Apply dnsmasq configuration
async fn apply_dnsmasq(
    State(state): State<DnsmasqState>,
    actor: Option<Extension<Actor>>,
) -> Result<Json<DnsmasqApplyResponse>, AppError> {
    info!("Applying dnsmasq configuration");

    // Check if configuration changes are disabled
    let global_settings = state.db.get_global_settings().await?;
    if global_settings.config_changes_disabled {
        return Ok(Json(DnsmasqApplyResponse {
            success: false,
            message: "Configuration changes are disabled. Unlock in Settings to apply changes."
                .to_string(),
        }));
    }

    let pool = state.db.pool();

    match dnsmasq::apply_dnsmasq_config(pool).await {
        Ok(()) => {
            let actor = actor.as_ref().map(|Extension(actor)| actor.0.as_str());
            snapshots::record_applied(&state.db, actor, None, "dnsmasq apply").await;
            Ok(Json(DnsmasqApplyResponse {
                success: true,
                message: "dnsmasq configuration applied successfully".to_string(),
            }))
        }
        Err(e) => Ok(Json(DnsmasqApplyResponse {
            success: false,
            message: format!("Failed to apply dnsmasq configuration: {}", e),
        })),
    }
}

/// GET /dnsmasq/status - Get dnsmasq service status
async fn get_dnsmasq_status(
    State(_state): State<DnsmasqState>,
) -> Result<Json<dnsmasq::DnsmasqServiceStatus>, AppError> {
    info!("Getting dnsmasq status");
    let status = dnsmasq::get_dnsmasq_status();
    Ok(Json(status))
}
