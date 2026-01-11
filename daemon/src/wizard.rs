//! Wizard API routes
//!
//! Handles setup wizard state and progression.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use keystone_core::{
    DhcpMode, FirewallPolicy, FirewallZone, InterfaceConfig, InterfaceRole, WizardAdvanceRequest,
    WizardAdvanceResponse, WizardInterfaceAssignment, WizardSaveInterfacesRequest,
    WizardSaveInterfacesResponse, WizardSkipRequest, WizardSkipResponse, WizardState,
    WizardStateResponse, WizardStep,
};
use tracing::{info, warn};

use crate::{AppError, db::Database, status};

/// Create wizard routes
pub fn wizard_routes(db: Database) -> Router<Arc<crate::AppState>> {
    Router::new()
        .route("/wizard", get(get_wizard_state))
        .route("/wizard/advance", post(advance_wizard))
        .route("/wizard/skip", post(skip_wizard))
        .route("/wizard/interfaces", post(save_wizard_interfaces))
        .with_state(db)
}

/// GET /wizard - Get current wizard state
async fn get_wizard_state(
    State(db): State<Database>,
) -> Result<Json<WizardStateResponse>, AppError> {
    info!("Getting wizard state");

    let settings = db.get_global_settings().await?;
    let current_step = WizardStep::from_u8(settings.wizard_step);

    // Include system status for the checks step
    let system_status = if current_step == WizardStep::PasswordChanged
        || current_step == WizardStep::SystemChecksCompleted
    {
        Some(status::perform_all_checks(settings.setup_complete))
    } else {
        None
    };

    let state = WizardState {
        current_step,
        is_complete: current_step.is_complete(),
        total_steps: WizardStep::Complete.as_u8(),
        system_status,
    };

    Ok(Json(WizardStateResponse { state }))
}

/// POST /wizard/advance - Advance to next wizard step
async fn advance_wizard(
    State(db): State<Database>,
    Json(request): Json<WizardAdvanceRequest>,
) -> Result<Json<WizardAdvanceResponse>, AppError> {
    info!("Advancing wizard from step: {:?}", request.completing_step);

    let settings = db.get_global_settings().await?;
    let current_step = WizardStep::from_u8(settings.wizard_step);

    // Validate that we're completing the current step
    if request.completing_step != current_step {
        return Ok(Json(WizardAdvanceResponse {
            success: false,
            message: format!(
                "Cannot complete step {:?} when current step is {:?}",
                request.completing_step, current_step
            ),
            new_step: current_step,
        }));
    }

    // Validate step-specific requirements
    match current_step {
        WizardStep::NotStarted => {
            // Just need to acknowledge the welcome screen
        }
        WizardStep::PasswordChanged => {
            // Password was changed; only allow proceeding if system checks pass.
            // Never trust the client to have run checks.
            let status = status::perform_all_checks(settings.setup_complete);
            if !status.all_checks_pass {
                return Ok(Json(WizardAdvanceResponse {
                    success: false,
                    message: format!(
                        "Cannot proceed: {} errors and {} warnings remain",
                        status.error_count, status.warning_count
                    ),
                    new_step: current_step,
                }));
            }
        }
        WizardStep::SystemChecksCompleted => {
            // System checks were already performed in the previous screen.
            // Don't re-run them here; this step is about interface assignment.

            // Require that at least one firewall zone exists (wizard creates wan/lan).
            let zones = db.get_firewall_zones().await?;
            if zones.is_empty() {
                return Ok(Json(WizardAdvanceResponse {
                    success: false,
                    message: "Please configure at least one firewall zone before proceeding"
                        .to_string(),
                    new_step: current_step,
                }));
            }
        }
        WizardStep::InterfacesAssigned => {
            // Final step - mark as complete
        }
        WizardStep::Complete => {
            return Ok(Json(WizardAdvanceResponse {
                success: true,
                message: "Wizard is already complete".to_string(),
                new_step: WizardStep::Complete,
            }));
        }
    }

    let new_step = current_step.next();
    db.set_wizard_step(new_step).await?;

    info!("Wizard advanced to step: {:?}", new_step);

    Ok(Json(WizardAdvanceResponse {
        success: true,
        message: format!("Advanced to step: {}", new_step.name()),
        new_step,
    }))
}

/// POST /wizard/skip - Skip the wizard entirely
async fn skip_wizard(
    State(db): State<Database>,
    Json(request): Json<WizardSkipRequest>,
) -> Result<Json<WizardSkipResponse>, AppError> {
    if !request.confirm_skip {
        return Ok(Json(WizardSkipResponse {
            success: false,
            message: "Must confirm skip by setting confirm_skip to true".to_string(),
        }));
    }

    warn!("Wizard being skipped by user request");

    db.set_wizard_step(WizardStep::Complete).await?;

    Ok(Json(WizardSkipResponse {
        success: true,
        message: "Wizard skipped. You can configure settings manually.".to_string(),
    }))
}

/// POST /wizard/interfaces - Save interface assignments and create zones
async fn save_wizard_interfaces(
    State(db): State<Database>,
    Json(request): Json<WizardSaveInterfacesRequest>,
) -> Result<Json<WizardSaveInterfacesResponse>, AppError> {
    info!(
        "Saving wizard interface assignments: {:?}",
        request.assignments
    );

    if request.assignments.is_empty() {
        return Ok(Json(WizardSaveInterfacesResponse {
            success: false,
            message: "No interfaces provided".to_string(),
        }));
    }

    // Group interfaces by role
    let wan_interfaces: Vec<_> = request
        .assignments
        .iter()
        .filter(|a| a.role == InterfaceRole::WAN)
        .collect();
    let lan_interfaces: Vec<_> = request
        .assignments
        .iter()
        .filter(|a| a.role == InterfaceRole::LAN)
        .collect();

    // Validate: need at least one WAN and one LAN
    if wan_interfaces.is_empty() {
        return Ok(Json(WizardSaveInterfacesResponse {
            success: false,
            message: "At least one WAN interface is required".to_string(),
        }));
    }
    if lan_interfaces.is_empty() {
        return Ok(Json(WizardSaveInterfacesResponse {
            success: false,
            message: "At least one LAN interface is required".to_string(),
        }));
    }

    // Create or update interface configs
    for assignment in &request.assignments {
        let config = create_interface_config(assignment);
        db.save_interface_config(&config).await?;
    }

    // Create firewall zones if they don't exist
    let existing_zones = db.get_firewall_zones().await?;

    // Create WAN zone
    let wan_zone_exists = existing_zones
        .iter()
        .any(|z| z.name.to_lowercase() == "wan");
    if !wan_zone_exists {
        let wan_zone = FirewallZone {
            id: None,
            name: "wan".to_string(),
            description: Some("Internet-facing interfaces".to_string()),
            interfaces: wan_interfaces.iter().map(|a| a.name.clone()).collect(),
            default_input_policy: FirewallPolicy::Drop,
            default_forward_policy: FirewallPolicy::Drop,
        };
        db.save_firewall_zone(&wan_zone).await?;
        info!(
            "Created WAN zone with interfaces: {:?}",
            wan_zone.interfaces
        );
    } else {
        info!("WAN zone already exists, skipping creation");
    }

    // Create LAN zone
    let lan_zone_exists = existing_zones
        .iter()
        .any(|z| z.name.to_lowercase() == "lan");
    if !lan_zone_exists {
        let lan_zone = FirewallZone {
            id: None,
            name: "lan".to_string(),
            description: Some("Local network interfaces".to_string()),
            interfaces: lan_interfaces.iter().map(|a| a.name.clone()).collect(),
            default_input_policy: FirewallPolicy::Accept,
            default_forward_policy: FirewallPolicy::Accept,
        };
        db.save_firewall_zone(&lan_zone).await?;
        info!(
            "Created LAN zone with interfaces: {:?}",
            lan_zone.interfaces
        );
    } else {
        info!("LAN zone already exists, skipping creation");
    }

    // Create zone forward policy (LAN -> WAN)
    let existing_forwards = db.get_zone_forwards().await?;
    let forward_exists = existing_forwards
        .iter()
        .any(|f| f.source_zone == "lan" && f.dest_zone == "wan");

    if !forward_exists {
        use keystone_core::{FirewallAction, ZoneForwardPolicy};
        let forward = ZoneForwardPolicy {
            id: None,
            source_zone: "lan".to_string(),
            dest_zone: "wan".to_string(),
            policy: FirewallAction::Accept,
            enabled: true,
        };
        db.save_zone_forward(&forward).await?;
        info!("Created LAN -> WAN forward policy");
    }

    Ok(Json(WizardSaveInterfacesResponse {
        success: true,
        message: format!(
            "Configured {} WAN and {} LAN interfaces",
            wan_interfaces.len(),
            lan_interfaces.len()
        ),
    }))
}

/// Helper to create InterfaceConfig from wizard assignment
fn create_interface_config(assignment: &WizardInterfaceAssignment) -> InterfaceConfig {
    let mut config = InterfaceConfig {
        id: None,
        name: assignment.name.clone(),
        role: assignment.role,
        enabled: true,
        description: Some(format!("{} interface", assignment.role)),
        ..Default::default()
    };

    match assignment.role {
        InterfaceRole::WAN => {
            if assignment.use_dhcp {
                config.dhcp_mode = DhcpMode::Yes;
            } else if let Some(ref ip) = assignment.static_ip {
                config.addresses.push(keystone_core::StaticAddress {
                    address: ip.clone(),
                    label: None,
                    scope: keystone_core::AddressScope::Global,
                });
            }
            // WAN interfaces typically forward traffic
            config.ip_forward = keystone_core::IpForwardMode::Yes;
            config.ip_masquerade = keystone_core::IpMasqueradeMode::Ipv4;
        }
        InterfaceRole::LAN => {
            // LAN interfaces use static IP
            if let Some(ref ip) = assignment.static_ip {
                config.addresses.push(keystone_core::StaticAddress {
                    address: ip.clone(),
                    label: None,
                    scope: keystone_core::AddressScope::Global,
                });
            }
            config.ip_forward = keystone_core::IpForwardMode::Yes;
        }
    }

    config
}
