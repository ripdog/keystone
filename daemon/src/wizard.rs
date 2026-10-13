//! Setup wizard API routes.

use keystone_core::api::{AdvanceWizard, Endpoint, Req, Res, SaveWizardInterfaces, SkipWizard};
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Extension, State},
    routing::{get, post},
};
use keystone_core::{
    InterfaceRole, WizardAdvanceResponse, WizardSaveInterfacesResponse, WizardSkipResponse,
    WizardState, WizardStateResponse, WizardStep,
};
use tracing::{info, warn};

use crate::{AppError, AppState, apply, soho, status};

/// Create wizard routes using the daemon's shared application state.
pub fn wizard_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/wizard", get(get_wizard_state))
        .route(AdvanceWizard::PATH, post(advance_wizard))
        .route(SkipWizard::PATH, post(skip_wizard))
        .route(SaveWizardInterfaces::PATH, post(save_wizard_interfaces))
}

/// GET /wizard - Get current wizard state.
async fn get_wizard_state(
    State(state): State<Arc<AppState>>,
) -> Result<Json<WizardStateResponse>, AppError> {
    info!("Getting wizard state");

    let settings = state.db.get_global_settings().await?;
    let current_step = WizardStep::from_u8(settings.wizard_step);
    let system_status = if current_step == WizardStep::PasswordChanged
        || current_step == WizardStep::SystemChecksCompleted
    {
        Some(status::perform_all_checks(settings.setup_complete))
    } else {
        None
    };

    Ok(Json(WizardStateResponse {
        state: WizardState {
            current_step,
            is_complete: current_step.is_complete(),
            total_steps: WizardStep::Complete.as_u8(),
            system_status,
        },
    }))
}

/// POST /wizard/advance - Advance to the next wizard step.
async fn advance_wizard(
    State(state): State<Arc<AppState>>,
    Json(request): Json<Req<AdvanceWizard>>,
) -> Result<Json<Res<AdvanceWizard>>, AppError> {
    info!("Advancing wizard from step: {:?}", request.completing_step);

    let settings = state.db.get_global_settings().await?;
    let current_step = WizardStep::from_u8(settings.wizard_step);

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

    match current_step {
        WizardStep::NotStarted | WizardStep::PasswordChanged => {}
        WizardStep::SystemChecksCompleted => {
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
        WizardStep::InterfacesAssigned => {
            let interfaces = state.db.get_interface_configs().await?;
            let zones = state.db.get_firewall_zones().await?;
            let has_wan = interfaces
                .iter()
                .any(|interface| interface.enabled && interface.role == InterfaceRole::WAN);
            let has_lan = interfaces
                .iter()
                .any(|interface| interface.enabled && interface.role == InterfaceRole::LAN);
            let wan_bound = zones
                .iter()
                .any(|zone| zone.is_wan && !zone.interfaces.is_empty());
            let lan_bound = zones
                .iter()
                .any(|zone| !zone.is_wan && !zone.interfaces.is_empty());

            if !(has_wan && has_lan && wan_bound && lan_bound) {
                return Ok(Json(WizardAdvanceResponse {
                    success: false,
                    message: "Activate the WAN/LAN router profile before continuing".to_string(),
                    new_step: current_step,
                }));
            }
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
    state.db.set_wizard_step(new_step).await?;
    if new_step == WizardStep::Complete {
        state.db.mark_setup_complete().await?;
    }

    Ok(Json(WizardAdvanceResponse {
        success: true,
        message: format!("Advanced to step: {}", new_step.name()),
        new_step,
    }))
}

/// POST /wizard/skip - Skip the wizard entirely.
async fn skip_wizard(
    State(state): State<Arc<AppState>>,
    Json(request): Json<Req<SkipWizard>>,
) -> Result<Json<Res<SkipWizard>>, AppError> {
    if !request.confirm_skip {
        return Ok(Json(WizardSkipResponse {
            success: false,
            message: "Must confirm skip by setting confirm_skip to true".to_string(),
        }));
    }

    warn!("Wizard being skipped by user request");
    state.db.set_wizard_step(WizardStep::Complete).await?;
    state.db.mark_setup_complete().await?;

    Ok(Json(WizardSkipResponse {
        success: true,
        message: "Wizard skipped. You can configure settings manually.".to_string(),
    }))
}

/// POST /wizard/interfaces - Build and activate a basic SOHO router profile.
async fn save_wizard_interfaces(
    State(state): State<Arc<AppState>>,
    actor: Option<Extension<crate::Actor>>,
    Json(request): Json<Req<SaveWizardInterfaces>>,
) -> Result<Json<Res<SaveWizardInterfaces>>, AppError> {
    info!(assignments = ?request.assignments, "Activating wizard router profile");

    let summary = match soho::configure_soho_profile(&state.db, &request.assignments).await {
        Ok(summary) => summary,
        Err(error) => {
            return Ok(Json(WizardSaveInterfacesResponse {
                success: false,
                message: error.to_string(),
                apply_result: None,
            }));
        }
    };

    let actor = actor.as_ref().map(|Extension(actor)| actor.0.as_str());
    let apply_result = apply::apply_all(&state.db, &state.firewall_manager, None, actor).await?;
    let success = apply_result.success;
    let message = if success {
        format!(
            "Activated SOHO profile: WAN {}, LAN {}",
            summary.wan_interface,
            summary.lan_interfaces.join(", ")
        )
    } else {
        apply_result.message.clone()
    };

    Ok(Json(WizardSaveInterfacesResponse {
        success,
        message,
        apply_result: Some(apply_result),
    }))
}
