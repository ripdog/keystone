//! UPnP API routes:
//! - `GET /upnp`: saved configuration, the interfaces to choose from and the binary check
//! - `PUT /upnp/config`: save the configuration (nothing is applied)
//! - `POST /upnp/apply`: apply the saved configuration
//! - `GET /upnp/status`: service state and the live port mappings

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Extension, State},
    routing::{get, post, put},
};
use keystone_core::InterfaceRole;
use keystone_core::api::{Endpoint, Req, Res, SaveUpnpConfig};
use keystone_core::changes::Component;
use keystone_core::upnp::{
    SaveUpnpConfigResponse, UpnpApplyResponse, UpnpStateResponse, UpnpStatusResponse,
};
use tracing::info;

use super::apply::{apply_saved, interface_candidates, read_status};
use super::config::validate_config;
use super::db::{load_upnp_config, save_upnp_config};
use super::detect::detect_binary;
use crate::db::Database;
use crate::snapshots;
use crate::{Actor, AppError};

const CHANGES_DISABLED_SAVE: &str =
    "Configuration changes are disabled. Unlock in Settings to change the configuration.";
const CHANGES_DISABLED_APPLY: &str =
    "Configuration changes are disabled. Unlock in Settings to apply changes.";

/// State shared with the UPnP routes.
#[derive(Clone)]
pub struct UpnpState {
    pub db: Database,
    pub firewall: Arc<crate::firewall::FirewallApplyManager>,
}

pub fn upnp_routes(state: UpnpState) -> Router<Arc<crate::AppState>> {
    Router::new()
        .route("/upnp", get(get_upnp))
        .route(SaveUpnpConfig::PATH, put(save_upnp_config_route))
        .route("/upnp/apply", post(apply_upnp))
        .route("/upnp/status", get(get_upnp_status))
        .with_state(state)
}

async fn changes_disabled(db: &Database) -> Result<bool, AppError> {
    Ok(db.get_global_settings().await?.config_changes_disabled)
}

/// GET /upnp - the saved configuration, the interfaces and the binary check.
async fn get_upnp(State(state): State<UpnpState>) -> Result<Json<UpnpStateResponse>, AppError> {
    let config = load_upnp_config(state.db.pool()).await?;
    let (lan_candidates, wan_candidates) = interface_candidates(&state.db).await?;
    let interfaces = state.db.get_interface_configs().await?;
    let default_wan = interfaces
        .iter()
        .find(|iface| iface.enabled && iface.role == InterfaceRole::WAN)
        .map(|iface| iface.name.clone());
    let binary = tokio::task::spawn_blocking(detect_binary)
        .await
        .unwrap_or(keystone_core::upnp::UpnpBinaryStatus::Unknown);
    Ok(Json(UpnpStateResponse {
        config,
        lan_candidates,
        wan_candidates,
        default_wan,
        binary,
        binary_message: binary.message().to_string(),
    }))
}

/// PUT /upnp/config - validate and save the configuration.
async fn save_upnp_config_route(
    State(state): State<UpnpState>,
    Json(request): Json<Req<SaveUpnpConfig>>,
) -> Result<Json<Res<SaveUpnpConfig>>, AppError> {
    info!("Saving UPnP config");
    if changes_disabled(&state.db).await? {
        return Ok(Json(SaveUpnpConfigResponse {
            success: false,
            message: CHANGES_DISABLED_SAVE.to_string(),
        }));
    }
    let (lan, wan) = interface_candidates(&state.db).await?;
    if let Err(message) = validate_config(&request.config, &lan, &wan) {
        return Ok(Json(SaveUpnpConfigResponse {
            success: false,
            message,
        }));
    }
    save_upnp_config(state.db.pool(), &request.config).await?;
    Ok(Json(SaveUpnpConfigResponse {
        success: true,
        message: "Configuration saved".to_string(),
    }))
}

/// POST /upnp/apply - write miniupnpd's configuration and restart it.
async fn apply_upnp(
    State(state): State<UpnpState>,
    actor: Option<Extension<Actor>>,
) -> Result<Json<UpnpApplyResponse>, AppError> {
    info!("Applying UPnP configuration");
    if changes_disabled(&state.db).await? {
        return Ok(Json(UpnpApplyResponse {
            success: false,
            message: CHANGES_DISABLED_APPLY.to_string(),
        }));
    }
    if crate::apply::pending_confirmation(&state.firewall)
        .await
        .is_some()
    {
        return Ok(Json(UpnpApplyResponse {
            success: false,
            message: crate::apply::AWAITING_CONFIRMATION_MESSAGE.to_string(),
        }));
    }

    match apply_saved(&state.db).await {
        Ok(()) => {
            let actor = actor.as_ref().map(|Extension(actor)| actor.0.as_str());
            snapshots::record_applied(&state.db, actor, None, &[Component::Upnp], "upnp apply")
                .await;
            Ok(Json(UpnpApplyResponse {
                success: true,
                message: "UPnP applied".to_string(),
            }))
        }
        Err(error) => Ok(Json(UpnpApplyResponse {
            success: false,
            message: format!("Failed to apply UPnP: {error:#}"),
        })),
    }
}

/// GET /upnp/status - binary check, service state and live mappings.
async fn get_upnp_status(
    State(_state): State<UpnpState>,
) -> Result<Json<UpnpStatusResponse>, AppError> {
    Ok(Json(read_status().await))
}
