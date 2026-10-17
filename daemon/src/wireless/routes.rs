//! Wireless API routes:
//! - `GET /wireless`: saved configuration, the interfaces and bridges to choose from
//! - `PUT /wireless/config`: save the configuration (nothing is applied)
//! - `POST /wireless/apply`: apply the saved configuration
//! - `GET /wireless/status`: service state and associated stations

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Extension, State},
    routing::{get, post, put},
};
use keystone_core::api::{Endpoint, Req, Res, SaveWirelessConfig};
use keystone_core::changes::Component;
use keystone_core::wireless::{
    SaveWirelessConfigResponse, WirelessApplyResponse, WirelessStateResponse,
    WirelessStatusResponse,
};
use tracing::info;

use super::apply::{apply_saved, bridge_candidates, read_status};
use super::db::{load_wireless_config, save_wireless_config};
use super::detect;
use crate::db::Database;
use crate::snapshots;
use crate::{Actor, AppError};

const CHANGES_DISABLED_SAVE: &str =
    "Configuration changes are disabled. Unlock in Settings to change the configuration.";
const CHANGES_DISABLED_APPLY: &str =
    "Configuration changes are disabled. Unlock in Settings to apply changes.";

/// State shared with the wireless routes.
#[derive(Clone)]
pub struct WirelessState {
    pub db: Database,
    pub firewall: Arc<crate::firewall::FirewallApplyManager>,
}

pub fn wireless_routes(state: WirelessState) -> Router<Arc<crate::AppState>> {
    Router::new()
        .route("/wireless", get(get_wireless))
        .route(SaveWirelessConfig::PATH, put(save_wireless_config_route))
        .route("/wireless/apply", post(apply_wireless))
        .route("/wireless/status", get(get_wireless_status))
        .with_state(state)
}

async fn changes_disabled(db: &Database) -> Result<bool, AppError> {
    Ok(db.get_global_settings().await?.config_changes_disabled)
}

/// GET /wireless - the saved configuration, the interfaces and the tool checks.
async fn get_wireless(
    State(state): State<WirelessState>,
) -> Result<Json<WirelessStateResponse>, AppError> {
    Ok(Json(WirelessStateResponse {
        config: load_wireless_config(state.db.pool()).await?,
        interfaces: detect::list_interfaces().await,
        bridge_candidates: bridge_candidates(&state.db).await?,
        hostapd_installed: detect::binary_installed("hostapd"),
        iw_installed: detect::binary_installed("iw"),
    }))
}

/// PUT /wireless/config - validate and save the configuration.
async fn save_wireless_config_route(
    State(state): State<WirelessState>,
    Json(request): Json<Req<SaveWirelessConfig>>,
) -> Result<Json<Res<SaveWirelessConfig>>, AppError> {
    info!("Saving wireless config");
    if changes_disabled(&state.db).await? {
        return Ok(Json(SaveWirelessConfigResponse {
            success: false,
            message: CHANGES_DISABLED_SAVE.to_string(),
        }));
    }
    let bridges = bridge_candidates(&state.db).await?;
    if let Err(message) = request.config.validate(&bridges) {
        return Ok(Json(SaveWirelessConfigResponse {
            success: false,
            message,
        }));
    }
    save_wireless_config(state.db.pool(), &request.config).await?;
    Ok(Json(SaveWirelessConfigResponse {
        success: true,
        message: "Configuration saved".to_string(),
    }))
}

/// POST /wireless/apply - write hostapd's configuration and restart it.
async fn apply_wireless(
    State(state): State<WirelessState>,
    actor: Option<Extension<Actor>>,
) -> Result<Json<WirelessApplyResponse>, AppError> {
    info!("Applying wireless configuration");
    if changes_disabled(&state.db).await? {
        return Ok(Json(WirelessApplyResponse {
            success: false,
            message: CHANGES_DISABLED_APPLY.to_string(),
        }));
    }
    if crate::apply::pending_confirmation(&state.firewall)
        .await
        .is_some()
    {
        return Ok(Json(WirelessApplyResponse {
            success: false,
            message: crate::apply::AWAITING_CONFIRMATION_MESSAGE.to_string(),
        }));
    }

    match apply_saved(&state.db).await {
        Ok(()) => {
            let actor = actor.as_ref().map(|Extension(actor)| actor.0.as_str());
            snapshots::record_applied(
                &state.db,
                actor,
                None,
                &[Component::Wireless],
                "wireless apply",
            )
            .await;
            Ok(Json(WirelessApplyResponse {
                success: true,
                message: "Access point applied".to_string(),
            }))
        }
        Err(error) => Ok(Json(WirelessApplyResponse {
            success: false,
            message: format!("Failed to apply the access point: {error:#}"),
        })),
    }
}

/// GET /wireless/status - service state and associated stations.
async fn get_wireless_status(
    State(state): State<WirelessState>,
) -> Result<Json<WirelessStatusResponse>, AppError> {
    Ok(Json(read_status(&state.db).await?))
}
