//! SQM API routes:
//! - `GET /sqm`: saved configuration and the interfaces to choose from
//! - `PUT /sqm/config`: save the configuration (nothing is applied)
//! - `POST /sqm/apply`: apply the saved configuration
//! - `GET /sqm/status`: live counters of the applied configuration

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Extension, State},
    routing::{get, post, put},
};
use keystone_core::InterfaceRole;
use keystone_core::api::{Endpoint, Req, Res, SaveSqmConfig};
use keystone_core::changes::Component;
use keystone_core::sqm::{
    SaveSqmConfigResponse, SqmApplyResponse, SqmStateResponse, SqmStatusResponse,
};
use tracing::info;

use super::{apply_saved, load_sqm_config, read_status, save_sqm_config, validate_config};
use crate::db::Database;
use crate::snapshots;
use crate::{Actor, AppError};

const CHANGES_DISABLED_SAVE: &str =
    "Configuration changes are disabled. Unlock in Settings to change the configuration.";
const CHANGES_DISABLED_APPLY: &str =
    "Configuration changes are disabled. Unlock in Settings to apply changes.";

/// State shared with the SQM routes.
#[derive(Clone)]
pub struct SqmState {
    pub db: Database,
    pub firewall: Arc<crate::firewall::FirewallApplyManager>,
}

pub fn sqm_routes(state: SqmState) -> Router<Arc<crate::AppState>> {
    Router::new()
        .route("/sqm", get(get_sqm))
        .route(SaveSqmConfig::PATH, put(save_sqm_config_route))
        .route("/sqm/apply", post(apply_sqm))
        .route("/sqm/status", get(get_sqm_status))
        .with_state(state)
}

async fn changes_disabled(db: &Database) -> Result<bool, AppError> {
    Ok(db.get_global_settings().await?.config_changes_disabled)
}

/// GET /sqm - the saved configuration, with the interfaces to shape.
async fn get_sqm(State(state): State<SqmState>) -> Result<Json<SqmStateResponse>, AppError> {
    let config = load_sqm_config(state.db.pool()).await?;
    let interfaces = state.db.get_interface_configs().await?;
    let default_interface = interfaces
        .iter()
        .find(|iface| iface.enabled && iface.role == InterfaceRole::WAN)
        .map(|iface| iface.name.clone());
    Ok(Json(SqmStateResponse {
        config,
        available_interfaces: interfaces.into_iter().map(|iface| iface.name).collect(),
        default_interface,
    }))
}

/// PUT /sqm/config - validate and save the configuration.
async fn save_sqm_config_route(
    State(state): State<SqmState>,
    Json(request): Json<Req<SaveSqmConfig>>,
) -> Result<Json<Res<SaveSqmConfig>>, AppError> {
    info!("Saving SQM config");
    if changes_disabled(&state.db).await? {
        return Ok(Json(SaveSqmConfigResponse {
            success: false,
            message: CHANGES_DISABLED_SAVE.to_string(),
        }));
    }
    let interfaces: Vec<String> = state
        .db
        .get_interface_configs()
        .await?
        .into_iter()
        .map(|iface| iface.name)
        .collect();
    if let Err(message) = validate_config(&request.config, &interfaces) {
        return Ok(Json(SaveSqmConfigResponse {
            success: false,
            message,
        }));
    }
    save_sqm_config(state.db.pool(), &request.config).await?;
    Ok(Json(SaveSqmConfigResponse {
        success: true,
        message: "Configuration saved".to_string(),
    }))
}

/// POST /sqm/apply - apply the saved configuration with `tc`.
async fn apply_sqm(
    State(state): State<SqmState>,
    actor: Option<Extension<Actor>>,
) -> Result<Json<SqmApplyResponse>, AppError> {
    info!("Applying SQM configuration");
    if changes_disabled(&state.db).await? {
        return Ok(Json(SqmApplyResponse {
            success: false,
            message: CHANGES_DISABLED_APPLY.to_string(),
        }));
    }
    if crate::apply::pending_confirmation(&state.firewall)
        .await
        .is_some()
    {
        return Ok(Json(SqmApplyResponse {
            success: false,
            message: crate::apply::AWAITING_CONFIRMATION_MESSAGE.to_string(),
        }));
    }

    match apply_saved(&state.db).await {
        Ok(()) => {
            let actor = actor.as_ref().map(|Extension(actor)| actor.0.as_str());
            snapshots::record_applied(&state.db, actor, None, &[Component::Sqm], "sqm apply").await;
            Ok(Json(SqmApplyResponse {
                success: true,
                message: "Traffic shaping applied".to_string(),
            }))
        }
        Err(error) => Ok(Json(SqmApplyResponse {
            success: false,
            message: format!("Failed to apply traffic shaping: {error:#}"),
        })),
    }
}

/// GET /sqm/status - live counters of the applied configuration.
async fn get_sqm_status(
    State(state): State<SqmState>,
) -> Result<Json<SqmStatusResponse>, AppError> {
    Ok(Json(read_status(state.db.pool()).await?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthManager;
    use crate::networkd::NetworkdApplyManager;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn apply_is_refused_while_a_confirmation_is_pending() {
        let db = Database::new_in_memory().await.unwrap();
        let firewall = Arc::new(crate::firewall::FirewallApplyManager::new(
            Arc::new(db.clone()),
            Arc::new(NetworkdApplyManager::system()),
        ));
        firewall.seed_pending_for_test("live", u64::MAX / 2).await;
        let state = Arc::new(crate::AppState::new(
            Arc::new(AuthManager::new(vec![7; 32])),
            db.clone(),
            firewall.clone(),
        ));
        let app = sqm_routes(SqmState {
            db: db.clone(),
            firewall,
        })
        .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/sqm/apply")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["success"], false);
        assert_eq!(body["message"], crate::apply::AWAITING_CONFIRMATION_MESSAGE);
        // Nothing was shaped, so no applied snapshot was recorded.
        assert!(
            crate::snapshots::list_snapshots(&db)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
