//! Blocky API routes:
//! - `GET /blocky`: saved configuration and the binary check
//! - `PUT /blocky/config`: save the configuration (nothing is applied)
//! - `POST /blocky/apply`: apply the saved configuration
//! - `GET /blocky/status`: service state and Blocky's blocking state
//! - `POST /blocky/pause`: pause blocking for some minutes, or resume
//! - `POST /blocky/refresh-lists`: download the lists again
//! - `POST /blocky/flush-cache`: empty Blocky's answer cache
//! - `GET /blocky/querylog`: filtered query log
//!
//! Only the configuration routes change what is applied. Pause, refresh, flush
//! and the query log are runtime actions and do not create snapshots.

use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Extension, Query, State},
    http::StatusCode,
    routing::{get, post, put},
};
use keystone_core::api::{Endpoint, Req, Res, SaveBlockyConfig};
use keystone_core::blocky::{
    BlockyActionResponse, BlockyPauseRequest, BlockyQueryLogResponse, BlockyStateResponse,
    BlockyStatusResponse, SaveBlockyConfigResponse,
};
use keystone_core::changes::Component;
use serde::Deserialize;
use tracing::{info, warn};

use super::api;
use super::apply::{apply_saved, binary_installed, binary_message, read_status, service_active};
use super::config::{BLOCKY_QUERY_LOG_DIR, dnsmasq_link_errors, validate_config};
use super::db::{load_blocky_config, save_blocky_config};
use super::querylog::{QueryLogFilter, read_query_log};
use crate::db::Database;
use crate::snapshots;
use crate::{Actor, AppError};

const CHANGES_DISABLED_SAVE: &str =
    "Configuration changes are disabled. Unlock in Settings to change the configuration.";
const CHANGES_DISABLED_APPLY: &str =
    "Configuration changes are disabled. Unlock in Settings to apply changes.";
const NOT_RUNNING: &str = "Blocky is not running. Enable DNS filtering and apply to start it.";
/// Longest pause the API accepts, in minutes (one day).
const PAUSE_MINUTES_MAX: u32 = 1440;
/// Longest domain filter accepted.
const DOMAIN_FILTER_MAX: usize = 253;

/// State shared with the Blocky routes.
#[derive(Clone)]
pub struct BlockyState {
    pub db: Database,
    pub firewall: Arc<crate::firewall::FirewallApplyManager>,
}

pub fn blocky_routes(state: BlockyState) -> Router<Arc<crate::AppState>> {
    Router::new()
        .route("/blocky", get(get_blocky))
        .route(SaveBlockyConfig::PATH, put(save_blocky_config_route))
        .route("/blocky/apply", post(apply_blocky))
        .route("/blocky/status", get(get_blocky_status))
        .route("/blocky/pause", post(pause_blocky))
        .route("/blocky/refresh-lists", post(refresh_lists))
        .route("/blocky/flush-cache", post(flush_cache))
        .route("/blocky/querylog", get(get_query_log))
        .with_state(state)
}

async fn changes_disabled(db: &Database) -> Result<bool, AppError> {
    Ok(db.get_global_settings().await?.config_changes_disabled)
}

/// GET /blocky - the saved configuration and the binary check.
async fn get_blocky(
    State(state): State<BlockyState>,
) -> Result<Json<BlockyStateResponse>, AppError> {
    let config = load_blocky_config(state.db.pool()).await?;
    let installed = binary_installed();
    Ok(Json(BlockyStateResponse {
        config,
        installed,
        binary_message: binary_message(installed).to_string(),
    }))
}

/// PUT /blocky/config - validate and save the configuration.
async fn save_blocky_config_route(
    State(state): State<BlockyState>,
    Json(request): Json<Req<SaveBlockyConfig>>,
) -> Result<Json<Res<SaveBlockyConfig>>, AppError> {
    info!("Saving Blocky config");
    if changes_disabled(&state.db).await? {
        return Ok(Json(SaveBlockyConfigResponse {
            success: false,
            message: CHANGES_DISABLED_SAVE.to_string(),
        }));
    }
    if let Err(message) = validate_config(&request.config) {
        return Ok(Json(SaveBlockyConfigResponse {
            success: false,
            message,
        }));
    }
    let dnsmasq = crate::dnsmasq::load_dnsmasq_state(state.db.pool()).await?;
    let link = dnsmasq_link_errors(&dnsmasq.config, request.config.enabled);
    if !link.is_empty() {
        return Ok(Json(SaveBlockyConfigResponse {
            success: false,
            message: link.join("; "),
        }));
    }
    save_blocky_config(state.db.pool(), &request.config).await?;
    Ok(Json(SaveBlockyConfigResponse {
        success: true,
        message: "Configuration saved".to_string(),
    }))
}

/// POST /blocky/apply - write Blocky's configuration and restart the service.
async fn apply_blocky(
    State(state): State<BlockyState>,
    actor: Option<Extension<Actor>>,
) -> Result<Json<BlockyActionResponse>, AppError> {
    info!("Applying Blocky configuration");
    if changes_disabled(&state.db).await? {
        return Ok(Json(BlockyActionResponse {
            success: false,
            message: CHANGES_DISABLED_APPLY.to_string(),
        }));
    }
    if crate::apply::pending_confirmation(&state.firewall)
        .await
        .is_some()
    {
        return Ok(Json(BlockyActionResponse {
            success: false,
            message: crate::apply::AWAITING_CONFIRMATION_MESSAGE.to_string(),
        }));
    }

    match apply_saved(&state.db).await {
        Ok(()) => {
            let actor = actor.as_ref().map(|Extension(actor)| actor.0.as_str());
            snapshots::record_applied(&state.db, actor, None, &[Component::Blocky], "blocky apply")
                .await;
            Ok(Json(BlockyActionResponse {
                success: true,
                message: "Blocky applied".to_string(),
            }))
        }
        Err(error) => Ok(Json(BlockyActionResponse {
            success: false,
            message: format!("Failed to apply Blocky: {error:#}"),
        })),
    }
}

/// GET /blocky/status - service state and Blocky's blocking state.
async fn get_blocky_status() -> Result<Json<BlockyStatusResponse>, AppError> {
    Ok(Json(read_status().await))
}

/// POST /blocky/pause - pause blocking for `minutes`, or resume when `minutes`
/// is absent.
async fn pause_blocky(Json(request): Json<BlockyPauseRequest>) -> Json<BlockyActionResponse> {
    if let Some(minutes) = request.minutes
        && !(1..=PAUSE_MINUTES_MAX).contains(&minutes)
    {
        return action_failed(format!(
            "pause must be between 1 and {PAUSE_MINUTES_MAX} minutes"
        ));
    }
    if !service_active().await {
        return action_failed(NOT_RUNNING.to_string());
    }
    let result = match request.minutes {
        Some(minutes) => api::disable_blocking(minutes)
            .await
            .map(|()| format!("Blocking paused for {minutes} minutes")),
        None => api::enable_blocking()
            .await
            .map(|()| "Blocking resumed".to_string()),
    };
    action_result(result)
}

/// POST /blocky/refresh-lists - download every list again.
async fn refresh_lists() -> Json<BlockyActionResponse> {
    if !service_active().await {
        return action_failed(NOT_RUNNING.to_string());
    }
    action_result(
        api::refresh_lists()
            .await
            .map(|()| "Lists refreshed".to_string()),
    )
}

/// POST /blocky/flush-cache - empty Blocky's answer cache.
async fn flush_cache() -> Json<BlockyActionResponse> {
    if !service_active().await {
        return action_failed(NOT_RUNNING.to_string());
    }
    action_result(
        api::flush_cache()
            .await
            .map(|()| "Cache flushed".to_string()),
    )
}

fn action_result(result: anyhow::Result<String>) -> Json<BlockyActionResponse> {
    match result {
        Ok(message) => Json(BlockyActionResponse {
            success: true,
            message,
        }),
        Err(error) => {
            warn!("Blocky action failed: {error:#}");
            action_failed(format!("{error:#}"))
        }
    }
}

fn action_failed(message: String) -> Json<BlockyActionResponse> {
    Json(BlockyActionResponse {
        success: false,
        message,
    })
}

/// Query string of `GET /blocky/querylog`.
#[derive(Debug, Deserialize)]
struct QueryLogParams {
    client: Option<String>,
    q: Option<String>,
    #[serde(default)]
    blocked: bool,
}

/// GET /blocky/querylog - recent queries, newest first, with optional filters.
async fn get_query_log(
    Query(params): Query<QueryLogParams>,
) -> Result<Json<BlockyQueryLogResponse>, (StatusCode, String)> {
    let filter = query_log_filter(params)?;
    let response = tokio::task::spawn_blocking(move || {
        let leases = match crate::dnsmasq::leases::get_active_leases() {
            Ok(leases) => leases,
            Err(error) => {
                warn!("Could not read DHCP leases for query log names: {error:#}");
                Vec::new()
            }
        };
        read_query_log(Path::new(BLOCKY_QUERY_LOG_DIR), &filter, &leases)
    })
    .await
    .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    Ok(Json(response))
}

fn query_log_filter(params: QueryLogParams) -> Result<QueryLogFilter, (StatusCode, String)> {
    let bad = |message: &str| (StatusCode::BAD_REQUEST, message.to_string());

    let client = match params.client.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(value) => {
            let address =
                IpAddr::from_str(value).map_err(|_| bad("client must be an IP address"))?;
            Some(address.to_string())
        }
    };
    let domain = match params.q.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(value) => {
            let valid =
                value.len() <= DOMAIN_FILTER_MAX && value.bytes().all(|b| b.is_ascii_graphic());
            if !valid {
                return Err(bad(
                    "domain filter must be up to 253 visible ASCII characters",
                ));
            }
            Some(value.to_string())
        }
    };
    Ok(QueryLogFilter {
        client,
        domain,
        blocked_only: params.blocked,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(client: Option<&str>, q: Option<&str>, blocked: bool) -> QueryLogParams {
        QueryLogParams {
            client: client.map(str::to_string),
            q: q.map(str::to_string),
            blocked,
        }
    }

    #[test]
    fn query_filters_are_validated_at_the_boundary() {
        let filter =
            query_log_filter(params(Some(" 192.168.1.20 "), Some("ads.example"), true)).unwrap();
        assert_eq!(filter.client.as_deref(), Some("192.168.1.20"));
        assert_eq!(filter.domain.as_deref(), Some("ads.example"));
        assert!(filter.blocked_only);

        let empty = query_log_filter(params(Some(""), Some("  "), false)).unwrap();
        assert_eq!(empty, QueryLogFilter::default());

        assert!(query_log_filter(params(Some("laptop"), None, false)).is_err());
        assert!(query_log_filter(params(None, Some("bad domain"), false)).is_err());
        assert!(query_log_filter(params(None, Some(&"a".repeat(254)), false)).is_err());
    }
}
