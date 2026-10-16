//! Packet capture API routes:
//! - `GET /capture`: the current capture and the interfaces to choose from
//! - `POST /capture`: start a capture
//! - `POST /capture/stop`: stop the running capture
//! - `DELETE /capture`: discard the finished capture and its file
//! - `GET /capture/packets?since=<seq>`: decoded lines, for the live view
//! - `GET /capture/pcap`: download the finished capture

use std::sync::Arc;

use axum::{
    Json, Router,
    body::Body,
    extract::{Extension, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use keystone_core::api::{DiscardCapture, Endpoint, Req, Res, StartCapture, StopCapture};
use keystone_core::capture::{CapturePacketsResponse, CaptureStateResponse};
use serde::Deserialize;
use tracing::{error, info};

use super::{CaptureError, CaptureManager};
use crate::Actor;

impl IntoResponse for CaptureError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            CaptureError::Invalid(message) => (StatusCode::BAD_REQUEST, message),
            CaptureError::NotFound(message) => (StatusCode::NOT_FOUND, message),
            CaptureError::Conflict(message) => (StatusCode::CONFLICT, message),
            CaptureError::Internal(error) => {
                error!("Capture error: {error:#}");
                (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
            }
        };
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

pub fn capture_routes(manager: Arc<CaptureManager>) -> Router<Arc<crate::AppState>> {
    Router::new()
        .route(
            StartCapture::PATH,
            get(get_capture).post(start_capture).delete(discard_capture),
        )
        .route(StopCapture::PATH, axum::routing::post(stop_capture))
        .route("/capture/packets", get(get_packets))
        .route("/capture/pcap", get(download_pcap))
        .with_state(manager)
}

async fn get_capture(State(manager): State<Arc<CaptureManager>>) -> Json<CaptureStateResponse> {
    Json(CaptureStateResponse {
        capture: manager.info().await,
        interfaces: manager.interfaces(),
    })
}

async fn start_capture(
    State(manager): State<Arc<CaptureManager>>,
    Extension(actor): Extension<Actor>,
    Json(request): Json<Req<StartCapture>>,
) -> Result<Json<Res<StartCapture>>, CaptureError> {
    // Capturing exposes other people's traffic, so who did it is recorded.
    info!(
        "{} started a packet capture on {} (filter: {:?})",
        actor.0,
        request.interface,
        request.filter.to_expression().unwrap_or_default()
    );
    Ok(Json(manager.start(request).await?))
}

async fn stop_capture(
    State(manager): State<Arc<CaptureManager>>,
    Extension(actor): Extension<Actor>,
    Json(_): Json<Req<StopCapture>>,
) -> Result<Json<Res<StopCapture>>, CaptureError> {
    info!("{} stopped the packet capture", actor.0);
    Ok(Json(manager.stop().await?))
}

async fn discard_capture(
    State(manager): State<Arc<CaptureManager>>,
    Json(_): Json<Req<DiscardCapture>>,
) -> Result<Json<Res<DiscardCapture>>, CaptureError> {
    manager.discard().await?;
    Ok(Json(CaptureStateResponse {
        capture: None,
        interfaces: manager.interfaces(),
    }))
}

#[derive(Deserialize)]
struct PacketsQuery {
    #[serde(default)]
    since: u64,
}

async fn get_packets(
    State(manager): State<Arc<CaptureManager>>,
    Query(query): Query<PacketsQuery>,
) -> Json<CapturePacketsResponse> {
    Json(manager.packets(query.since).await)
}

async fn download_pcap(
    State(manager): State<Arc<CaptureManager>>,
) -> Result<Response, CaptureError> {
    let (path, info) = manager.pcap_for_download().await?;
    let bytes = tokio::fs::read(&path).await?;
    let filename = format!(
        "keystone-{}-{}.pcap",
        // The interface name is validated, so it is safe in a header.
        info.request.interface,
        info.started_at
    );
    Ok((
        [
            (
                header::CONTENT_TYPE,
                "application/vnd.tcpdump.pcap".to_string(),
            ),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        Body::from(bytes),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::*;
    use crate::capture::CaptureState;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use keystone_core::capture::{CaptureInfo, CaptureRequest};
    use tower::ServiceExt;

    /// The capture routes behind a stand-in authenticated user, on a manager
    /// that runs the stand-in programs.
    async fn router(fixture: &Fixture) -> (Router, Arc<CaptureManager>) {
        let db = crate::db::Database::new_in_memory().await.unwrap();
        let networkd = Arc::new(crate::networkd::NetworkdApplyManager::system());
        let firewall = Arc::new(crate::firewall::FirewallApplyManager::new(
            Arc::new(db.clone()),
            networkd,
        ));
        let state = Arc::new(crate::AppState::new(
            Arc::new(crate::auth::AuthManager::new(vec![7; 32])),
            db,
            firewall,
        ));
        let manager = CaptureManager::new(fixture.env.clone());
        let router = capture_routes(manager.clone())
            .layer(Extension(Actor("tester".into())))
            .with_state(state);
        (router, manager)
    }

    async fn send(router: &Router, method: &str, path: &str, body: &str) -> (StatusCode, Response) {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        (response.status(), response)
    }

    async fn json(response: Response) -> serde_json::Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn bad_requests_get_a_400_with_the_reason() {
        let fx = fixture(sample_command);
        let (router, _) = router(&fx).await;
        let bad = serde_json::json!({
            "interface": "eth1",
            "filter": {"clauses": [{"kind": "host", "address": "1.2.3.4 or host 5.6.7.8"}]},
        });
        let (status, response) = send(&router, "POST", "/capture", &bad.to_string()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let error = json(response).await["error"].as_str().unwrap().to_string();
        assert!(error.contains("condition 1"), "{error}");
    }

    #[tokio::test]
    async fn state_lists_interfaces_and_no_capture_at_first() {
        let fx = fixture(sample_command);
        let (router, _) = router(&fx).await;
        let (status, response) = send(&router, "GET", "/capture", "").await;
        assert_eq!(status, StatusCode::OK);
        let body = json(response).await;
        assert!(body["capture"].is_null());
        assert_eq!(body["interfaces"], serde_json::json!(["any", "eth1"]));

        let (status, response) = send(&router, "GET", "/capture/packets?since=7", "").await;
        assert_eq!(status, StatusCode::OK);
        let body = json(response).await;
        assert_eq!(body["lines"], serde_json::json!([]));
        assert_eq!(body["next"], 7);

        for (method, path) in [("POST", "/capture/stop"), ("GET", "/capture/pcap")] {
            let (status, _) = send(&router, method, path, "{}").await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}");
        }
    }

    #[tokio::test]
    async fn a_capture_is_started_polled_and_downloaded_over_http() {
        let fx = fixture(sample_command);
        let (router, manager) = router(&fx).await;
        let body = serde_json::to_string(&CaptureRequest {
            max_seconds: 30,
            ..request(vec![])
        })
        .unwrap();
        let (status, response) = send(&router, "POST", "/capture", &body).await;
        assert_eq!(status, StatusCode::OK);
        let started: CaptureInfo = serde_json::from_value(json(response).await).unwrap();
        assert_eq!(started.state, CaptureState::Running);

        for _ in 0..200 {
            if manager.info().await.unwrap().state != CaptureState::Running {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        let (status, response) = send(&router, "GET", "/capture/packets?since=0", "").await;
        assert_eq!(status, StatusCode::OK);
        let packets = json(response).await;
        assert_eq!(packets["lines"].as_array().unwrap().len(), 3);
        assert_eq!(packets["info"]["state"], "finished");

        let (status, response) = send(&router, "GET", "/capture/pcap", "").await;
        assert_eq!(status, StatusCode::OK);
        let headers = response.headers().clone();
        assert_eq!(
            headers[header::CONTENT_TYPE],
            "application/vnd.tcpdump.pcap"
        );
        let disposition = headers[header::CONTENT_DISPOSITION].to_str().unwrap();
        assert!(disposition.starts_with("attachment; filename=\"keystone-eth1-"));
        assert!(disposition.ends_with(".pcap\""), "{disposition}");
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], &sample_pcap(3)[..]);

        let (status, response) = send(&router, "DELETE", "/capture", "{}").await;
        assert_eq!(status, StatusCode::OK);
        assert!(json(response).await["capture"].is_null());
        let (status, _) = send(&router, "GET", "/capture/pcap", "").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
