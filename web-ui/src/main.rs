//! Keystone Web UI - Server
//!
//! Unprivileged web server that:
//! 1. Serves the Leptos WASM frontend
//! 2. Proxies API requests from HTTP to the daemon's Unix socket

#[cfg(feature = "server")]
use axum::{
    Router,
    body::Body,
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
#[cfg(feature = "server")]
use hyper_util::rt::TokioIo;
#[cfg(feature = "server")]
use tokio::net::UnixStream;
#[cfg(feature = "server")]
use tower_http::cors::CorsLayer;
#[cfg(feature = "server")]
use tower_http::services::ServeDir;
#[cfg(feature = "server")]
use tracing::{error, info};

#[cfg(feature = "server")]
const DAEMON_SOCKET: &str = "/run/keystone.sock";
#[cfg(feature = "server")]
const LISTEN_ADDR: &str = "127.0.0.1:8080";

#[cfg(feature = "server")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "keystone_web_ui=debug,tower_http=debug".into()),
        )
        .init();

    info!("Starting Keystone Web UI");

    // Determine asset directory relative to binary location
    let exe_path = std::env::current_exe()?;
    let exe_dir = exe_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Failed to get binary directory"))?;
    let dist_dir = exe_dir.join("dist");
    
    info!("Serving static assets from: {}", dist_dir.display());

    // Build the router
    let app = Router::new()
        .route("/api/{*path}", get(proxy_to_daemon).post(proxy_to_daemon))
        .route("/health", get(health_check))
        .fallback_service(ServeDir::new(dist_dir))
        .layer(CorsLayer::permissive());

    let listener = tokio::net::TcpListener::bind(LISTEN_ADDR).await?;
    info!("Web UI listening on http://{}", LISTEN_ADDR);

    axum::serve(listener, app).await?;

    Ok(())
}

#[cfg(feature = "server")]
async fn health_check() -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "status": "healthy",
        "service": "keystone-web-ui"
    }))
}

#[cfg(feature = "server")]
async fn proxy_to_daemon(req: Request) -> Result<Response, StatusCode> {
    // Strip /api prefix from path first, before moving req
    let path = req
        .uri()
        .path()
        .strip_prefix("/api")
        .unwrap_or(req.uri().path())
        .to_string();

    info!("Proxying request to daemon: {} {}", req.method(), path);

    // Connect to Unix socket
    let stream = UnixStream::connect(DAEMON_SOCKET).await.map_err(|e| {
        error!("Failed to connect to daemon socket: {}", e);
        StatusCode::BAD_GATEWAY
    })?;

    let io = TokioIo::new(stream);

    // Create hyper HTTP/1 connection
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| {
            error!("Failed to establish connection: {}", e);
            StatusCode::BAD_GATEWAY
        })?;

    // Spawn connection handler
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            error!("Connection error: {}", e);
        }
    });

    // Build new request
    let (parts, body) = req.into_parts();
    let mut new_req = Request::builder()
        .method(parts.method)
        .uri(path)
        .version(parts.version);

    // Copy headers
    for (key, value) in parts.headers.iter() {
        new_req = new_req.header(key, value);
    }

    let new_req = new_req.body(body).map_err(|e| {
        error!("Failed to build request: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Send request
    let response = sender.send_request(new_req).await.map_err(|e| {
        error!("Failed to send request to daemon: {}", e);
        StatusCode::BAD_GATEWAY
    })?;

    Ok(response.map(Body::new))
}
