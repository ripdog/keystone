/// Keystone Web UI - Server
/// 
/// Unprivileged web server that:
/// 1. Serves the WASM frontend bundle
/// 2. Proxies API requests from HTTP to the daemon's Unix socket

use axum::{
    body::Body,
    extract::Request,
    http::{StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tower_http::cors::CorsLayer;
use tracing::{error, info};

const DAEMON_SOCKET: &str = "/run/keystone.sock";
const LISTEN_ADDR: &str = "127.0.0.1:8080";

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

    // Build the router
    let app = Router::new()
        .route("/api/*path", get(proxy_to_daemon).post(proxy_to_daemon))
        .route("/health", get(health_check))
        .fallback(serve_frontend)
        .layer(CorsLayer::permissive());

    let listener = tokio::net::TcpListener::bind(LISTEN_ADDR).await?;
    info!("Web UI listening on http://{}", LISTEN_ADDR);

    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "status": "healthy",
        "service": "keystone-web-ui"
    }))
}

async fn serve_frontend(_uri: Uri) -> Response {
    // For now, return a simple HTML page
    // TODO: Serve actual WASM bundle
    let html = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Keystone Router Manager</title>
    <style>
        body {
            font-family: system-ui, -apple-system, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
            background: #0f172a;
            color: #e2e8f0;
        }
        .container {
            background: #1e293b;
            border-radius: 0.5rem;
            padding: 2rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }
        h1 {
            color: #60a5fa;
            border-bottom: 2px solid #3b82f6;
            padding-bottom: 0.5rem;
        }
        .status {
            background: #065f46;
            color: #6ee7b7;
            padding: 0.5rem 1rem;
            border-radius: 0.25rem;
            display: inline-block;
            margin: 1rem 0;
        }
        .info {
            background: #1e3a8a;
            border-left: 4px solid #3b82f6;
            padding: 1rem;
            margin: 1rem 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Keystone Router Manager</h1>
        <div class="status">✓ System Running</div>
        
        <div class="info">
            <h2>Welcome to Keystone</h2>
            <p>A secure, split-privilege router management system for Arch Linux.</p>
            <p><strong>Status:</strong> Frontend placeholder active</p>
            <p><strong>Next Steps:</strong> The Leptos WASM frontend will be integrated here.</p>
        </div>

        <h2>API Endpoints</h2>
        <ul>
            <li><code>GET /health</code> - Health check</li>
            <li><code>GET /api/state</code> - Get system state (proxied to daemon)</li>
            <li><code>POST /api/apply</code> - Apply configuration (proxied to daemon)</li>
        </ul>
    </div>
</body>
</html>
    "#;

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(Body::from(html))
        .unwrap()
}

async fn proxy_to_daemon(req: Request) -> Result<Response, StatusCode> {
    // Strip /api prefix from path first, before moving req
    let path = req.uri().path().strip_prefix("/api").unwrap_or(req.uri().path()).to_string();
    
    info!("Proxying request to daemon: {} {}", req.method(), path);

    // Connect to Unix socket
    let stream = UnixStream::connect(DAEMON_SOCKET)
        .await
        .map_err(|e| {
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
