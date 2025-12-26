/// Keystone Daemon
/// 
/// The privileged backend service that runs as root and performs system mutations.
/// Listens only on a Unix Domain Socket at /run/keystone.sock for security.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use keystone_core::{ApplyConfigRequest, ApplyConfigResponse, KeystoneError, SystemState};
use std::path::Path;
use std::sync::Arc;
use tokio::net::UnixListener;
use tower::ServiceExt;
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};

const SOCKET_PATH: &str = "/run/keystone.sock";

#[derive(Clone)]
struct AppState {
    // Add state here as needed (e.g., config file paths)
}

impl AppState {
    fn new() -> Self {
        Self {}
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "keystone_daemon=debug,tower_http=debug".into()),
        )
        .init();

    info!("Starting Keystone Daemon");

    // Check if running as root
    if !nix::unistd::Uid::effective().is_root() {
        error!("Daemon must run as root");
        anyhow::bail!("This daemon requires root privileges");
    }

    // Remove old socket if it exists
    if Path::new(SOCKET_PATH).exists() {
        warn!("Removing existing socket at {}", SOCKET_PATH);
        std::fs::remove_file(SOCKET_PATH)?;
    }

    let state = Arc::new(AppState::new());

    // Build the router
    let app = Router::new()
        .route("/state", get(get_state))
        .route("/apply", post(apply_config))
        .route("/health", get(health_check))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Bind to Unix socket
    info!("Binding to Unix socket: {}", SOCKET_PATH);
    let listener = UnixListener::bind(SOCKET_PATH)?;

    // Set socket permissions (0660 - owner and group can read/write)
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(SOCKET_PATH, fs::Permissions::from_mode(0o660))?;

    info!("Daemon listening on {}", SOCKET_PATH);

    // Serve the application using tower
    loop {
        let (socket, _addr) = listener.accept().await?;
        let app = app.clone();
        
        tokio::spawn(async move {
            let socket = hyper_util::rt::TokioIo::new(socket);
            
            let hyper_service = hyper::service::service_fn(move |request| {
                app.clone().oneshot(request)
            });
            
            if let Err(err) = hyper_util::server::conn::auto::Builder::new(
                hyper_util::rt::TokioExecutor::new()
            )
            .serve_connection(socket, hyper_service)
            .await
            {
                error!("Error serving connection: {:?}", err);
            }
        });
    }
}

/// GET /health - Health check endpoint
async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy",
        "service": "keystone-daemon"
    }))
}

/// GET /state - Retrieve current system state
async fn get_state(State(_state): State<Arc<AppState>>) -> Result<Json<SystemState>, AppError> {
    info!("Retrieving system state");

    // TODO: Implement actual system state reading
    // For now, return a mock state
    let state = SystemState::default();

    Ok(Json(state))
}

/// POST /apply - Apply a new configuration
async fn apply_config(
    State(_state): State<Arc<AppState>>,
    Json(_request): Json<ApplyConfigRequest>,
) -> Result<Json<ApplyConfigResponse>, AppError> {
    info!("Applying configuration");

    // TODO: Implement actual configuration application
    // This should:
    // 1. Validate the configuration
    // 2. Generate systemd-networkd .network files
    // 3. Generate nftables configuration
    // 4. Reload services (systemctl restart systemd-networkd, nft -f /etc/nftables.conf)

    // Mock response for now
    let response = ApplyConfigResponse {
        success: true,
        message: "Configuration applied successfully (mock)".to_string(),
        errors: Vec::new(),
    };

    info!("Configuration applied successfully");
    Ok(Json(response))
}

/// Error wrapper for Axum handlers
struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        error!("Request error: {:?}", self.0);
        
        let error = KeystoneError::Internal(self.0.to_string());
        let body = Json(error);
        
        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}
