//! Keystone Daemon
//!
//! The privileged backend service that runs as root and performs system mutations.
//! Listens only on a Unix Domain Socket at /run/keystone.sock for security.

mod auth;
mod config;

use auth::AuthManager;
use axum::{
    Json, Router,
    extract::State,
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use config::Config;
use keystone_core::{
    ApplyConfigRequest, ApplyConfigResponse, DashboardResponse, InterfaceCounters, KeystoneError,
    LoginRequest, LoginResponse, SystemState,
};
use serde::Deserialize;
use std::path::Path;
use std::sync::Arc;
use tokio::net::UnixListener;
use tower::ServiceExt;
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};

const SOCKET_PATH: &str = "/run/keystone.sock";
const DEV_HTTP_ADDR: &str = "127.0.0.1:3000";

#[derive(Clone)]
struct AppState {
    auth: Arc<AuthManager>,
}

impl AppState {
    fn new(auth: Arc<AuthManager>) -> Self {
        Self { auth }
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

    // Load configuration
    let config = Config::load()?;
    info!("Configuration loaded");

    // Initialize authentication manager
    let auth_manager = Arc::new(AuthManager::new(config.admin_password_hash));
    info!("Authentication system initialized");

    // Remove old socket if it exists
    if Path::new(SOCKET_PATH).exists() {
        warn!("Removing existing socket at {}", SOCKET_PATH);
        std::fs::remove_file(SOCKET_PATH)?;
    }

    let state = Arc::new(AppState::new(auth_manager));

    // Build the router with protected routes
    let protected = Router::new()
        .route("/state", get(get_state))
        .route("/dashboard", get(get_dashboard))
        .route("/apply", post(apply_config))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/login", post(login))
        .merge(protected)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Check for development mode (HTTP listener instead of Unix socket)
    let dev_mode = std::env::var("KEYSTONE_DEV").is_ok();

    if dev_mode {
        // Development mode: Listen on HTTP for easy proxying from Trunk
        warn!("⚠️  Running in DEVELOPMENT mode - HTTP listener enabled!");
        warn!("⚠️  Do NOT use this in production!");
        
        let listener = tokio::net::TcpListener::bind(DEV_HTTP_ADDR).await?;
        info!("Daemon listening on http://{}", DEV_HTTP_ADDR);
        
        axum::serve(listener, app).await?;
    } else {
        // Production mode: Unix socket only
        info!("Binding to Unix socket: {}", SOCKET_PATH);
        let listener = UnixListener::bind(SOCKET_PATH)?;

        // Set socket permissions (0660 - owner and group can read/write)
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(SOCKET_PATH, fs::Permissions::from_mode(0o660))?;

        // Set socket group to 'wheel' so non-root users in wheel group can access it
        use std::ffi::CString;
        use std::os::unix::fs::MetadataExt;

        let metadata = fs::metadata(SOCKET_PATH)?;
        let uid = metadata.uid();

        // Try to set group to 'wheel'
        match nix::unistd::Group::from_name("wheel") {
            Ok(Some(group)) => {
                let path_cstr = CString::new(SOCKET_PATH)?;
                let result = unsafe { libc::chown(path_cstr.as_ptr(), uid, group.gid.as_raw()) };
                if result != 0 {
                    warn!("Failed to set socket group to wheel");
                } else {
                    info!("Socket group set to wheel");
                }
            }
            _ => {
                warn!("Could not find 'wheel' group, socket will be root:root only");
            }
        }

        info!("Daemon listening on {}", SOCKET_PATH);

        // Serve the application using tower
        loop {
            let (socket, _addr) = listener.accept().await?;
            let app = app.clone();

            tokio::spawn(async move {
                let socket = hyper_util::rt::TokioIo::new(socket);

                let hyper_service =
                    hyper::service::service_fn(move |request| app.clone().oneshot(request));

                if let Err(err) =
                    hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                        .serve_connection(socket, hyper_service)
                        .await
                {
                    error!("Error serving connection: {:?}", err);
                }
            });
        }
    }

    Ok(())
}

/// GET /health - Health check endpoint
async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy",
        "service": "keystone-daemon"
    }))
}

/// POST /login - Authenticate and receive JWT token
async fn login(
    State(state): State<Arc<AppState>>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    info!("Login attempt");

    match state.auth.login(&request.password) {
        Ok(token) => {
            info!("Login successful");
            Ok(Json(LoginResponse {
                success: true,
                token: Some(token),
                message: "Login successful".to_string(),
            }))
        }
        Err(e) => {
            warn!("Login failed: {}", e);
            Ok(Json(LoginResponse {
                success: false,
                token: None,
                message: "Invalid password".to_string(),
            }))
        }
    }
}

/// Authentication middleware - validates JWT token in Authorization header
async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());

    if let Some(auth_value) = auth_header
        && let Some(token) = auth_value.strip_prefix("Bearer ")
        && state.auth.verify(token)
    {
        return Ok(next.run(request).await);
    }

    warn!("Unauthorized request - invalid or missing token");
    Err(StatusCode::UNAUTHORIZED)
}

/// GET /state - Retrieve current system state
async fn get_state(State(_state): State<Arc<AppState>>) -> Result<Json<SystemState>, AppError> {
    info!("Retrieving system state");

    Ok(Json(read_system_state().unwrap_or_default()))
}

/// GET /dashboard - Dashboard payload (state + interface counters)
async fn get_dashboard(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<DashboardResponse>, AppError> {
    info!("Retrieving dashboard");

    Ok(Json(read_dashboard().unwrap_or_default()))
}

fn read_dashboard() -> anyhow::Result<DashboardResponse> {
    let state = read_system_state().unwrap_or_default();
    let interface_counters = read_interface_counters()?;

    let timestamp_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    Ok(DashboardResponse {
        state,
        interface_counters,
        timestamp_ms,
    })
}

fn read_interface_counters() -> anyhow::Result<Vec<InterfaceCounters>> {
    use std::fs;

    let mut counters = Vec::new();
    let entries = fs::read_dir("/sys/class/net")?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let base = entry.path().join("statistics");

        let read_u64 = |p: &std::path::Path| -> u64 {
            fs::read_to_string(p)
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .unwrap_or(0)
        };

        counters.push(InterfaceCounters {
            name,
            rx_bytes: read_u64(&base.join("rx_bytes")),
            tx_bytes: read_u64(&base.join("tx_bytes")),
            rx_packets: read_u64(&base.join("rx_packets")),
            tx_packets: read_u64(&base.join("tx_packets")),
        });
    }

    counters.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(counters)
}

fn read_system_state() -> anyhow::Result<SystemState> {
    use std::collections::{HashMap, HashSet};
    use std::fs;
    use std::process::Command;

    #[derive(Debug, Deserialize)]
    struct IpAddrEntry {
        ifname: String,
        #[serde(default)]
        addr_info: Vec<AddrInfo>,
    }

    #[derive(Debug, Deserialize)]
    struct AddrInfo {
        #[serde(default)]
        family: String,
        local: Option<String>,
        prefixlen: Option<u8>,
    }

    #[derive(Debug, Deserialize)]
    struct RouteEntry {
        dev: Option<String>,
    }

    let ip_forwarding_enabled = fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
        .ok()
        .map(|s| s.trim() == "1")
        .unwrap_or(false);

    // We don't yet introspect nftables; keep this conservative.
    let nat_enabled = false;

    let default_route_ifaces: HashSet<String> = Command::new("ip")
        .args(["-j", "route", "show", "default"])
        .output()
        .ok()
        .and_then(|o| {
            if !o.status.success() {
                return None;
            }
            serde_json::from_slice::<Vec<RouteEntry>>(&o.stdout).ok()
        })
        .map(|routes| {
            routes
                .into_iter()
                .filter_map(|r| r.dev)
                .collect::<HashSet<_>>()
        })
        .unwrap_or_default();

    let addr_map: HashMap<String, String> = Command::new("ip")
        .args(["-j", "-4", "addr", "show"])
        .output()
        .ok()
        .and_then(|o| {
            if !o.status.success() {
                return None;
            }
            serde_json::from_slice::<Vec<IpAddrEntry>>(&o.stdout).ok()
        })
        .map(|entries| {
            entries
                .into_iter()
                .filter_map(|e| {
                    let addr = e
                        .addr_info
                        .iter()
                        .find(|a| a.family == "inet")
                        .and_then(|a| Some((a.local.clone()?, a.prefixlen?)))
                        .map(|(ip, prefix)| format!("{}/{}", ip, prefix));
                    Some((e.ifname, addr?))
                })
                .collect::<HashMap<_, _>>()
        })
        .unwrap_or_default();

    let mut interfaces = Vec::new();
    for entry in fs::read_dir("/sys/class/net")?.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();

        let operstate = fs::read_to_string(entry.path().join("operstate"))
            .unwrap_or_else(|_| "unknown".to_string());
        let enabled = operstate.trim() == "up";

        let role = if default_route_ifaces.contains(&name) {
            keystone_core::InterfaceRole::WAN
        } else {
            keystone_core::InterfaceRole::LAN
        };

        interfaces.push(keystone_core::Interface {
            name: name.clone(),
            address: addr_map.get(&name).cloned(),
            dhcp_enabled: false,
            role,
            enabled,
        });
    }
    interfaces.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(SystemState {
        interfaces,
        firewall_rules: Vec::new(),
        ip_forwarding_enabled,
        nat_enabled,
    })
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
