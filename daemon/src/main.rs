//! Keystone Daemon
//!
//! The privileged backend service that runs as root and performs system mutations.
//! Listens only on a Unix Domain Socket at /run/keystone.sock for security.

mod apply;
mod auth;
mod caddy;
mod config;
mod db;
mod dnsmasq;
mod firewall;
mod networkd;
mod systemd;

use auth::AuthManager;
use axum::{
    Json, Router,
    extract::State,
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use config::Config;
use db::Database;
use keystone_core::{
    ApplyConfigRequest, ApplyConfigResponse, DashboardResponse, DeleteUserRequest,
    DeleteUserResponse, DeleteVlanResponse, GlobalSettingsResponse, InterfaceConfigResponse,
    InterfaceConfigsResponse, InterfaceCounters, KeystoneError, LoginRequest, LoginResponse,
    ManagedInterfacesResponse, SaveGlobalSettingsRequest, SaveGlobalSettingsResponse,
    SaveInterfaceConfigRequest, SaveInterfaceConfigResponse, SaveManagedInterfacesRequest,
    SaveManagedInterfacesResponse, SaveUserRequest, SaveUserResponse, SaveVlanConfigRequest,
    SaveVlanConfigResponse, SystemState, UsersResponse, VlanConfigResponse, VlanConfigsResponse,
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
    db: Database,
    firewall_manager: Arc<firewall::FirewallApplyManager>,
}

impl AppState {
    fn new(
        auth: Arc<AuthManager>,
        db: Database,
        firewall_manager: Arc<firewall::FirewallApplyManager>,
    ) -> Self {
        Self {
            auth,
            db,
            firewall_manager,
        }
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

    // Initialize database
    let db = Database::new().await?;
    info!("Database initialized");

    // Get or create JWT key from database
    let jwt_key = db.get_or_create_jwt_key().await?;

    // Initialize authentication manager with persistent key
    let auth_manager = Arc::new(AuthManager::new(jwt_key));
    info!("Authentication system initialized");

    // Migrate from old config file if needed
    if let Ok(old_config) = Config::load() {
        // Check if we have any users in the database
        let users = db.get_users().await?;
        if users.is_empty() {
            info!("Migrating admin user from config file");
            // Create default admin user with the password from config
            db.create_user("admin", None, &old_config.admin_password_hash)
                .await?;
            info!("Created admin user from config file");
        }
    } else {
        // No config file, check if we need to create default user
        let users = db.get_users().await?;
        if users.is_empty() {
            info!("Creating default admin user");
            let default_hash = AuthManager::hash_password("admin")?;
            db.create_user("admin", None, &default_hash).await?;
            warn!(
                "⚠️  Created default admin user with password 'admin' - CHANGE THIS IMMEDIATELY!"
            );
        }
    }

    // Remove old socket if it exists
    if Path::new(SOCKET_PATH).exists() {
        warn!("Removing existing socket at {}", SOCKET_PATH);
        std::fs::remove_file(SOCKET_PATH)?;
    }

    // Create the firewall apply manager
    let firewall_apply_manager =
        Arc::new(firewall::FirewallApplyManager::new(Arc::new(db.clone())));

    // Initialize firewall manager (check for pending rollbacks from previous run)
    firewall_apply_manager.init().await?;
    info!("Firewall apply manager initialized");

    let state = Arc::new(AppState::new(
        auth_manager,
        db.clone(),
        firewall_apply_manager.clone(),
    ));

    // Create firewall state for firewall routes
    let firewall_state = firewall::routes::FirewallState {
        db: db.clone(),
        apply_manager: firewall_apply_manager,
    };

    // Create dnsmasq state for dnsmasq routes
    let dnsmasq_state = dnsmasq::routes::DnsmasqState { db: db.clone() };

    // Create Caddy state for Caddy routes
    let caddy_state = caddy::routes::CaddyState { db: db.clone() };

    // Build the router with protected routes
    let protected = Router::new()
        .route("/state", get(get_state))
        .route("/dashboard", get(get_dashboard))
        .route("/apply", post(apply_config))
        .route("/apply-networkd", post(apply_networkd))
        .route("/apply-all", post(apply_all))
        .route("/networkd-preview", get(networkd_preview))
        .route("/managed-interfaces", get(get_managed_interfaces))
        .route("/managed-interfaces", post(save_managed_interfaces))
        .route("/interface-config", get(get_interface_configs))
        .route("/interface-config/{name}", get(get_interface_config))
        .route("/interface-config", post(save_interface_config))
        .route("/interface-config/{name}", delete(delete_interface_config))
        .route("/vlans", get(get_vlans))
        .route("/vlans/{id}", get(get_vlan))
        .route("/vlans", post(save_vlan))
        .route("/vlans/{id}", delete(delete_vlan))
        .route("/bridges", get(get_bridges))
        .route("/bridges/{id}", get(get_bridge))
        .route("/bridges", post(save_bridge))
        .route("/bridges/{id}", delete(delete_bridge))
        .route("/users", get(get_users))
        .route("/users", post(save_user))
        .route("/users", delete(delete_user))
        .route("/settings", get(get_global_settings))
        .route("/settings", post(save_global_settings))
        // Merge firewall routes
        .merge(firewall::routes::firewall_routes(firewall_state))
        // Merge dnsmasq routes
        .merge(dnsmasq::routes::dnsmasq_routes(dnsmasq_state))
        // Merge Caddy routes
        .merge(caddy::routes::caddy_routes(caddy_state))
        // Merge systemd routes
        .merge(systemd::routes::systemd_routes())
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

                if let Err(err) = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
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
    info!("Login attempt for user: {}", request.username);

    // Look up user in database
    let user = state.db.get_user_by_username(&request.username).await?;

    match user {
        Some(user) => {
            match state.auth.verify_and_login(
                &user.username,
                &request.password,
                &user.password_hash,
            ) {
                Ok(token) => {
                    info!("Login successful for user: {}", request.username);
                    Ok(Json(LoginResponse {
                        success: true,
                        token: Some(token),
                        message: "Login successful".to_string(),
                    }))
                }
                Err(e) => {
                    warn!("Login failed for user {}: {}", request.username, e);
                    Ok(Json(LoginResponse {
                        success: false,
                        token: None,
                        message: "Invalid password".to_string(),
                    }))
                }
            }
        }
        None => {
            warn!("Login failed: user {} not found", request.username);
            Ok(Json(LoginResponse {
                success: false,
                token: None,
                message: "Invalid username or password".to_string(),
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

    Ok(SystemState { interfaces })
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

/// GET /managed-interfaces - Get all managed interfaces
async fn get_managed_interfaces(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ManagedInterfacesResponse>, AppError> {
    info!("Retrieving managed interfaces");

    let interfaces = state.db.get_managed_interfaces().await?;

    Ok(Json(ManagedInterfacesResponse { interfaces }))
}

/// POST /managed-interfaces - Save managed interfaces configuration
async fn save_managed_interfaces(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SaveManagedInterfacesRequest>,
) -> Result<Json<SaveManagedInterfacesResponse>, AppError> {
    info!("Saving {} managed interfaces", request.interfaces.len());

    state
        .db
        .save_managed_interfaces(&request.interfaces)
        .await?;

    Ok(Json(SaveManagedInterfacesResponse {
        success: true,
        message: format!("Saved {} managed interfaces", request.interfaces.len()),
    }))
}

// ============================================================================
// Interface Configuration Endpoints
// ============================================================================

/// GET /interface-config - Get all interface configurations
async fn get_interface_configs(
    State(state): State<Arc<AppState>>,
) -> Result<Json<InterfaceConfigsResponse>, AppError> {
    info!("Retrieving interface configurations");

    let configs = state.db.get_interface_configs().await?;

    Ok(Json(InterfaceConfigsResponse { configs }))
}

/// GET /interface-config/:name - Get a single interface configuration
async fn get_interface_config(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Result<Json<InterfaceConfigResponse>, AppError> {
    info!("Retrieving interface config for: {}", name);

    let config = state.db.get_interface_config(&name).await?;

    Ok(Json(InterfaceConfigResponse { config }))
}

/// POST /interface-config - Save an interface configuration
async fn save_interface_config(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SaveInterfaceConfigRequest>,
) -> Result<Json<SaveInterfaceConfigResponse>, AppError> {
    info!("Saving interface config for: {}", request.config.name);

    // Validate interface name
    if request.config.name.is_empty() {
        return Ok(Json(SaveInterfaceConfigResponse {
            success: false,
            message: "Interface name is required".to_string(),
            config_id: None,
        }));
    }

    // Validate addresses format (basic CIDR check)
    for addr in &request.config.addresses {
        if !addr.address.contains('/') {
            return Ok(Json(SaveInterfaceConfigResponse {
                success: false,
                message: format!(
                    "Address '{}' must be in CIDR notation (e.g., 192.168.1.1/24)",
                    addr.address
                ),
                config_id: None,
            }));
        }
    }

    let config_id = state.db.save_interface_config(&request.config).await?;

    Ok(Json(SaveInterfaceConfigResponse {
        success: true,
        message: "Interface configuration saved".to_string(),
        config_id: Some(config_id),
    }))
}

/// DELETE /interface-config/:name - Delete an interface configuration
async fn delete_interface_config(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Result<Json<SaveInterfaceConfigResponse>, AppError> {
    info!("Deleting interface config for: {}", name);

    state.db.delete_interface_config(&name).await?;

    // Also remove the networkd file if it exists
    if let Err(e) = networkd::remove_network_file(&name) {
        warn!("Failed to remove network file for {}: {}", name, e);
    }

    Ok(Json(SaveInterfaceConfigResponse {
        success: true,
        message: format!("Interface configuration '{}' deleted", name),
        config_id: None,
    }))
}

// ============================================================================
// VLAN Configuration Endpoints
// ============================================================================

/// GET /vlans - Get all VLAN configurations
async fn get_vlans(
    State(state): State<Arc<AppState>>,
) -> Result<Json<VlanConfigsResponse>, AppError> {
    info!("Retrieving VLAN configurations");

    let configs = state.db.get_all_vlans().await?;

    Ok(Json(VlanConfigsResponse { configs }))
}

/// GET /vlans/:id - Get a single VLAN configuration
async fn get_vlan(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Result<Json<VlanConfigResponse>, AppError> {
    info!("Retrieving VLAN config for id: {}", id);

    let config = state.db.get_vlan(id).await?;

    Ok(Json(VlanConfigResponse { config }))
}

/// POST /vlans - Save a VLAN configuration
async fn save_vlan(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SaveVlanConfigRequest>,
) -> Result<Json<SaveVlanConfigResponse>, AppError> {
    info!("Saving VLAN config: {}", request.config.name);

    // Validate VLAN name
    if request.config.name.is_empty() {
        return Ok(Json(SaveVlanConfigResponse {
            success: false,
            message: "VLAN name is required".to_string(),
            vlan_id: None,
        }));
    }

    // Validate parent interface
    if request.config.parent_interface.is_empty() {
        return Ok(Json(SaveVlanConfigResponse {
            success: false,
            message: "Parent interface is required".to_string(),
            vlan_id: None,
        }));
    }

    // Validate VLAN ID range
    if request.config.vlan_id < 1 || request.config.vlan_id > 4094 {
        return Ok(Json(SaveVlanConfigResponse {
            success: false,
            message: "VLAN ID must be between 1 and 4094".to_string(),
            vlan_id: None,
        }));
    }

    let vlan_id = state.db.save_vlan(&request.config).await?;

    Ok(Json(SaveVlanConfigResponse {
        success: true,
        message: "VLAN configuration saved".to_string(),
        vlan_id: Some(vlan_id),
    }))
}

/// DELETE /vlans/:id - Delete a VLAN configuration
async fn delete_vlan(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Result<Json<DeleteVlanResponse>, AppError> {
    info!("Deleting VLAN config id: {}", id);

    // Get the VLAN first to know its name for file cleanup
    let vlan = state.db.get_vlan(id).await?;

    let deleted = state.db.delete_vlan(id).await?;

    if deleted {
        // Also remove the netdev file if it exists
        if let Some(vlan) = vlan
            && let Err(e) = networkd::remove_vlan_netdev_file(&vlan.name)
        {
            warn!("Failed to remove VLAN netdev file for {}: {}", vlan.name, e);
        }
    }

    Ok(Json(DeleteVlanResponse {
        success: deleted,
        message: if deleted {
            "VLAN configuration deleted".to_string()
        } else {
            "VLAN configuration not found".to_string()
        },
    }))
}

// ============================================================================
// Bridge Configuration Handlers
// ============================================================================

/// GET /bridges - Get all bridge configurations
async fn get_bridges(
    State(state): State<Arc<AppState>>,
) -> Result<Json<keystone_core::BridgeConfigsResponse>, AppError> {
    info!("Getting all bridge configs");
    let configs = state.db.get_all_bridges().await?;
    Ok(Json(keystone_core::BridgeConfigsResponse { configs }))
}

/// GET /bridges/:id - Get a single bridge configuration
async fn get_bridge(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Result<Json<keystone_core::BridgeConfigResponse>, AppError> {
    info!("Getting bridge config id: {}", id);
    let config = state.db.get_bridge(id).await?;
    Ok(Json(keystone_core::BridgeConfigResponse { config }))
}

/// POST /bridges - Save a bridge configuration
async fn save_bridge(
    State(state): State<Arc<AppState>>,
    Json(request): Json<keystone_core::SaveBridgeConfigRequest>,
) -> Result<Json<keystone_core::SaveBridgeConfigResponse>, AppError> {
    info!("Saving bridge config: {:?}", request.config.name);

    // Validate bridge name
    if request.config.name.is_empty() {
        return Ok(Json(keystone_core::SaveBridgeConfigResponse {
            success: false,
            message: "Bridge name cannot be empty".to_string(),
            bridge_id: None,
        }));
    }

    // Validate STP forward delay (2-30 seconds per IEEE 802.1D)
    if request.config.stp
        && (request.config.stp_forward_delay < 2 || request.config.stp_forward_delay > 30)
    {
        return Ok(Json(keystone_core::SaveBridgeConfigResponse {
            success: false,
            message: "STP forward delay must be between 2 and 30 seconds".to_string(),
            bridge_id: None,
        }));
    }

    let bridge_id = state.db.save_bridge(&request.config).await?;

    Ok(Json(keystone_core::SaveBridgeConfigResponse {
        success: true,
        message: "Bridge configuration saved".to_string(),
        bridge_id: Some(bridge_id),
    }))
}

/// DELETE /bridges/:id - Delete a bridge configuration
async fn delete_bridge(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Result<Json<keystone_core::DeleteBridgeResponse>, AppError> {
    info!("Deleting bridge config id: {}", id);

    // Get the bridge first to know its name for file cleanup
    let bridge = state.db.get_bridge(id).await?;

    let deleted = state.db.delete_bridge(id).await?;

    if deleted {
        // Also remove the netdev file if it exists
        if let Some(bridge) = bridge
            && let Err(e) = networkd::remove_bridge_netdev_file(&bridge.name)
        {
            warn!(
                "Failed to remove bridge netdev file for {}: {}",
                bridge.name, e
            );
        }
    }

    Ok(Json(keystone_core::DeleteBridgeResponse {
        success: deleted,
        message: if deleted {
            "Bridge configuration deleted".to_string()
        } else {
            "Bridge configuration not found".to_string()
        },
    }))
}

/// GET /networkd-preview - Preview networkd files without writing to disk
async fn networkd_preview(
    State(state): State<Arc<AppState>>,
) -> Result<Json<keystone_core::NetworkdPreviewResponse>, AppError> {
    info!("Generating networkd preview");

    // Get all interface configs from database
    let configs = state.db.get_interface_configs().await?;

    // Get all VLAN configs from database
    let vlans = state.db.get_all_vlans().await?;

    // Get all bridge configs from database
    let bridges = state.db.get_all_bridges().await?;

    // Generate preview for all enabled interface configs
    let mut files: Vec<keystone_core::NetworkdFilePreview> = configs
        .iter()
        .filter(|config| config.enabled)
        .map(|config| keystone_core::NetworkdFilePreview {
            filename: networkd::get_network_filename(&config.name),
            content: networkd::generate_network_file(config),
        })
        .collect();

    // Add VLAN .netdev files
    for vlan in &vlans {
        files.push(keystone_core::NetworkdFilePreview {
            filename: networkd::get_vlan_netdev_filename(&vlan.name),
            content: networkd::generate_vlan_netdev_file(vlan),
        });
    }

    // Add bridge .netdev files
    for bridge in &bridges {
        files.push(keystone_core::NetworkdFilePreview {
            filename: networkd::get_bridge_netdev_filename(&bridge.name),
            content: networkd::generate_bridge_netdev_file(bridge),
        });
        // Also add bridge member .network files
        for member in &bridge.members {
            files.push(keystone_core::NetworkdFilePreview {
                filename: format!("50-keystone-{}.network", member),
                content: networkd::generate_bridge_member_network_file(member, &bridge.name),
            });
        }
    }

    Ok(Json(keystone_core::NetworkdPreviewResponse { files }))
}

/// POST /apply-networkd - Write interface configs to networkd and reload
async fn apply_networkd(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ApplyConfigResponse>, AppError> {
    info!("Applying networkd configuration");

    // Get all interface configs from database
    let configs = state.db.get_interface_configs().await?;

    // Get all VLAN configs from database
    let vlans = state.db.get_all_vlans().await?;

    // Get all bridge configs from database
    let bridges = state.db.get_all_bridges().await?;

    // Ensure networkd directory exists
    networkd::ensure_networkd_dir()?;

    // Write all enabled configs to disk
    let mut written = Vec::new();
    let mut vlan_written = Vec::new();
    let mut bridge_written = Vec::new();
    let mut errors = Vec::new();

    for config in &configs {
        if config.enabled {
            match networkd::write_network_file(config) {
                Ok(()) => {
                    written.push(config.name.clone());
                }
                Err(e) => {
                    errors.push(format!("{}: {}", config.name, e));
                }
            }
        } else {
            // Remove disabled interface configs
            if let Err(e) = networkd::remove_network_file(&config.name) {
                warn!(
                    "Failed to remove network file for disabled interface {}: {}",
                    config.name, e
                );
            }
        }
    }

    // Write all VLAN .netdev files
    for vlan in &vlans {
        match networkd::write_vlan_netdev_file(vlan) {
            Ok(()) => {
                vlan_written.push(vlan.name.clone());
            }
            Err(e) => {
                errors.push(format!("VLAN {}: {}", vlan.name, e));
            }
        }
    }

    // Write all bridge .netdev files and member .network files
    for bridge in &bridges {
        match networkd::write_bridge_netdev_file(bridge) {
            Ok(()) => {
                bridge_written.push(bridge.name.clone());
            }
            Err(e) => {
                errors.push(format!("Bridge {}: {}", bridge.name, e));
            }
        }
        // Write bridge member .network files
        if let Err(e) = networkd::write_bridge_member_network_files(bridge) {
            errors.push(format!("Bridge {} members: {}", bridge.name, e));
        }
    }

    if !errors.is_empty() {
        return Ok(Json(ApplyConfigResponse {
            success: false,
            message: "Failed to write some config files".to_string(),
            errors,
        }));
    }

    // Reload networkd to apply changes
    if let Err(e) = networkd::reload_networkd() {
        return Ok(Json(ApplyConfigResponse {
            success: false,
            message: format!("Config files written but reload failed: {}", e),
            errors: vec![e.to_string()],
        }));
    }

    Ok(Json(ApplyConfigResponse {
        success: true,
        message: format!(
            "Applied networkd config for {} interfaces, {} VLANs, and {} bridges",
            written.len(),
            vlan_written.len(),
            bridge_written.len()
        ),
        errors: Vec::new(),
    }))
}

/// POST /apply-all - Apply all configuration (networkd, firewall, dnsmasq, caddy)
async fn apply_all(
    State(state): State<Arc<AppState>>,
) -> Result<Json<apply::ApplyAllResult>, AppError> {
    info!("Applying all configuration");

    let result = apply::apply_all(&state.db, &state.firewall_manager, None).await?;

    Ok(Json(result))
}

/// GET /users - Get all users
async fn get_users(State(state): State<Arc<AppState>>) -> Result<Json<UsersResponse>, AppError> {
    info!("Retrieving users");

    let users = state.db.get_users().await?;

    Ok(Json(UsersResponse { users }))
}

/// POST /users - Create or update a user
async fn save_user(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SaveUserRequest>,
) -> Result<Json<SaveUserResponse>, AppError> {
    info!("Saving user: {}", request.username);

    // Validate username
    if request.username.is_empty() || request.username.len() > 50 {
        return Ok(Json(SaveUserResponse {
            success: false,
            message: "Username must be 1-50 characters".to_string(),
            user_id: None,
        }));
    }

    match request.id {
        Some(id) => {
            // Update existing user
            let password_hash = if let Some(password) = request.password {
                if password.len() < 6 {
                    return Ok(Json(SaveUserResponse {
                        success: false,
                        message: "Password must be at least 6 characters".to_string(),
                        user_id: None,
                    }));
                }
                Some(AuthManager::hash_password(&password)?)
            } else {
                None
            };

            state
                .db
                .update_user(
                    id,
                    &request.username,
                    request.email.as_deref(),
                    password_hash.as_deref(),
                )
                .await?;

            Ok(Json(SaveUserResponse {
                success: true,
                message: "User updated successfully".to_string(),
                user_id: Some(id),
            }))
        }
        None => {
            // Create new user
            let password = request
                .password
                .ok_or_else(|| anyhow::anyhow!("Password required for new user"))?;

            if password.len() < 6 {
                return Ok(Json(SaveUserResponse {
                    success: false,
                    message: "Password must be at least 6 characters".to_string(),
                    user_id: None,
                }));
            }

            let password_hash = AuthManager::hash_password(&password)?;
            let user_id = state
                .db
                .create_user(&request.username, request.email.as_deref(), &password_hash)
                .await?;

            Ok(Json(SaveUserResponse {
                success: true,
                message: "User created successfully".to_string(),
                user_id: Some(user_id),
            }))
        }
    }
}

/// DELETE /users - Delete a user
async fn delete_user(
    State(state): State<Arc<AppState>>,
    Json(request): Json<DeleteUserRequest>,
) -> Result<Json<DeleteUserResponse>, AppError> {
    info!("Deleting user id: {}", request.id);

    // Don't allow deleting the last user
    let users = state.db.get_users().await?;
    if users.len() <= 1 {
        return Ok(Json(DeleteUserResponse {
            success: false,
            message: "Cannot delete the last user".to_string(),
        }));
    }

    state.db.delete_user(request.id).await?;

    Ok(Json(DeleteUserResponse {
        success: true,
        message: "User deleted successfully".to_string(),
    }))
}

// ============================================================================
// Global Settings Endpoints
// ============================================================================

/// GET /settings - Get global application settings
async fn get_global_settings(
    State(state): State<Arc<AppState>>,
) -> Result<Json<GlobalSettingsResponse>, AppError> {
    info!("Retrieving global settings");

    let settings = state.db.get_global_settings().await?;

    Ok(Json(GlobalSettingsResponse { settings }))
}

/// POST /settings - Save global application settings
async fn save_global_settings(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SaveGlobalSettingsRequest>,
) -> Result<Json<SaveGlobalSettingsResponse>, AppError> {
    info!(
        "Saving global settings: config_changes_disabled={}",
        request.settings.config_changes_disabled
    );

    state.db.save_global_settings(&request.settings).await?;

    Ok(Json(SaveGlobalSettingsResponse {
        success: true,
        message: if request.settings.config_changes_disabled {
            "Configuration lock enabled".to_string()
        } else {
            "Configuration lock disabled".to_string()
        },
    }))
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
