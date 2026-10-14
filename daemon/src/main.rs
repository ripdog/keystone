//! Keystone Daemon
//!
//! The privileged backend service that runs as root and performs system mutations.
//! Listens only on a Unix Domain Socket for security.

mod apply;
mod auth;
mod blocky;
mod caddy;
mod changes;
mod clients;
mod config;
mod config_validation;
mod consistency;
mod db;
mod dnsmasq;
mod firewall;
mod gateway;
mod logs;
mod networkd;
mod snapshot_validation;
mod snapshots;
mod soho;
mod sqm;
mod ssh;
mod status;
mod systemd;
mod traffic;
mod upnp;
mod wizard;

use auth::AuthManager;
use axum::{
    Json, Router,
    extract::{Extension, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use config::Config;
use db::Database;
use keystone_core::api::{
    ConfirmNetworkd, DeleteUser, Endpoint, Login, Req, Res, SaveBridge, SaveGlobalSettings,
    SaveInterfaceConfig, SaveManagedInterfaces, SaveUser, SaveVlan,
};
use keystone_core::{
    ApplyConfigResponse, CheckCategory, CheckSeverity, CompleteSetupResponse, DashboardResponse,
    DeleteUserResponse, DeleteVlanResponse, GlobalSettingsResponse, InterfaceConfigResponse,
    InterfaceConfigsResponse, InterfaceCounters, LoginResponse, ManagedInterfacesResponse,
    RenewInterfaceResponse, SaveGlobalSettingsResponse, SaveInterfaceConfigResponse,
    SaveManagedInterfacesResponse, SaveUserResponse, SaveVlanConfigResponse, SystemCheck,
    SystemState, SystemStatusResponse, UsersResponse, VlanConfigResponse, VlanConfigsResponse,
};
use serde::Deserialize;
use std::path::Path;
use std::sync::Arc;
use tokio::net::UnixListener;
use tower::ServiceExt;
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};

const DEV_HTTP_ADDR: &str = "127.0.0.1:3000";

/// Username of the authenticated caller, set by the auth middleware and used
/// to attribute configuration snapshots.
#[derive(Clone)]
pub struct Actor(pub String);

#[derive(Clone)]
struct AppState {
    auth: Arc<AuthManager>,
    db: Database,
    firewall_manager: Arc<firewall::FirewallApplyManager>,
    gateways: gateway::GatewaySnapshot,
    traffic: traffic::TrafficSnapshot,
    login_slots: Arc<tokio::sync::Semaphore>,
    login_attempts:
        Arc<tokio::sync::Mutex<std::collections::HashMap<String, (std::time::Instant, u32)>>>,
}

impl AppState {
    fn new(
        auth: Arc<AuthManager>,
        db: Database,
        firewall_manager: Arc<firewall::FirewallApplyManager>,
    ) -> Self {
        Self {
            auth,
            gateways: gateway::start(db.clone()),
            traffic: traffic::start(),
            db,
            firewall_manager,
            login_slots: Arc::new(tokio::sync::Semaphore::new(3)),
            login_attempts: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    // Colour codes are for terminals; in the journal they are noise.
    tracing_subscriber::fmt()
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
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

    let config = Config::load().unwrap_or_else(|err| {
        warn!("Failed to load config file, using defaults: {}", err);
        Config::default()
    });

    // No network-accessible bootstrap account. The first administrator must be
    // created locally using: sudo keystonectl bootstrap-admin
    if db.get_users().await?.is_empty() {
        warn!("No administrator configured. Run 'sudo keystonectl bootstrap-admin' locally.");
    }

    let socket_path = config.daemon.socket_path.clone();
    if let Some(parent) = Path::new(&socket_path).parent()
        && let Err(err) = std::fs::create_dir_all(parent)
    {
        warn!(
            "Failed to ensure runtime directory {}: {}",
            parent.display(),
            err
        );
    }

    // Never allow the unprivileged web account to replace the socket itself.
    if let Some(parent) = Path::new(&socket_path).parent() {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755))?;
    }

    // Remove old socket if it exists
    if Path::new(&socket_path).exists() {
        warn!("Removing existing socket at {}", socket_path);
        std::fs::remove_file(&socket_path)?;
    }

    // Networkd rollbacks performed by its timer also settle the matching
    // configuration snapshot.
    let snapshot_db = db.clone();
    let networkd_apply_manager = Arc::new(
        networkd::NetworkdApplyManager::system().with_rollback_listener(Arc::new(
            move |session: &str| {
                let db = snapshot_db.clone();
                let session = session.to_owned();
                tokio::spawn(async move {
                    snapshots::settle_session(&db, &session, snapshots::SnapshotStatus::RolledBack)
                        .await;
                });
            },
        )),
    );

    // Create the firewall apply manager
    let firewall_apply_manager = Arc::new(firewall::FirewallApplyManager::new(
        Arc::new(db.clone()),
        networkd_apply_manager.clone(),
    ));

    // Restore or re-arm any unconfirmed networkd change from a previous run.
    networkd_apply_manager.init().await?;
    info!("Networkd apply manager initialized");

    // Initialize firewall manager (check for pending rollbacks from previous run)
    firewall_apply_manager.init().await?;
    info!("Firewall apply manager initialized");

    // Reconcile configuration snapshots with the apply sessions restored above.
    // Snapshot bookkeeping must never stop the daemon from starting.
    let mut live_sessions = Vec::new();
    if let Some(info) = networkd_apply_manager.pending_info().await {
        live_sessions.push(info.session_id);
    }
    let firewall_status = firewall_apply_manager.status().await;
    if firewall_status.pending_confirmation
        && let Some(session) = firewall_status.session_id
        && !live_sessions.contains(&session)
    {
        live_sessions.push(session);
    }
    if let Err(error) = snapshots::reconcile_on_startup(&db, &live_sessions).await {
        warn!("Failed to reconcile configuration snapshots: {error:#}");
    }
    ssh::start_reconciler(db.clone());
    caddy::start_reconciler(db.pool().clone());
    sqm::start_reconciler(db.clone());
    upnp::start_reconciler(db.clone());

    let state = Arc::new(AppState::new(
        auth_manager,
        db.clone(),
        firewall_apply_manager.clone(),
    ));

    // Pending-change and snapshot routes share the firewall's pending state
    // so they can refuse to run while an apply awaits confirmation.
    let changes_state = changes::ChangesState {
        db: db.clone(),
        firewall: firewall_apply_manager.clone(),
    };

    // Every per-component apply checks the firewall's pending confirmation.
    let applies_firewall = firewall_apply_manager.clone();

    // Create firewall state for firewall routes
    let firewall_state = firewall::routes::FirewallState {
        db: db.clone(),
        apply_manager: firewall_apply_manager,
    };

    // Create dnsmasq state for dnsmasq routes
    let dnsmasq_state = dnsmasq::routes::DnsmasqState {
        db: db.clone(),
        firewall: applies_firewall.clone(),
    };

    // Create Caddy state for Caddy routes
    let caddy_state = caddy::routes::CaddyState {
        db: db.clone(),
        firewall: applies_firewall.clone(),
    };

    // Create SQM state for traffic-shaping routes
    let sqm_state = sqm::routes::SqmState {
        db: db.clone(),
        firewall: applies_firewall.clone(),
    };

    // Create UPnP state for port-mapping routes
    let upnp_state = upnp::routes::UpnpState {
        db: db.clone(),
        firewall: applies_firewall.clone(),
    };

    // Create Blocky state for DNS filtering routes
    let blocky_state = blocky::routes::BlockyState {
        db: db.clone(),
        firewall: applies_firewall,
    };

    // Build the router with protected routes
    let protected = Router::new()
        .route("/state", get(get_state))
        .route("/dashboard", get(get_dashboard))
        .route("/apply-networkd", post(apply_networkd))
        .route("/apply-all", post(apply_all))
        .route(ConfirmNetworkd::PATH, post(confirm_networkd))
        .route("/networkd/rollback", post(rollback_networkd))
        .route("/networkd/status", get(networkd_status))
        .route("/networkd-preview", get(networkd_preview))
        .route("/managed-interfaces", get(get_managed_interfaces))
        .route(SaveManagedInterfaces::PATH, post(save_managed_interfaces))
        .route("/interface-config", get(get_interface_configs))
        .route("/interface-config/{name}", get(get_interface_config))
        .route(SaveInterfaceConfig::PATH, post(save_interface_config))
        .route("/interface-config/{name}", delete(delete_interface_config))
        .route("/interfaces/{name}/renew", post(renew_interface))
        .route(
            "/interfaces/{name}/reconfigure",
            post(reconfigure_interface),
        )
        .route("/vlans", get(get_vlans))
        .route("/vlans/{id}", get(get_vlan))
        .route(SaveVlan::PATH, post(save_vlan))
        .route("/vlans/{id}", delete(delete_vlan))
        .route("/bridges", get(get_bridges))
        .route("/bridges/{id}", get(get_bridge))
        .route(SaveBridge::PATH, post(save_bridge))
        .route("/bridges/{id}", delete(delete_bridge))
        .route("/users", get(get_users))
        .route(SaveUser::PATH, post(save_user))
        .route(DeleteUser::PATH, delete(delete_user))
        .route("/settings", get(get_global_settings))
        .route(SaveGlobalSettings::PATH, post(save_global_settings))
        .route("/complete-setup", post(complete_setup))
        // Merge firewall routes
        .merge(firewall::routes::firewall_routes(firewall_state))
        // Merge dnsmasq routes
        .merge(dnsmasq::routes::dnsmasq_routes(dnsmasq_state))
        // Unified LAN client inventory
        .merge(clients::clients_routes(db.clone()))
        // Merge Caddy routes
        .merge(caddy::routes::caddy_routes(caddy_state))
        // Merge traffic shaping (SQM) routes
        .merge(sqm::routes::sqm_routes(sqm_state))
        // Merge UPnP / NAT-PMP routes
        .merge(upnp::routes::upnp_routes(upnp_state))
        // Merge DNS filtering (Blocky) routes
        .merge(blocky::routes::blocky_routes(blocky_state))
        // Merge pending-change and snapshot routes
        .merge(changes::changes_routes(changes_state))
        // Merge systemd routes
        .merge(systemd::routes::systemd_routes())
        .merge(ssh::routes())
        // Merge wizard routes
        .merge(wizard::wizard_routes())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    // The log viewer polls the journal this daemon writes to. Tracing its own
    // requests would add new lines to every poll's answer, so it sits outside
    // the TraceLayer below, behind the same authentication.
    let logs_app = logs::logs_routes()
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state.clone());

    let app = Router::new()
        .route("/health", get(health_check))
        .route(Login::PATH, post(login))
        .route("/system-status", get(get_system_status))
        .route("/lan-bind-addresses", get(lan_bind_addresses))
        .merge(protected)
        // State must be applied before TraceLayer so middleware/handlers can
        // reliably extract State<Arc<AppState>>.
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .merge(logs_app);

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
        info!("Binding to Unix socket: {}", socket_path);
        let listener = UnixListener::bind(&socket_path)?;

        // Set socket permissions (0660 - owner and group can read/write)
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            &socket_path,
            fs::Permissions::from_mode(config.daemon.socket_mode & 0o660),
        )?;

        // Set socket group so non-root users can access it
        use std::ffi::CString;
        use std::os::unix::fs::MetadataExt;

        let metadata = fs::metadata(&socket_path)?;
        let uid = metadata.uid();

        // Try to set group from config
        match nix::unistd::Group::from_name(&config.daemon.socket_group) {
            Ok(Some(group)) => {
                let path_cstr = CString::new(socket_path.clone())?;
                let result = unsafe { libc::chown(path_cstr.as_ptr(), uid, group.gid.as_raw()) };
                if result != 0 {
                    warn!(
                        "Failed to set socket group to {}",
                        config.daemon.socket_group
                    );
                } else {
                    info!("Socket group set to {}", config.daemon.socket_group);
                }
            }
            _ => {
                warn!(
                    "Could not find '{}' group, socket will be root:root only",
                    config.daemon.socket_group
                );
            }
        }

        info!("Daemon listening on {}", socket_path);

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

/// Addresses eligible for the unprivileged HTTP listener.
/// LAN roles come exclusively from the daemon database, not from user-supplied
/// HTTP headers, the default gateway, or the web service's environment.
async fn lan_bind_addresses(
    State(state): State<Arc<AppState>>,
) -> Result<Json<keystone_core::LanBindAddressesResponse>, AppError> {
    use keystone_core::InterfaceRole;
    use std::collections::HashSet;

    let lan_names: HashSet<String> = state
        .db
        .get_interface_configs()
        .await?
        .into_iter()
        .filter(|interface| interface.enabled && interface.role == InterfaceRole::LAN)
        .map(|interface| interface.name)
        .collect();

    if lan_names.is_empty() {
        return Ok(Json(keystone_core::LanBindAddressesResponse {
            addresses: vec![],
        }));
    }

    let output = tokio::process::Command::new("ip")
        .args(["-j", "address", "show"])
        .output()
        .await?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Cannot enumerate LAN addresses: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    let interfaces: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)?;
    let mut addresses = HashSet::new();
    for interface in interfaces {
        if !interface
            .get("ifname")
            .and_then(|v| v.as_str())
            .is_some_and(|name| lan_names.contains(name))
        {
            continue;
        }
        if let Some(info) = interface.get("addr_info").and_then(|v| v.as_array()) {
            for address in info {
                // Ignore link-local IPv6: without an interface scope, it
                // cannot be bound as a normal SocketAddr and isn't LAN-routable.
                if address.get("scope").and_then(|v| v.as_str()) != Some("global") {
                    continue;
                }
                if let Some(ip) = address.get("local").and_then(|v| v.as_str())
                    && let Ok(parsed) = ip.parse::<std::net::IpAddr>()
                {
                    addresses.insert(parsed.to_string());
                }
            }
        }
    }
    let mut addresses: Vec<_> = addresses.into_iter().collect();
    addresses.sort();
    Ok(Json(keystone_core::LanBindAddressesResponse { addresses }))
}

/// GET /system-status - Get system status checks (public endpoint)
async fn get_system_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<SystemStatusResponse>, AppError> {
    info!("Performing system status checks");

    let settings = state.db.get_global_settings().await?;
    let mut response = status::perform_all_checks(settings.setup_complete);

    // Database probe check: verify DB is usable at runtime
    let db_check = match state.db.get_global_settings().await {
        Ok(_) => SystemCheck {
            id: "db_probe".to_string(),
            name: "Database".to_string(),
            category: CheckCategory::Configuration,
            severity: CheckSeverity::Pass,
            message: "Database is accessible".to_string(),
            fix_advice: None,
        },
        Err(e) => SystemCheck {
            id: "db_probe".to_string(),
            name: "Database".to_string(),
            category: CheckCategory::Configuration,
            severity: CheckSeverity::Error,
            message: format!("Database error: {}", e),
            fix_advice: Some("Check /var/lib/keystone permissions and disk space".to_string()),
        },
    };

    if db_check.severity == CheckSeverity::Error {
        response.error_count += 1;
        response.all_checks_pass = false;
    }

    response.checks.push(db_check);

    // Configuration consistency (warnings about settings that make no sense)
    if settings.setup_complete {
        for check in consistency::config_checks(&state.db).await {
            match check.severity {
                CheckSeverity::Error => {
                    response.error_count += 1;
                    response.all_checks_pass = false;
                }
                CheckSeverity::Warning => response.warning_count += 1,
                CheckSeverity::Pass => {}
            }
            response.checks.push(check);
        }
    }

    Ok(Json(response))
}

/// POST /login - Authenticate and receive JWT token
async fn login(
    State(state): State<Arc<AppState>>,
    Json(request): Json<Req<Login>>,
) -> Result<Json<Res<Login>>, AppError> {
    info!("Login attempt for user: {}", request.username);

    // Bound simultaneous expensive Argon2 verification and limit guesses per
    // username. Fail without doing any password hashing after the limit.
    let _slot = state
        .login_slots
        .acquire()
        .await
        .map_err(|_| anyhow::anyhow!("Login verification unavailable"))?;
    {
        let mut attempts = state.login_attempts.lock().await;
        // Bound memory use under random-username attacks.
        if attempts.len() >= 1024 && !attempts.contains_key(&request.username) {
            attempts.retain(|_, (start, _)| start.elapsed().as_secs() < 60);
            if attempts.len() >= 1024 {
                return Ok(Json(LoginResponse {
                    success: false,
                    token: None,
                    message: "Login capacity exceeded. Try again shortly.".to_string(),
                }));
            }
        }
        let entry = attempts
            .entry(request.username.clone())
            .or_insert((std::time::Instant::now(), 0));
        if entry.0.elapsed().as_secs() >= 60 {
            *entry = (std::time::Instant::now(), 0);
        }
        if entry.1 >= 10 {
            return Ok(Json(LoginResponse {
                success: false,
                token: None,
                message: "Too many attempts. Try again later.".to_string(),
            }));
        }
        entry.1 += 1;
    }

    // Look up user in database
    let user = state.db.get_user_by_username(&request.username).await?;

    match user {
        Some(user) => {
            match state.auth.verify_and_login(
                &user.username,
                user.id,
                user.auth_version,
                &request.password,
                &user.password_hash,
            ) {
                Ok(token) => {
                    state.login_attempts.lock().await.remove(&request.username);
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
fn is_blocked_before_setup(path: &str) -> bool {
    let firewall_recovery_endpoint = matches!(
        path,
        "/firewall/confirm"
            | "/firewall/rollback"
            | "/firewall/status"
            | "/networkd/confirm"
            | "/networkd/rollback"
            | "/networkd/status"
    );

    path == "/dashboard"
        || path == "/clients"
        || path == "/apply-networkd"
        || path == "/apply-all"
        || path == "/networkd-preview"
        || (path.starts_with("/interfaces/")
            && (path.ends_with("/renew") || path.ends_with("/reconfigure")))
        || (path.starts_with("/firewall/") && !firewall_recovery_endpoint)
        || path.starts_with("/dnsmasq/")
        || path.starts_with("/caddy/")
        || path.starts_with("/systemd/")
}

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let path = request.uri().path();

    // Allow configuring the system before setup is complete, but block
    // operational/read-heavy endpoints until /complete-setup succeeds.
    //
    // - Allowed pre-setup: wizard endpoints, user management (password change),
    //   and all other config save endpoints.
    // - Blocked pre-setup: dashboard/state reads and any endpoints that apply
    //   configuration live.
    let settings = state
        .db
        .get_global_settings()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if !settings.setup_complete && is_blocked_before_setup(path) {
        warn!("Rejected request before setup complete: {}", path);
        // Use a status code that indicates "setup required".
        return Err(StatusCode::PRECONDITION_REQUIRED);
    }
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());

    if let Some(auth_value) = auth_header
        && let Some(token) = auth_value.strip_prefix("Bearer ")
        && let Some(claims) = state.auth.decode_claims(token)
    {
        let revision = state
            .db
            .get_auth_revision(claims.uid)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if let Some((username, version)) = revision
            && username == claims.sub
            && version == claims.version
        {
            request.extensions_mut().insert(Actor(claims.sub));
            return Ok(next.run(request).await);
        }
    }

    warn!("Unauthorized request - invalid or missing token");
    Err(StatusCode::UNAUTHORIZED)
}

/// GET /state - Retrieve current system state
async fn get_state(State(state): State<Arc<AppState>>) -> Result<Json<SystemState>, AppError> {
    info!("Retrieving system state");

    let configs = state.db.get_interface_configs().await?;
    Ok(Json(read_system_state(&configs).unwrap_or_default()))
}

/// GET /dashboard - Dashboard payload (state + interface counters)
async fn get_dashboard(
    State(state): State<Arc<AppState>>,
) -> Result<Json<DashboardResponse>, AppError> {
    info!("Retrieving dashboard");

    let configs = state.db.get_interface_configs().await?;
    let gateways = state.gateways.read().await.clone();
    let traffic = state.traffic.read().await.clone();
    Ok(Json(
        read_dashboard(&configs, gateways, traffic).unwrap_or_default(),
    ))
}

fn read_dashboard(
    configs: &[keystone_core::InterfaceConfig],
    gateways: Vec<keystone_core::GatewayStatus>,
    traffic: Vec<keystone_core::InterfaceTraffic>,
) -> anyhow::Result<DashboardResponse> {
    let mut state = read_system_state(configs).unwrap_or_default();
    let mut interface_counters = read_interface_counters()?;
    let mut traffic = traffic;
    restrict_dashboard_to_managed(configs, &mut state, &mut interface_counters, &mut traffic);

    let timestamp_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    Ok(DashboardResponse {
        state,
        interface_counters,
        gateways,
        traffic,
        timestamp_ms,
    })
}

/// The system discovery endpoint deliberately includes unmanaged hardware so it
/// can be configured. Dashboard visibility, unlike discovery, must follow only
/// the enabled, persisted networkd configurations (not inferred fallback roles).
fn restrict_dashboard_to_managed(
    configs: &[keystone_core::InterfaceConfig],
    state: &mut SystemState,
    counters: &mut Vec<InterfaceCounters>,
    traffic: &mut Vec<keystone_core::InterfaceTraffic>,
) {
    use std::collections::HashMap;

    let roles: HashMap<&str, keystone_core::InterfaceRole> = configs
        .iter()
        .filter(|config| config.enabled)
        .map(|config| (config.name.as_str(), config.role))
        .collect();

    state
        .interfaces
        .retain(|iface| roles.contains_key(iface.name.as_str()));
    for iface in &mut state.interfaces {
        iface.role = roles[iface.name.as_str()];
    }
    counters.retain(|counter| roles.contains_key(counter.name.as_str()));
    traffic.retain(|entry| roles.contains_key(entry.name.as_str()));
    for entry in traffic {
        entry.role = roles.get(entry.name.as_str()).copied();
    }
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

fn read_system_state(configs: &[keystone_core::InterfaceConfig]) -> anyhow::Result<SystemState> {
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

    let default_route_ifaces: HashSet<String> = ["-4", "-6"]
        .iter()
        .flat_map(|family| {
            Command::new("ip")
                .args(["-j", family, "route", "show", "default"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| serde_json::from_slice::<Vec<RouteEntry>>(&o.stdout).ok())
                .unwrap_or_default()
                .into_iter()
                .filter_map(|r| r.dev)
                .collect::<Vec<_>>()
        })
        .collect();

    let configured_roles: HashMap<&str, keystone_core::InterfaceRole> = configs
        .iter()
        .filter(|config| config.enabled)
        .map(|config| (config.name.as_str(), config.role))
        .collect();

    let addr_map: HashMap<String, (Vec<String>, Vec<String>)> = Command::new("ip")
        .args(["-j", "addr", "show"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                serde_json::from_slice::<Vec<IpAddrEntry>>(&o.stdout).ok()
            } else {
                None
            }
        })
        .map(|entries| {
            entries
                .into_iter()
                .map(|e| {
                    let mut ipv4 = Vec::new();
                    let mut ipv6 = Vec::new();
                    for addr in e.addr_info {
                        if let (Some(local), Some(prefix)) = (addr.local, addr.prefixlen) {
                            let cidr = format!("{local}/{prefix}");
                            match addr.family.as_str() {
                                "inet" => ipv4.push(cidr),
                                "inet6" => ipv6.push(cidr),
                                _ => {}
                            }
                        }
                    }
                    (e.ifname, (ipv4, ipv6))
                })
                .collect()
        })
        .unwrap_or_default();

    let physical_interfaces = status::get_physical_interfaces()
        .into_iter()
        .collect::<HashSet<_>>();
    let mut interfaces = Vec::new();
    for entry in fs::read_dir("/sys/class/net")?.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !physical_interfaces.contains(&name) {
            continue;
        }

        let operstate = fs::read_to_string(entry.path().join("operstate"))
            .unwrap_or_else(|_| "unknown".to_string());
        let enabled = operstate.trim() == "up";

        let role = configured_roles
            .get(name.as_str())
            .copied()
            .unwrap_or_else(|| {
                if default_route_ifaces.contains(&name) {
                    keystone_core::InterfaceRole::WAN
                } else {
                    keystone_core::InterfaceRole::LAN
                }
            });
        let (ipv4_addresses, ipv6_addresses) = addr_map.get(&name).cloned().unwrap_or_default();
        let address = ipv4_addresses
            .iter()
            .find(|ip| !ip.starts_with("169.254."))
            .or_else(|| ipv4_addresses.first())
            .cloned();
        interfaces.push(keystone_core::Interface {
            name: name.clone(),
            address,
            ipv4_addresses,
            ipv6_addresses,
            dhcp_enabled: configs.iter().any(|c| {
                c.enabled
                    && c.name == name
                    && matches!(
                        c.dhcp_mode,
                        keystone_core::DhcpMode::Yes | keystone_core::DhcpMode::Ipv4
                    )
            }),
            role,
            enabled,
        });
    }
    interfaces.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(SystemState { interfaces })
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
    Json(request): Json<Req<SaveManagedInterfaces>>,
) -> Result<Json<Res<SaveManagedInterfaces>>, AppError> {
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
    Json(request): Json<Req<SaveInterfaceConfig>>,
) -> Result<Json<Res<SaveInterfaceConfig>>, AppError> {
    info!("Saving interface config for: {}", request.config.name);

    // Validate interface name
    if request.config.name.is_empty() {
        return Ok(Json(SaveInterfaceConfigResponse {
            success: false,
            message: "Interface name is required".to_string(),
            config_id: None,
        }));
    }

    // Reject addresses, gateways, routes, DNS servers, MTU and PD uplinks that make no sense
    let errors = config_validation::validate_interface_config(&request.config);
    if !errors.is_empty() {
        return Ok(Json(SaveInterfaceConfigResponse {
            success: false,
            message: errors.join("; "),
            config_id: None,
        }));
    }

    // A bridge member's .network file replaces its own interface config
    if request.config.enabled {
        let bridges = state.db.get_all_bridges().await?;
        if let Some(bridge) = bridges
            .iter()
            .find(|b| b.members.contains(&request.config.name))
        {
            return Ok(Json(SaveInterfaceConfigResponse {
                success: false,
                message: format!(
                    "{} is a member of bridge {}; remove it from the bridge before enabling its own interface configuration",
                    request.config.name, bridge.name
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

    // Refuse while other configuration still depends on this interface
    let configs = state.db.get_interface_configs().await?;
    let zones = state.db.get_firewall_zones().await?;
    let ranges = dnsmasq::load_dhcp_ranges(state.db.pool()).await?;
    let caddy_config = caddy::load_caddy_config(state.db.pool()).await?;
    let vlans = state.db.get_all_vlans().await?;
    let bridges = state.db.get_all_bridges().await?;
    let refs = config_validation::interface_references(
        &name,
        &configs,
        &zones,
        &ranges,
        &caddy_config,
        &vlans,
        &bridges,
    );
    if !refs.is_empty() {
        return Ok(Json(SaveInterfaceConfigResponse {
            success: false,
            message: format!(
                "Cannot delete '{}': it is still referenced by {}. Remove those references first.",
                name,
                refs.join(", ")
            ),
            config_id: None,
        }));
    }

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

/// POST /interfaces/:name/renew - Ask networkd to renew dynamic settings.
async fn renew_interface(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Result<Json<RenewInterfaceResponse>, AppError> {
    run_networkctl_on_managed_link(&state, "renew", &name).await?;
    Ok(Json(RenewInterfaceResponse {
        success: true,
        message: format!("Renewal requested for {name}"),
    }))
}

/// POST /interfaces/:name/reconfigure - Re-apply the link's `.network` file.
async fn reconfigure_interface(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Result<Json<RenewInterfaceResponse>, AppError> {
    run_networkctl_on_managed_link(&state, "reconfigure", &name).await?;
    Ok(Json(RenewInterfaceResponse {
        success: true,
        message: format!("Reconfiguration requested for {name}"),
    }))
}

/// Run `networkctl <action> <name>` for a real, enabled, Keystone-managed link.
/// Execute fixed arguments directly, never through a shell.
async fn run_networkctl_on_managed_link(
    state: &AppState,
    action: &'static str,
    name: &str,
) -> Result<(), AppError> {
    keystone_core::validation::interface_name(name)
        .map_err(|err| AppError(anyhow::anyhow!(err)))?;
    let config = state.db.get_interface_config(name).await?;
    if !config.is_some_and(|config| config.enabled) {
        return Err(AppError(anyhow::anyhow!(
            "Interface is not managed or is disabled"
        )));
    }
    if !Path::new("/sys/class/net").join(name).exists() {
        return Err(AppError(anyhow::anyhow!(
            "Interface does not exist on this system"
        )));
    }

    let output = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        tokio::process::Command::new("/usr/bin/networkctl")
            .arg(action)
            .arg(name)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("networkctl {action} timed out"))??;
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        return Err(AppError(anyhow::anyhow!(
            "networkctl {action} failed: {}",
            error.trim()
        )));
    }
    Ok(())
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
    Json(request): Json<Req<SaveVlan>>,
) -> Result<Json<Res<SaveVlan>>, AppError> {
    info!("Saving VLAN config: {}", request.config.name);

    let fields = networkd::validate_vlan_fields(&request.config);
    if !fields.is_empty() {
        return Ok(Json(SaveVlanConfigResponse {
            success: false,
            message: fields.join("; "),
            vlan_id: None,
        }));
    }

    // Validate against the other VLANs
    let mut vlans = state.db.get_all_vlans().await?;
    vlans.retain(|v| {
        !(request.config.id.is_some() && v.id == request.config.id) && v.name != request.config.name
    });
    vlans.push(request.config.clone());
    let errors = networkd::validate_vlans(&vlans);
    if !errors.is_empty() {
        return Ok(Json(SaveVlanConfigResponse {
            success: false,
            message: errors.join("; "),
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
    Json(request): Json<Req<SaveBridge>>,
) -> Result<Json<Res<SaveBridge>>, AppError> {
    info!("Saving bridge config: {:?}", request.config.name);

    let fields = networkd::validate_bridge_fields(&request.config);
    if !fields.is_empty() {
        return Ok(Json(keystone_core::SaveBridgeConfigResponse {
            success: false,
            message: fields.join("; "),
            bridge_id: None,
        }));
    }

    // Validate membership against interface configs and other bridges
    let configs = state.db.get_interface_configs().await?;
    let mut bridges = state.db.get_all_bridges().await?;
    bridges.retain(|b| {
        !(request.config.id.is_some() && b.id == request.config.id) && b.name != request.config.name
    });
    bridges.push(request.config.clone());
    let errors: Vec<String> = networkd::validate_topology(&configs, &[], &bridges);
    if !errors.is_empty() {
        return Ok(Json(keystone_core::SaveBridgeConfigResponse {
            success: false,
            message: errors.join("; "),
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

/// Every file the networkd apply writes for the current database state, in
/// write order. Later entries replace earlier ones with the same name, as they
/// do on disk.
pub(crate) async fn networkd_preview_files(
    db: &Database,
) -> anyhow::Result<Vec<keystone_core::NetworkdFilePreview>> {
    // Get all interface configs from database
    let configs = db.get_interface_configs().await?;

    // Get all VLAN configs from database
    let vlans = db.get_all_vlans().await?;

    // Get all bridge configs from database
    let bridges = db.get_all_bridges().await?;

    // Forwarding settings are written before the link files.
    let mut files: Vec<keystone_core::NetworkdFilePreview> = Vec::new();
    if let Some(content) = networkd::generate_networkd_global_config(&configs) {
        files.push(keystone_core::NetworkdFilePreview {
            filename: format!(
                "{}/{}",
                networkd::NETWORKD_CONFIG_DIR,
                networkd::NETWORKD_ROUTER_CONFIG
            ),
            content,
        });
    }
    files.push(keystone_core::NetworkdFilePreview {
        filename: networkd::ROUTER_SYSCTL_CONFIG.to_string(),
        content: networkd::generate_router_sysctl_config(&configs),
    });

    // Generate preview for all enabled interface configs
    files.extend(
        configs
            .iter()
            .filter(|config| config.enabled)
            .map(|config| keystone_core::NetworkdFilePreview {
                filename: networkd::get_network_filename(&config.name),
                content: networkd::generate_network_file(config),
            }),
    );

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
                content: networkd::generate_bridge_member_network_file(
                    member,
                    &bridge.name,
                    &vlans,
                ),
            });
        }
    }

    // Minimal .network files for VLAN parents with no interface config
    for (filename, content) in networkd::vlan_parent_network_files(&configs, &vlans, &bridges) {
        files.push(keystone_core::NetworkdFilePreview { filename, content });
    }

    Ok(files)
}

/// GET /networkd-preview - Preview networkd files without writing to disk
async fn networkd_preview(
    State(state): State<Arc<AppState>>,
) -> Result<Json<keystone_core::NetworkdPreviewResponse>, AppError> {
    info!("Generating networkd preview");
    let files = networkd_preview_files(&state.db).await?;
    Ok(Json(keystone_core::NetworkdPreviewResponse { files }))
}

/// POST /apply-networkd - Write interface configs to networkd and reload
async fn apply_networkd(
    State(state): State<Arc<AppState>>,
    actor: Option<Extension<Actor>>,
) -> Result<Json<ApplyConfigResponse>, AppError> {
    info!("Applying networkd configuration");

    // Check if configuration changes are disabled
    let global_settings = state.db.get_global_settings().await?;
    if global_settings.config_changes_disabled {
        return Ok(Json(ApplyConfigResponse {
            success: false,
            message: "Configuration changes are disabled. Unlock in Settings to apply changes."
                .to_string(),
            errors: Vec::new(),
            pending_confirmation: false,
            confirm_deadline: None,
            session_id: None,
        }));
    }
    if apply::pending_confirmation(&state.firewall_manager)
        .await
        .is_some()
    {
        return Ok(Json(ApplyConfigResponse {
            success: false,
            message: apply::AWAITING_CONFIRMATION_MESSAGE.to_string(),
            errors: Vec::new(),
            pending_confirmation: true,
            confirm_deadline: None,
            session_id: None,
        }));
    }

    let configs = state.db.get_interface_configs().await?;
    let vlans = state.db.get_all_vlans().await?;
    let bridges = state.db.get_all_bridges().await?;

    let result = state
        .firewall_manager
        .networkd()
        .apply(
            &configs,
            &vlans,
            &bridges,
            firewall::DEFAULT_CONFIRM_TIMEOUT_SECS,
        )
        .await;
    match result {
        Ok(applied) => {
            let summary = applied.summary;
            let mut message = format!(
                "Applied networkd config for {} interfaces, {} VLANs, and {} bridges",
                summary.interfaces, summary.vlans, summary.bridges
            );
            let actor = actor.as_ref().map(|Extension(actor)| actor.0.as_str());
            if let Some(pending) = &applied.pending {
                message.push_str(&format!(
                    ". Confirm within {} seconds or the change will be rolled back.",
                    firewall::DEFAULT_CONFIRM_TIMEOUT_SECS
                ));
                snapshots::record_applied(
                    &state.db,
                    actor,
                    Some(&pending.session_id),
                    &[snapshots::Component::Networkd],
                    "networkd apply",
                )
                .await;
                return Ok(Json(ApplyConfigResponse {
                    success: true,
                    message,
                    errors: Vec::new(),
                    pending_confirmation: true,
                    confirm_deadline: Some(pending.deadline),
                    session_id: Some(pending.session_id.clone()),
                }));
            }
            snapshots::record_applied(
                &state.db,
                actor,
                None,
                &[snapshots::Component::Networkd],
                "networkd apply",
            )
            .await;
            Ok(Json(ApplyConfigResponse {
                success: true,
                message,
                errors: Vec::new(),
                pending_confirmation: false,
                confirm_deadline: None,
                session_id: None,
            }))
        }
        Err(error) => Ok(Json(ApplyConfigResponse {
            success: false,
            message: error.to_string(),
            errors: vec![error.to_string()],
            pending_confirmation: false,
            confirm_deadline: None,
            session_id: None,
        })),
    }
}

/// POST /networkd/confirm - Confirm a pending networkd change (or a shared
/// firewall + networkd session).
async fn confirm_networkd(
    State(state): State<Arc<AppState>>,
    Json(request): Json<Req<ConfirmNetworkd>>,
) -> Result<Json<Res<ConfirmNetworkd>>, AppError> {
    Ok(Json(
        state.firewall_manager.confirm(&request.session_id).await?,
    ))
}

/// POST /networkd/rollback - Roll back pending changes immediately.
async fn rollback_networkd(
    State(state): State<Arc<AppState>>,
) -> Result<Json<keystone_core::NetworkdRollbackResponse>, AppError> {
    Ok(Json(state.firewall_manager.rollback().await?))
}

/// GET /networkd/status - Pending-confirmation status.
async fn networkd_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<keystone_core::NetworkdStatusResponse>, AppError> {
    Ok(Json(state.firewall_manager.status().await))
}

/// POST /apply-all - Apply all configuration (networkd, firewall, sqm, upnp, blocky, dnsmasq, caddy)
async fn apply_all(
    State(state): State<Arc<AppState>>,
    actor: Option<Extension<Actor>>,
) -> Result<Json<apply::ApplyAllResult>, AppError> {
    info!("Applying all configuration");

    let actor = actor.as_ref().map(|Extension(actor)| actor.0.as_str());
    let result = apply::apply_all(&state.db, &state.firewall_manager, None, actor).await?;

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
    Json(request): Json<Req<SaveUser>>,
) -> Result<Json<Res<SaveUser>>, AppError> {
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
    Json(request): Json<Req<DeleteUser>>,
) -> Result<Json<Res<DeleteUser>>, AppError> {
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
    Json(request): Json<Req<SaveGlobalSettings>>,
) -> Result<Json<Res<SaveGlobalSettings>>, AppError> {
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

/// POST /complete-setup - Mark initial setup as complete
async fn complete_setup(
    State(state): State<Arc<AppState>>,
) -> Result<Json<CompleteSetupResponse>, AppError> {
    info!("Completing initial setup");

    // Perform status checks to ensure all required checks pass
    let settings = state.db.get_global_settings().await?;
    let status = status::perform_all_checks(settings.setup_complete);

    if !status.all_checks_pass {
        return Ok(Json(CompleteSetupResponse {
            success: false,
            message: format!(
                "Cannot complete setup: {} error(s) must be resolved first",
                status.error_count
            ),
        }));
    }

    // Mark setup as complete
    state.db.mark_setup_complete().await?;

    Ok(Json(CompleteSetupResponse {
        success: true,
        message: "Setup completed successfully".to_string(),
    }))
}

/// Error wrapper for Axum handlers
struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        error!("Request error: {:?}", self.0);

        let body = Json(serde_json::json!({ "error": self.0.to_string() }));

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

#[cfg(test)]
mod tests {
    use super::is_blocked_before_setup;
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use keystone_core::api::{SaveCaddyConfig, SaveDnsmasqConfig, SaveFirewallZone, SaveInputRule};
    use keystone_core::{
        CaddyConfig, DnsmasqConfig, FirewallZone, InputRule, SaveCaddyConfigRequest,
        SaveDnsmasqConfigRequest, SaveFirewallZoneRequest, SaveInputRuleRequest,
    };

    /// Router built from the same sub-routers as production, on an in-memory
    /// database, without the auth layer or any system access.
    async fn test_router() -> Router {
        let db = Database::new_in_memory().await.unwrap();
        let networkd = Arc::new(networkd::NetworkdApplyManager::system());
        let manager = Arc::new(firewall::FirewallApplyManager::new(
            Arc::new(db.clone()),
            networkd,
        ));
        let state = Arc::new(AppState::new(
            Arc::new(AuthManager::new(vec![7; 32])),
            db.clone(),
            manager.clone(),
        ));
        Router::new()
            .merge(firewall::routes::firewall_routes(
                firewall::routes::FirewallState {
                    db: db.clone(),
                    apply_manager: manager.clone(),
                },
            ))
            .merge(dnsmasq::routes::dnsmasq_routes(
                dnsmasq::routes::DnsmasqState {
                    db: db.clone(),
                    firewall: manager.clone(),
                },
            ))
            .merge(caddy::routes::caddy_routes(caddy::routes::CaddyState {
                db,
                firewall: manager,
            }))
            .with_state(state)
    }

    /// Send a typed request to the endpoint and assert it reached the handler
    /// (not unrouted, wrong method, or a body-shape rejection).
    async fn assert_routed<E: Endpoint>(app: &Router, body: &E::Request) {
        let request = Request::builder()
            .method(E::METHOD.as_str())
            .uri(E::PATH)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap();
        let status = app.clone().oneshot(request).await.unwrap().status();
        assert!(
            ![
                StatusCode::NOT_FOUND,
                StatusCode::METHOD_NOT_ALLOWED,
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                StatusCode::UNPROCESSABLE_ENTITY,
                StatusCode::BAD_REQUEST,
            ]
            .contains(&status),
            "{} {} was not routed to its handler: {status}",
            E::METHOD.as_str(),
            E::PATH
        );
    }

    #[tokio::test]
    async fn typed_endpoints_are_routed_with_their_request_bodies() {
        let app = test_router().await;
        assert_routed::<SaveDnsmasqConfig>(
            &app,
            &SaveDnsmasqConfigRequest {
                config: DnsmasqConfig::default(),
            },
        )
        .await;
        assert_routed::<SaveCaddyConfig>(
            &app,
            &SaveCaddyConfigRequest {
                config: CaddyConfig::default(),
            },
        )
        .await;
        assert_routed::<SaveFirewallZone>(
            &app,
            &SaveFirewallZoneRequest {
                zone: FirewallZone {
                    name: "lan".into(),
                    ..Default::default()
                },
            },
        )
        .await;
        assert_routed::<SaveInputRule>(
            &app,
            &SaveInputRuleRequest {
                rule: InputRule {
                    name: "ssh".into(),
                    ..Default::default()
                },
            },
        )
        .await;
    }

    #[tokio::test]
    async fn app_error_body_is_json_with_error_message() {
        use axum::response::IntoResponse;
        let response = AppError(anyhow::anyhow!("zone name is invalid")).into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"], "zone name is invalid");
    }

    #[tokio::test]
    async fn bare_body_without_wrapper_is_rejected() {
        let app = test_router().await;
        let request = Request::builder()
            .method("PUT")
            .uri(SaveDnsmasqConfig::PATH)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&DnsmasqConfig::default()).unwrap(),
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn pre_setup_allows_firewall_recovery_but_not_mutation() {
        assert!(!is_blocked_before_setup("/firewall/confirm"));
        assert!(!is_blocked_before_setup("/firewall/rollback"));
        assert!(!is_blocked_before_setup("/firewall/status"));
        assert!(is_blocked_before_setup("/firewall/apply"));
        assert!(is_blocked_before_setup("/firewall/zones"));
    }

    #[test]
    fn pre_setup_allows_wizard_and_completion_endpoints() {
        assert!(!is_blocked_before_setup("/wizard/interfaces"));
        assert!(!is_blocked_before_setup("/complete-setup"));
        assert!(!is_blocked_before_setup("/state"));
        assert!(is_blocked_before_setup("/dashboard"));
        assert!(is_blocked_before_setup("/clients"));
        assert!(is_blocked_before_setup("/apply-all"));
        assert!(is_blocked_before_setup("/interfaces/enp3s0/renew"));
        assert!(is_blocked_before_setup("/interfaces/enp3s0/reconfigure"));
    }

    #[test]
    fn dashboard_excludes_unmanaged_and_disabled_interfaces() {
        use super::restrict_dashboard_to_managed;
        use keystone_core::{
            Interface, InterfaceConfig, InterfaceCounters, InterfaceRole, InterfaceTraffic,
            SystemState,
        };

        let configs = [
            InterfaceConfig {
                name: "enp2s0".into(),
                role: InterfaceRole::LAN,
                enabled: true,
                ..Default::default()
            },
            InterfaceConfig {
                name: "enp3s0".into(),
                role: InterfaceRole::WAN,
                enabled: true,
                ..Default::default()
            },
            InterfaceConfig {
                name: "enp4s0".into(),
                role: InterfaceRole::LAN,
                enabled: false,
                ..Default::default()
            },
        ];
        let names = ["wlp4s0bl", "enp2s0", "enp3s0", "enp4s0"];
        let mut state = SystemState {
            interfaces: names
                .iter()
                .map(|name| Interface {
                    name: (*name).into(),
                    address: None,
                    ipv4_addresses: vec![],
                    ipv6_addresses: vec![],
                    dhcp_enabled: false,
                    role: InterfaceRole::LAN,
                    enabled: true,
                })
                .collect(),
        };
        let mut counters = names
            .iter()
            .map(|name| InterfaceCounters {
                name: (*name).into(),
                ..Default::default()
            })
            .collect();
        let mut traffic = names
            .iter()
            .map(|name| InterfaceTraffic {
                name: (*name).into(),
                role: None,
                samples: vec![],
            })
            .collect();

        restrict_dashboard_to_managed(&configs, &mut state, &mut counters, &mut traffic);

        let expected = ["enp2s0", "enp3s0"];
        assert_eq!(
            state
                .interfaces
                .iter()
                .map(|i| i.name.as_str())
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(
            counters.iter().map(|i| i.name.as_str()).collect::<Vec<_>>(),
            expected
        );
        assert_eq!(
            traffic.iter().map(|i| i.name.as_str()).collect::<Vec<_>>(),
            expected
        );
        assert_eq!(state.interfaces[1].role, InterfaceRole::WAN);
        assert_eq!(traffic[0].role, Some(InterfaceRole::LAN));
        assert_eq!(traffic[1].role, Some(InterfaceRole::WAN));
    }
}
