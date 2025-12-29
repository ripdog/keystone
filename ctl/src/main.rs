//! keystonectl - Command-line interface for Keystone
//!
//! Communicates with the keystone-daemon over Unix socket at /run/keystone.sock

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use keystone_core::{
    ApplyConfigRequest, ApplyConfigResponse, DashboardResponse, DeleteUserRequest,
    DeleteUserResponse, LoginRequest, LoginResponse, ManagedInterfacesResponse,
    SaveManagedInterfacesRequest, SaveManagedInterfacesResponse, SaveUserRequest,
    SaveUserResponse, SystemState, UsersResponse,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tokio::net::UnixStream;

const SOCKET_PATH: &str = "/run/keystone.sock";

/// Get the path to the token file
fn get_token_path() -> Result<PathBuf> {
    let state_dir = if let Ok(dir) = std::env::var("XDG_STATE_HOME") {
        PathBuf::from(dir)
    } else {
        let home = std::env::var("HOME").context("HOME environment variable not set")?;
        PathBuf::from(home).join(".local/state")
    };
    
    let keystone_dir = state_dir.join("keystone");
    fs::create_dir_all(&keystone_dir)
        .context("Failed to create keystone state directory")?;
    
    Ok(keystone_dir.join("token"))
}

/// Save token to file with 0600 permissions
fn save_token(token: &str) -> Result<()> {
    let token_path = get_token_path()?;
    fs::write(&token_path, token)
        .context("Failed to write token file")?;
    
    // Set permissions to 0600 (owner read/write only)
    fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600))
        .context("Failed to set token file permissions")?;
    
    Ok(())
}

/// Load token from file
fn load_token() -> Result<String> {
    let token_path = get_token_path()?;
    fs::read_to_string(&token_path)
        .context("Failed to read token file. Use 'keystonectl login' to authenticate.")
}

/// Get token from argument, environment variable, or stored file
fn get_token(token_arg: Option<String>) -> Result<String> {
    if let Some(token) = token_arg {
        return Ok(token);
    }
    
    if let Ok(token) = std::env::var("KEYSTONE_TOKEN") {
        return Ok(token);
    }
    
    load_token()
}


/// Keystone CLI - manage your router/firewall from the command line
#[derive(Parser)]
#[command(name = "keystonectl")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Output raw JSON instead of pretty-printed human-readable format
    #[arg(short, long, global = true)]
    json: bool,

    /// Path to Unix socket (default: /run/keystone.sock)
    #[arg(short, long, global = true, default_value = SOCKET_PATH)]
    socket: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check daemon health
    Health,

    /// Login to get a JWT token
    Login {
        /// Username
        #[arg(short, long)]
        username: String,

        /// Password (will prompt securely if not provided)
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Get current system state
    State {
        /// JWT token for authentication (reads from file if not provided)
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,
    },

    /// Get dashboard data (state + interface counters)
    Dashboard {
        /// JWT token for authentication (reads from file if not provided)
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,
    },

    /// Apply a new system configuration (reads JSON from stdin)
    Apply {
        /// JWT token for authentication (reads from file if not provided)
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,

        /// Path to JSON config file (reads from stdin if not provided)
        #[arg(short, long)]
        file: Option<String>,
    },

    /// Manage users
    #[command(subcommand)]
    Users(UsersCommands),

    /// Manage interfaces
    #[command(subcommand)]
    Interfaces(InterfacesCommands),
}

#[derive(Subcommand)]
enum UsersCommands {
    /// List all users
    List {
        /// JWT token for authentication (reads from file if not provided)
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,
    },

    /// Create a new user
    Create {
        /// JWT token for authentication (reads from file if not provided)
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,

        /// Username
        #[arg(short = 'U', long)]
        username: String,

        /// Email (optional)
        #[arg(short, long)]
        email: Option<String>,

        /// Password (will prompt securely if not provided)
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Update an existing user
    Update {
        /// JWT token for authentication (reads from file if not provided)
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,

        /// User ID to update
        #[arg(short, long)]
        id: i64,

        /// New username
        #[arg(short = 'U', long)]
        username: String,

        /// New email (optional)
        #[arg(short, long)]
        email: Option<String>,

        /// New password (optional, only if changing)
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Delete a user
    Delete {
        /// JWT token for authentication (reads from file if not provided)
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,

        /// User ID to delete
        #[arg(short, long)]
        id: i64,
    },
}

#[derive(Subcommand)]
enum InterfacesCommands {
    /// List managed interfaces
    List {
        /// JWT token for authentication (reads from file if not provided)
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,
    },

    /// Save managed interfaces configuration (reads JSON from stdin)
    Save {
        /// JWT token for authentication (reads from file if not provided)
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,

        /// Path to JSON config file (reads from stdin if not provided)
        #[arg(short, long)]
        file: Option<String>,
    },
}

/// HTTP client for Unix socket communication
struct DaemonClient {
    socket_path: String,
}

impl DaemonClient {
    fn new(socket_path: String) -> Self {
        Self { socket_path }
    }

    async fn request<T: DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        body: Option<&impl Serialize>,
        token: Option<&str>,
    ) -> Result<T> {
        // Connect to Unix socket
        let stream = UnixStream::connect(&self.socket_path)
            .await
            .with_context(|| format!("Failed to connect to daemon at {}", self.socket_path))?;

        let io = TokioIo::new(stream);

        // Create HTTP/1 connection
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .context("Failed to establish HTTP connection")?;

        // Spawn connection handler
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                eprintln!("Connection error: {}", e);
            }
        });

        // Build request
        let body_bytes = match body {
            Some(b) => serde_json::to_vec(b).context("Failed to serialize request body")?,
            None => Vec::new(),
        };

        let mut req_builder = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header("Content-Type", "application/json");

        if let Some(t) = token {
            req_builder = req_builder.header("Authorization", format!("Bearer {}", t));
        }

        let req = req_builder
            .body(Full::new(Bytes::from(body_bytes)))
            .context("Failed to build request")?;

        // Send request
        let response = sender
            .send_request(req)
            .await
            .context("Failed to send request to daemon")?;

        let status = response.status();
        let body_bytes = response
            .into_body()
            .collect()
            .await
            .context("Failed to read response body")?
            .to_bytes();

        if !status.is_success() {
            let error_msg = String::from_utf8_lossy(&body_bytes);
            anyhow::bail!("Request failed with status {}: {}", status, error_msg);
        }

        serde_json::from_slice(&body_bytes).context("Failed to parse response JSON")
    }

    async fn get<T: DeserializeOwned>(&self, path: &str, token: Option<&str>) -> Result<T> {
        self.request::<T>("GET", path, None::<&()>, token).await
    }

    async fn post<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &impl Serialize,
        token: Option<&str>,
    ) -> Result<T> {
        self.request("POST", path, Some(body), token).await
    }

    async fn delete<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &impl Serialize,
        token: Option<&str>,
    ) -> Result<T> {
        self.request("DELETE", path, Some(body), token).await
    }
}

/// Pretty print functions for human-readable output
mod pretty {
    use keystone_core::*;
    use super::{save_token, get_token_path};
    use std::path::PathBuf;

    pub fn health(json: &serde_json::Value) {
        if let Some(status) = json.get("status").and_then(|s| s.as_str()) {
            let emoji = if status == "healthy" { "✓" } else { "✗" };
            println!("{} Daemon status: {}", emoji, status);
        }
    }

    pub fn login(response: &LoginResponse) {
        if response.success {
            println!("✓ Login successful");
            if let Some(token) = &response.token {
                // Save token to file
                if let Err(e) = save_token(token) {
                    eprintln!("Warning: Failed to save token: {}", e);
                    println!("\nManually export token:");
                    println!("  export KEYSTONE_TOKEN=\"{}\"", token);
                } else {
                    let token_path = get_token_path().unwrap_or_else(|_| PathBuf::from("~/.local/state/keystone/token"));
                    println!("\n✓ Token saved to {}", token_path.display());
                    println!("  You can now run commands without specifying a token");
                }
            }
        } else {
            println!("✗ Login failed: {}", response.message);
        }
    }

    pub fn state(state: &SystemState) {
        println!("=== System State ===\n");

        println!("Global Settings:");
        println!(
            "  IP Forwarding: {}",
            if state.ip_forwarding_enabled {
                "enabled"
            } else {
                "disabled"
            }
        );
        println!(
            "  NAT:           {}",
            if state.nat_enabled {
                "enabled"
            } else {
                "disabled"
            }
        );

        println!("\nInterfaces ({}):", state.interfaces.len());
        for iface in &state.interfaces {
            let status = if iface.enabled { "UP" } else { "DOWN" };
            let addr = iface.address.as_deref().unwrap_or("no address");
            let dhcp = if iface.dhcp_enabled { "DHCP" } else { "static" };
            println!("  {} [{}] {} ({}, {})", iface.name, iface.role, addr, dhcp, status);
        }

        // TODO: Add firewall zone display once FirewallConfig is integrated
        println!("\nFirewall: Zone-based firewall (run 'keystonectl firewall' for details)");
    }

    pub fn dashboard(dashboard: &DashboardResponse) {
        state(&dashboard.state);

        println!("\nInterface Counters:");
        for counter in &dashboard.interface_counters {
            println!(
                "  {}: RX {} bytes ({} pkts), TX {} bytes ({} pkts)",
                counter.name,
                format_bytes(counter.rx_bytes),
                counter.rx_packets,
                format_bytes(counter.tx_bytes),
                counter.tx_packets
            );
        }
    }

    fn format_bytes(bytes: u64) -> String {
        if bytes >= 1_000_000_000 {
            format!("{:.2}G", bytes as f64 / 1_000_000_000.0)
        } else if bytes >= 1_000_000 {
            format!("{:.2}M", bytes as f64 / 1_000_000.0)
        } else if bytes >= 1_000 {
            format!("{:.2}K", bytes as f64 / 1_000.0)
        } else {
            format!("{}", bytes)
        }
    }

    pub fn apply(response: &ApplyConfigResponse) {
        if response.success {
            println!("✓ Configuration applied: {}", response.message);
        } else {
            println!("✗ Failed to apply configuration: {}", response.message);
            for err in &response.errors {
                println!("  - {}", err);
            }
        }
    }

    pub fn users(response: &UsersResponse) {
        println!("=== Users ===\n");
        println!("{:<6} {:<20} {:<30}", "ID", "Username", "Email");
        println!("{}", "-".repeat(60));
        for user in &response.users {
            let email = user.email.as_deref().unwrap_or("-");
            println!("{:<6} {:<20} {:<30}", user.id, user.username, email);
        }
    }

    pub fn save_user(response: &SaveUserResponse) {
        if response.success {
            println!("✓ {}", response.message);
            if let Some(id) = response.user_id {
                println!("  User ID: {}", id);
            }
        } else {
            println!("✗ {}", response.message);
        }
    }

    pub fn delete_user(response: &DeleteUserResponse) {
        if response.success {
            println!("✓ {}", response.message);
        } else {
            println!("✗ {}", response.message);
        }
    }

    pub fn managed_interfaces(response: &ManagedInterfacesResponse) {
        println!("=== Managed Interfaces ===\n");
        println!(
            "{:<15} {:<6} {:<20} {:<8}",
            "Name", "Role", "Static IP", "Enabled"
        );
        println!("{}", "-".repeat(55));
        for iface in &response.interfaces {
            let ip = iface.static_ip.as_deref().unwrap_or("DHCP");
            let enabled = if iface.enabled { "yes" } else { "no" };
            println!(
                "{:<15} {:<6} {:<20} {:<8}",
                iface.name, iface.role, ip, enabled
            );
        }
    }

    pub fn save_interfaces(response: &SaveManagedInterfacesResponse) {
        if response.success {
            println!("✓ {}", response.message);
        } else {
            println!("✗ {}", response.message);
        }
    }
}

fn output<T: Serialize>(json_mode: bool, value: &T, pretty_fn: impl FnOnce(&T)) {
    if json_mode {
        println!(
            "{}",
            serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        pretty_fn(value);
    }
}

fn read_json_input(file: Option<&str>) -> Result<String> {
    match file {
        Some(path) => {
            std::fs::read_to_string(path).with_context(|| format!("Failed to read file: {}", path))
        }
        None => {
            use std::io::Read;
            let mut buffer = String::new();
            std::io::stdin()
                .read_to_string(&mut buffer)
                .context("Failed to read from stdin")?;
            Ok(buffer)
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Check socket exists before trying to connect
    if !Path::new(&cli.socket).exists() {
        eprintln!(
            "Error: Daemon socket not found at {}\n\
             Is keystone-daemon running?",
            cli.socket
        );
        std::process::exit(1);
    }

    let client = DaemonClient::new(cli.socket);

    match cli.command {
        Commands::Health => {
            let response: serde_json::Value = client.get("/health", None).await?;
            output(cli.json, &response, pretty::health);
        }

        Commands::Login { username, password } => {
            let password = match password {
                Some(p) => p,
                None => {
                    // Prompt for password securely
                    rpassword::prompt_password(format!("Password for {}: ", username))
                        .context("Failed to read password")?
                }
            };
            let request = LoginRequest { username, password };
            let response: LoginResponse = client.post("/login", &request, None).await?;
            output(cli.json, &response, pretty::login);
            if !response.success {
                std::process::exit(1);
            }
        }

        Commands::State { token } => {
            let token = get_token(token)?;
            let response: SystemState = client.get("/state", Some(&token)).await?;
            output(cli.json, &response, pretty::state);
        }

        Commands::Dashboard { token } => {
            let token = get_token(token)?;
            let response: DashboardResponse = client.get("/dashboard", Some(&token)).await?;
            output(cli.json, &response, pretty::dashboard);
        }

        Commands::Apply { token, file } => {
            let token = get_token(token)?;
            let json_input = read_json_input(file.as_deref())?;
            let state: SystemState =
                serde_json::from_str(&json_input).context("Invalid JSON input")?;
            let request = ApplyConfigRequest { state };
            let response: ApplyConfigResponse =
                client.post("/apply", &request, Some(&token)).await?;
            output(cli.json, &response, pretty::apply);
            if !response.success {
                std::process::exit(1);
            }
        }

        Commands::Users(subcmd) => match subcmd {
            UsersCommands::List { token } => {
                let token = get_token(token)?;
                let response: UsersResponse = client.get("/users", Some(&token)).await?;
                output(cli.json, &response, pretty::users);
            }

            UsersCommands::Create {
                token,
                username,
                email,
                password,
            } => {
                let token = get_token(token)?;
                let password = match password {
                    Some(p) => p,
                    None => {
                        // Prompt for password securely
                        let pass1 = rpassword::prompt_password(format!("Password for {}: ", username))
                            .context("Failed to read password")?;
                        let pass2 = rpassword::prompt_password("Confirm password: ")
                            .context("Failed to read password confirmation")?;
                        if pass1 != pass2 {
                            eprintln!("Error: Passwords do not match");
                            std::process::exit(1);
                        }
                        pass1
                    }
                };
                let request = SaveUserRequest {
                    id: None,
                    username,
                    email,
                    password: Some(password),
                };
                let response: SaveUserResponse =
                    client.post("/users", &request, Some(&token)).await?;
                output(cli.json, &response, pretty::save_user);
                if !response.success {
                    std::process::exit(1);
                }
            }

            UsersCommands::Update {
                token,
                id,
                username,
                email,
                password,
            } => {
                let token = get_token(token)?;
                let request = SaveUserRequest {
                    id: Some(id),
                    username,
                    email,
                    password,
                };
                let response: SaveUserResponse =
                    client.post("/users", &request, Some(&token)).await?;
                output(cli.json, &response, pretty::save_user);
                if !response.success {
                    std::process::exit(1);
                }
            }

            UsersCommands::Delete { token, id } => {
                let token = get_token(token)?;
                let request = DeleteUserRequest { id };
                let response: DeleteUserResponse =
                    client.delete("/users", &request, Some(&token)).await?;
                output(cli.json, &response, pretty::delete_user);
                if !response.success {
                    std::process::exit(1);
                }
            }
        },

        Commands::Interfaces(subcmd) => match subcmd {
            InterfacesCommands::List { token } => {
                let token = get_token(token)?;
                let response: ManagedInterfacesResponse =
                    client.get("/managed-interfaces", Some(&token)).await?;
                output(cli.json, &response, pretty::managed_interfaces);
            }

            InterfacesCommands::Save { token, file } => {
                let token = get_token(token)?;
                let json_input = read_json_input(file.as_deref())?;
                let request: SaveManagedInterfacesRequest =
                    serde_json::from_str(&json_input).context("Invalid JSON input")?;
                let response: SaveManagedInterfacesResponse = client
                    .post("/managed-interfaces", &request, Some(&token))
                    .await?;
                output(cli.json, &response, pretty::save_interfaces);
                if !response.success {
                    std::process::exit(1);
                }
            }
        },
    }

    Ok(())
}
