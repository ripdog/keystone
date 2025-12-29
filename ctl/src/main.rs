//! keystonectl - Command-line interface for Keystone
//!
//! Communicates with the keystone-daemon over Unix socket at /run/keystone.sock

// CLI argument enums naturally have variant size differences - this is expected
#![allow(clippy::large_enum_variant)]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use keystone_core::{
    ApplyConfigRequest, ApplyConfigResponse, DashboardResponse, DeleteUserRequest,
    DeleteUserResponse, FirewallAction, FirewallApplyRequest, FirewallApplyResponse,
    FirewallConfirmRequest, FirewallConfirmResponse, FirewallGlobalSettings,
    FirewallGlobalSettingsResponse, FirewallPolicy, FirewallPreviewResponse,
    FirewallRollbackResponse, FirewallStatusResponse, FirewallZone, FirewallZonesResponse,
    ForwardRule, ForwardRulesResponse, InputRule, InputRulesResponse, LoginRequest, LoginResponse,
    ManagedInterfacesResponse, PortForward, PortForwardsResponse, RuleProtocol,
    SaveFirewallGlobalSettingsRequest, SaveFirewallGlobalSettingsResponse,
    SaveFirewallZoneRequest, SaveFirewallZoneResponse, SaveForwardRuleRequest,
    SaveForwardRuleResponse, SaveInputRuleRequest, SaveInputRuleResponse,
    SaveManagedInterfacesRequest, SaveManagedInterfacesResponse, SavePortForwardRequest,
    SavePortForwardResponse, SaveUserRequest, SaveUserResponse, SaveZoneForwardRequest,
    SaveZoneForwardResponse, SystemState, UsersResponse, ZoneForwardPolicy, ZoneForwardsResponse,
    DeleteFirewallZoneRequest, DeleteFirewallZoneResponse, DeleteZoneForwardRequest,
    DeleteZoneForwardResponse, DeletePortForwardRequest, DeletePortForwardResponse,
    DeleteInputRuleRequest, DeleteInputRuleResponse, DeleteForwardRuleRequest, 
    DeleteForwardRuleResponse,
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

    /// Manage firewall configuration
    #[command(subcommand)]
    Firewall(FirewallCommands),
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

#[derive(Subcommand)]
enum FirewallCommands {
    /// Manage firewall zones
    #[command(subcommand)]
    Zones(ZonesCommands),

    /// Manage zone-to-zone forwarding policies
    #[command(subcommand)]
    ZoneForwards(ZoneForwardsCommands),

    /// Manage port forwards (DNAT)
    #[command(subcommand)]
    PortForwards(PortForwardsCommands),

    /// Manage input rules (traffic to router)
    #[command(subcommand)]
    InputRules(InputRulesCommands),

    /// Manage forward rules (traffic between zones)
    #[command(subcommand)]
    ForwardRules(ForwardRulesCommands),

    /// Manage global firewall settings
    #[command(subcommand)]
    Settings(SettingsCommands),

    /// Preview generated nftables ruleset
    Preview {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,
    },

    /// Apply firewall configuration (with 60s rollback timeout)
    Apply {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,
    },

    /// Confirm applied changes (prevents rollback)
    Confirm {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,

        /// Session ID from apply command
        #[arg(short, long)]
        session_id: String,
    },

    /// Rollback to previous firewall configuration
    Rollback {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,
    },

    /// Show firewall apply status
    Status {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,
    },
}

#[derive(Subcommand)]
enum SettingsCommands {
    /// Show current global settings
    Get {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,
    },

    /// Update global settings
    Set {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,

        /// Enable/disable ping from WAN (true/false)
        #[arg(long)]
        ping_wan: Option<bool>,

        /// Enable/disable ping from LAN (true/false)
        #[arg(long)]
        ping_lan: Option<bool>,

        /// Enable/disable hairpin NAT (true/false)
        #[arg(long)]
        hairpin_nat: Option<bool>,
    },
}

#[derive(Subcommand)]
enum ZonesCommands {
    /// List all firewall zones
    List {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,
    },

    /// Add a new firewall zone
    Add {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,

        /// Zone name
        #[arg(short, long)]
        name: String,

        /// Description
        #[arg(short, long)]
        description: Option<String>,

        /// Comma-separated list of interfaces
        #[arg(short, long)]
        interfaces: Option<String>,

        /// Default input policy (accept or drop)
        #[arg(long, default_value = "drop")]
        input_policy: String,

        /// Default forward policy (accept or drop)
        #[arg(long, default_value = "drop")]
        forward_policy: String,
    },

    /// Delete a firewall zone
    Delete {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,

        /// Zone ID to delete
        #[arg(long)]
        id: i64,
    },
}

#[derive(Subcommand)]
enum ZoneForwardsCommands {
    /// List all zone-to-zone forwarding policies
    List {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,
    },

    /// Add a zone forwarding policy
    Add {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,

        /// Source zone name
        #[arg(long)]
        source: String,

        /// Destination zone name
        #[arg(long)]
        dest: String,

        /// Policy (accept, drop, or reject)
        #[arg(long, default_value = "drop")]
        policy: String,

        /// Whether the policy is enabled
        #[arg(long, default_value = "true")]
        enabled: bool,
    },

    /// Delete a zone forwarding policy
    Delete {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,

        /// Policy ID to delete
        #[arg(long)]
        id: i64,
    },
}

#[derive(Subcommand)]
enum PortForwardsCommands {
    /// List all port forwards
    List {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,
    },

    /// Add a port forward
    Add {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,

        /// Port forward name
        #[arg(short, long)]
        name: String,

        /// Description
        #[arg(short, long)]
        description: Option<String>,

        /// Protocol (tcp, udp, or tcp+udp)
        #[arg(long, default_value = "tcp")]
        protocol: String,

        /// Source zone (optional)
        #[arg(long)]
        source_zone: Option<String>,

        /// External port (or start of range)
        #[arg(long)]
        external_port: u16,

        /// External port range end (optional)
        #[arg(long)]
        external_port_end: Option<u16>,

        /// Source IP restriction (optional)
        #[arg(long)]
        source_ip: Option<String>,

        /// Destination IP
        #[arg(long)]
        dest_ip: String,

        /// Destination port (optional, defaults to external port)
        #[arg(long)]
        dest_port: Option<u16>,

        /// Whether enabled
        #[arg(long, default_value = "true")]
        enabled: bool,
    },

    /// Delete a port forward
    Delete {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,

        /// Port forward ID to delete
        #[arg(long)]
        id: i64,
    },
}

#[derive(Subcommand)]
enum InputRulesCommands {
    /// List all input rules
    List {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,
    },

    /// Add an input rule
    Add {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,

        /// Rule name
        #[arg(short, long)]
        name: String,

        /// Description
        #[arg(short, long)]
        description: Option<String>,

        /// Source zone (optional)
        #[arg(long)]
        zone: Option<String>,

        /// Protocol (any, tcp, udp, icmp, icmpv6)
        #[arg(long)]
        protocol: Option<String>,

        /// Port (or start of range)
        #[arg(long)]
        port: Option<u16>,

        /// Port range end (optional)
        #[arg(long)]
        port_end: Option<u16>,

        /// Source IP/CIDR (optional)
        #[arg(long)]
        source_ip: Option<String>,

        /// Action (accept, drop, or reject)
        #[arg(long, default_value = "accept")]
        action: String,

        /// Enable logging
        #[arg(long, default_value = "false")]
        log: bool,

        /// Log prefix
        #[arg(long)]
        log_prefix: Option<String>,

        /// Rate limit (e.g. "10/minute")
        #[arg(long)]
        rate_limit: Option<String>,

        /// Position/priority (lower = evaluated first)
        #[arg(long, default_value = "0")]
        position: i32,

        /// Whether enabled
        #[arg(long, default_value = "true")]
        enabled: bool,
    },

    /// Delete an input rule
    Delete {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,

        /// Rule ID to delete
        #[arg(long)]
        id: i64,
    },
}

#[derive(Subcommand)]
enum ForwardRulesCommands {
    /// List all forward rules
    List {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,
    },

    /// Add a forward rule
    Add {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,

        /// Rule name
        #[arg(short, long)]
        name: String,

        /// Description
        #[arg(short, long)]
        description: Option<String>,

        /// Source zone (optional)
        #[arg(long)]
        source_zone: Option<String>,

        /// Destination zone (optional)
        #[arg(long)]
        dest_zone: Option<String>,

        /// Protocol (any, tcp, udp, icmp, icmpv6)
        #[arg(long)]
        protocol: Option<String>,

        /// Destination port (or start of range)
        #[arg(long)]
        dest_port: Option<u16>,

        /// Destination port range end (optional)
        #[arg(long)]
        dest_port_end: Option<u16>,

        /// Source IP/CIDR (optional)
        #[arg(long)]
        source_ip: Option<String>,

        /// Destination IP/CIDR (optional)
        #[arg(long)]
        dest_ip: Option<String>,

        /// Action (accept, drop, or reject)
        #[arg(long, default_value = "accept")]
        action: String,

        /// Enable logging
        #[arg(long, default_value = "false")]
        log: bool,

        /// Log prefix
        #[arg(long)]
        log_prefix: Option<String>,

        /// Rate limit (e.g. "10/minute")
        #[arg(long)]
        rate_limit: Option<String>,

        /// Position/priority (lower = evaluated first)
        #[arg(long, default_value = "0")]
        position: i32,

        /// Whether enabled
        #[arg(long, default_value = "true")]
        enabled: bool,
    },

    /// Delete a forward rule
    Delete {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,

        /// Rule ID to delete
        #[arg(long)]
        id: i64,
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

    // ========================================================================
    // Firewall pretty print functions
    // ========================================================================

    pub fn firewall_zones(response: &FirewallZonesResponse) {
        println!("=== Firewall Zones ===\n");
        if response.zones.is_empty() {
            println!("No zones configured.");
            return;
        }
        println!(
            "{:<6} {:<15} {:<25} {:<10} {:<10}",
            "ID", "Name", "Interfaces", "Input", "Forward"
        );
        println!("{}", "-".repeat(70));
        for zone in &response.zones {
            let id = zone.id.map(|i| i.to_string()).unwrap_or("-".to_string());
            let interfaces = if zone.interfaces.is_empty() {
                "(none)".to_string()
            } else {
                zone.interfaces.join(", ")
            };
            println!(
                "{:<6} {:<15} {:<25} {:<10} {:<10}",
                id,
                zone.name,
                interfaces,
                zone.default_input_policy,
                zone.default_forward_policy
            );
        }
    }

    pub fn save_zone(response: &SaveFirewallZoneResponse) {
        if response.success {
            println!("✓ {}", response.message);
            if let Some(id) = response.zone_id {
                println!("  Zone ID: {}", id);
            }
        } else {
            println!("✗ {}", response.message);
        }
    }

    pub fn delete_zone(response: &DeleteFirewallZoneResponse) {
        if response.success {
            println!("✓ {}", response.message);
        } else {
            println!("✗ {}", response.message);
        }
    }

    pub fn zone_forwards(response: &ZoneForwardsResponse) {
        println!("=== Zone Forward Policies ===\n");
        if response.forwards.is_empty() {
            println!("No zone forwarding policies configured.");
            return;
        }
        println!(
            "{:<6} {:<15} {:<15} {:<10} {:<8}",
            "ID", "Source", "Destination", "Policy", "Enabled"
        );
        println!("{}", "-".repeat(60));
        for fwd in &response.forwards {
            let id = fwd.id.map(|i| i.to_string()).unwrap_or("-".to_string());
            let enabled = if fwd.enabled { "yes" } else { "no" };
            println!(
                "{:<6} {:<15} {:<15} {:<10} {:<8}",
                id, fwd.source_zone, fwd.dest_zone, fwd.policy, enabled
            );
        }
    }

    pub fn save_zone_forward(response: &SaveZoneForwardResponse) {
        if response.success {
            println!("✓ {}", response.message);
            if let Some(id) = response.forward_id {
                println!("  Forward Policy ID: {}", id);
            }
        } else {
            println!("✗ {}", response.message);
        }
    }

    pub fn delete_zone_forward(response: &DeleteZoneForwardResponse) {
        if response.success {
            println!("✓ {}", response.message);
        } else {
            println!("✗ {}", response.message);
        }
    }

    pub fn port_forwards(response: &PortForwardsResponse) {
        println!("=== Port Forwards ===\n");
        if response.port_forwards.is_empty() {
            println!("No port forwards configured.");
            return;
        }
        println!(
            "{:<6} {:<20} {:<8} {:<12} {:<18} {:<8}",
            "ID", "Name", "Proto", "Ext Port", "Destination", "Enabled"
        );
        println!("{}", "-".repeat(80));
        for pf in &response.port_forwards {
            let id = pf.id.map(|i| i.to_string()).unwrap_or("-".to_string());
            let ext_port = match pf.external_port_end {
                Some(end) => format!("{}-{}", pf.external_port_start, end),
                None => pf.external_port_start.to_string(),
            };
            let dest = match pf.dest_port {
                Some(port) => format!("{}:{}", pf.dest_ip, port),
                None => format!("{}:{}", pf.dest_ip, pf.external_port_start),
            };
            let enabled = if pf.enabled { "yes" } else { "no" };
            println!(
                "{:<6} {:<20} {:<8} {:<12} {:<18} {:<8}",
                id, pf.name, pf.protocol, ext_port, dest, enabled
            );
        }
    }

    pub fn save_port_forward(response: &SavePortForwardResponse) {
        if response.success {
            println!("✓ {}", response.message);
            if let Some(id) = response.port_forward_id {
                println!("  Port Forward ID: {}", id);
            }
        } else {
            println!("✗ {}", response.message);
        }
    }

    pub fn delete_port_forward(response: &DeletePortForwardResponse) {
        if response.success {
            println!("✓ {}", response.message);
        } else {
            println!("✗ {}", response.message);
        }
    }

    pub fn input_rules(response: &InputRulesResponse) {
        println!("=== Input Rules ===\n");
        if response.rules.is_empty() {
            println!("No input rules configured.");
            return;
        }
        println!(
            "{:<6} {:<4} {:<20} {:<10} {:<8} {:<12} {:<8} {:<8}",
            "ID", "Pos", "Name", "Zone", "Proto", "Port", "Action", "Enabled"
        );
        println!("{}", "-".repeat(85));
        for rule in &response.rules {
            let id = rule.id.map(|i| i.to_string()).unwrap_or("-".to_string());
            let zone = rule.zone.as_deref().unwrap_or("any");
            let proto = rule.protocol.map(|p| p.to_string()).unwrap_or("any".to_string());
            let port = match (rule.port_start, rule.port_end) {
                (None, _) => "any".to_string(),
                (Some(start), None) => start.to_string(),
                (Some(start), Some(end)) => format!("{}-{}", start, end),
            };
            let enabled = if rule.enabled { "yes" } else { "no" };
            println!(
                "{:<6} {:<4} {:<20} {:<10} {:<8} {:<12} {:<8} {:<8}",
                id, rule.position, rule.name, zone, proto, port, rule.action, enabled
            );
        }
    }

    pub fn save_input_rule(response: &SaveInputRuleResponse) {
        if response.success {
            println!("✓ {}", response.message);
            if let Some(id) = response.rule_id {
                println!("  Input Rule ID: {}", id);
            }
        } else {
            println!("✗ {}", response.message);
        }
    }

    pub fn delete_input_rule(response: &DeleteInputRuleResponse) {
        if response.success {
            println!("✓ {}", response.message);
        } else {
            println!("✗ {}", response.message);
        }
    }

    pub fn forward_rules(response: &ForwardRulesResponse) {
        println!("=== Forward Rules ===\n");
        if response.rules.is_empty() {
            println!("No forward rules configured.");
            return;
        }
        println!(
            "{:<6} {:<4} {:<18} {:<10} {:<10} {:<8} {:<10} {:<8} {:<8}",
            "ID", "Pos", "Name", "Src Zone", "Dst Zone", "Proto", "Dst Port", "Action", "Enabled"
        );
        println!("{}", "-".repeat(95));
        for rule in &response.rules {
            let id = rule.id.map(|i| i.to_string()).unwrap_or("-".to_string());
            let src_zone = rule.source_zone.as_deref().unwrap_or("any");
            let dst_zone = rule.dest_zone.as_deref().unwrap_or("any");
            let proto = rule.protocol.map(|p| p.to_string()).unwrap_or("any".to_string());
            let port = match (rule.dest_port_start, rule.dest_port_end) {
                (None, _) => "any".to_string(),
                (Some(start), None) => start.to_string(),
                (Some(start), Some(end)) => format!("{}-{}", start, end),
            };
            let enabled = if rule.enabled { "yes" } else { "no" };
            println!(
                "{:<6} {:<4} {:<18} {:<10} {:<10} {:<8} {:<10} {:<8} {:<8}",
                id, rule.position, rule.name, src_zone, dst_zone, proto, port, rule.action, enabled
            );
        }
    }

    pub fn save_forward_rule(response: &SaveForwardRuleResponse) {
        if response.success {
            println!("✓ {}", response.message);
            if let Some(id) = response.rule_id {
                println!("  Forward Rule ID: {}", id);
            }
        } else {
            println!("✗ {}", response.message);
        }
    }

    pub fn delete_forward_rule(response: &DeleteForwardRuleResponse) {
        if response.success {
            println!("✓ {}", response.message);
        } else {
            println!("✗ {}", response.message);
        }
    }

    pub fn firewall_preview(response: &FirewallPreviewResponse) {
        println!("=== nftables Ruleset Preview ===\n");
        println!("{}", response.ruleset);
    }

    pub fn firewall_apply(response: &FirewallApplyResponse) {
        if response.success {
            println!("✓ {}", response.message);
            if response.pending_confirmation && response.session_id.is_some() {
                let session_id = response.session_id.as_ref().unwrap();
                println!("\n  Session ID: {}", session_id);
                println!("  IMPORTANT: Confirm within 60 seconds or changes will be rolled back!");
                println!("\n  To confirm: keystonectl firewall confirm --session-id {}", session_id);
                println!("  To rollback: keystonectl firewall rollback");
            }
        } else {
            println!("✗ {}", response.message);
        }
    }

    pub fn firewall_confirm(response: &FirewallConfirmResponse) {
        if response.success {
            println!("✓ {}", response.message);
        } else {
            println!("✗ {}", response.message);
        }
    }

    pub fn firewall_rollback(response: &FirewallRollbackResponse) {
        if response.success {
            println!("✓ {}", response.message);
        } else {
            println!("✗ {}", response.message);
        }
    }

    pub fn firewall_status(response: &FirewallStatusResponse) {
        println!("=== Firewall Status ===\n");
        if response.pending_confirmation {
            println!("Status: PENDING CONFIRMATION");
            if let Some(session_id) = &response.session_id {
                println!("Session ID: {}", session_id);
            }
            if let Some(secs) = response.seconds_remaining {
                println!("Time remaining: {} seconds", secs);
                println!("\nChanges will be rolled back automatically if not confirmed!");
            }
        } else {
            println!("Status: No pending changes");
        }
    }

    pub fn firewall_settings(response: &FirewallGlobalSettingsResponse) {
        println!("=== Firewall Global Settings ===\n");
        
        println!("ICMP Settings:");
        println!("  Ping from WAN: {}", if response.settings.ping_wan_enabled { "Enabled" } else { "Disabled" });
        println!("  Ping from LAN: {}", if response.settings.ping_lan_enabled { "Enabled" } else { "Disabled" });
        println!();
        
        println!("NAT Settings:");
        println!("  Hairpin NAT: {}", if response.settings.hairpin_nat_enabled { "Enabled" } else { "Disabled" });
        println!();
        
        println!("Note: Dangerous ICMP types (timestamp, redirect, address-mask) are always blocked.");
    }

    pub fn save_firewall_settings(response: &SaveFirewallGlobalSettingsResponse) {
        if response.success {
            println!("Settings saved successfully");
            println!("\nNote: Apply firewall configuration for changes to take effect.");
        } else {
            println!("Error: {}", response.message);
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

        Commands::Firewall(subcmd) => match subcmd {
            FirewallCommands::Zones(zones_cmd) => match zones_cmd {
                ZonesCommands::List { token } => {
                    let token = get_token(token)?;
                    let response: FirewallZonesResponse =
                        client.get("/firewall/zones", Some(&token)).await?;
                    output(cli.json, &response, pretty::firewall_zones);
                }

                ZonesCommands::Add {
                    token,
                    name,
                    description,
                    interfaces,
                    input_policy,
                    forward_policy,
                } => {
                    let token = get_token(token)?;
                    let interfaces_vec: Vec<String> = interfaces
                        .map(|s| s.split(',').map(|i| i.trim().to_string()).collect())
                        .unwrap_or_default();
                    let input_policy: FirewallPolicy = input_policy
                        .parse()
                        .map_err(|e: String| anyhow::anyhow!(e))?;
                    let forward_policy: FirewallPolicy = forward_policy
                        .parse()
                        .map_err(|e: String| anyhow::anyhow!(e))?;
                    let zone = FirewallZone {
                        id: None,
                        name,
                        description,
                        interfaces: interfaces_vec,
                        default_input_policy: input_policy,
                        default_forward_policy: forward_policy,
                    };
                    let request = SaveFirewallZoneRequest { zone };
                    let response: SaveFirewallZoneResponse =
                        client.post("/firewall/zones", &request, Some(&token)).await?;
                    output(cli.json, &response, pretty::save_zone);
                    if !response.success {
                        std::process::exit(1);
                    }
                }

                ZonesCommands::Delete { token, id } => {
                    let token = get_token(token)?;
                    let request = DeleteFirewallZoneRequest { id };
                    let response: DeleteFirewallZoneResponse =
                        client.delete("/firewall/zones", &request, Some(&token)).await?;
                    output(cli.json, &response, pretty::delete_zone);
                    if !response.success {
                        std::process::exit(1);
                    }
                }
            },

            FirewallCommands::ZoneForwards(zf_cmd) => match zf_cmd {
                ZoneForwardsCommands::List { token } => {
                    let token = get_token(token)?;
                    let response: ZoneForwardsResponse =
                        client.get("/firewall/zone-forwards", Some(&token)).await?;
                    output(cli.json, &response, pretty::zone_forwards);
                }

                ZoneForwardsCommands::Add {
                    token,
                    source,
                    dest,
                    policy,
                    enabled,
                } => {
                    let token = get_token(token)?;
                    let policy: FirewallAction = policy
                        .parse()
                        .map_err(|e: String| anyhow::anyhow!(e))?;
                    let forward = ZoneForwardPolicy {
                        id: None,
                        source_zone: source,
                        dest_zone: dest,
                        policy,
                        enabled,
                    };
                    let request = SaveZoneForwardRequest { forward };
                    let response: SaveZoneForwardResponse = client
                        .post("/firewall/zone-forwards", &request, Some(&token))
                        .await?;
                    output(cli.json, &response, pretty::save_zone_forward);
                    if !response.success {
                        std::process::exit(1);
                    }
                }

                ZoneForwardsCommands::Delete { token, id } => {
                    let token = get_token(token)?;
                    let request = DeleteZoneForwardRequest { id };
                    let response: DeleteZoneForwardResponse = client
                        .delete("/firewall/zone-forwards", &request, Some(&token))
                        .await?;
                    output(cli.json, &response, pretty::delete_zone_forward);
                    if !response.success {
                        std::process::exit(1);
                    }
                }
            },

            FirewallCommands::PortForwards(pf_cmd) => match pf_cmd {
                PortForwardsCommands::List { token } => {
                    let token = get_token(token)?;
                    let response: PortForwardsResponse =
                        client.get("/firewall/port-forwards", Some(&token)).await?;
                    output(cli.json, &response, pretty::port_forwards);
                }

                PortForwardsCommands::Add {
                    token,
                    name,
                    description,
                    protocol,
                    source_zone,
                    external_port,
                    external_port_end,
                    source_ip,
                    dest_ip,
                    dest_port,
                    enabled,
                } => {
                    let token = get_token(token)?;
                    let protocol: RuleProtocol = protocol
                        .parse()
                        .map_err(|e: String| anyhow::anyhow!(e))?;
                    let port_forward = PortForward {
                        id: None,
                        name,
                        description,
                        enabled,
                        protocol,
                        source_zone,
                        external_port_start: external_port,
                        external_port_end,
                        source_ip,
                        dest_ip,
                        dest_port,
                    };
                    let request = SavePortForwardRequest { port_forward };
                    let response: SavePortForwardResponse = client
                        .post("/firewall/port-forwards", &request, Some(&token))
                        .await?;
                    output(cli.json, &response, pretty::save_port_forward);
                    if !response.success {
                        std::process::exit(1);
                    }
                }

                PortForwardsCommands::Delete { token, id } => {
                    let token = get_token(token)?;
                    let request = DeletePortForwardRequest { id };
                    let response: DeletePortForwardResponse = client
                        .delete("/firewall/port-forwards", &request, Some(&token))
                        .await?;
                    output(cli.json, &response, pretty::delete_port_forward);
                    if !response.success {
                        std::process::exit(1);
                    }
                }
            },

            FirewallCommands::InputRules(ir_cmd) => match ir_cmd {
                InputRulesCommands::List { token } => {
                    let token = get_token(token)?;
                    let response: InputRulesResponse =
                        client.get("/firewall/input-rules", Some(&token)).await?;
                    output(cli.json, &response, pretty::input_rules);
                }

                InputRulesCommands::Add {
                    token,
                    name,
                    description,
                    zone,
                    protocol,
                    port,
                    port_end,
                    source_ip,
                    action,
                    log,
                    log_prefix,
                    rate_limit,
                    position,
                    enabled,
                } => {
                    let token = get_token(token)?;
                    let protocol: Option<RuleProtocol> = protocol
                        .map(|p| p.parse())
                        .transpose()
                        .map_err(|e: String| anyhow::anyhow!(e))?;
                    let action: FirewallAction = action
                        .parse()
                        .map_err(|e: String| anyhow::anyhow!(e))?;
                    let rule = InputRule {
                        id: None,
                        name,
                        description,
                        enabled,
                        position,
                        zone,
                        protocol,
                        port_start: port,
                        port_end,
                        source_ip,
                        action,
                        log_enabled: log,
                        log_prefix,
                        rate_limit,
                    };
                    let request = SaveInputRuleRequest { rule };
                    let response: SaveInputRuleResponse = client
                        .post("/firewall/input-rules", &request, Some(&token))
                        .await?;
                    output(cli.json, &response, pretty::save_input_rule);
                    if !response.success {
                        std::process::exit(1);
                    }
                }

                InputRulesCommands::Delete { token, id } => {
                    let token = get_token(token)?;
                    let request = DeleteInputRuleRequest { id };
                    let response: DeleteInputRuleResponse = client
                        .delete("/firewall/input-rules", &request, Some(&token))
                        .await?;
                    output(cli.json, &response, pretty::delete_input_rule);
                    if !response.success {
                        std::process::exit(1);
                    }
                }
            },

            FirewallCommands::ForwardRules(fr_cmd) => match fr_cmd {
                ForwardRulesCommands::List { token } => {
                    let token = get_token(token)?;
                    let response: ForwardRulesResponse =
                        client.get("/firewall/forward-rules", Some(&token)).await?;
                    output(cli.json, &response, pretty::forward_rules);
                }

                ForwardRulesCommands::Add {
                    token,
                    name,
                    description,
                    source_zone,
                    dest_zone,
                    protocol,
                    dest_port,
                    dest_port_end,
                    source_ip,
                    dest_ip,
                    action,
                    log,
                    log_prefix,
                    rate_limit,
                    position,
                    enabled,
                } => {
                    let token = get_token(token)?;
                    let protocol: Option<RuleProtocol> = protocol
                        .map(|p| p.parse())
                        .transpose()
                        .map_err(|e: String| anyhow::anyhow!(e))?;
                    let action: FirewallAction = action
                        .parse()
                        .map_err(|e: String| anyhow::anyhow!(e))?;
                    let rule = ForwardRule {
                        id: None,
                        name,
                        description,
                        enabled,
                        position,
                        source_zone,
                        dest_zone,
                        protocol,
                        dest_port_start: dest_port,
                        dest_port_end,
                        source_ip,
                        dest_ip,
                        action,
                        log_enabled: log,
                        log_prefix,
                        rate_limit,
                    };
                    let request = SaveForwardRuleRequest { rule };
                    let response: SaveForwardRuleResponse = client
                        .post("/firewall/forward-rules", &request, Some(&token))
                        .await?;
                    output(cli.json, &response, pretty::save_forward_rule);
                    if !response.success {
                        std::process::exit(1);
                    }
                }

                ForwardRulesCommands::Delete { token, id } => {
                    let token = get_token(token)?;
                    let request = DeleteForwardRuleRequest { id };
                    let response: DeleteForwardRuleResponse = client
                        .delete("/firewall/forward-rules", &request, Some(&token))
                        .await?;
                    output(cli.json, &response, pretty::delete_forward_rule);
                    if !response.success {
                        std::process::exit(1);
                    }
                }
            },

            FirewallCommands::Settings(settings_cmd) => match settings_cmd {
                SettingsCommands::Get { token } => {
                    let token = get_token(token)?;
                    let response: FirewallGlobalSettingsResponse =
                        client.get("/firewall/settings", Some(&token)).await?;
                    output(cli.json, &response, pretty::firewall_settings);
                }

                SettingsCommands::Set {
                    token,
                    ping_wan,
                    ping_lan,
                    hairpin_nat,
                } => {
                    let token = get_token(token)?;
                    
                    // First, fetch current settings
                    let current: FirewallGlobalSettingsResponse =
                        client.get("/firewall/settings", Some(&token)).await?;
                    
                    // Update with any provided values
                    let settings = FirewallGlobalSettings {
                        ping_wan_enabled: ping_wan.unwrap_or(current.settings.ping_wan_enabled),
                        ping_lan_enabled: ping_lan.unwrap_or(current.settings.ping_lan_enabled),
                        hairpin_nat_enabled: hairpin_nat.unwrap_or(current.settings.hairpin_nat_enabled),
                    };
                    
                    let request = SaveFirewallGlobalSettingsRequest { settings };
                    let response: SaveFirewallGlobalSettingsResponse =
                        client.post("/firewall/settings", &request, Some(&token)).await?;
                    output(cli.json, &response, pretty::save_firewall_settings);
                    if !response.success {
                        std::process::exit(1);
                    }
                }
            },

            FirewallCommands::Preview { token } => {
                let token = get_token(token)?;
                let response: FirewallPreviewResponse =
                    client.get("/firewall/preview", Some(&token)).await?;
                output(cli.json, &response, pretty::firewall_preview);
            }

            FirewallCommands::Apply { token } => {
                let token = get_token(token)?;
                let request = FirewallApplyRequest {};
                let response: FirewallApplyResponse =
                    client.post("/firewall/apply", &request, Some(&token)).await?;
                output(cli.json, &response, pretty::firewall_apply);
                if !response.success {
                    std::process::exit(1);
                }
            }

            FirewallCommands::Confirm { token, session_id } => {
                let token = get_token(token)?;
                let request = FirewallConfirmRequest { session_id };
                let response: FirewallConfirmResponse =
                    client.post("/firewall/confirm", &request, Some(&token)).await?;
                output(cli.json, &response, pretty::firewall_confirm);
                if !response.success {
                    std::process::exit(1);
                }
            }

            FirewallCommands::Rollback { token } => {
                let token = get_token(token)?;
                let response: FirewallRollbackResponse =
                    client.post("/firewall/rollback", &(), Some(&token)).await?;
                output(cli.json, &response, pretty::firewall_rollback);
                if !response.success {
                    std::process::exit(1);
                }
            }

            FirewallCommands::Status { token } => {
                let token = get_token(token)?;
                let response: FirewallStatusResponse =
                    client.get("/firewall/status", Some(&token)).await?;
                output(cli.json, &response, pretty::firewall_status);
            }
        },
    }

    Ok(())
}
