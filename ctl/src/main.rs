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
    ApplyConfigRequest,
    ApplyConfigResponse,
    DashboardResponse,
    DeleteAddressOverrideRequest,
    DeleteCnameRecordRequest,
    DeleteDhcpOptionRequest,
    DeleteDhcpRangeRequest,
    DeleteFirewallZoneRequest,
    DeleteFirewallZoneResponse,
    DeleteForwardRuleRequest,
    DeleteForwardRuleResponse,
    DeleteHostRecordRequest,
    DeleteInputRuleRequest,
    DeleteInputRuleResponse,
    DeletePortForwardRequest,
    DeletePortForwardResponse,
    DeleteStaticLeaseRequest,
    DeleteUserRequest,
    DeleteUserResponse,
    DeleteZoneForwardRequest,
    DeleteZoneForwardResponse,
    DhcpLeasesResponse,
    DnsmasqAddressAction,
    DnsmasqAddressOverride,
    DnsmasqApplyRequest,
    DnsmasqApplyResponse,
    DnsmasqCnameRecord,
    DnsmasqConfig,
    DnsmasqDhcpOption,
    DnsmasqDhcpRange,
    DnsmasqHostRecord,
    DnsmasqPreviewResponse,
    // Dnsmasq types
    DnsmasqStateResponse,
    DnsmasqStaticLease,
    DnsmasqUpstreamMode,
    FirewallAction,
    FirewallApplyRequest,
    FirewallApplyResponse,
    FirewallConfirmRequest,
    FirewallConfirmResponse,
    FirewallGlobalSettings,
    FirewallGlobalSettingsResponse,
    FirewallPolicy,
    FirewallPreviewResponse,
    FirewallRollbackResponse,
    FirewallStatusResponse,
    FirewallZone,
    FirewallZonesResponse,
    ForwardRule,
    ForwardRulesResponse,
    InputRule,
    InputRulesResponse,
    LoginRequest,
    LoginResponse,
    ManagedInterfacesResponse,
    PortForward,
    PortForwardsResponse,
    RuleProtocol,
    SaveAddressOverrideRequest,
    SaveAddressOverrideResponse,
    SaveCnameRecordRequest,
    SaveCnameRecordResponse,
    SaveDhcpOptionRequest,
    SaveDhcpOptionResponse,
    SaveDhcpRangeRequest,
    SaveDhcpRangeResponse,
    SaveDnsmasqConfigRequest,
    SaveDnsmasqConfigResponse,
    SaveFirewallGlobalSettingsRequest,
    SaveFirewallGlobalSettingsResponse,
    SaveFirewallZoneRequest,
    SaveFirewallZoneResponse,
    SaveForwardRuleRequest,
    SaveForwardRuleResponse,
    SaveHostRecordRequest,
    SaveHostRecordResponse,
    SaveInputRuleRequest,
    SaveInputRuleResponse,
    SaveManagedInterfacesRequest,
    SaveManagedInterfacesResponse,
    SavePortForwardRequest,
    SavePortForwardResponse,
    SaveStaticLeaseRequest,
    SaveStaticLeaseResponse,
    SaveUserRequest,
    SaveUserResponse,
    SaveZoneForwardRequest,
    SaveZoneForwardResponse,
    SystemState,
    UsersResponse,
    ZoneForwardPolicy,
    ZoneForwardsResponse,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
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
    fs::create_dir_all(&keystone_dir).context("Failed to create keystone state directory")?;

    Ok(keystone_dir.join("token"))
}

/// Save token to file with 0600 permissions
fn save_token(token: &str) -> Result<()> {
    let token_path = get_token_path()?;
    fs::write(&token_path, token).context("Failed to write token file")?;

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

    /// Manage DNS & DHCP (dnsmasq) configuration
    #[command(subcommand)]
    Dnsmasq(DnsmasqCommands),
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

// ============================================================================
// Dnsmasq Commands
// ============================================================================

#[derive(Subcommand)]
enum DnsmasqCommands {
    /// Get full dnsmasq state (config + all records)
    State {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,
    },

    /// Manage global DNS settings
    #[command(subcommand)]
    Config(DnsmasqConfigCommands),

    /// Manage DHCP address pools
    #[command(subcommand)]
    Ranges(DhcpRangeCommands),

    /// Manage static DHCP leases (reservations)
    #[command(subcommand)]
    Leases(StaticLeaseCommands),

    /// Manage custom DHCP options
    #[command(subcommand)]
    Options(DhcpOptionCommands),

    /// Manage DNS host records
    #[command(subcommand)]
    Hosts(HostRecordCommands),

    /// Manage CNAME records
    #[command(subcommand)]
    Cnames(CnameRecordCommands),

    /// Manage address overrides (blocking/redirects)
    #[command(subcommand)]
    Overrides(AddressOverrideCommands),

    /// View current active DHCP leases
    ActiveLeases {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,
    },

    /// Preview generated dnsmasq config file
    Preview {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,
    },

    /// Apply dnsmasq configuration and restart service
    Apply {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,
    },
}

#[derive(Subcommand)]
enum DnsmasqConfigCommands {
    /// Show current DNS configuration
    Get {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,
    },

    /// Update DNS configuration
    Set {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,

        /// Enable/disable dnsmasq service
        #[arg(long)]
        enabled: Option<bool>,

        /// DNS cache size (0 = disable)
        #[arg(long)]
        cache_size: Option<u32>,

        /// Local domain name (e.g., "lan", "home.local")
        #[arg(long)]
        local_domain: Option<String>,

        /// Upstream DNS mode: system, custom, localadguard
        #[arg(long)]
        upstream_mode: Option<String>,

        /// Enable DNSSEC validation
        #[arg(long)]
        dnssec: Option<bool>,

        /// Enable query logging
        #[arg(long)]
        log_queries: Option<bool>,

        /// Enable DHCP logging
        #[arg(long)]
        log_dhcp: Option<bool>,
    },
}

#[derive(Subcommand)]
enum DhcpRangeCommands {
    /// List all DHCP ranges
    List {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,
    },

    /// Add a DHCP range
    Add {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,

        /// Range name (description)
        #[arg(short, long)]
        name: String,

        /// Interface to serve DHCP on
        #[arg(short, long)]
        interface: String,

        /// Start IP address
        #[arg(long)]
        start: String,

        /// End IP address
        #[arg(long)]
        end: String,

        /// Netmask (optional, e.g., "255.255.255.0")
        #[arg(long)]
        netmask: Option<String>,

        /// Lease time (e.g., "24h", "12h", "1w")
        #[arg(long, default_value = "24h")]
        lease_time: String,

        /// Whether enabled
        #[arg(long, default_value = "true")]
        enabled: bool,
    },

    /// Delete a DHCP range
    Delete {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,

        /// Range ID to delete
        #[arg(long)]
        id: i64,
    },
}

#[derive(Subcommand)]
enum StaticLeaseCommands {
    /// List all static leases
    List {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,
    },

    /// Add a static lease (DHCP reservation)
    Add {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,

        /// MAC address (e.g., "00:11:22:33:44:55")
        #[arg(short, long)]
        mac: String,

        /// IP address to assign
        #[arg(short, long)]
        ip: String,

        /// Hostname (optional)
        #[arg(short = 'H', long)]
        hostname: Option<String>,

        /// Whether enabled
        #[arg(long, default_value = "true")]
        enabled: bool,
    },

    /// Delete a static lease
    Delete {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,

        /// Lease ID to delete
        #[arg(long)]
        id: i64,
    },
}

#[derive(Subcommand)]
enum DhcpOptionCommands {
    /// List all DHCP options
    List {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,
    },

    /// Add a DHCP option
    Add {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,

        /// Option name or number (e.g., "option:router", "6", "option:ntp-server")
        #[arg(short, long)]
        option: String,

        /// Option value
        #[arg(short, long)]
        value: String,

        /// Description (optional)
        #[arg(short, long)]
        description: Option<String>,

        /// Is IPv6 option
        #[arg(long, default_value = "false")]
        ipv6: bool,

        /// Force send even if not requested
        #[arg(long, default_value = "false")]
        force: bool,

        /// Whether enabled
        #[arg(long, default_value = "true")]
        enabled: bool,
    },

    /// Delete a DHCP option
    Delete {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,

        /// Option ID to delete
        #[arg(long)]
        id: i64,
    },
}

#[derive(Subcommand)]
enum HostRecordCommands {
    /// List all host records
    List {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,
    },

    /// Add a host record
    Add {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,

        /// Hostnames (comma-separated, e.g., "server,server.lan")
        #[arg(short = 'H', long)]
        hostnames: String,

        /// IPv4 address
        #[arg(long)]
        ipv4: Option<String>,

        /// IPv6 address
        #[arg(long)]
        ipv6: Option<String>,

        /// Whether enabled
        #[arg(long, default_value = "true")]
        enabled: bool,
    },

    /// Delete a host record
    Delete {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,

        /// Record ID to delete
        #[arg(long)]
        id: i64,
    },
}

#[derive(Subcommand)]
enum CnameRecordCommands {
    /// List all CNAME records
    List {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,
    },

    /// Add a CNAME record
    Add {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,

        /// Alias name (the CNAME)
        #[arg(short, long)]
        alias: String,

        /// Target hostname
        #[arg(long)]
        target: String,

        /// Whether enabled
        #[arg(long, default_value = "true")]
        enabled: bool,
    },

    /// Delete a CNAME record
    Delete {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,

        /// Record ID to delete
        #[arg(long)]
        id: i64,
    },
}

#[derive(Subcommand)]
enum AddressOverrideCommands {
    /// List all address overrides
    List {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,
    },

    /// Add an address override
    Add {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,

        /// Domain pattern (e.g., "ads.example.com", ".malware.com")
        #[arg(short, long)]
        domain: String,

        /// Action: block, redirect, null
        #[arg(short, long, default_value = "block")]
        action: String,

        /// Redirect address (required if action is redirect)
        #[arg(long)]
        redirect_to: Option<String>,

        /// Whether enabled
        #[arg(long, default_value = "true")]
        enabled: bool,
    },

    /// Delete an address override
    Delete {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,

        /// Override ID to delete
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
    use super::{get_token_path, save_token};
    use keystone_core::*;
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
                    let token_path = get_token_path()
                        .unwrap_or_else(|_| PathBuf::from("~/.local/state/keystone/token"));
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

        println!("Interfaces ({}):", state.interfaces.len());
        for iface in &state.interfaces {
            let status = if iface.enabled { "UP" } else { "DOWN" };
            let addr = iface.address.as_deref().unwrap_or("no address");
            let dhcp = if iface.dhcp_enabled { "DHCP" } else { "static" };
            println!(
                "  {} [{}] {} ({}, {})",
                iface.name, iface.role, addr, dhcp, status
            );
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
                id, zone.name, interfaces, zone.default_input_policy, zone.default_forward_policy
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
            let proto = rule
                .protocol
                .map(|p| p.to_string())
                .unwrap_or("any".to_string());
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
            let proto = rule
                .protocol
                .map(|p| p.to_string())
                .unwrap_or("any".to_string());
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
                println!(
                    "\n  To confirm: keystonectl firewall confirm --session-id {}",
                    session_id
                );
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
        println!(
            "  Ping from WAN: {}",
            if response.settings.ping_wan_enabled {
                "Enabled"
            } else {
                "Disabled"
            }
        );
        println!(
            "  Ping from LAN: {}",
            if response.settings.ping_lan_enabled {
                "Enabled"
            } else {
                "Disabled"
            }
        );
        println!();

        println!("NAT Settings:");
        println!(
            "  Hairpin NAT: {}",
            if response.settings.hairpin_nat_enabled {
                "Enabled"
            } else {
                "Disabled"
            }
        );
        println!();

        println!(
            "Note: Dangerous ICMP types (timestamp, redirect, address-mask) are always blocked."
        );
    }

    pub fn save_firewall_settings(response: &SaveFirewallGlobalSettingsResponse) {
        if response.success {
            println!("Settings saved successfully");
            println!("\nNote: Apply firewall configuration for changes to take effect.");
        } else {
            println!("Error: {}", response.message);
        }
    }

    // ========================================================================
    // Dnsmasq pretty print functions
    // ========================================================================

    pub fn dnsmasq_state(response: &DnsmasqStateResponse) {
        println!("=== DNS & DHCP State ===\n");

        // Config summary
        println!(
            "Service: {}",
            if response.config.enabled {
                "Enabled"
            } else {
                "Disabled"
            }
        );
        println!("Upstream DNS: {}", response.config.upstream_mode);
        println!("Cache Size: {}", response.config.cache_size);
        if let Some(domain) = &response.config.local_domain {
            println!("Local Domain: {}", domain);
        }
        println!(
            "DNSSEC: {}",
            if response.config.dnssec_enabled {
                "Enabled"
            } else {
                "Disabled"
            }
        );

        println!("\nStatistics:");
        println!("  DHCP Ranges: {}", response.dhcp_ranges.len());
        println!("  Static Leases: {}", response.static_leases.len());
        println!("  DHCP Options: {}", response.dhcp_options.len());
        println!("  Host Records: {}", response.host_records.len());
        println!("  CNAME Records: {}", response.cname_records.len());
        println!("  Address Overrides: {}", response.address_overrides.len());
    }

    pub fn dnsmasq_config(config: &DnsmasqConfig) {
        println!("=== DNS Configuration ===\n");
        println!(
            "Service: {}",
            if config.enabled {
                "Enabled"
            } else {
                "Disabled"
            }
        );
        println!("DNS Port: {}", config.dns_port);
        println!("Upstream Mode: {}", config.upstream_mode);
        println!("Cache Size: {}", config.cache_size);
        println!(
            "Local Domain: {}",
            config.local_domain.as_deref().unwrap_or("-")
        );
        println!(
            "DNSSEC: {}",
            if config.dnssec_enabled {
                "Enabled"
            } else {
                "Disabled"
            }
        );
        println!(
            "Domain Needed: {}",
            if config.domain_needed { "Yes" } else { "No" }
        );
        println!(
            "Bogus Priv: {}",
            if config.bogus_priv { "Yes" } else { "No" }
        );
        println!(
            "Expand Hosts: {}",
            if config.expand_hosts { "Yes" } else { "No" }
        );
        println!(
            "Log Queries: {}",
            if config.log_queries { "Yes" } else { "No" }
        );
        println!("Log DHCP: {}", if config.log_dhcp { "Yes" } else { "No" });
    }

    pub fn save_dnsmasq_config(response: &SaveDnsmasqConfigResponse) {
        if response.success {
            println!("✓ {}", response.message);
        } else {
            println!("✗ {}", response.message);
        }
    }

    pub fn dhcp_ranges(ranges: &Vec<DnsmasqDhcpRange>) {
        println!("=== DHCP Ranges ===\n");
        if ranges.is_empty() {
            println!("No DHCP ranges configured.");
            return;
        }
        println!(
            "{:<6} {:<15} {:<12} {:<30} {:<8} {:<8}",
            "ID", "Name", "Interface", "Range", "Lease", "Enabled"
        );
        println!("{}", "-".repeat(85));
        for range in ranges {
            let id = range.id.map(|i| i.to_string()).unwrap_or("-".to_string());
            let range_str = format!("{} - {}", range.start_address, range.end_address);
            let enabled = if range.enabled { "yes" } else { "no" };
            println!(
                "{:<6} {:<15} {:<12} {:<30} {:<8} {:<8}",
                id, range.name, range.interface, range_str, range.lease_time, enabled
            );
        }
    }

    pub fn save_dhcp_range(response: &SaveDhcpRangeResponse) {
        if response.success {
            println!("✓ {}", response.message);
            if let Some(id) = response.range_id {
                println!("  Range ID: {}", id);
            }
        } else {
            println!("✗ {}", response.message);
        }
    }

    pub fn static_leases(leases: &Vec<DnsmasqStaticLease>) {
        println!("=== Static Leases ===\n");
        if leases.is_empty() {
            println!("No static leases configured.");
            return;
        }
        println!(
            "{:<6} {:<20} {:<18} {:<20} {:<8}",
            "ID", "MAC Address", "IP Address", "Hostname", "Enabled"
        );
        println!("{}", "-".repeat(75));
        for lease in leases {
            let id = lease.id.map(|i| i.to_string()).unwrap_or("-".to_string());
            let hostname = lease.hostname.as_deref().unwrap_or("-");
            let enabled = if lease.enabled { "yes" } else { "no" };
            println!(
                "{:<6} {:<20} {:<18} {:<20} {:<8}",
                id, lease.mac_address, lease.ip_address, hostname, enabled
            );
        }
    }

    pub fn save_static_lease(response: &SaveStaticLeaseResponse) {
        if response.success {
            println!("✓ {}", response.message);
            if let Some(id) = response.lease_id {
                println!("  Lease ID: {}", id);
            }
        } else {
            println!("✗ {}", response.message);
        }
    }

    pub fn dhcp_options(options: &Vec<DnsmasqDhcpOption>) {
        println!("=== DHCP Options ===\n");
        if options.is_empty() {
            println!("No DHCP options configured.");
            return;
        }
        println!(
            "{:<6} {:<20} {:<15} {:<30} {:<8}",
            "ID", "Description", "Option", "Value", "Enabled"
        );
        println!("{}", "-".repeat(85));
        for opt in options {
            let id = opt.id.map(|i| i.to_string()).unwrap_or("-".to_string());
            let desc = opt.description.as_deref().unwrap_or("-");
            let enabled = if opt.enabled { "yes" } else { "no" };
            // Truncate value if too long
            let value = if opt.value.len() > 28 {
                format!("{}...", &opt.value[..25])
            } else {
                opt.value.clone()
            };
            println!(
                "{:<6} {:<20} {:<15} {:<30} {:<8}",
                id, desc, opt.option, value, enabled
            );
        }
    }

    pub fn save_dhcp_option(response: &SaveDhcpOptionResponse) {
        if response.success {
            println!("✓ {}", response.message);
            if let Some(id) = response.option_id {
                println!("  Option ID: {}", id);
            }
        } else {
            println!("✗ {}", response.message);
        }
    }

    pub fn host_records(records: &Vec<DnsmasqHostRecord>) {
        println!("=== Host Records ===\n");
        if records.is_empty() {
            println!("No host records configured.");
            return;
        }
        println!(
            "{:<6} {:<30} {:<18} {:<25} {:<8}",
            "ID", "Hostnames", "IPv4", "IPv6", "Enabled"
        );
        println!("{}", "-".repeat(90));
        for rec in records {
            let id = rec.id.map(|i| i.to_string()).unwrap_or("-".to_string());
            let hostnames = if rec.hostnames.len() > 2 {
                format!(
                    "{}, {} (+{})",
                    rec.hostnames[0],
                    rec.hostnames[1],
                    rec.hostnames.len() - 2
                )
            } else {
                rec.hostnames.join(", ")
            };
            let ipv4 = rec.ipv4_address.as_deref().unwrap_or("-");
            let ipv6 = rec.ipv6_address.as_deref().unwrap_or("-");
            let enabled = if rec.enabled { "yes" } else { "no" };
            println!(
                "{:<6} {:<30} {:<18} {:<25} {:<8}",
                id, hostnames, ipv4, ipv6, enabled
            );
        }
    }

    pub fn save_host_record(response: &SaveHostRecordResponse) {
        if response.success {
            println!("✓ {}", response.message);
            if let Some(id) = response.record_id {
                println!("  Record ID: {}", id);
            }
        } else {
            println!("✗ {}", response.message);
        }
    }

    pub fn cname_records(records: &Vec<DnsmasqCnameRecord>) {
        println!("=== CNAME Records ===\n");
        if records.is_empty() {
            println!("No CNAME records configured.");
            return;
        }
        println!(
            "{:<6} {:<25} {:<25} {:<8}",
            "ID", "Alias", "Target", "Enabled"
        );
        println!("{}", "-".repeat(70));
        for rec in records {
            let id = rec.id.map(|i| i.to_string()).unwrap_or("-".to_string());
            let enabled = if rec.enabled { "yes" } else { "no" };
            println!(
                "{:<6} {:<25} {:<25} {:<8}",
                id, rec.alias, rec.target, enabled
            );
        }
    }

    pub fn save_cname_record(response: &SaveCnameRecordResponse) {
        if response.success {
            println!("✓ {}", response.message);
            if let Some(id) = response.record_id {
                println!("  Record ID: {}", id);
            }
        } else {
            println!("✗ {}", response.message);
        }
    }

    pub fn address_overrides(overrides: &Vec<DnsmasqAddressOverride>) {
        println!("=== Address Overrides ===\n");
        if overrides.is_empty() {
            println!("No address overrides configured.");
            return;
        }
        println!(
            "{:<6} {:<30} {:<10} {:<20} {:<8}",
            "ID", "Domain", "Action", "Redirect To", "Enabled"
        );
        println!("{}", "-".repeat(80));
        for ovr in overrides {
            let id = ovr.id.map(|i| i.to_string()).unwrap_or("-".to_string());
            let redirect = ovr.redirect_address.as_deref().unwrap_or("-");
            let enabled = if ovr.enabled { "yes" } else { "no" };
            println!(
                "{:<6} {:<30} {:<10} {:<20} {:<8}",
                id, ovr.domain, ovr.action, redirect, enabled
            );
        }
    }

    pub fn save_address_override(response: &SaveAddressOverrideResponse) {
        if response.success {
            println!("✓ {}", response.message);
            if let Some(id) = response.override_id {
                println!("  Override ID: {}", id);
            }
        } else {
            println!("✗ {}", response.message);
        }
    }

    pub fn active_leases(response: &DhcpLeasesResponse) {
        println!("=== Active DHCP Leases ===\n");
        if response.leases.is_empty() {
            println!("No active DHCP leases.");
            return;
        }
        println!(
            "{:<20} {:<18} {:<20} {:<15}",
            "MAC Address", "IP Address", "Hostname", "Expires"
        );
        println!("{}", "-".repeat(75));
        for lease in &response.leases {
            let hostname = lease.hostname.as_deref().unwrap_or("-");
            let expires = format_lease_expiry(lease.expires_at);
            println!(
                "{:<20} {:<18} {:<20} {:<15}",
                lease.mac_address, lease.ip_address, hostname, expires
            );
        }
    }

    fn format_lease_expiry(expires_at: u64) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if expires_at <= now {
            return "Expired".to_string();
        }

        let remaining = expires_at - now;
        if remaining < 60 {
            format!("{}s", remaining)
        } else if remaining < 3600 {
            format!("{}m", remaining / 60)
        } else if remaining < 86400 {
            format!("{}h", remaining / 3600)
        } else {
            format!("{}d", remaining / 86400)
        }
    }

    pub fn dnsmasq_preview(response: &DnsmasqPreviewResponse) {
        println!("=== dnsmasq Configuration Preview ===\n");
        println!("{}", response.config_content);
    }

    pub fn dnsmasq_apply(response: &DnsmasqApplyResponse) {
        if response.success {
            println!("✓ {}", response.message);
        } else {
            println!("✗ {}", response.message);
        }
    }

    pub fn delete_success(success: bool, message: &str) {
        if success {
            println!("✓ Deleted successfully");
        } else {
            println!("✗ {}", message);
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
                        let pass1 =
                            rpassword::prompt_password(format!("Password for {}: ", username))
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
                    let response: SaveFirewallZoneResponse = client
                        .post("/firewall/zones", &request, Some(&token))
                        .await?;
                    output(cli.json, &response, pretty::save_zone);
                    if !response.success {
                        std::process::exit(1);
                    }
                }

                ZonesCommands::Delete { token, id } => {
                    let token = get_token(token)?;
                    let request = DeleteFirewallZoneRequest { id };
                    let response: DeleteFirewallZoneResponse = client
                        .delete("/firewall/zones", &request, Some(&token))
                        .await?;
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
                    let policy: FirewallAction =
                        policy.parse().map_err(|e: String| anyhow::anyhow!(e))?;
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
                    let protocol: RuleProtocol =
                        protocol.parse().map_err(|e: String| anyhow::anyhow!(e))?;
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
                    let action: FirewallAction =
                        action.parse().map_err(|e: String| anyhow::anyhow!(e))?;
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
                    let action: FirewallAction =
                        action.parse().map_err(|e: String| anyhow::anyhow!(e))?;
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
                        hairpin_nat_enabled: hairpin_nat
                            .unwrap_or(current.settings.hairpin_nat_enabled),
                    };

                    let request = SaveFirewallGlobalSettingsRequest { settings };
                    let response: SaveFirewallGlobalSettingsResponse = client
                        .post("/firewall/settings", &request, Some(&token))
                        .await?;
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
                let response: FirewallApplyResponse = client
                    .post("/firewall/apply", &request, Some(&token))
                    .await?;
                output(cli.json, &response, pretty::firewall_apply);
                if !response.success {
                    std::process::exit(1);
                }
            }

            FirewallCommands::Confirm { token, session_id } => {
                let token = get_token(token)?;
                let request = FirewallConfirmRequest { session_id };
                let response: FirewallConfirmResponse = client
                    .post("/firewall/confirm", &request, Some(&token))
                    .await?;
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

        Commands::Dnsmasq(subcmd) => match subcmd {
            DnsmasqCommands::State { token } => {
                let token = get_token(token)?;
                let response: DnsmasqStateResponse =
                    client.get("/dnsmasq/state", Some(&token)).await?;
                output(cli.json, &response, pretty::dnsmasq_state);
            }

            DnsmasqCommands::Config(config_cmd) => match config_cmd {
                DnsmasqConfigCommands::Get { token } => {
                    let token = get_token(token)?;
                    let response: DnsmasqStateResponse =
                        client.get("/dnsmasq/state", Some(&token)).await?;
                    output(cli.json, &response.config, pretty::dnsmasq_config);
                }

                DnsmasqConfigCommands::Set {
                    token,
                    enabled,
                    cache_size,
                    local_domain,
                    upstream_mode,
                    dnssec,
                    log_queries,
                    log_dhcp,
                } => {
                    let token = get_token(token)?;

                    // Fetch current config
                    let current: DnsmasqStateResponse =
                        client.get("/dnsmasq/state", Some(&token)).await?;

                    // Parse upstream mode if provided
                    let upstream = match upstream_mode.as_deref() {
                        Some("system") => Some(DnsmasqUpstreamMode::System),
                        Some("custom") => Some(DnsmasqUpstreamMode::Custom),
                        Some("localadguard") => Some(DnsmasqUpstreamMode::LocalAdGuard),
                        Some(other) => {
                            anyhow::bail!(
                                "Invalid upstream mode '{}'. Valid options: system, custom, localadguard",
                                other
                            );
                        }
                        None => None,
                    };

                    // Merge updates with current config
                    let config = DnsmasqConfig {
                        enabled: enabled.unwrap_or(current.config.enabled),
                        dns_port: current.config.dns_port,
                        cache_size: cache_size.unwrap_or(current.config.cache_size),
                        local_domain: local_domain.or(current.config.local_domain),
                        upstream_mode: upstream.unwrap_or(current.config.upstream_mode),
                        upstream_servers: current.config.upstream_servers,
                        dnssec_enabled: dnssec.unwrap_or(current.config.dnssec_enabled),
                        domain_needed: current.config.domain_needed,
                        bogus_priv: current.config.bogus_priv,
                        expand_hosts: current.config.expand_hosts,
                        listen_interfaces: current.config.listen_interfaces,
                        except_interfaces: current.config.except_interfaces,
                        no_dhcp_interfaces: current.config.no_dhcp_interfaces,
                        bind_dynamic: current.config.bind_dynamic,
                        log_queries: log_queries.unwrap_or(current.config.log_queries),
                        log_dhcp: log_dhcp.unwrap_or(current.config.log_dhcp),
                    };

                    let request = SaveDnsmasqConfigRequest { config };
                    let response: SaveDnsmasqConfigResponse = client
                        .post("/dnsmasq/config", &request, Some(&token))
                        .await?;
                    output(cli.json, &response, pretty::save_dnsmasq_config);
                    if !response.success {
                        std::process::exit(1);
                    }
                }
            },

            DnsmasqCommands::Ranges(ranges_cmd) => match ranges_cmd {
                DhcpRangeCommands::List { token } => {
                    let token = get_token(token)?;
                    let response: DnsmasqStateResponse =
                        client.get("/dnsmasq/state", Some(&token)).await?;
                    output(cli.json, &response.dhcp_ranges, pretty::dhcp_ranges);
                }

                DhcpRangeCommands::Add {
                    token,
                    name,
                    interface,
                    start,
                    end,
                    netmask,
                    lease_time,
                    enabled,
                } => {
                    let token = get_token(token)?;
                    let range = DnsmasqDhcpRange {
                        id: None,
                        name,
                        interface,
                        start_address: start,
                        end_address: end,
                        netmask,
                        lease_time,
                        enabled,
                        ipv6_mode: None,
                        ipv6_prefix: None,
                    };
                    let request = SaveDhcpRangeRequest { range };
                    let response: SaveDhcpRangeResponse = client
                        .post("/dnsmasq/ranges", &request, Some(&token))
                        .await?;
                    output(cli.json, &response, pretty::save_dhcp_range);
                    if !response.success {
                        std::process::exit(1);
                    }
                }

                DhcpRangeCommands::Delete { token, id } => {
                    let token = get_token(token)?;
                    let request = DeleteDhcpRangeRequest { id };
                    let response: serde_json::Value = client
                        .delete("/dnsmasq/ranges", &request, Some(&token))
                        .await?;
                    let success = response
                        .get("success")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let message = response
                        .get("message")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&response).unwrap_or_default()
                        );
                    } else {
                        pretty::delete_success(success, message);
                    }
                    if !success {
                        std::process::exit(1);
                    }
                }
            },

            DnsmasqCommands::Leases(leases_cmd) => match leases_cmd {
                StaticLeaseCommands::List { token } => {
                    let token = get_token(token)?;
                    let response: DnsmasqStateResponse =
                        client.get("/dnsmasq/state", Some(&token)).await?;
                    output(cli.json, &response.static_leases, pretty::static_leases);
                }

                StaticLeaseCommands::Add {
                    token,
                    mac,
                    ip,
                    hostname,
                    enabled,
                } => {
                    let token = get_token(token)?;
                    let lease = DnsmasqStaticLease {
                        id: None,
                        mac_address: mac,
                        ip_address: ip,
                        hostname,
                        enabled,
                        lease_time: None,
                        client_id: None,
                        set_tags: Vec::new(),
                    };
                    let request = SaveStaticLeaseRequest { lease };
                    let response: SaveStaticLeaseResponse = client
                        .post("/dnsmasq/static-leases", &request, Some(&token))
                        .await?;
                    output(cli.json, &response, pretty::save_static_lease);
                    if !response.success {
                        std::process::exit(1);
                    }
                }

                StaticLeaseCommands::Delete { token, id } => {
                    let token = get_token(token)?;
                    let request = DeleteStaticLeaseRequest { id };
                    let response: serde_json::Value = client
                        .delete("/dnsmasq/static-leases", &request, Some(&token))
                        .await?;
                    let success = response
                        .get("success")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let message = response
                        .get("message")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&response).unwrap_or_default()
                        );
                    } else {
                        pretty::delete_success(success, message);
                    }
                    if !success {
                        std::process::exit(1);
                    }
                }
            },

            DnsmasqCommands::Options(options_cmd) => match options_cmd {
                DhcpOptionCommands::List { token } => {
                    let token = get_token(token)?;
                    let response: DnsmasqStateResponse =
                        client.get("/dnsmasq/state", Some(&token)).await?;
                    output(cli.json, &response.dhcp_options, pretty::dhcp_options);
                }

                DhcpOptionCommands::Add {
                    token,
                    option,
                    value,
                    description,
                    ipv6,
                    force,
                    enabled,
                } => {
                    let token = get_token(token)?;
                    let opt = DnsmasqDhcpOption {
                        id: None,
                        option,
                        value,
                        description,
                        match_tags: Vec::new(),
                        enabled,
                        ipv6,
                        force,
                    };
                    let request = SaveDhcpOptionRequest { option: opt };
                    let response: SaveDhcpOptionResponse = client
                        .post("/dnsmasq/dhcp-options", &request, Some(&token))
                        .await?;
                    output(cli.json, &response, pretty::save_dhcp_option);
                    if !response.success {
                        std::process::exit(1);
                    }
                }

                DhcpOptionCommands::Delete { token, id } => {
                    let token = get_token(token)?;
                    let request = DeleteDhcpOptionRequest { id };
                    let response: serde_json::Value = client
                        .delete("/dnsmasq/dhcp-options", &request, Some(&token))
                        .await?;
                    let success = response
                        .get("success")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let message = response
                        .get("message")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&response).unwrap_or_default()
                        );
                    } else {
                        pretty::delete_success(success, message);
                    }
                    if !success {
                        std::process::exit(1);
                    }
                }
            },

            DnsmasqCommands::Hosts(hosts_cmd) => match hosts_cmd {
                HostRecordCommands::List { token } => {
                    let token = get_token(token)?;
                    let response: DnsmasqStateResponse =
                        client.get("/dnsmasq/state", Some(&token)).await?;
                    output(cli.json, &response.host_records, pretty::host_records);
                }

                HostRecordCommands::Add {
                    token,
                    hostnames,
                    ipv4,
                    ipv6,
                    enabled,
                } => {
                    let token = get_token(token)?;
                    // Parse comma-separated hostnames
                    let hostnames_vec: Vec<String> = hostnames
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();

                    if hostnames_vec.is_empty() {
                        anyhow::bail!("At least one hostname is required");
                    }

                    if ipv4.is_none() && ipv6.is_none() {
                        anyhow::bail!("At least one of --ipv4 or --ipv6 is required");
                    }

                    let record = DnsmasqHostRecord {
                        id: None,
                        hostnames: hostnames_vec,
                        ipv4_address: ipv4,
                        ipv6_address: ipv6,
                        ttl: None,
                        enabled,
                    };
                    let request = SaveHostRecordRequest { record };
                    let response: SaveHostRecordResponse = client
                        .post("/dnsmasq/host-records", &request, Some(&token))
                        .await?;
                    output(cli.json, &response, pretty::save_host_record);
                    if !response.success {
                        std::process::exit(1);
                    }
                }

                HostRecordCommands::Delete { token, id } => {
                    let token = get_token(token)?;
                    let request = DeleteHostRecordRequest { id };
                    let response: serde_json::Value = client
                        .delete("/dnsmasq/host-records", &request, Some(&token))
                        .await?;
                    let success = response
                        .get("success")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let message = response
                        .get("message")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&response).unwrap_or_default()
                        );
                    } else {
                        pretty::delete_success(success, message);
                    }
                    if !success {
                        std::process::exit(1);
                    }
                }
            },

            DnsmasqCommands::Cnames(cnames_cmd) => match cnames_cmd {
                CnameRecordCommands::List { token } => {
                    let token = get_token(token)?;
                    let response: DnsmasqStateResponse =
                        client.get("/dnsmasq/state", Some(&token)).await?;
                    output(cli.json, &response.cname_records, pretty::cname_records);
                }

                CnameRecordCommands::Add {
                    token,
                    alias,
                    target,
                    enabled,
                } => {
                    let token = get_token(token)?;
                    let record = DnsmasqCnameRecord {
                        id: None,
                        alias,
                        target,
                        ttl: None,
                        enabled,
                    };
                    let request = SaveCnameRecordRequest { record };
                    let response: SaveCnameRecordResponse = client
                        .post("/dnsmasq/cname-records", &request, Some(&token))
                        .await?;
                    output(cli.json, &response, pretty::save_cname_record);
                    if !response.success {
                        std::process::exit(1);
                    }
                }

                CnameRecordCommands::Delete { token, id } => {
                    let token = get_token(token)?;
                    let request = DeleteCnameRecordRequest { id };
                    let response: serde_json::Value = client
                        .delete("/dnsmasq/cname-records", &request, Some(&token))
                        .await?;
                    let success = response
                        .get("success")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let message = response
                        .get("message")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&response).unwrap_or_default()
                        );
                    } else {
                        pretty::delete_success(success, message);
                    }
                    if !success {
                        std::process::exit(1);
                    }
                }
            },

            DnsmasqCommands::Overrides(overrides_cmd) => match overrides_cmd {
                AddressOverrideCommands::List { token } => {
                    let token = get_token(token)?;
                    let response: DnsmasqStateResponse =
                        client.get("/dnsmasq/state", Some(&token)).await?;
                    output(
                        cli.json,
                        &response.address_overrides,
                        pretty::address_overrides,
                    );
                }

                AddressOverrideCommands::Add {
                    token,
                    domain,
                    action,
                    redirect_to,
                    enabled,
                } => {
                    let token = get_token(token)?;

                    // Parse action
                    let action_enum = match action.to_lowercase().as_str() {
                        "block" => DnsmasqAddressAction::Block,
                        "redirect" => DnsmasqAddressAction::Redirect,
                        "null" => DnsmasqAddressAction::Null,
                        other => {
                            anyhow::bail!(
                                "Invalid action '{}'. Valid options: block, redirect, null",
                                other
                            );
                        }
                    };

                    // Validate redirect_to is provided when action is redirect
                    if matches!(action_enum, DnsmasqAddressAction::Redirect)
                        && redirect_to.is_none()
                    {
                        anyhow::bail!("--redirect-to is required when action is 'redirect'");
                    }

                    let ovr = DnsmasqAddressOverride {
                        id: None,
                        domain,
                        action: action_enum,
                        redirect_address: redirect_to,
                        enabled,
                    };
                    let request = SaveAddressOverrideRequest {
                        override_entry: ovr,
                    };
                    let response: SaveAddressOverrideResponse = client
                        .post("/dnsmasq/address-overrides", &request, Some(&token))
                        .await?;
                    output(cli.json, &response, pretty::save_address_override);
                    if !response.success {
                        std::process::exit(1);
                    }
                }

                AddressOverrideCommands::Delete { token, id } => {
                    let token = get_token(token)?;
                    let request = DeleteAddressOverrideRequest { id };
                    let response: serde_json::Value = client
                        .delete("/dnsmasq/address-overrides", &request, Some(&token))
                        .await?;
                    let success = response
                        .get("success")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let message = response
                        .get("message")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&response).unwrap_or_default()
                        );
                    } else {
                        pretty::delete_success(success, message);
                    }
                    if !success {
                        std::process::exit(1);
                    }
                }
            },

            DnsmasqCommands::ActiveLeases { token } => {
                let token = get_token(token)?;
                let response: DhcpLeasesResponse =
                    client.get("/dnsmasq/leases", Some(&token)).await?;
                output(cli.json, &response, pretty::active_leases);
            }

            DnsmasqCommands::Preview { token } => {
                let token = get_token(token)?;
                let response: DnsmasqPreviewResponse =
                    client.get("/dnsmasq/preview", Some(&token)).await?;
                output(cli.json, &response, pretty::dnsmasq_preview);
            }

            DnsmasqCommands::Apply { token } => {
                let token = get_token(token)?;
                let request = DnsmasqApplyRequest {};
                let response: DnsmasqApplyResponse = client
                    .post("/dnsmasq/apply", &request, Some(&token))
                    .await?;
                output(cli.json, &response, pretty::dnsmasq_apply);
                if !response.success {
                    std::process::exit(1);
                }
            }
        },
    }

    Ok(())
}
