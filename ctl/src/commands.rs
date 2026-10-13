use clap::{Parser, Subcommand};

use crate::SOCKET_PATH;

/// Keystone CLI - manage your router/firewall from the command line
#[derive(Parser)]
#[command(name = "keystonectl")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Output raw JSON instead of pretty-printed human-readable format
    #[arg(short, long, global = true)]
    pub json: bool,

    /// Path to Unix socket (default: /run/keystone/keystone.sock)
    #[arg(short, long, global = true, default_value = SOCKET_PATH)]
    pub socket: String,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Check daemon health
    Health,

    /// Create the initial administrator locally (requires root; only works with no users)
    BootstrapAdmin {
        /// Initial administrator username
        #[arg(short, long, default_value = "admin")]
        username: String,
    },

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

    /// Apply all saved configuration (networkd, firewall, dnsmasq, caddy)
    Apply {
        /// JWT token for authentication (reads from file if not provided)
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,
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

    /// Run interactive first-run setup wizard
    Setup,

    /// Mark setup complete after running all checks
    ///
    /// Intended for automation: scripts can configure the system via other
    /// commands, then call this once to run checks and flip the setup flag.
    CompleteSetupNow {
        /// JWT token for authentication (reads from file if not provided)
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,
    },

    /// Manage DNS & DHCP (dnsmasq) configuration
    #[command(subcommand)]
    Dnsmasq(DnsmasqCommands),
}

#[derive(Subcommand)]
pub enum UsersCommands {
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
pub enum InterfacesCommands {
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
pub enum FirewallCommands {
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
        #[arg(long)]
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
pub enum SettingsCommands {
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
pub enum ZonesCommands {
    /// List all firewall zones
    List {
        /// JWT token for authentication
        #[arg(short, long, env = "KEYSTONE_TOKEN")]
        token: Option<String>,
    },

    /// Add a new firewall zone
    Add {
        /// Zone ID to update (optional)
        #[arg(long)]
        id: Option<i64>,
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

        /// Mark this as an Internet-facing zone
        #[arg(long, default_value_t = false)]
        wan: bool,

        /// Apply IPv4 masquerading to traffic leaving this zone
        #[arg(long, default_value_t = false)]
        masquerade_ipv4: bool,
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
pub enum ZoneForwardsCommands {
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
pub enum PortForwardsCommands {
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
pub enum InputRulesCommands {
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
pub enum ForwardRulesCommands {
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

// Dnsmasq commands

#[derive(Subcommand)]
pub enum DnsmasqCommands {
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
pub enum DnsmasqConfigCommands {
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
pub enum DhcpRangeCommands {
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
pub enum StaticLeaseCommands {
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
pub enum DhcpOptionCommands {
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
pub enum HostRecordCommands {
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
pub enum CnameRecordCommands {
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
pub enum AddressOverrideCommands {
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
