//! Keystone Core Library
//!
//! This crate contains shared type definitions used by both the daemon and web-ui.
//! All types must be serializable to ensure strict type safety across the system boundary.

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ============================================================================
// Network Configuration Types (systemd-networkd compatible)
// ============================================================================

/// DHCP client mode for an interface
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum DhcpMode {
    /// DHCP disabled
    #[default]
    No,
    /// Both IPv4 and IPv6 DHCP enabled
    Yes,
    /// Only IPv4 DHCP enabled
    Ipv4,
    /// Only IPv6 DHCP enabled
    Ipv6,
}

impl std::fmt::Display for DhcpMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DhcpMode::No => write!(f, "no"),
            DhcpMode::Yes => write!(f, "yes"),
            DhcpMode::Ipv4 => write!(f, "ipv4"),
            DhcpMode::Ipv6 => write!(f, "ipv6"),
        }
    }
}

impl std::str::FromStr for DhcpMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "no" | "false" => Ok(DhcpMode::No),
            "yes" | "true" => Ok(DhcpMode::Yes),
            "ipv4" => Ok(DhcpMode::Ipv4),
            "ipv6" => Ok(DhcpMode::Ipv6),
            _ => Err(format!("Unknown DHCP mode: {}", s)),
        }
    }
}

/// IP forwarding mode
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum IpForwardMode {
    /// Forwarding disabled
    #[default]
    No,
    /// Both IPv4 and IPv6 forwarding enabled
    Yes,
    /// Only IPv4 forwarding enabled
    Ipv4,
    /// Only IPv6 forwarding enabled
    Ipv6,
}

impl std::fmt::Display for IpForwardMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpForwardMode::No => write!(f, "no"),
            IpForwardMode::Yes => write!(f, "yes"),
            IpForwardMode::Ipv4 => write!(f, "ipv4"),
            IpForwardMode::Ipv6 => write!(f, "ipv6"),
        }
    }
}

impl std::str::FromStr for IpForwardMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "no" | "false" => Ok(IpForwardMode::No),
            "yes" | "true" => Ok(IpForwardMode::Yes),
            "ipv4" => Ok(IpForwardMode::Ipv4),
            "ipv6" => Ok(IpForwardMode::Ipv6),
            _ => Err(format!("Unknown IP forward mode: {}", s)),
        }
    }
}

/// IP masquerade (NAT) mode
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum IpMasqueradeMode {
    /// Masquerading disabled
    #[default]
    No,
    /// Both IPv4 and IPv6 masquerading enabled
    Both,
    /// Only IPv4 masquerading enabled
    Ipv4,
    /// Only IPv6 masquerading enabled
    Ipv6,
}

impl std::fmt::Display for IpMasqueradeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpMasqueradeMode::No => write!(f, "no"),
            IpMasqueradeMode::Both => write!(f, "both"),
            IpMasqueradeMode::Ipv4 => write!(f, "ipv4"),
            IpMasqueradeMode::Ipv6 => write!(f, "ipv6"),
        }
    }
}

impl std::str::FromStr for IpMasqueradeMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "no" | "false" => Ok(IpMasqueradeMode::No),
            "both" | "yes" | "true" => Ok(IpMasqueradeMode::Both),
            "ipv4" => Ok(IpMasqueradeMode::Ipv4),
            "ipv6" => Ok(IpMasqueradeMode::Ipv6),
            _ => Err(format!("Unknown IP masquerade mode: {}", s)),
        }
    }
}

/// Link-local addressing mode
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum LinkLocalMode {
    /// Link-local disabled
    No,
    /// Both IPv4 and IPv6 link-local enabled
    #[default]
    Yes,
    /// Only IPv4 link-local enabled
    Ipv4,
    /// Only IPv6 link-local enabled (most common default)
    Ipv6,
}

impl std::fmt::Display for LinkLocalMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkLocalMode::No => write!(f, "no"),
            LinkLocalMode::Yes => write!(f, "yes"),
            LinkLocalMode::Ipv4 => write!(f, "ipv4"),
            LinkLocalMode::Ipv6 => write!(f, "ipv6"),
        }
    }
}

impl std::str::FromStr for LinkLocalMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "no" | "false" => Ok(LinkLocalMode::No),
            "yes" | "true" => Ok(LinkLocalMode::Yes),
            "ipv4" => Ok(LinkLocalMode::Ipv4),
            "ipv6" => Ok(LinkLocalMode::Ipv6),
            _ => Err(format!("Unknown link-local mode: {}", s)),
        }
    }
}

/// Activation policy for interface management
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ActivationPolicy {
    /// Bring up interface automatically
    #[default]
    Up,
    /// Start with interface down, allow manual activation
    AlwaysUp,
    /// Keep interface in current state
    Manual,
    /// Always keep interface down
    AlwaysDown,
    /// Bring interface down
    Down,
    /// Bound to carrier state
    Bound,
}

impl std::fmt::Display for ActivationPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActivationPolicy::Up => write!(f, "up"),
            ActivationPolicy::AlwaysUp => write!(f, "always-up"),
            ActivationPolicy::Manual => write!(f, "manual"),
            ActivationPolicy::AlwaysDown => write!(f, "always-down"),
            ActivationPolicy::Down => write!(f, "down"),
            ActivationPolicy::Bound => write!(f, "bound"),
        }
    }
}

impl std::str::FromStr for ActivationPolicy {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "up" => Ok(ActivationPolicy::Up),
            "always-up" => Ok(ActivationPolicy::AlwaysUp),
            "manual" => Ok(ActivationPolicy::Manual),
            "always-down" => Ok(ActivationPolicy::AlwaysDown),
            "down" => Ok(ActivationPolicy::Down),
            "bound" => Ok(ActivationPolicy::Bound),
            _ => Err(format!("Unknown activation policy: {}", s)),
        }
    }
}

/// Address scope for static addresses
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum AddressScope {
    /// Global scope (routable)
    #[default]
    Global,
    /// Link-local scope
    Link,
    /// Host-local scope
    Host,
}

impl std::fmt::Display for AddressScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressScope::Global => write!(f, "global"),
            AddressScope::Link => write!(f, "link"),
            AddressScope::Host => write!(f, "host"),
        }
    }
}

impl std::str::FromStr for AddressScope {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "global" => Ok(AddressScope::Global),
            "link" => Ok(AddressScope::Link),
            "host" => Ok(AddressScope::Host),
            _ => Err(format!("Unknown address scope: {}", s)),
        }
    }
}

/// Route type for static routes
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum RouteType {
    /// Standard unicast route
    #[default]
    Unicast,
    /// Local route (to local interface)
    Local,
    /// Broadcast route
    Broadcast,
    /// Anycast route
    Anycast,
    /// Multicast route
    Multicast,
    /// Silently drop packets
    Blackhole,
    /// Drop with ICMP unreachable
    Unreachable,
    /// Drop with ICMP prohibited
    Prohibit,
    /// Continue routing table lookup
    Throw,
    /// NAT route (rarely used)
    Nat,
    /// External route (for multipath)
    Xresolve,
}

impl std::fmt::Display for RouteType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouteType::Unicast => write!(f, "unicast"),
            RouteType::Local => write!(f, "local"),
            RouteType::Broadcast => write!(f, "broadcast"),
            RouteType::Anycast => write!(f, "anycast"),
            RouteType::Multicast => write!(f, "multicast"),
            RouteType::Blackhole => write!(f, "blackhole"),
            RouteType::Unreachable => write!(f, "unreachable"),
            RouteType::Prohibit => write!(f, "prohibit"),
            RouteType::Throw => write!(f, "throw"),
            RouteType::Nat => write!(f, "nat"),
            RouteType::Xresolve => write!(f, "xresolve"),
        }
    }
}

impl std::str::FromStr for RouteType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "unicast" => Ok(RouteType::Unicast),
            "local" => Ok(RouteType::Local),
            "broadcast" => Ok(RouteType::Broadcast),
            "anycast" => Ok(RouteType::Anycast),
            "multicast" => Ok(RouteType::Multicast),
            "blackhole" => Ok(RouteType::Blackhole),
            "unreachable" => Ok(RouteType::Unreachable),
            "prohibit" => Ok(RouteType::Prohibit),
            "throw" => Ok(RouteType::Throw),
            "nat" => Ok(RouteType::Nat),
            "xresolve" => Ok(RouteType::Xresolve),
            _ => Err(format!("Unknown route type: {}", s)),
        }
    }
}

/// A static IP address configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StaticAddress {
    /// IP address with CIDR prefix (e.g., "192.168.1.1/24")
    pub address: String,
    /// Optional label for the address (max 15 chars)
    pub label: Option<String>,
    /// Address scope (global, link, host)
    #[serde(default)]
    pub scope: AddressScope,
}

/// A static route configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StaticRoute {
    /// Destination network (CIDR notation), None for default route
    pub destination: Option<String>,
    /// Gateway IP address
    pub gateway: String,
    /// Route metric (lower = higher priority)
    pub metric: Option<u32>,
    /// Routing table (main, local, or custom name/number)
    #[serde(default)]
    pub table: Option<String>,
    /// Route type
    #[serde(default)]
    pub route_type: RouteType,
}

/// DHCPv4 client configuration options
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Dhcpv4ClientConfig {
    /// Send hostname to DHCP server
    pub send_hostname: bool,
    /// Custom hostname to send (if different from system hostname)
    pub hostname: Option<String>,
    /// Use DNS servers provided by DHCP
    pub use_dns: bool,
    /// Use NTP servers provided by DHCP
    pub use_ntp: bool,
    /// Use routes provided by DHCP
    pub use_routes: bool,
    /// Use gateway provided by DHCP
    pub use_gateway: bool,
    /// Use MTU provided by DHCP
    pub use_mtu: bool,
    /// Use domains provided by DHCP (yes/no/route)
    pub use_domains: String,
    /// Route metric for DHCP-provided routes
    pub route_metric: Option<u32>,
}

impl Default for Dhcpv4ClientConfig {
    fn default() -> Self {
        Self {
            send_hostname: true,
            hostname: None,
            use_dns: true,
            use_ntp: true,
            use_routes: true,
            use_gateway: true,
            use_mtu: true,
            use_domains: "yes".to_string(),
            route_metric: None,
        }
    }
}

/// DHCPv6 client configuration options
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Dhcpv6ClientConfig {
    /// Use DNS servers provided by DHCPv6
    pub use_dns: bool,
    /// Use NTP servers provided by DHCPv6
    pub use_ntp: bool,
    /// Use domains provided by DHCPv6 (yes/no/route)
    pub use_domains: String,
    /// Request specific prefix for prefix delegation (CIDR notation, e.g., "::1/64")
    pub prefix_delegation_hint: Option<String>,
    /// Use DHCPv6 rapid commit (2-message exchange instead of 4)
    pub rapid_commit: bool,
    /// DHCPv6 operation mode without Router Advertisement
    /// Values: "no" (wait for RA), "solicit" (send solicit immediately), "information-request"
    pub without_ra: String,
}

impl Default for Dhcpv6ClientConfig {
    fn default() -> Self {
        Self {
            use_dns: true,
            use_ntp: true,
            use_domains: "yes".to_string(),
            prefix_delegation_hint: None,
            rapid_commit: true,
            without_ra: "no".to_string(),
        }
    }
}

/// IPv6 Accept Router Advertisement client configuration
/// Controls what information to accept from Router Advertisements
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Ipv6AcceptRaConfig {
    /// Use DNS servers from RA (RDNSS option)
    pub use_dns: bool,
    /// Use default gateway from RA
    pub use_gateway: bool,
    /// Use route prefixes from RA
    pub use_route_prefix: bool,
    /// Use autonomous prefixes for SLAAC addresses
    pub use_autonomous_prefix: bool,
}

impl Default for Ipv6AcceptRaConfig {
    fn default() -> Self {
        Self {
            use_dns: true,
            use_gateway: true,
            use_route_prefix: true,
            use_autonomous_prefix: true,
        }
    }
}

/// DHCP static lease for reserving IP addresses
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DhcpStaticLease {
    /// Client MAC address (e.g., "00:11:22:33:44:55")
    pub mac_address: String,
    /// Reserved IP address (e.g., "192.168.1.100")
    pub ip_address: String,
    /// Optional hostname for the client
    pub hostname: Option<String>,
}

/// DHCP server configuration for LAN interfaces
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DhcpServerConfig {
    /// Whether DHCP server is enabled
    pub enabled: bool,
    /// Offset from network address for pool start (e.g., 100 for .100)
    pub pool_offset: Option<u32>,
    /// Number of addresses in the pool
    pub pool_size: Option<u32>,
    /// Default lease time in seconds
    pub default_lease_time_secs: Option<u32>,
    /// Maximum lease time in seconds
    pub max_lease_time_secs: Option<u32>,
    /// Whether to provide DNS servers to clients
    pub emit_dns: bool,
    /// DNS servers to provide (if empty, uses interface's DNS)
    pub dns_servers: Vec<String>,
    /// Whether to provide NTP servers to clients
    pub emit_ntp: bool,
    /// NTP servers to provide
    pub ntp_servers: Vec<String>,
    /// Whether to provide router/gateway to clients
    pub emit_router: bool,
    /// Router address to provide (if None, uses interface's address)
    pub router_address: Option<String>,
    /// Static DHCP leases (MAC to IP reservations)
    pub static_leases: Vec<DhcpStaticLease>,
}

impl Default for DhcpServerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            pool_offset: Some(100),
            pool_size: Some(100),
            default_lease_time_secs: Some(3600),
            max_lease_time_secs: Some(86400),
            emit_dns: true,
            dns_servers: Vec::new(),
            emit_ntp: false,
            ntp_servers: Vec::new(),
            emit_router: true,
            router_address: None,
            static_leases: Vec::new(),
        }
    }
}

/// IPv6 prefix to advertise via Router Advertisement
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Ipv6RaPrefix {
    /// IPv6 prefix in CIDR notation (e.g., "2001:db8::/64")
    pub prefix: String,
    /// Preferred lifetime in seconds (None = infinite)
    pub preferred_lifetime_secs: Option<u32>,
    /// Valid lifetime in seconds (None = infinite)
    pub valid_lifetime_secs: Option<u32>,
    /// On-link flag (prefix is on-link)
    pub on_link: bool,
    /// Autonomous flag (use for SLAAC)
    pub autonomous: bool,
}

impl Default for Ipv6RaPrefix {
    fn default() -> Self {
        Self {
            prefix: String::new(),
            preferred_lifetime_secs: None,
            valid_lifetime_secs: None,
            on_link: true,
            autonomous: true,
        }
    }
}

/// IPv6 Router Advertisement configuration for LAN interfaces
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Ipv6RaConfig {
    /// Whether to send Router Advertisements
    pub enabled: bool,
    /// Router lifetime in seconds
    pub router_lifetime_secs: Option<u32>,
    /// Router preference (low, medium, high)
    pub router_preference: Option<String>,
    /// Managed flag - clients should use DHCPv6 for addresses
    pub managed: bool,
    /// Other information flag - clients should use DHCPv6 for other config
    pub other_information: bool,
    /// Whether to include DNS servers in RA
    pub emit_dns: bool,
    /// DNS servers to advertise (RDNSS)
    pub dns_servers: Vec<String>,
    /// DNS search domains to advertise (DNSSL)
    pub search_domains: Vec<String>,
    /// Prefixes to advertise
    pub prefixes: Vec<Ipv6RaPrefix>,
}

impl Default for Ipv6RaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            router_lifetime_secs: Some(1800),
            router_preference: Some("medium".to_string()),
            managed: false,
            other_information: false,
            emit_dns: true,
            dns_servers: Vec::new(),
            search_domains: Vec::new(),
            prefixes: Vec::new(),
        }
    }
}

/// Complete interface configuration for systemd-networkd
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InterfaceConfig {
    /// Database ID (None for new configs)
    pub id: Option<i64>,
    /// Interface name (e.g., "eth0", "enp3s0")
    pub name: String,
    /// Role (WAN or LAN)
    pub role: InterfaceRole,
    /// Whether this interface is enabled
    pub enabled: bool,
    /// Human-readable description of the interface
    pub description: Option<String>,
    
    // Basic IP configuration
    /// DHCP mode
    pub dhcp_mode: DhcpMode,
    /// Static IP addresses
    pub addresses: Vec<StaticAddress>,
    /// Static routes
    pub routes: Vec<StaticRoute>,
    /// DNS servers
    pub dns_servers: Vec<String>,
    /// Search domains for DNS resolution
    pub search_domains: Vec<String>,
    /// Default gateway (convenience field, also creates a route)
    pub gateway: Option<String>,
    
    // Link-local and interface state settings
    /// Link-local addressing mode
    #[serde(default)]
    pub link_local: LinkLocalMode,
    /// Whether interface is required for network-online.target
    #[serde(default = "default_true")]
    pub required_for_online: bool,
    /// Interface activation policy
    #[serde(default)]
    pub activation_policy: ActivationPolicy,
    
    // DHCP client settings
    /// DHCPv4 client configuration (only used when dhcp_mode includes IPv4)
    pub dhcpv4_client: Option<Dhcpv4ClientConfig>,
    /// DHCPv6 client configuration (only used when dhcp_mode includes IPv6)
    pub dhcpv6_client: Option<Dhcpv6ClientConfig>,
    
    // DHCP server settings (for LAN interfaces)
    /// DHCP server configuration (typically for LAN interfaces)
    #[serde(default)]
    pub dhcp_server: Option<DhcpServerConfig>,
    
    // IPv6 settings
    /// Accept IPv6 Router Advertisements
    pub ipv6_accept_ra: bool,
    /// IPv6 Accept RA client configuration (controls what to accept from RAs)
    #[serde(default)]
    pub ipv6_accept_ra_config: Option<Ipv6AcceptRaConfig>,
    /// IPv6 Router Advertisement server configuration (for LAN interfaces)
    #[serde(default)]
    pub ipv6_ra: Option<Ipv6RaConfig>,
    
    // Forwarding & NAT (typically for WAN interfaces)
    /// IP forwarding mode
    pub ip_forward: IpForwardMode,
    /// IP masquerading (NAT) mode
    pub ip_masquerade: IpMasqueradeMode,
    
    // Link settings
    /// Maximum Transmission Unit (MTU) in bytes
    /// Common values: 1500 (default), 1492 (PPPoE), 9000 (jumbo frames)
    #[serde(default)]
    pub mtu: Option<u32>,
}

fn default_true() -> bool {
    true
}

impl Default for InterfaceConfig {
    fn default() -> Self {
        Self {
            id: None,
            name: String::new(),
            role: InterfaceRole::LAN,
            enabled: true,
            description: None,
            dhcp_mode: DhcpMode::No,
            addresses: Vec::new(),
            routes: Vec::new(),
            dns_servers: Vec::new(),
            search_domains: Vec::new(),
            gateway: None,
            link_local: LinkLocalMode::default(),
            required_for_online: true,
            activation_policy: ActivationPolicy::default(),
            dhcpv4_client: None,
            dhcpv6_client: None,
            dhcp_server: None,
            ipv6_accept_ra: true,
            ipv6_accept_ra_config: None,
            ipv6_ra: None,
            ip_forward: IpForwardMode::No,
            ip_masquerade: IpMasqueradeMode::No,
            mtu: None,
        }
    }
}

/// Request to save an interface configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveInterfaceConfigRequest {
    pub config: InterfaceConfig,
}

/// Response from saving interface configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveInterfaceConfigResponse {
    pub success: bool,
    pub message: String,
    pub config_id: Option<i64>,
}

/// Response containing a single interface configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceConfigResponse {
    pub config: Option<InterfaceConfig>,
}

/// Response containing all interface configurations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceConfigsResponse {
    pub configs: Vec<InterfaceConfig>,
}

/// Single networkd file preview
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkdFilePreview {
    pub filename: String,
    pub content: String,
}

/// Response containing networkd file previews
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkdPreviewResponse {
    pub files: Vec<NetworkdFilePreview>,
}

// ============================================================================
// Legacy Types (kept for compatibility)
// ============================================================================

/// Errors that can occur in the Keystone system
#[derive(Debug, Error, Serialize, Deserialize, Clone)]
pub enum KeystoneError {
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("System command failed: {0}")]
    SystemCommandFailed(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Represents a network interface configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Interface {
    /// Interface name (e.g., "eth0", "wlan0")
    pub name: String,

    /// IP address with CIDR notation (e.g., "192.168.1.1/24")
    pub address: Option<String>,

    /// Whether DHCP is enabled for this interface
    pub dhcp_enabled: bool,

    /// Interface role (WAN or LAN)
    pub role: InterfaceRole,

    /// Whether the interface is currently enabled
    pub enabled: bool,
}

/// Interface role in the router
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum InterfaceRole {
    /// Wide Area Network (Internet-facing)
    WAN,
    /// Local Area Network (Internal network)
    LAN,
}

impl std::fmt::Display for InterfaceRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InterfaceRole::WAN => write!(f, "WAN"),
            InterfaceRole::LAN => write!(f, "LAN"),
        }
    }
}

impl std::str::FromStr for InterfaceRole {
    type Err = String;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "WAN" => Ok(InterfaceRole::WAN),
            "LAN" => Ok(InterfaceRole::LAN),
            _ => Err(format!("Unknown role: {}", s)),
        }
    }
}

/// A network interface that Keystone is configured to manage
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ManagedInterface {
    /// Interface name (e.g., "eth0", "enp3s0")
    pub name: String,
    
    /// Role/label for this interface (WAN, LAN)
    pub role: InterfaceRole,
    
    /// Optional static IP configuration (CIDR notation, e.g., "192.168.1.1/24")
    /// If None, DHCP will be used
    pub static_ip: Option<String>,
    
    /// Whether this interface configuration is enabled
    pub enabled: bool,
}

/// Request to save managed interfaces configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveManagedInterfacesRequest {
    pub interfaces: Vec<ManagedInterface>,
}

/// Response from saving managed interfaces
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveManagedInterfacesResponse {
    pub success: bool,
    pub message: String,
}

/// Response containing list of managed interfaces
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedInterfacesResponse {
    pub interfaces: Vec<ManagedInterface>,
}

/// Firewall protocol
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
}

/// Firewall action
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FirewallAction {
    Accept,
    Drop,
    Reject,
}

/// Represents an nftables firewall rule
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FirewallRule {
    /// Rule identifier
    pub id: String,

    /// Port number or range
    pub port: u16,

    /// Protocol (TCP/UDP/ICMP)
    pub protocol: Protocol,

    /// Action to take
    pub action: FirewallAction,

    /// Optional source IP/CIDR
    pub source: Option<String>,

    /// Optional destination IP/CIDR
    pub destination: Option<String>,

    /// Rule description
    pub description: String,

    /// Whether the rule is enabled
    pub enabled: bool,
}

/// Complete system state representing the router configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SystemState {
    /// All configured network interfaces
    pub interfaces: Vec<Interface>,

    /// All firewall rules
    pub firewall_rules: Vec<FirewallRule>,

    /// Whether IP forwarding is enabled
    pub ip_forwarding_enabled: bool,

    /// Whether NAT/masquerading is enabled
    pub nat_enabled: bool,
}

/// Simple interface counters for dashboard/network activity.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct InterfaceCounters {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

/// Dashboard payload (polled by the web UI).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DashboardResponse {
    pub state: SystemState,
    pub interface_counters: Vec<InterfaceCounters>,
    pub timestamp_ms: u64,
}

/// Request to apply a new system configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyConfigRequest {
    pub state: SystemState,
}

/// Response from applying configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyConfigResponse {
    pub success: bool,
    pub message: String,
    pub errors: Vec<String>,
}

/// Login request containing username and password
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// Login response containing JWT token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub success: bool,
    pub token: Option<String>,
    pub message: String,
}

/// JWT claims structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // Subject (username)
    pub exp: u64,    // Expiration time (Unix timestamp)
}

/// User account
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub email: Option<String>,
    pub password_hash: String,
    pub created_at: i64,
}

/// Request to create or update a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveUserRequest {
    pub id: Option<i64>, // None for new user
    pub username: String,
    pub email: Option<String>,
    pub password: Option<String>, // Only required for new users or password changes
}

/// Response from saving a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveUserResponse {
    pub success: bool,
    pub message: String,
    pub user_id: Option<i64>,
}

/// Request to delete a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteUserRequest {
    pub id: i64,
}

/// Response from deleting a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteUserResponse {
    pub success: bool,
    pub message: String,
}

/// Response containing list of users (without password hashes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsersResponse {
    pub users: Vec<UserInfo>,
}

/// User information without sensitive data
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserInfo {
    pub id: i64,
    pub username: String,
    pub email: Option<String>,
    pub created_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_serialization() {
        let iface = Interface {
            name: "eth0".to_string(),
            address: Some("192.168.1.1/24".to_string()),
            dhcp_enabled: true,
            role: InterfaceRole::LAN,
            enabled: true,
        };

        let json = serde_json::to_string(&iface).unwrap();
        let deserialized: Interface = serde_json::from_str(&json).unwrap();

        assert_eq!(iface, deserialized);
    }

    #[test]
    fn test_firewall_rule_serialization() {
        let rule = FirewallRule {
            id: "rule1".to_string(),
            port: 80,
            protocol: Protocol::TCP,
            action: FirewallAction::Accept,
            source: None,
            destination: Some("192.168.1.0/24".to_string()),
            description: "Allow HTTP".to_string(),
            enabled: true,
        };

        let json = serde_json::to_string(&rule).unwrap();
        let deserialized: FirewallRule = serde_json::from_str(&json).unwrap();

        assert_eq!(rule, deserialized);
    }

    #[test]
    fn test_dashboard_response_serialization() {
        let dashboard = DashboardResponse {
            state: SystemState::default(),
            interface_counters: vec![InterfaceCounters {
                name: "eth0".to_string(),
                rx_bytes: 1,
                tx_bytes: 2,
                rx_packets: 3,
                tx_packets: 4,
            }],
            timestamp_ms: 123,
        };

        let json = serde_json::to_string(&dashboard).unwrap();
        let deserialized: DashboardResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(dashboard.timestamp_ms, deserialized.timestamp_ms);
        assert_eq!(
            dashboard.interface_counters,
            deserialized.interface_counters
        );
    }

    #[test]
    fn test_interface_config_serialization() {
        let config = InterfaceConfig {
            id: Some(1),
            name: "eth0".to_string(),
            role: InterfaceRole::WAN,
            enabled: true,
            description: Some("Main WAN connection".to_string()),
            dhcp_mode: DhcpMode::Ipv4,
            addresses: vec![StaticAddress {
                address: "192.168.1.1/24".to_string(),
                label: Some("primary".to_string()),
                scope: AddressScope::Global,
            }],
            routes: vec![StaticRoute {
                destination: None,
                gateway: "192.168.1.254".to_string(),
                metric: Some(100),
                table: None,
                route_type: RouteType::Unicast,
            }],
            dns_servers: vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()],
            search_domains: vec!["example.com".to_string()],
            gateway: Some("192.168.1.254".to_string()),
            link_local: LinkLocalMode::Ipv6,
            required_for_online: true,
            activation_policy: ActivationPolicy::Up,
            dhcpv4_client: Some(Dhcpv4ClientConfig {
                send_hostname: true,
                hostname: None,
                use_dns: true,
                use_ntp: true,
                use_routes: true,
                use_gateway: true,
                use_mtu: true,
                use_domains: "yes".to_string(),
                route_metric: Some(100),
            }),
            dhcpv6_client: Some(Dhcpv6ClientConfig {
                use_dns: true,
                use_ntp: true,
                use_domains: "yes".to_string(),
                prefix_delegation_hint: Some("::1/64".to_string()),
                rapid_commit: true,
                without_ra: "no".to_string(),
            }),
            dhcp_server: Some(DhcpServerConfig {
                enabled: true,
                pool_offset: Some(100),
                pool_size: Some(50),
                default_lease_time_secs: Some(3600),
                max_lease_time_secs: Some(86400),
                emit_dns: true,
                dns_servers: vec!["192.168.1.1".to_string()],
                emit_ntp: false,
                ntp_servers: vec![],
                emit_router: true,
                router_address: None,
                static_leases: vec![DhcpStaticLease {
                    mac_address: "00:11:22:33:44:55".to_string(),
                    ip_address: "192.168.1.200".to_string(),
                    hostname: Some("server1".to_string()),
                }],
            }),
            ipv6_accept_ra: true,
            ipv6_accept_ra_config: None,
            ipv6_ra: None,
            ip_forward: IpForwardMode::Yes,
            ip_masquerade: IpMasqueradeMode::Ipv4,
            mtu: Some(1492),
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: InterfaceConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config, deserialized);
    }

    #[test]
    fn test_dhcp_mode_parsing() {
        assert_eq!("no".parse::<DhcpMode>().unwrap(), DhcpMode::No);
        assert_eq!("yes".parse::<DhcpMode>().unwrap(), DhcpMode::Yes);
        assert_eq!("ipv4".parse::<DhcpMode>().unwrap(), DhcpMode::Ipv4);
        assert_eq!("ipv6".parse::<DhcpMode>().unwrap(), DhcpMode::Ipv6);
        assert_eq!(DhcpMode::Ipv4.to_string(), "ipv4");
    }

    #[test]
    fn test_ip_forward_mode_parsing() {
        assert_eq!("no".parse::<IpForwardMode>().unwrap(), IpForwardMode::No);
        assert_eq!("yes".parse::<IpForwardMode>().unwrap(), IpForwardMode::Yes);
        assert_eq!(IpForwardMode::Ipv6.to_string(), "ipv6");
    }

    #[test]
    fn test_ip_masquerade_mode_parsing() {
        assert_eq!("no".parse::<IpMasqueradeMode>().unwrap(), IpMasqueradeMode::No);
        assert_eq!("both".parse::<IpMasqueradeMode>().unwrap(), IpMasqueradeMode::Both);
        assert_eq!("ipv4".parse::<IpMasqueradeMode>().unwrap(), IpMasqueradeMode::Ipv4);
        assert_eq!(IpMasqueradeMode::Both.to_string(), "both");
    }
}
