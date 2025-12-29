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

// ============================================================================
// VLAN Configuration Types
// ============================================================================

/// VLAN encapsulation protocol
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum VlanProtocol {
    /// Standard 802.1Q VLAN tagging
    #[default]
    #[serde(rename = "802.1q")]
    Dot1Q,
    /// 802.1ad (QinQ/Provider Bridging)
    #[serde(rename = "802.1ad")]
    Dot1Ad,
}

impl std::fmt::Display for VlanProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VlanProtocol::Dot1Q => write!(f, "802.1q"),
            VlanProtocol::Dot1Ad => write!(f, "802.1ad"),
        }
    }
}

impl std::str::FromStr for VlanProtocol {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "802.1q" | "dot1q" | "1q" => Ok(VlanProtocol::Dot1Q),
            "802.1ad" | "dot1ad" | "1ad" | "qinq" => Ok(VlanProtocol::Dot1Ad),
            _ => Err(format!("Unknown VLAN protocol: {}", s)),
        }
    }
}

/// VLAN configuration for virtual network interfaces
/// 
/// VLANs create virtual interfaces on top of physical interfaces,
/// allowing traffic segmentation using IEEE 802.1Q tagging.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VlanConfig {
    /// Database ID (None for new configs)
    pub id: Option<i64>,
    /// VLAN interface name (e.g., "vlan10", "eth0.10")
    /// This becomes the netdev name in systemd-networkd
    pub name: String,
    /// Parent interface name (e.g., "eth0", "enp3s0")
    pub parent_interface: String,
    /// VLAN ID (1-4094)
    pub vlan_id: u16,
    /// VLAN protocol (802.1Q or 802.1ad for QinQ)
    #[serde(default)]
    pub protocol: VlanProtocol,
    /// Optional description
    pub description: Option<String>,
    /// Associated InterfaceConfig ID for the VLAN's network settings
    /// This links to an InterfaceConfig that configures the VLAN interface
    pub interface_config_id: Option<i64>,
}

impl Default for VlanConfig {
    fn default() -> Self {
        Self {
            id: None,
            name: String::new(),
            parent_interface: String::new(),
            vlan_id: 1,
            protocol: VlanProtocol::default(),
            description: None,
            interface_config_id: None,
        }
    }
}

/// Request to save a VLAN configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveVlanConfigRequest {
    pub config: VlanConfig,
}

/// Response from saving VLAN configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveVlanConfigResponse {
    pub success: bool,
    pub message: String,
    pub vlan_id: Option<i64>,
}

/// Request to delete a VLAN
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteVlanRequest {
    pub id: i64,
}

/// Response from deleting a VLAN
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteVlanResponse {
    pub success: bool,
    pub message: String,
}

/// Response containing a single VLAN configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VlanConfigResponse {
    pub config: Option<VlanConfig>,
}

/// Response containing all VLAN configurations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VlanConfigsResponse {
    pub configs: Vec<VlanConfig>,
}

// ============================================================================
// Bridge Configuration
// ============================================================================

/// Bridge configuration for combining multiple interfaces
/// 
/// Bridges create virtual switches that connect multiple network interfaces,
/// allowing them to communicate as if on the same physical network.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BridgeConfig {
    /// Database ID (None for new configs)
    pub id: Option<i64>,
    /// Bridge interface name (e.g., "br0", "bridge-lan")
    pub name: String,
    /// Interfaces that are members of this bridge (e.g., ["eth1", "eth2"])
    pub members: Vec<String>,
    /// Enable Spanning Tree Protocol (STP)
    #[serde(default)]
    pub stp: bool,
    /// STP forward delay in seconds (2-30, default 15)
    #[serde(default = "default_stp_forward_delay")]
    pub stp_forward_delay: u32,
    /// Optional description
    pub description: Option<String>,
    /// Associated InterfaceConfig ID for the bridge's network settings
    /// This links to an InterfaceConfig that configures the bridge interface
    pub interface_config_id: Option<i64>,
}

fn default_stp_forward_delay() -> u32 {
    15
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            id: None,
            name: String::new(),
            members: Vec::new(),
            stp: false,
            stp_forward_delay: 15,
            description: None,
            interface_config_id: None,
        }
    }
}

/// Request to save a bridge configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveBridgeConfigRequest {
    pub config: BridgeConfig,
}

/// Response from saving bridge configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveBridgeConfigResponse {
    pub success: bool,
    pub message: String,
    pub bridge_id: Option<i64>,
}

/// Request to delete a bridge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteBridgeRequest {
    pub id: i64,
}

/// Response from deleting a bridge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteBridgeResponse {
    pub success: bool,
    pub message: String,
}

/// Response containing a single bridge configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfigResponse {
    pub config: Option<BridgeConfig>,
}

/// Response containing all bridge configurations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfigsResponse {
    pub configs: Vec<BridgeConfig>,
}

/// Generic delete response (used by firewall endpoints)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteResponse {
    pub success: bool,
    pub message: String,
}

// ============================================================================
// Complete Interface Configuration
// ============================================================================

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
    
    // VLAN settings
    /// VLANs attached to this interface (only populated when this is a parent interface)
    /// This is used to generate VLAN= lines in the .network file
    #[serde(default)]
    pub vlans: Vec<String>,
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
            vlans: Vec::new(),
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

// ============================================================================
// Firewall Configuration Types (nftables)
// ============================================================================

/// Default policy for a firewall zone
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum FirewallPolicy {
    /// Accept packets by default
    Accept,
    /// Drop packets by default
    #[default]
    Drop,
}

impl std::fmt::Display for FirewallPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirewallPolicy::Accept => write!(f, "accept"),
            FirewallPolicy::Drop => write!(f, "drop"),
        }
    }
}

impl std::str::FromStr for FirewallPolicy {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "accept" => Ok(FirewallPolicy::Accept),
            "drop" => Ok(FirewallPolicy::Drop),
            _ => Err(format!("Unknown firewall policy: {}", s)),
        }
    }
}

/// Action to take on a matched packet
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum FirewallAction {
    /// Accept the packet
    #[default]
    Accept,
    /// Silently drop the packet
    Drop,
    /// Reject with ICMP error
    Reject,
}

impl std::fmt::Display for FirewallAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirewallAction::Accept => write!(f, "accept"),
            FirewallAction::Drop => write!(f, "drop"),
            FirewallAction::Reject => write!(f, "reject"),
        }
    }
}

impl std::str::FromStr for FirewallAction {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "accept" => Ok(FirewallAction::Accept),
            "drop" => Ok(FirewallAction::Drop),
            "reject" => Ok(FirewallAction::Reject),
            _ => Err(format!("Unknown firewall action: {}", s)),
        }
    }
}

/// Protocol for firewall rules
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum RuleProtocol {
    /// Any protocol
    #[default]
    Any,
    /// TCP only
    Tcp,
    /// UDP only
    Udp,
    /// Both TCP and UDP
    #[serde(rename = "tcp+udp")]
    TcpUdp,
    /// ICMP (IPv4)
    Icmp,
    /// ICMPv6 (IPv6)
    Icmpv6,
}

impl std::fmt::Display for RuleProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleProtocol::Any => write!(f, "any"),
            RuleProtocol::Tcp => write!(f, "tcp"),
            RuleProtocol::Udp => write!(f, "udp"),
            RuleProtocol::TcpUdp => write!(f, "tcp+udp"),
            RuleProtocol::Icmp => write!(f, "icmp"),
            RuleProtocol::Icmpv6 => write!(f, "icmpv6"),
        }
    }
}

impl std::str::FromStr for RuleProtocol {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "any" | "" => Ok(RuleProtocol::Any),
            "tcp" => Ok(RuleProtocol::Tcp),
            "udp" => Ok(RuleProtocol::Udp),
            "tcp+udp" | "tcpudp" | "both" => Ok(RuleProtocol::TcpUdp),
            "icmp" => Ok(RuleProtocol::Icmp),
            "icmpv6" => Ok(RuleProtocol::Icmpv6),
            _ => Err(format!("Unknown protocol: {}", s)),
        }
    }
}

/// A firewall zone groups interfaces with common policies
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FirewallZone {
    pub id: Option<i64>,
    pub name: String,
    pub description: Option<String>,
    /// Interfaces belonging to this zone
    pub interfaces: Vec<String>,
    /// Default policy for incoming traffic to the router
    pub default_input_policy: FirewallPolicy,
    /// Default policy for forwarded traffic from this zone
    pub default_forward_policy: FirewallPolicy,
}

impl Default for FirewallZone {
    fn default() -> Self {
        Self {
            id: None,
            name: String::new(),
            description: None,
            interfaces: Vec::new(),
            default_input_policy: FirewallPolicy::Drop,
            default_forward_policy: FirewallPolicy::Drop,
        }
    }
}

/// Policy for traffic forwarding between two zones
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ZoneForwardPolicy {
    pub id: Option<i64>,
    pub source_zone: String,
    pub dest_zone: String,
    pub policy: FirewallAction,
    pub enabled: bool,
}

impl Default for ZoneForwardPolicy {
    fn default() -> Self {
        Self {
            id: None,
            source_zone: String::new(),
            dest_zone: String::new(),
            policy: FirewallAction::Drop,
            enabled: true,
        }
    }
}

/// Port forward (DNAT) rule
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PortForward {
    pub id: Option<i64>,
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
    /// Protocol to match
    pub protocol: RuleProtocol,
    /// Source zone (None = any incoming interface)
    pub source_zone: Option<String>,
    /// External port range start
    pub external_port_start: u16,
    /// External port range end (None = single port)
    pub external_port_end: Option<u16>,
    /// Restrict to source IP/CIDR (None = any)
    pub source_ip: Option<String>,
    /// Internal destination IP
    pub dest_ip: String,
    /// Internal destination port (None = same as external)
    pub dest_port: Option<u16>,
}

impl Default for PortForward {
    fn default() -> Self {
        Self {
            id: None,
            name: String::new(),
            description: None,
            enabled: true,
            protocol: RuleProtocol::Tcp,
            source_zone: None,
            external_port_start: 0,
            external_port_end: None,
            source_ip: None,
            dest_ip: String::new(),
            dest_port: None,
        }
    }
}

/// Input rule controlling access to the router itself
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InputRule {
    pub id: Option<i64>,
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
    /// Position for ordering (lower = evaluated first)
    pub position: i32,
    /// Source zone (None = any)
    pub zone: Option<String>,
    /// Protocol to match (None = any)
    pub protocol: Option<RuleProtocol>,
    /// Port range start (None = any port)
    pub port_start: Option<u16>,
    /// Port range end (None = single port)
    pub port_end: Option<u16>,
    /// Source IP/CIDR (None = any)
    pub source_ip: Option<String>,
    /// Action to take
    pub action: FirewallAction,
    /// Enable logging for matched packets
    pub log_enabled: bool,
    /// Log prefix string
    pub log_prefix: Option<String>,
    /// Rate limit (e.g., "10/minute")
    pub rate_limit: Option<String>,
}

impl Default for InputRule {
    fn default() -> Self {
        Self {
            id: None,
            name: String::new(),
            description: None,
            enabled: true,
            position: 0,
            zone: None,
            protocol: None,
            port_start: None,
            port_end: None,
            source_ip: None,
            action: FirewallAction::Accept,
            log_enabled: false,
            log_prefix: None,
            rate_limit: None,
        }
    }
}

/// Forward rule controlling traffic between zones
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ForwardRule {
    pub id: Option<i64>,
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
    /// Position for ordering
    pub position: i32,
    /// Source zone (None = any)
    pub source_zone: Option<String>,
    /// Destination zone (None = any)
    pub dest_zone: Option<String>,
    /// Protocol to match
    pub protocol: Option<RuleProtocol>,
    /// Destination port range start
    pub dest_port_start: Option<u16>,
    /// Destination port range end
    pub dest_port_end: Option<u16>,
    /// Source IP/CIDR
    pub source_ip: Option<String>,
    /// Destination IP/CIDR
    pub dest_ip: Option<String>,
    /// Action to take
    pub action: FirewallAction,
    /// Enable logging
    pub log_enabled: bool,
    /// Log prefix
    pub log_prefix: Option<String>,
    /// Rate limit
    pub rate_limit: Option<String>,
}

impl Default for ForwardRule {
    fn default() -> Self {
        Self {
            id: None,
            name: String::new(),
            description: None,
            enabled: true,
            position: 0,
            source_zone: None,
            dest_zone: None,
            protocol: None,
            dest_port_start: None,
            dest_port_end: None,
            source_ip: None,
            dest_ip: None,
            action: FirewallAction::Accept,
            log_enabled: false,
            log_prefix: None,
            rate_limit: None,
        }
    }
}

/// Complete firewall configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct FirewallConfig {
    pub zones: Vec<FirewallZone>,
    pub zone_forwards: Vec<ZoneForwardPolicy>,
    pub port_forwards: Vec<PortForward>,
    pub input_rules: Vec<InputRule>,
    pub forward_rules: Vec<ForwardRule>,
    pub global_settings: FirewallGlobalSettings,
}

/// Global firewall settings (singleton)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FirewallGlobalSettings {
    /// Allow responding to ping (ICMP echo-request) from WAN zones
    /// Note: Dangerous ICMP types (timestamp, redirect, address-mask) are always blocked
    pub ping_wan_enabled: bool,
    /// Allow responding to ping from LAN zones
    pub ping_lan_enabled: bool,
    /// Enable hairpin NAT (NAT reflection) - allows LAN clients to access
    /// port-forwarded services using the external/WAN IP address
    pub hairpin_nat_enabled: bool,
}

impl Default for FirewallGlobalSettings {
    fn default() -> Self {
        Self {
            ping_wan_enabled: false,   // Don't respond to WAN pings by default (stealth)
            ping_lan_enabled: true,    // Respond to LAN pings (useful for diagnostics)
            hairpin_nat_enabled: true, // Enable hairpin NAT by default (common expectation)
        }
    }
}

// ============================================================================
// Firewall API Request/Response Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveFirewallZoneRequest {
    pub zone: FirewallZone,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveFirewallZoneResponse {
    pub success: bool,
    pub message: String,
    pub zone_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteFirewallZoneRequest {
    pub id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteFirewallZoneResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallZonesResponse {
    pub zones: Vec<FirewallZone>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveZoneForwardRequest {
    pub forward: ZoneForwardPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveZoneForwardResponse {
    pub success: bool,
    pub message: String,
    pub forward_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteZoneForwardRequest {
    pub id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteZoneForwardResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneForwardsResponse {
    pub forwards: Vec<ZoneForwardPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavePortForwardRequest {
    pub port_forward: PortForward,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavePortForwardResponse {
    pub success: bool,
    pub message: String,
    pub port_forward_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletePortForwardRequest {
    pub id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletePortForwardResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortForwardsResponse {
    pub port_forwards: Vec<PortForward>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveInputRuleRequest {
    pub rule: InputRule,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveInputRuleResponse {
    pub success: bool,
    pub message: String,
    pub rule_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteInputRuleRequest {
    pub id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteInputRuleResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputRulesResponse {
    pub rules: Vec<InputRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveForwardRuleRequest {
    pub rule: ForwardRule,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveForwardRuleResponse {
    pub success: bool,
    pub message: String,
    pub rule_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteForwardRuleRequest {
    pub id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteForwardRuleResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardRulesResponse {
    pub rules: Vec<ForwardRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReorderRulesRequest {
    /// List of rule IDs in desired order
    pub rule_ids: Vec<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReorderRulesResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallPreviewResponse {
    /// The generated nftables ruleset as text
    pub ruleset: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallApplyRequest {
    // Empty - applies current config from database
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallApplyResponse {
    pub success: bool,
    pub message: String,
    /// Whether changes require confirmation
    pub pending_confirmation: bool,
    /// Unix timestamp - confirm before this time or rollback
    pub confirm_deadline: Option<u64>,
    /// Session ID for confirmation
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallConfirmRequest {
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallConfirmResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRollbackResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallStatusResponse {
    /// Is there a pending apply waiting for confirmation?
    pub pending_confirmation: bool,
    /// Seconds remaining until automatic rollback
    pub seconds_remaining: Option<u32>,
    /// Session ID if pending
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallConfigResponse {
    pub config: FirewallConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallGlobalSettingsResponse {
    pub settings: FirewallGlobalSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveFirewallGlobalSettingsRequest {
    pub settings: FirewallGlobalSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveFirewallGlobalSettingsResponse {
    pub success: bool,
    pub message: String,
}

/// Firewall rule counters from nftables
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct FirewallRuleCounter {
    /// Rule comment/name (used to identify the rule)
    pub name: String,
    /// Chain the rule belongs to (input, forward, etc.)
    pub chain: String,
    /// Number of packets matched
    pub packets: u64,
    /// Number of bytes matched
    pub bytes: u64,
}

/// Response containing all firewall rule counters
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FirewallCountersResponse {
    pub counters: Vec<FirewallRuleCounter>,
}

/// Complete system state representing the router configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SystemState {
    /// All configured network interfaces
    pub interfaces: Vec<Interface>,

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
    fn test_firewall_zone_serialization() {
        let zone = FirewallZone {
            id: Some(1),
            name: "lan".to_string(),
            description: Some("Local network".to_string()),
            interfaces: vec!["eth1".to_string(), "eth2".to_string()],
            default_input_policy: FirewallPolicy::Accept,
            default_forward_policy: FirewallPolicy::Accept,
        };

        let json = serde_json::to_string(&zone).unwrap();
        let deserialized: FirewallZone = serde_json::from_str(&json).unwrap();

        assert_eq!(zone, deserialized);
    }

    #[test]
    fn test_port_forward_serialization() {
        let pf = PortForward {
            id: Some(1),
            name: "Web Server".to_string(),
            description: Some("Forward HTTP to internal server".to_string()),
            enabled: true,
            protocol: RuleProtocol::Tcp,
            source_zone: Some("wan".to_string()),
            external_port_start: 8080,
            external_port_end: None,
            source_ip: None,
            dest_ip: "192.168.1.100".to_string(),
            dest_port: Some(80),
        };

        let json = serde_json::to_string(&pf).unwrap();
        let deserialized: PortForward = serde_json::from_str(&json).unwrap();

        assert_eq!(pf, deserialized);
    }

    #[test]
    fn test_firewall_action_parsing() {
        assert_eq!("accept".parse::<FirewallAction>().unwrap(), FirewallAction::Accept);
        assert_eq!("drop".parse::<FirewallAction>().unwrap(), FirewallAction::Drop);
        assert_eq!("reject".parse::<FirewallAction>().unwrap(), FirewallAction::Reject);
        assert_eq!(FirewallAction::Accept.to_string(), "accept");
    }

    #[test]
    fn test_rule_protocol_parsing() {
        assert_eq!("tcp".parse::<RuleProtocol>().unwrap(), RuleProtocol::Tcp);
        assert_eq!("udp".parse::<RuleProtocol>().unwrap(), RuleProtocol::Udp);
        assert_eq!("tcp+udp".parse::<RuleProtocol>().unwrap(), RuleProtocol::TcpUdp);
        assert_eq!("icmp".parse::<RuleProtocol>().unwrap(), RuleProtocol::Icmp);
        assert_eq!("icmpv6".parse::<RuleProtocol>().unwrap(), RuleProtocol::Icmpv6);
        assert_eq!("any".parse::<RuleProtocol>().unwrap(), RuleProtocol::Any);
        assert_eq!(RuleProtocol::TcpUdp.to_string(), "tcp+udp");
    }

    #[test]
    fn test_firewall_policy_parsing() {
        assert_eq!("accept".parse::<FirewallPolicy>().unwrap(), FirewallPolicy::Accept);
        assert_eq!("drop".parse::<FirewallPolicy>().unwrap(), FirewallPolicy::Drop);
        assert_eq!(FirewallPolicy::Drop.to_string(), "drop");
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
            vlans: vec!["vlan10".to_string(), "vlan20".to_string()],
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

    #[test]
    fn test_vlan_config_serialization() {
        let vlan = VlanConfig {
            id: Some(1),
            name: "vlan10".to_string(),
            parent_interface: "eth0".to_string(),
            vlan_id: 10,
            protocol: VlanProtocol::Dot1Q,
            description: Some("Management VLAN".to_string()),
            interface_config_id: Some(5),
        };

        let json = serde_json::to_string(&vlan).unwrap();
        let deserialized: VlanConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(vlan, deserialized);
    }

    #[test]
    fn test_vlan_protocol_parsing() {
        assert_eq!("802.1q".parse::<VlanProtocol>().unwrap(), VlanProtocol::Dot1Q);
        assert_eq!("802.1ad".parse::<VlanProtocol>().unwrap(), VlanProtocol::Dot1Ad);
        assert_eq!("qinq".parse::<VlanProtocol>().unwrap(), VlanProtocol::Dot1Ad);
        assert_eq!(VlanProtocol::Dot1Q.to_string(), "802.1q");
        assert_eq!(VlanProtocol::Dot1Ad.to_string(), "802.1ad");
    }
}
