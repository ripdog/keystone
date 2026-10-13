//! Keystone Core Library
//!
//! This crate contains shared type definitions used by both the daemon and web-ui.
//! All types must be serializable to ensure strict type safety across the system boundary.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod api;
pub mod changes;
pub mod sqm;
pub mod upnp;
pub mod validation;

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

/// Identity sent as DHCPv4 option 61. Some ISPs authorise traffic based on it.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Dhcpv4ClientIdentifier {
    Duid,
    Mac,
}

impl std::fmt::Display for Dhcpv4ClientIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Duid => write!(f, "duid"),
            Self::Mac => write!(f, "mac"),
        }
    }
}

/// DHCPv4 client configuration options
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Dhcpv4ClientConfig {
    /// None preserves systemd-networkd's default (DUID). MAC is common on residential WANs.
    #[serde(default)]
    pub client_identifier: Option<Dhcpv4ClientIdentifier>,
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
            client_identifier: None,
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
    /// Request delegated prefixes from the DHCPv6 server
    #[serde(default = "default_true")]
    pub use_delegated_prefix: bool,
    /// Request specific prefix for prefix delegation (CIDR notation, e.g., "::/56")
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
            use_delegated_prefix: true,
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

/// Assign a subnet from a delegated DHCPv6 prefix to this downstream interface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DhcpPrefixDelegationConfig {
    /// Interface that acquired the delegated prefix. `None` lets networkd auto-select.
    pub uplink_interface: Option<String>,
    /// Stable subnet identifier selected from the delegated prefix.
    pub subnet_id: Option<u64>,
    /// Optional IPv6 interface identifier to use within the delegated prefix.
    /// For example, `::1` assigns the router address ending in `::1` instead of EUI-64.
    #[serde(default)]
    pub ipv6_token: Option<String>,
    /// Advertise the delegated subnet through Router Advertisements.
    #[serde(default = "default_true")]
    pub announce: bool,
}

impl Default for DhcpPrefixDelegationConfig {
    fn default() -> Self {
        Self {
            uplink_interface: None,
            subnet_id: None,
            ipv6_token: None,
            announce: true,
        }
    }
}

// ============================================================================
// Dnsmasq Configuration Types
// ============================================================================

/// Global dnsmasq configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsmasqConfig {
    /// Whether dnsmasq is enabled
    pub enabled: bool,

    // --- DNS Settings ---
    /// DNS port (53 by default, 0 to disable DNS)
    pub dns_port: u16,
    /// DNS cache size (0 to disable caching)
    pub cache_size: u32,
    /// Enable DNSSEC validation (requires trust-anchors)
    pub dnssec_enabled: bool,
    /// Never forward plain names (no dots)
    pub domain_needed: bool,
    /// Never forward addresses in non-routed address spaces
    pub bogus_priv: bool,
    /// Local domain name (e.g., "home.lan", "local")
    pub local_domain: Option<String>,
    /// Expand simple hostnames with the local domain
    pub expand_hosts: bool,

    // --- Upstream DNS ---
    /// DNS forwarding mode
    pub upstream_mode: DnsmasqUpstreamMode,
    /// Custom upstream DNS servers (when mode is Custom)
    pub upstream_servers: Vec<DnsmasqUpstreamServer>,

    // --- Interface Binding ---
    /// Interfaces to listen on (empty = all interfaces)
    pub listen_interfaces: Vec<String>,
    /// Interfaces to NOT listen on
    pub except_interfaces: Vec<String>,
    /// Interfaces where DHCP is disabled (DNS only)
    pub no_dhcp_interfaces: Vec<String>,
    /// Use bind-dynamic mode (recommended for routers)
    pub bind_dynamic: bool,

    // --- Logging ---
    /// Log DNS queries
    pub log_queries: bool,
    /// Log DHCP transactions
    pub log_dhcp: bool,
}

impl Default for DnsmasqConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dns_port: 53,
            cache_size: 1000,
            dnssec_enabled: false,
            domain_needed: true,
            bogus_priv: true,
            local_domain: Some("lan".to_string()),
            expand_hosts: true,
            upstream_mode: DnsmasqUpstreamMode::System,
            upstream_servers: Vec::new(),
            listen_interfaces: Vec::new(),
            except_interfaces: Vec::new(),
            no_dhcp_interfaces: Vec::new(),
            bind_dynamic: true,
            log_queries: false,
            log_dhcp: false,
        }
    }
}

/// How dnsmasq resolves upstream DNS queries
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum DnsmasqUpstreamMode {
    /// Use system resolv.conf
    #[default]
    System,
    /// Use custom upstream servers only (--no-resolv)
    Custom,
    /// Chain to local AdGuard Home (localhost:5353 or similar)
    LocalAdGuard,
}

impl std::fmt::Display for DnsmasqUpstreamMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsmasqUpstreamMode::System => write!(f, "system"),
            DnsmasqUpstreamMode::Custom => write!(f, "custom"),
            DnsmasqUpstreamMode::LocalAdGuard => write!(f, "localadguard"),
        }
    }
}

impl std::str::FromStr for DnsmasqUpstreamMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "system" => Ok(DnsmasqUpstreamMode::System),
            "custom" => Ok(DnsmasqUpstreamMode::Custom),
            "localadguard" | "adguard" => Ok(DnsmasqUpstreamMode::LocalAdGuard),
            _ => Err(format!("Unknown upstream mode: {}", s)),
        }
    }
}

/// Upstream DNS server configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsmasqUpstreamServer {
    /// Server address (IP or hostname)
    pub address: String,
    /// Port (default 53)
    pub port: Option<u16>,
    /// Specific domain this server handles (None = all)
    /// e.g., "internal.company.com" for private DNS
    pub domain: Option<String>,
}

/// DHCP range/pool configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsmasqDhcpRange {
    pub id: Option<i64>,
    /// Human-readable name for this pool
    pub name: String,
    /// Interface this pool serves
    pub interface: String,
    /// Pool start address (e.g., "192.168.1.100")
    pub start_address: String,
    /// Pool end address (e.g., "192.168.1.200")
    pub end_address: String,
    /// Subnet mask (e.g., "255.255.255.0")
    /// If not specified, derived from interface address
    pub netmask: Option<String>,
    /// Lease duration (e.g., "12h", "1d", "infinite")
    pub lease_time: String,
    /// Whether this range is enabled
    pub enabled: bool,

    // --- DHCPv6 / SLAAC options ---
    /// IPv6 mode for this range
    pub ipv6_mode: Option<DnsmasqIpv6Mode>,
    /// IPv6 prefix for this range (e.g., "2001:db8::/64")
    pub ipv6_prefix: Option<String>,
}

impl Default for DnsmasqDhcpRange {
    fn default() -> Self {
        Self {
            id: None,
            name: String::new(),
            interface: String::new(),
            start_address: String::new(),
            end_address: String::new(),
            netmask: None,
            lease_time: "24h".to_string(),
            enabled: true,
            ipv6_mode: None,
            ipv6_prefix: None,
        }
    }
}

/// IPv6 DHCP/RA mode
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DnsmasqIpv6Mode {
    /// Router Advertisement only (SLAAC)
    RaOnly,
    /// RA with stateless DHCPv6 (addresses via SLAAC, other config via DHCP)
    RaStateless,
    /// RA + DHCPv6 + SLAAC
    Slaac,
    /// Full DHCPv6 (managed addresses, no SLAAC)
    Dhcpv6,
}

impl std::fmt::Display for DnsmasqIpv6Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsmasqIpv6Mode::RaOnly => write!(f, "ra-only"),
            DnsmasqIpv6Mode::RaStateless => write!(f, "ra-stateless"),
            DnsmasqIpv6Mode::Slaac => write!(f, "slaac"),
            DnsmasqIpv6Mode::Dhcpv6 => write!(f, "dhcpv6"),
        }
    }
}

impl std::str::FromStr for DnsmasqIpv6Mode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().replace('_', "-").as_str() {
            "ra-only" | "raonly" => Ok(DnsmasqIpv6Mode::RaOnly),
            "ra-stateless" | "rastateless" => Ok(DnsmasqIpv6Mode::RaStateless),
            "slaac" => Ok(DnsmasqIpv6Mode::Slaac),
            "dhcpv6" => Ok(DnsmasqIpv6Mode::Dhcpv6),
            _ => Err(format!("Unknown IPv6 mode: {}", s)),
        }
    }
}

/// Static DHCP lease/reservation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsmasqStaticLease {
    pub id: Option<i64>,
    /// MAC address (e.g., "00:11:22:33:44:55")
    /// Supports wildcards like "00:11:22:*:*:*"
    pub mac_address: String,
    /// Reserved IP address
    pub ip_address: String,
    /// Client hostname (optional)
    pub hostname: Option<String>,
    /// Lease time override (optional, e.g., "infinite")
    pub lease_time: Option<String>,
    /// Client ID (alternative to MAC, for DHCPv6)
    pub client_id: Option<String>,
    /// Tags to set when this host is matched
    pub set_tags: Vec<String>,
    /// Whether this reservation is enabled
    pub enabled: bool,
}

impl Default for DnsmasqStaticLease {
    fn default() -> Self {
        Self {
            id: None,
            mac_address: String::new(),
            ip_address: String::new(),
            hostname: None,
            lease_time: None,
            client_id: None,
            set_tags: Vec::new(),
            enabled: true,
        }
    }
}

/// DHCP options sent to clients
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsmasqDhcpOption {
    pub id: Option<i64>,
    /// Human-readable description
    pub description: Option<String>,
    /// DHCP option number (e.g., 3 for router, 6 for DNS)
    /// Can also be option name like "router", "dns-server"
    pub option: String,
    /// Value(s) for the option
    pub value: String,
    /// Only apply to clients with these tags
    pub match_tags: Vec<String>,
    /// Whether this option is enabled
    pub enabled: bool,
    /// Is this an IPv6 option (option6:)
    pub ipv6: bool,
    /// Force send even if client didn't request it
    pub force: bool,
}

impl Default for DnsmasqDhcpOption {
    fn default() -> Self {
        Self {
            id: None,
            description: None,
            option: String::new(),
            value: String::new(),
            match_tags: Vec::new(),
            enabled: true,
            ipv6: false,
            force: false,
        }
    }
}

/// Custom DNS host record
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsmasqHostRecord {
    pub id: Option<i64>,
    /// Hostname(s) for this record
    pub hostnames: Vec<String>,
    /// IPv4 address (optional)
    pub ipv4_address: Option<String>,
    /// IPv6 address (optional)
    pub ipv6_address: Option<String>,
    /// TTL in seconds (optional)
    pub ttl: Option<u32>,
    /// Whether this record is enabled
    pub enabled: bool,
}

impl Default for DnsmasqHostRecord {
    fn default() -> Self {
        Self {
            id: None,
            hostnames: Vec::new(),
            ipv4_address: None,
            ipv6_address: None,
            ttl: None,
            enabled: true,
        }
    }
}

/// Custom CNAME record
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsmasqCnameRecord {
    pub id: Option<i64>,
    /// Alias name (the CNAME)
    pub alias: String,
    /// Target hostname
    pub target: String,
    /// TTL in seconds (optional)
    pub ttl: Option<u32>,
    /// Whether this record is enabled
    pub enabled: bool,
}

impl Default for DnsmasqCnameRecord {
    fn default() -> Self {
        Self {
            id: None,
            alias: String::new(),
            target: String::new(),
            ttl: None,
            enabled: true,
        }
    }
}

/// Address override (block or redirect domain)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsmasqAddressOverride {
    pub id: Option<i64>,
    /// Domain pattern (e.g., "ads.example.com", "*.malware.com")
    pub domain: String,
    /// Override action
    pub action: DnsmasqAddressAction,
    /// Custom IP address (when action is Redirect)
    pub redirect_address: Option<String>,
    /// Whether this override is enabled
    pub enabled: bool,
}

impl Default for DnsmasqAddressOverride {
    fn default() -> Self {
        Self {
            id: None,
            domain: String::new(),
            action: DnsmasqAddressAction::Block,
            redirect_address: None,
            enabled: true,
        }
    }
}

/// Action for address override
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum DnsmasqAddressAction {
    /// Return NXDOMAIN (block the domain)
    #[default]
    Block,
    /// Redirect to specific IP
    Redirect,
    /// Return 0.0.0.0 / :: (NULL address)
    Null,
}

impl std::fmt::Display for DnsmasqAddressAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsmasqAddressAction::Block => write!(f, "block"),
            DnsmasqAddressAction::Redirect => write!(f, "redirect"),
            DnsmasqAddressAction::Null => write!(f, "null"),
        }
    }
}

impl std::str::FromStr for DnsmasqAddressAction {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "block" | "nxdomain" => Ok(DnsmasqAddressAction::Block),
            "redirect" => Ok(DnsmasqAddressAction::Redirect),
            "null" | "0.0.0.0" => Ok(DnsmasqAddressAction::Null),
            _ => Err(format!("Unknown address action: {}", s)),
        }
    }
}

/// Current DHCP lease (read from dnsmasq lease file)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DhcpLease {
    pub mac_address: String,
    pub ip_address: String,
    pub hostname: Option<String>,
    /// Unix timestamp when lease expires
    pub expires_at: u64,
    pub client_id: Option<String>,
}

// ============================================================================
// Dnsmasq API Request/Response Types
// ============================================================================

/// Complete dnsmasq state for UI
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsmasqStateResponse {
    pub config: DnsmasqConfig,
    pub dhcp_ranges: Vec<DnsmasqDhcpRange>,
    pub static_leases: Vec<DnsmasqStaticLease>,
    pub dhcp_options: Vec<DnsmasqDhcpOption>,
    pub host_records: Vec<DnsmasqHostRecord>,
    pub cname_records: Vec<DnsmasqCnameRecord>,
    pub address_overrides: Vec<DnsmasqAddressOverride>,
}

/// Request to save global dnsmasq config
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveDnsmasqConfigRequest {
    pub config: DnsmasqConfig,
}

/// Response from saving dnsmasq config
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveDnsmasqConfigResponse {
    pub success: bool,
    pub message: String,
}

/// Request to save a DHCP range
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveDhcpRangeRequest {
    pub range: DnsmasqDhcpRange,
}

/// Response from saving DHCP range
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveDhcpRangeResponse {
    pub success: bool,
    pub message: String,
    pub range_id: Option<i64>,
}

/// Request to delete a DHCP range
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteDhcpRangeRequest {
    pub id: i64,
}

/// Response containing DHCP ranges
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpRangesResponse {
    pub ranges: Vec<DnsmasqDhcpRange>,
}

/// Request to save a static lease
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveStaticLeaseRequest {
    pub lease: DnsmasqStaticLease,
}

/// Response from saving static lease
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveStaticLeaseResponse {
    pub success: bool,
    pub message: String,
    pub lease_id: Option<i64>,
}

/// Request to delete a static lease
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteStaticLeaseRequest {
    pub id: i64,
}

/// Response containing static leases
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticLeasesResponse {
    pub leases: Vec<DnsmasqStaticLease>,
}

/// Request to save a DHCP option
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveDhcpOptionRequest {
    pub option: DnsmasqDhcpOption,
}

/// Response from saving DHCP option
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveDhcpOptionResponse {
    pub success: bool,
    pub message: String,
    pub option_id: Option<i64>,
}

/// Request to delete a DHCP option
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteDhcpOptionRequest {
    pub id: i64,
}

/// Response containing DHCP options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpOptionsResponse {
    pub options: Vec<DnsmasqDhcpOption>,
}

/// Request to save a host record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveHostRecordRequest {
    pub record: DnsmasqHostRecord,
}

/// Response from saving host record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveHostRecordResponse {
    pub success: bool,
    pub message: String,
    pub record_id: Option<i64>,
}

/// Request to delete a host record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteHostRecordRequest {
    pub id: i64,
}

/// Response containing host records
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostRecordsResponse {
    pub records: Vec<DnsmasqHostRecord>,
}

/// Request to save a CNAME record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveCnameRecordRequest {
    pub record: DnsmasqCnameRecord,
}

/// Response from saving CNAME record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveCnameRecordResponse {
    pub success: bool,
    pub message: String,
    pub record_id: Option<i64>,
}

/// Request to delete a CNAME record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteCnameRecordRequest {
    pub id: i64,
}

/// Response containing CNAME records
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnameRecordsResponse {
    pub records: Vec<DnsmasqCnameRecord>,
}

/// Request to save an address override
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveAddressOverrideRequest {
    pub override_entry: DnsmasqAddressOverride,
}

/// Response from saving address override
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveAddressOverrideResponse {
    pub success: bool,
    pub message: String,
    pub override_id: Option<i64>,
}

/// Request to delete an address override
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteAddressOverrideRequest {
    pub id: i64,
}

/// Response containing address overrides
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressOverridesResponse {
    pub overrides: Vec<DnsmasqAddressOverride>,
}

/// Response containing current active DHCP leases
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpLeasesResponse {
    pub leases: Vec<DhcpLease>,
}

/// Preview of generated dnsmasq config file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsmasqPreviewResponse {
    pub config_content: String,
}

/// Request to apply dnsmasq config
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsmasqApplyRequest {
    // Empty - applies current config from database
}

/// Response from applying dnsmasq config
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsmasqApplyResponse {
    pub success: bool,
    pub message: String,
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

    // IPv6 settings
    /// Accept IPv6 Router Advertisements
    pub ipv6_accept_ra: bool,
    /// IPv6 Accept RA client configuration (controls what to accept from RAs)
    #[serde(default)]
    pub ipv6_accept_ra_config: Option<Ipv6AcceptRaConfig>,
    /// Send IPv6 Router Advertisements on this link.
    #[serde(default)]
    pub ipv6_send_ra: bool,
    /// Assign and announce a subnet from an upstream delegated prefix.
    #[serde(default)]
    pub dhcp_prefix_delegation: Option<DhcpPrefixDelegationConfig>,

    // Forwarding & NAT (typically for router interfaces)
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
            ipv6_accept_ra: true,
            ipv6_accept_ra_config: None,
            ipv6_send_ra: false,
            dhcp_prefix_delegation: None,
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

    /// All assigned IPv4 addresses, including secondary addresses.
    #[serde(default)]
    pub ipv4_addresses: Vec<String>,

    /// All assigned IPv6 addresses, including link-local and delegated addresses.
    #[serde(default)]
    pub ipv6_addresses: Vec<String>,

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
    /// Whether this is an Internet-facing zone.
    #[serde(default)]
    pub is_wan: bool,
    /// Apply IPv4 source NAT to traffic leaving this zone.
    #[serde(default)]
    pub masquerade_ipv4: bool,
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
            is_wan: false,
            masquerade_ipv4: false,
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
    /// Restrict to an IPv4 address group (mutually exclusive with `source_ip`)
    #[serde(default)]
    pub source_group: Option<String>,
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
            source_group: None,
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
    /// Source address group (mutually exclusive with `source_ip`)
    #[serde(default)]
    pub source_group: Option<String>,
    /// Destination port group (mutually exclusive with `port_start`/`port_end`)
    #[serde(default)]
    pub dest_port_group: Option<String>,
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
            source_group: None,
            dest_port_group: None,
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
    /// Source address group (mutually exclusive with `source_ip`)
    #[serde(default)]
    pub source_group: Option<String>,
    /// Destination address group (mutually exclusive with `dest_ip`)
    #[serde(default)]
    pub dest_group: Option<String>,
    /// Destination port group (mutually exclusive with the destination port range)
    #[serde(default)]
    pub dest_port_group: Option<String>,
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
            source_group: None,
            dest_group: None,
            dest_port_group: None,
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
    #[serde(default)]
    pub address_groups: Vec<AddressGroup>,
    #[serde(default)]
    pub port_groups: Vec<PortGroup>,
    pub global_settings: FirewallGlobalSettings,
    /// Set while UPnP / NAT-PMP is enabled. Loaded from the UPnP configuration,
    /// not stored with the firewall rows, and kept out of API responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upnp_forward: Option<upnp::UpnpForwardAccept>,
}

/// A named set of IPv4/IPv6 addresses and CIDR networks (may mix families).
/// Rules reference it by name as a source or destination.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct AddressGroup {
    pub id: Option<i64>,
    /// Unique across address and port groups: `[a-z][a-z0-9_]{0,30}`
    pub name: String,
    pub description: Option<String>,
    /// One address or CIDR per entry, e.g. `10.0.0.0/8` or `fd00::1`
    pub entries: Vec<String>,
}

/// A named set of ports: single ports (`443`) or inclusive ranges (`8000-8100`).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct PortGroup {
    pub id: Option<i64>,
    /// Unique across address and port groups: `[a-z][a-z0-9_]{0,30}`
    pub name: String,
    pub description: Option<String>,
    /// One port or `start-end` range per entry
    pub entries: Vec<String>,
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
pub struct SaveAddressGroupRequest {
    pub group: AddressGroup,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveAddressGroupResponse {
    pub success: bool,
    pub message: String,
    pub group_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressGroupsResponse {
    pub groups: Vec<AddressGroup>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavePortGroupRequest {
    pub group: PortGroup,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavePortGroupResponse {
    pub success: bool,
    pub message: String,
    pub group_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortGroupsResponse {
    pub groups: Vec<PortGroup>,
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

/// A device discovered on a LAN interface, grouped by neighbour MAC address.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LanDevice {
    pub mac: String,
    pub hostname: Option<String>,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanDevicesResponse {
    pub devices: Vec<LanDevice>,
}

/// A device seen on the LAN, merged from the neighbour table, DHCP leases,
/// static reservations, firewall zones and simple port forwards.
/// One record per MAC address.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Client {
    /// Lowercase colon-separated MAC address.
    pub mac: String,
    /// Hostname from an active DHCP lease, else from the static reservation.
    pub hostname: Option<String>,
    /// Manufacturer from the IEEE OUI registry, or "Private (randomized)" for
    /// locally administered (randomized) MAC addresses.
    pub vendor: Option<String>,
    /// LAN interface the device was seen on (from the neighbour table).
    pub interface: Option<String>,
    /// Firewall zone containing `interface`, if any.
    pub zone: Option<String>,
    /// IPv4 addresses, including an enabled static reservation's address.
    pub ipv4: Vec<String>,
    /// IPv6 addresses, excluding link-local.
    pub ipv6: Vec<String>,
    /// True while the neighbour table lists the device as reachable or recently reachable.
    pub online: bool,
    /// Best neighbour-table state seen for the device (e.g. REACHABLE, STALE).
    pub neighbour_state: Option<String>,
    /// Unix time when the active DHCP lease expires. None when there is no
    /// lease or the lease is infinite.
    pub lease_expires_at: Option<u64>,
    /// ID of an enabled static reservation whose MAC matches exactly.
    pub static_lease_id: Option<i64>,
    /// Address reserved by `static_lease_id`.
    pub static_ip: Option<String>,
    /// Simple port forwards whose destination is one of this device's addresses.
    pub port_forward_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientsResponse {
    pub clients: Vec<Client>,
}

/// One logical WAN exposure. Both families may belong to the same forward.
/// The underlying firewall rule IDs remain the source of truth.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SimplePortForward {
    /// ID to use when editing or deleting this logical forward.
    pub rule_id: i64,
    pub ipv4_rule_id: Option<i64>,
    pub ipv6_rule_id: Option<i64>,
    pub name: String,
    pub description: Option<String>,
    pub protocol: RuleProtocol,
    pub external_port: u16,
    pub destination_port: u16,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub source_zone: Option<String>,
    pub source_ip: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimplePortForwardsResponse {
    pub forwards: Vec<SimplePortForward>,
    /// Port forwards (DNAT rows) not part of any simple forward, e.g. created
    /// through the CLI/API. Read-only in the simple editor.
    #[serde(default)]
    pub other_port_forwards: Vec<PortForward>,
}

/// Create or replace a logical dual-stack exposure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSimplePortForwardRequest {
    pub tcp: bool,
    pub udp: bool,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub port: u16,
    pub destination_port: Option<u16>,
    #[serde(default)]
    pub description: Option<String>,
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
    /// A networkd change is also awaiting this confirmation.
    #[serde(default)]
    pub networkd_pending: bool,
}

/// Request body for `POST /networkd/confirm`.
pub type NetworkdConfirmRequest = FirewallConfirmRequest;
/// Response for `POST /networkd/confirm`.
pub type NetworkdConfirmResponse = FirewallConfirmResponse;
/// Response for `POST /networkd/rollback`.
pub type NetworkdRollbackResponse = FirewallRollbackResponse;
/// Response for `GET /networkd/status`.
pub type NetworkdStatusResponse = FirewallStatusResponse;

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

/// Hit counters for one user-configured rule, summed over every nftables
/// rule generated from it (a rule over a mixed-family group yields one nftables
/// rule per family).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct FirewallRuleCounter {
    /// Which configuration list the rule belongs to: `input`, `forward`,
    /// `portfwd` (external DNAT), `portfwd-hairpin` (LAN DNAT) or
    /// `portfwd-accept` (forward-chain accept for a port forward).
    pub kind: String,
    /// Database ID of the rule (or port forward) the counter belongs to.
    pub rule_id: i64,
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

// ============================================================================
// Packet Tester Types
// ============================================================================

/// A packet to trace through the firewall. The trace is a simulation from the
/// configuration: connection state and kernel behaviour are not modelled
/// beyond what the response notes say.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TestPacketRequest {
    /// Interface the packet arrives on. Set exactly one of this and `ingress_zone`.
    #[serde(default)]
    pub ingress_interface: Option<String>,
    /// Zone the packet arrives in, on any of its interfaces.
    #[serde(default)]
    pub ingress_zone: Option<String>,
    pub source_ip: String,
    /// May be one of the router's own addresses, or a host behind it.
    pub destination_ip: String,
    /// `any`, `tcp`, `udp`, `icmp` or `icmpv6`. `tcp+udp` is not a packet protocol.
    pub protocol: RuleProtocol,
    #[serde(default)]
    pub source_port: Option<u16>,
    /// Required for `tcp` and `udp`, and not allowed otherwise.
    #[serde(default)]
    pub destination_port: Option<u16>,
    /// ICMP or ICMPv6 type. Defaults to echo request.
    #[serde(default)]
    pub icmp_type: Option<u8>,
    /// Interface a forwarded packet leaves through. Omit to use the live routing table.
    #[serde(default)]
    pub egress_interface: Option<String>,
}

/// Where in the pipeline a trace step happens.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceStage {
    Prerouting,
    Routing,
    Input,
    Forward,
    Postrouting,
}

/// Which rule a trace step is about.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TraceOrigin {
    /// A rule the user configured. `rule_kind` is `input`, `forward`,
    /// `portfwd`, `portfwd-accept`, `portfwd-hairpin` or `portfwd-hairpin-snat`.
    User {
        rule_kind: String,
        rule_id: Option<i64>,
    },
    /// Keystone's own rule, such as the ICMP safety drops.
    Builtin,
    /// A zone-level policy: zone-to-zone forwarding, or a zone default accept.
    Policy,
    /// The routing decision between the input and forward chains.
    Routing,
    /// A chain's default policy, applied when no rule matched.
    ChainPolicy,
}

/// One rule the packet was tested against, in evaluation order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceStep {
    pub stage: TraceStage,
    pub origin: TraceOrigin,
    /// The rule's name, or its built-in or policy description.
    pub label: String,
    pub matched: bool,
    /// True for the step that decided the packet's fate in its chain.
    pub decisive: bool,
    /// Short reason: the condition that failed, or what matched.
    pub reason: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TraceVerdict {
    Accept,
    Drop,
    Reject,
}

/// Destination rewrite applied by a port forward.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceDnat {
    pub address: String,
    /// `None` when the original port is kept.
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TestPacketResponse {
    /// `saved` when the configuration as edited was traced, `applied` when the
    /// last applied configuration was.
    pub baseline: String,
    /// Snapshot whose configuration was traced, for `applied`.
    pub applied_snapshot_id: Option<i64>,
    /// Interfaces the packet was treated as arriving on.
    pub ingress: Vec<String>,
    /// Interface a forwarded packet leaves through, if known.
    pub egress: Option<String>,
    /// Chain the packet reaches after routing.
    pub path: TraceStage,
    pub dnat: Option<TraceDnat>,
    /// Whether the packet's source is rewritten on the way out.
    pub masquerade: bool,
    pub steps: Vec<TraceStep>,
    pub verdict: TraceVerdict,
    /// What the simulation does not model, and other context for the verdict.
    pub notes: Vec<String>,
}

// ============================================================================
// Global Settings Types
// ============================================================================

/// Global application settings that affect system-wide behavior
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct GlobalSettings {
    /// When true, prevents applying any configuration changes to the router.
    /// Useful for preventing accidental changes in production.
    pub config_changes_disabled: bool,
    /// When true, indicates that initial setup is complete and system checks passed.
    /// Until this is true, the web UI will redirect all routes to /status.
    #[serde(default)]
    pub setup_complete: bool,
    /// Current wizard step (0-4). When >= 4, wizard is complete.
    #[serde(default)]
    pub wizard_step: u8,
}

/// Response containing global settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalSettingsResponse {
    pub settings: GlobalSettings,
}

/// Request to save global settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveGlobalSettingsRequest {
    pub settings: GlobalSettings,
}

/// Response from saving global settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveGlobalSettingsResponse {
    pub success: bool,
    pub message: String,
}

// ============================================================================
// System Status Check Types
// ============================================================================

/// Severity level for a system status check
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CheckSeverity {
    /// Check passed
    Pass,
    /// Warning - system may work but with limitations
    Warning,
    /// Error - system will not function correctly
    Error,
}

impl std::fmt::Display for CheckSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckSeverity::Pass => write!(f, "pass"),
            CheckSeverity::Warning => write!(f, "warning"),
            CheckSeverity::Error => write!(f, "error"),
        }
    }
}

/// Category of system check
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckCategory {
    /// Required package installation
    Package,
    /// Service status
    Service,
    /// File/directory permissions
    Permission,
    /// Network interfaces
    Network,
    /// System configuration
    Configuration,
}

impl std::fmt::Display for CheckCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckCategory::Package => write!(f, "Package"),
            CheckCategory::Service => write!(f, "Service"),
            CheckCategory::Permission => write!(f, "Permission"),
            CheckCategory::Network => write!(f, "Network"),
            CheckCategory::Configuration => write!(f, "Configuration"),
        }
    }
}

/// A single system status check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemCheck {
    /// Unique identifier for this check
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Category of this check
    pub category: CheckCategory,
    /// Severity level (pass, warning, error)
    pub severity: CheckSeverity,
    /// Detailed message explaining the check result
    pub message: String,
    /// Advice on how to fix the issue (if not passing)
    pub fix_advice: Option<String>,
}

/// Complete system status response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatusResponse {
    /// Whether all required checks pass (no errors)
    pub all_checks_pass: bool,
    /// Whether setup is already complete
    pub setup_complete: bool,
    /// Total count of errors
    pub error_count: u32,
    /// Total count of warnings
    pub warning_count: u32,
    /// All individual check results
    pub checks: Vec<SystemCheck>,
}

/// Request to complete setup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompleteSetupRequest {
    // Empty - just marks setup as complete
}

/// Response from completing setup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompleteSetupResponse {
    pub success: bool,
    pub message: String,
}

// ============================================================================
// System State Types
// ============================================================================

/// Complete system state representing the router configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SystemState {
    /// All configured network interfaces
    pub interfaces: Vec<Interface>,
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

/// One daemon-collected interface transfer-rate sample.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrafficSample {
    pub timestamp_ms: u64,
    pub rx_bytes_per_sec: u64,
    pub tx_bytes_per_sec: u64,
}

/// One interface's rolling 60-second traffic history.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterfaceTraffic {
    pub name: String,
    /// Set in dashboard responses using Keystone's configured interface role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<InterfaceRole>,
    pub samples: Vec<TrafficSample>,
}

/// Address family of a WAN default gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayFamily {
    Ipv4,
    Ipv6,
}

/// One daemon-collected ICMP sample. None means a timeout or probe error.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GatewaySample {
    pub timestamp_ms: u64,
    pub latency_ms: Option<f64>,
}

/// Rolling statistics for one active or recently disappeared WAN gateway.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GatewayStatus {
    pub interface: String,
    pub family: GatewayFamily,
    pub gateway: String,
    pub active_route: bool,
    pub latest_latency_ms: Option<f64>,
    pub average_latency_ms: Option<f64>,
    pub packet_loss_percent: f64,
    pub history: Vec<GatewaySample>,
}

/// Result of asking networkd to renew an interface's dynamic configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewInterfaceResponse {
    pub success: bool,
    pub message: String,
}

/// Dashboard payload (polled by the web UI).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DashboardResponse {
    pub state: SystemState,
    pub interface_counters: Vec<InterfaceCounters>,
    #[serde(default)]
    pub traffic: Vec<InterfaceTraffic>,
    #[serde(default)]
    pub gateways: Vec<GatewayStatus>,
    pub timestamp_ms: u64,
}

/// Response from applying configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyConfigResponse {
    pub success: bool,
    pub message: String,
    pub errors: Vec<String>,
    /// The change was applied but will be rolled back unless confirmed.
    #[serde(default)]
    pub pending_confirmation: bool,
    /// Unix timestamp - confirm before this time or the change is rolled back.
    #[serde(default)]
    pub confirm_deadline: Option<u64>,
    /// Session ID to pass to `POST /networkd/confirm` (or `/firewall/confirm`).
    #[serde(default)]
    pub session_id: Option<String>,
}

// ============================================================================
// Unified Apply Types
// ============================================================================

/// Result of applying all configuration via /apply-all
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyAllResponse {
    /// Overall success status
    pub success: bool,
    /// Summary message
    pub message: String,
    /// Individual component results
    pub components: ApplyComponentResults,
    /// If the apply requires confirmation. The `firewall_*` fields describe the
    /// shared confirmation session: one `/firewall/confirm` confirms both the
    /// firewall and any pending networkd change. If only networkd is pending,
    /// they carry the networkd session.
    pub firewall_pending_confirmation: bool,
    /// Confirmation deadline (unix timestamp)
    pub firewall_confirm_deadline: Option<u64>,
    /// Session ID for confirmation
    pub firewall_session_id: Option<String>,
    /// A networkd change is part of the pending confirmation.
    #[serde(default)]
    pub networkd_pending_confirmation: bool,
}

/// Results for each component in a unified apply
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApplyComponentResults {
    pub networkd: ComponentResult,
    pub firewall: ComponentResult,
    #[serde(default)]
    pub sqm: ComponentResult,
    #[serde(default)]
    pub upnp: ComponentResult,
    pub dnsmasq: ComponentResult,
    pub caddy: ComponentResult,
}

/// Result for a single component
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComponentResult {
    pub success: bool,
    pub message: String,
    pub skipped: bool,
}

/// The numeric IP addresses currently assigned to enabled LAN interfaces.
/// The web service must bind only these addresses (plus loopback).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanBindAddressesResponse {
    pub addresses: Vec<String>,
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
    pub sub: String,  // Subject (username)
    pub exp: u64,     // Expiration time (Unix timestamp)
    pub uid: i64,     // Immutable database user ID
    pub version: i64, // Invalidated on account modification
}

/// User account
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub email: Option<String>,
    pub password_hash: String,
    pub created_at: i64,
    pub auth_version: i64,
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

// ============================================================================
// Caddy Configuration Types
// ============================================================================

/// HTTPS mode for Caddy configuration
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CaddyHttpsMode {
    /// HTTPS disabled - serve over plain HTTP only
    #[default]
    Disabled,
    /// Use Caddy's internal self-signed certificate
    SelfSigned,
    /// Use custom ACME configuration (e.g., DNS challenge with Cloudflare, etc.)
    AcmeCustom,
}

impl std::fmt::Display for CaddyHttpsMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaddyHttpsMode::Disabled => write!(f, "disabled"),
            CaddyHttpsMode::SelfSigned => write!(f, "self_signed"),
            CaddyHttpsMode::AcmeCustom => write!(f, "acme_custom"),
        }
    }
}

impl std::str::FromStr for CaddyHttpsMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().replace('-', "_").as_str() {
            "disabled" | "off" | "no" => Ok(CaddyHttpsMode::Disabled),
            "self_signed" | "selfsigned" | "internal" => Ok(CaddyHttpsMode::SelfSigned),
            "acme_custom" | "acmecustom" | "custom" => Ok(CaddyHttpsMode::AcmeCustom),
            _ => Err(format!("Unknown HTTPS mode: {}", s)),
        }
    }
}

/// Caddy reverse proxy configuration for serving Keystone web UI
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CaddyConfig {
    /// Whether Caddy is enabled
    pub enabled: bool,
    /// Domain name or IP address for the server block
    /// Examples: "router.lan", "192.168.1.1", "keystone.home.arpa"
    pub server_address: String,
    /// LAN interface to bind to (Caddy will only listen on this interface's IP)
    /// Examples: "eth1", "br-lan", "enp3s0"
    pub bind_interface: String,
    /// HTTPS mode
    pub https_mode: CaddyHttpsMode,
    /// Custom TLS/ACME configuration block (raw Caddyfile directives)
    /// This is inserted into the site block for custom certificate handling.
    ///
    /// Example for Cloudflare DNS challenge:
    /// ```text
    /// tls {
    ///     dns cloudflare {env.CF_API_TOKEN}
    /// }
    /// ```
    ///
    /// Example for custom certificate files:
    /// ```text
    /// tls /path/to/cert.pem /path/to/key.pem
    /// ```
    pub custom_tls_config: String,
    /// Port for HTTPS (default 443)
    pub https_port: u16,
    /// Port for HTTP (default 80, used for redirect when HTTPS is enabled)
    pub http_port: u16,
    /// Last validation status from `caddy validate`
    pub last_validation_status: Option<String>,
    /// Unix timestamp of last validation
    pub last_validation_time: Option<i64>,
}

impl Default for CaddyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server_address: String::new(),
            bind_interface: String::new(),
            https_mode: CaddyHttpsMode::Disabled,
            custom_tls_config: String::new(),
            https_port: 443,
            http_port: 80,
            last_validation_status: None,
            last_validation_time: None,
        }
    }
}

// ============================================================================
// Caddy API Request/Response Types
// ============================================================================

/// Complete Caddy state for UI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaddyStateResponse {
    pub config: CaddyConfig,
    /// Available interfaces for binding (from system)
    pub available_interfaces: Vec<String>,
}

/// Request to save Caddy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveCaddyConfigRequest {
    pub config: CaddyConfig,
}

/// Response from saving Caddy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveCaddyConfigResponse {
    pub success: bool,
    pub message: String,
}

/// Preview of generated Caddyfile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaddyPreviewResponse {
    pub caddyfile: String,
}

/// Request to validate Caddyfile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaddyValidateRequest {
    // Empty - validates current config from database
}

/// Response from validating Caddyfile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaddyValidateResponse {
    pub valid: bool,
    pub message: String,
    /// Full output from caddy validate command
    pub output: String,
}

/// Request to apply Caddy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaddyApplyRequest {
    // Empty - applies current config from database
}

/// Response from applying Caddy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaddyApplyResponse {
    pub success: bool,
    pub message: String,
}

// ============================================================================
// Systemd Service Types
// ============================================================================

/// Active state of a systemd unit
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "lowercase")]
pub enum SystemdActiveState {
    /// Unit is active and running
    Active,
    /// Unit is being started
    Activating,
    /// Unit is being stopped
    Deactivating,
    /// Unit is not running
    #[default]
    Inactive,
    /// Unit failed to start
    Failed,
    /// Unit is being reloaded
    Reloading,
}

impl std::fmt::Display for SystemdActiveState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SystemdActiveState::Active => write!(f, "active"),
            SystemdActiveState::Activating => write!(f, "activating"),
            SystemdActiveState::Deactivating => write!(f, "deactivating"),
            SystemdActiveState::Inactive => write!(f, "inactive"),
            SystemdActiveState::Failed => write!(f, "failed"),
            SystemdActiveState::Reloading => write!(f, "reloading"),
        }
    }
}

impl std::str::FromStr for SystemdActiveState {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "active" => Ok(SystemdActiveState::Active),
            "activating" => Ok(SystemdActiveState::Activating),
            "deactivating" => Ok(SystemdActiveState::Deactivating),
            "inactive" => Ok(SystemdActiveState::Inactive),
            "failed" => Ok(SystemdActiveState::Failed),
            "reloading" => Ok(SystemdActiveState::Reloading),
            _ => Err(format!("Unknown active state: {}", s)),
        }
    }
}

/// Load state of a systemd unit
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum SystemdLoadState {
    /// Unit file is loaded
    #[default]
    Loaded,
    /// Unit file could not be found
    NotFound,
    /// Unit file has errors
    Error,
    /// Unit is masked (disabled permanently)
    Masked,
}

impl std::fmt::Display for SystemdLoadState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SystemdLoadState::Loaded => write!(f, "loaded"),
            SystemdLoadState::NotFound => write!(f, "not-found"),
            SystemdLoadState::Error => write!(f, "error"),
            SystemdLoadState::Masked => write!(f, "masked"),
        }
    }
}

impl std::str::FromStr for SystemdLoadState {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().replace('-', "").as_str() {
            "loaded" => Ok(SystemdLoadState::Loaded),
            "notfound" => Ok(SystemdLoadState::NotFound),
            "error" => Ok(SystemdLoadState::Error),
            "masked" => Ok(SystemdLoadState::Masked),
            _ => Err(format!("Unknown load state: {}", s)),
        }
    }
}

/// Settings for Keystone's SSH listener. These do not govern administrator-owned
/// OpenSSH configuration outside Keystone's own drop-in.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SshConfig {
    pub enabled: bool,
    pub port: u16,
    pub ipv4: bool,
    pub ipv6: bool,
    /// Explicitly extend the listener to WAN interfaces; off by default.
    pub wan_access: bool,
    pub password_authentication: bool,
    pub public_key_authentication: bool,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: 22,
            ipv4: true,
            ipv6: true,
            wan_access: false,
            // Do not lock an existing system out of SSH on first adoption.
            password_authentication: true,
            public_key_authentication: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshStateResponse {
    pub config: SshConfig,
    pub managed: bool,
    pub running: bool,
    pub interface_addresses: Vec<String>,
    pub listening_addresses: Vec<String>,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshApplyResponse {
    pub success: bool,
    pub message: String,
    /// Firewall changes require confirmation before the rollback deadline.
    pub firewall_session_id: Option<String>,
}

/// A systemd unit summary for listing
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SystemdUnit {
    /// Unit name (e.g., "keystone-daemon.service")
    pub name: String,
    /// Description from unit file
    pub description: String,
    /// Load state (loaded, not-found, masked, etc.)
    pub load_state: SystemdLoadState,
    /// Active state (active, inactive, failed, etc.)
    pub active_state: SystemdActiveState,
    /// Sub state (running, dead, exited, etc.)
    pub sub_state: String,
    /// Whether the unit is enabled (starts on boot)
    pub enabled: bool,
}

impl Default for SystemdUnit {
    fn default() -> Self {
        Self {
            name: String::new(),
            description: String::new(),
            load_state: SystemdLoadState::default(),
            active_state: SystemdActiveState::default(),
            sub_state: "dead".to_string(),
            enabled: false,
        }
    }
}

/// Detailed status of a systemd unit
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SystemdUnitDetail {
    /// Basic unit info
    pub unit: SystemdUnit,
    /// Main process PID (if running)
    pub main_pid: Option<u32>,
    /// Memory usage in bytes (if available)
    pub memory_bytes: Option<u64>,
    /// When the unit was activated (Unix timestamp)
    pub active_enter_timestamp: Option<u64>,
    /// When the unit was deactivated (Unix timestamp)
    pub inactive_enter_timestamp: Option<u64>,
    /// Result of last run (success, exit-code, signal, etc.)
    pub result: Option<String>,
    /// Recent log lines from journald
    pub recent_logs: Vec<String>,
}

// ============================================================================
// Systemd API Request/Response Types
// ============================================================================

/// Response containing list of systemd units
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemdUnitsResponse {
    pub units: Vec<SystemdUnit>,
}

/// Response containing detailed unit info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemdUnitDetailResponse {
    pub unit: Option<SystemdUnitDetail>,
}

/// Request to control a systemd unit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemdUnitControlRequest {
    /// The unit name (e.g., "keystone-daemon.service")
    pub unit_name: String,
}

/// Response from unit control operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemdUnitControlResponse {
    pub success: bool,
    pub message: String,
}

// ============================================================================
// Setup Wizard Types
// ============================================================================

/// Wizard step identifier
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(u8)]
pub enum WizardStep {
    /// Wizard not started - show welcome screen
    #[default]
    NotStarted = 0,
    /// User has changed the default password
    PasswordChanged = 1,
    /// System checks have passed
    SystemChecksCompleted = 2,
    /// Interfaces have been assigned to zones (WAN/LAN)
    InterfacesAssigned = 3,
    /// Wizard is complete
    Complete = 4,
}

impl WizardStep {
    /// Get the step number (0-4)
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Create from a step number
    pub fn from_u8(n: u8) -> Self {
        match n {
            0 => WizardStep::NotStarted,
            1 => WizardStep::PasswordChanged,
            2 => WizardStep::SystemChecksCompleted,
            3 => WizardStep::InterfacesAssigned,
            _ => WizardStep::Complete,
        }
    }

    /// Get the next step
    pub fn next(&self) -> Self {
        WizardStep::from_u8(self.as_u8().saturating_add(1))
    }

    /// Check if the wizard is complete
    pub fn is_complete(&self) -> bool {
        *self == WizardStep::Complete
    }

    /// Get human-readable step name
    pub fn name(&self) -> &'static str {
        match self {
            WizardStep::NotStarted => "Welcome",
            WizardStep::PasswordChanged => "Change Password",
            WizardStep::SystemChecksCompleted => "System Checks",
            WizardStep::InterfacesAssigned => "Configure Interfaces",
            WizardStep::Complete => "Complete",
        }
    }
}

impl std::fmt::Display for WizardStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Current wizard state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WizardState {
    /// Current step in the wizard
    pub current_step: WizardStep,
    /// Whether the wizard is complete
    pub is_complete: bool,
    /// Total number of steps
    pub total_steps: u8,
    /// System status (from checks)
    pub system_status: Option<SystemStatusResponse>,
}

impl Default for WizardState {
    fn default() -> Self {
        Self {
            current_step: WizardStep::NotStarted,
            is_complete: false,
            total_steps: WizardStep::Complete.as_u8(),
            system_status: None,
        }
    }
}

/// Response containing wizard state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WizardStateResponse {
    pub state: WizardState,
}

/// Request to advance wizard to next step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WizardAdvanceRequest {
    /// The step we're completing (for validation)
    pub completing_step: WizardStep,
}

/// Response from advancing wizard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WizardAdvanceResponse {
    pub success: bool,
    pub message: String,
    /// The new current step
    pub new_step: WizardStep,
}

/// Request to skip wizard (for advanced users)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WizardSkipRequest {
    /// Confirmation that user understands the risks
    pub confirm_skip: bool,
}

/// Response from skipping wizard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WizardSkipResponse {
    pub success: bool,
    pub message: String,
}

/// Interface assignment for wizard step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WizardInterfaceAssignment {
    /// Interface name
    pub name: String,
    /// Assigned role (WAN or LAN)
    pub role: InterfaceRole,
    /// Whether to use DHCP (for WAN interfaces)
    pub use_dhcp: bool,
    /// Static IP if not using DHCP (CIDR notation)
    pub static_ip: Option<String>,
}

/// Request to save interface assignments in wizard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WizardSaveInterfacesRequest {
    pub assignments: Vec<WizardInterfaceAssignment>,
}

/// Response from saving interface assignments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WizardSaveInterfacesResponse {
    pub success: bool,
    pub message: String,
    /// Result of activating the generated router profile.
    pub apply_result: Option<ApplyAllResponse>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_serialization() {
        let iface = Interface {
            ipv4_addresses: vec!["192.168.1.1/24".to_string()],
            ipv6_addresses: vec!["2407:8b00:1168:3200::1/64".to_string()],
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
            is_wan: false,
            masquerade_ipv4: false,
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
            source_group: None,
            dest_ip: "192.168.1.100".to_string(),
            dest_port: Some(80),
        };

        let json = serde_json::to_string(&pf).unwrap();
        let deserialized: PortForward = serde_json::from_str(&json).unwrap();

        assert_eq!(pf, deserialized);
    }

    #[test]
    fn test_firewall_action_parsing() {
        assert_eq!(
            "accept".parse::<FirewallAction>().unwrap(),
            FirewallAction::Accept
        );
        assert_eq!(
            "drop".parse::<FirewallAction>().unwrap(),
            FirewallAction::Drop
        );
        assert_eq!(
            "reject".parse::<FirewallAction>().unwrap(),
            FirewallAction::Reject
        );
        assert_eq!(FirewallAction::Accept.to_string(), "accept");
    }

    #[test]
    fn test_rule_protocol_parsing() {
        assert_eq!("tcp".parse::<RuleProtocol>().unwrap(), RuleProtocol::Tcp);
        assert_eq!("udp".parse::<RuleProtocol>().unwrap(), RuleProtocol::Udp);
        assert_eq!(
            "tcp+udp".parse::<RuleProtocol>().unwrap(),
            RuleProtocol::TcpUdp
        );
        assert_eq!("icmp".parse::<RuleProtocol>().unwrap(), RuleProtocol::Icmp);
        assert_eq!(
            "icmpv6".parse::<RuleProtocol>().unwrap(),
            RuleProtocol::Icmpv6
        );
        assert_eq!("any".parse::<RuleProtocol>().unwrap(), RuleProtocol::Any);
        assert_eq!(RuleProtocol::TcpUdp.to_string(), "tcp+udp");
    }

    #[test]
    fn test_firewall_policy_parsing() {
        assert_eq!(
            "accept".parse::<FirewallPolicy>().unwrap(),
            FirewallPolicy::Accept
        );
        assert_eq!(
            "drop".parse::<FirewallPolicy>().unwrap(),
            FirewallPolicy::Drop
        );
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
            gateways: vec![],
            traffic: vec![InterfaceTraffic {
                name: "eth0".into(),
                role: Some(InterfaceRole::WAN),
                samples: vec![TrafficSample {
                    timestamp_ms: 100,
                    rx_bytes_per_sec: 20,
                    tx_bytes_per_sec: 40,
                }],
            }],
            timestamp_ms: 123,
        };

        let json = serde_json::to_string(&dashboard).unwrap();
        let deserialized: DashboardResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(dashboard.timestamp_ms, deserialized.timestamp_ms);
        assert_eq!(dashboard.traffic, deserialized.traffic);
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
                client_identifier: None,
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
                use_delegated_prefix: true,
                prefix_delegation_hint: Some("::1/64".to_string()),
                rapid_commit: true,
                without_ra: "no".to_string(),
            }),
            ipv6_accept_ra: true,
            ipv6_accept_ra_config: None,
            ipv6_send_ra: false,
            dhcp_prefix_delegation: None,
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
        assert_eq!(
            "no".parse::<IpMasqueradeMode>().unwrap(),
            IpMasqueradeMode::No
        );
        assert_eq!(
            "both".parse::<IpMasqueradeMode>().unwrap(),
            IpMasqueradeMode::Both
        );
        assert_eq!(
            "ipv4".parse::<IpMasqueradeMode>().unwrap(),
            IpMasqueradeMode::Ipv4
        );
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
        assert_eq!(
            "802.1q".parse::<VlanProtocol>().unwrap(),
            VlanProtocol::Dot1Q
        );
        assert_eq!(
            "802.1ad".parse::<VlanProtocol>().unwrap(),
            VlanProtocol::Dot1Ad
        );
        assert_eq!(
            "qinq".parse::<VlanProtocol>().unwrap(),
            VlanProtocol::Dot1Ad
        );
        assert_eq!(VlanProtocol::Dot1Q.to_string(), "802.1q");
        assert_eq!(VlanProtocol::Dot1Ad.to_string(), "802.1ad");
    }

    #[test]
    fn test_dnsmasq_config_serialization() {
        let config = DnsmasqConfig {
            enabled: true,
            dns_port: 53,
            cache_size: 1000,
            dnssec_enabled: false,
            domain_needed: true,
            bogus_priv: true,
            local_domain: Some("lan".to_string()),
            expand_hosts: true,
            upstream_mode: DnsmasqUpstreamMode::LocalAdGuard,
            upstream_servers: vec![DnsmasqUpstreamServer {
                address: "127.0.0.1".to_string(),
                port: Some(5353),
                domain: None,
            }],
            listen_interfaces: vec!["br-lan".to_string()],
            except_interfaces: vec!["eth0".to_string()],
            no_dhcp_interfaces: vec![],
            bind_dynamic: true,
            log_queries: false,
            log_dhcp: true,
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: DnsmasqConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config, deserialized);
    }

    #[test]
    fn test_dnsmasq_dhcp_range_serialization() {
        let range = DnsmasqDhcpRange {
            id: Some(1),
            name: "LAN Pool".to_string(),
            interface: "br-lan".to_string(),
            start_address: "192.168.1.100".to_string(),
            end_address: "192.168.1.200".to_string(),
            netmask: Some("255.255.255.0".to_string()),
            lease_time: "24h".to_string(),
            enabled: true,
            ipv6_mode: Some(DnsmasqIpv6Mode::RaStateless),
            ipv6_prefix: Some("2001:db8::/64".to_string()),
        };

        let json = serde_json::to_string(&range).unwrap();
        let deserialized: DnsmasqDhcpRange = serde_json::from_str(&json).unwrap();

        assert_eq!(range, deserialized);
    }

    #[test]
    fn test_dnsmasq_static_lease_serialization() {
        let lease = DnsmasqStaticLease {
            id: Some(1),
            mac_address: "00:11:22:33:44:55".to_string(),
            ip_address: "192.168.1.10".to_string(),
            hostname: Some("server1".to_string()),
            lease_time: Some("infinite".to_string()),
            client_id: None,
            set_tags: vec!["servers".to_string()],
            enabled: true,
        };

        let json = serde_json::to_string(&lease).unwrap();
        let deserialized: DnsmasqStaticLease = serde_json::from_str(&json).unwrap();

        assert_eq!(lease, deserialized);
    }

    #[test]
    fn test_dnsmasq_upstream_mode_parsing() {
        assert_eq!(
            "system".parse::<DnsmasqUpstreamMode>().unwrap(),
            DnsmasqUpstreamMode::System
        );
        assert_eq!(
            "custom".parse::<DnsmasqUpstreamMode>().unwrap(),
            DnsmasqUpstreamMode::Custom
        );
        assert_eq!(
            "localadguard".parse::<DnsmasqUpstreamMode>().unwrap(),
            DnsmasqUpstreamMode::LocalAdGuard
        );
        assert_eq!(
            DnsmasqUpstreamMode::LocalAdGuard.to_string(),
            "localadguard"
        );
    }

    #[test]
    fn test_dnsmasq_ipv6_mode_parsing() {
        assert_eq!(
            "ra-only".parse::<DnsmasqIpv6Mode>().unwrap(),
            DnsmasqIpv6Mode::RaOnly
        );
        assert_eq!(
            "ra-stateless".parse::<DnsmasqIpv6Mode>().unwrap(),
            DnsmasqIpv6Mode::RaStateless
        );
        assert_eq!(
            "slaac".parse::<DnsmasqIpv6Mode>().unwrap(),
            DnsmasqIpv6Mode::Slaac
        );
        assert_eq!(
            "dhcpv6".parse::<DnsmasqIpv6Mode>().unwrap(),
            DnsmasqIpv6Mode::Dhcpv6
        );
        assert_eq!(DnsmasqIpv6Mode::RaStateless.to_string(), "ra-stateless");
    }

    #[test]
    fn test_dnsmasq_address_action_parsing() {
        assert_eq!(
            "block".parse::<DnsmasqAddressAction>().unwrap(),
            DnsmasqAddressAction::Block
        );
        assert_eq!(
            "redirect".parse::<DnsmasqAddressAction>().unwrap(),
            DnsmasqAddressAction::Redirect
        );
        assert_eq!(
            "null".parse::<DnsmasqAddressAction>().unwrap(),
            DnsmasqAddressAction::Null
        );
        assert_eq!(DnsmasqAddressAction::Block.to_string(), "block");
    }

    #[test]
    fn test_caddy_config_serialization() {
        let config = CaddyConfig {
            enabled: true,
            server_address: "router.lan".to_string(),
            bind_interface: "br-lan".to_string(),
            https_mode: CaddyHttpsMode::AcmeCustom,
            custom_tls_config: "tls {\n    dns cloudflare {env.CF_API_TOKEN}\n}".to_string(),
            https_port: 443,
            http_port: 80,
            last_validation_status: Some("Valid configuration".to_string()),
            last_validation_time: Some(1234567890),
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: CaddyConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config, deserialized);
    }

    #[test]
    fn test_caddy_https_mode_parsing() {
        assert_eq!(
            "disabled".parse::<CaddyHttpsMode>().unwrap(),
            CaddyHttpsMode::Disabled
        );
        assert_eq!(
            "self_signed".parse::<CaddyHttpsMode>().unwrap(),
            CaddyHttpsMode::SelfSigned
        );
        assert_eq!(
            "acme_custom".parse::<CaddyHttpsMode>().unwrap(),
            CaddyHttpsMode::AcmeCustom
        );
        assert_eq!(
            "internal".parse::<CaddyHttpsMode>().unwrap(),
            CaddyHttpsMode::SelfSigned
        );
        assert_eq!(CaddyHttpsMode::SelfSigned.to_string(), "self_signed");
    }
}
