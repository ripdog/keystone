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

/// A static IP address configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StaticAddress {
    /// IP address with CIDR prefix (e.g., "192.168.1.1/24")
    pub address: String,
    /// Optional label for the address (max 15 chars)
    pub label: Option<String>,
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
    
    // DHCP client settings
    /// DHCPv4 client configuration (only used when dhcp_mode includes IPv4)
    pub dhcpv4_client: Option<Dhcpv4ClientConfig>,
    
    // IPv6 settings
    /// Accept IPv6 Router Advertisements
    pub ipv6_accept_ra: bool,
    
    // Forwarding & NAT (typically for WAN interfaces)
    /// IP forwarding mode
    pub ip_forward: IpForwardMode,
    /// IP masquerading (NAT) mode
    pub ip_masquerade: IpMasqueradeMode,
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
            dhcpv4_client: None,
            ipv6_accept_ra: true,
            ip_forward: IpForwardMode::No,
            ip_masquerade: IpMasqueradeMode::No,
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
            }],
            routes: vec![StaticRoute {
                destination: None,
                gateway: "192.168.1.254".to_string(),
                metric: Some(100),
            }],
            dns_servers: vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()],
            search_domains: vec!["example.com".to_string()],
            gateway: Some("192.168.1.254".to_string()),
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
            ipv6_accept_ra: true,
            ip_forward: IpForwardMode::Yes,
            ip_masquerade: IpMasqueradeMode::Ipv4,
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
