//! Keystone Core Library
//!
//! This crate contains shared type definitions used by both the daemon and web-ui.
//! All types must be serializable to ensure strict type safety across the system boundary.

use serde::{Deserialize, Serialize};
use thiserror::Error;

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

/// Login request containing password
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
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
}
