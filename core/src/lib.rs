/// Keystone Core Library
/// 
/// This crate contains shared type definitions used by both the daemon and web-ui.
/// All types must be serializable to ensure strict type safety across the system boundary.

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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl Default for SystemState {
    fn default() -> Self {
        Self {
            interfaces: Vec::new(),
            firewall_rules: Vec::new(),
            ip_forwarding_enabled: false,
            nat_enabled: false,
        }
    }
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
}
