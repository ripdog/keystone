//! API client functions for communicating with the Keystone daemon
//!
//! This module is organized into submodules by domain:
//! - `auth` - Authentication (login)
//! - `dashboard` - Dashboard data
//! - `users` - User management
//! - `interfaces` - Managed interfaces and interface configuration
//! - `vlans` - VLAN configuration
//! - `bridges` - Bridge configuration
//! - `firewall` - Firewall zones, rules, and settings
//! - `dnsmasq` - DNS/DHCP configuration
//! - `blocky` - DNS filtering (ad-blocking and encrypted upstream DNS)
//! - `clients` - Unified LAN client inventory
//! - `caddy` - Caddy reverse proxy configuration
//! - `changes` - Pending changes, apply-all and configuration snapshots
//! - `sqm` - Traffic shaping (SQM / CAKE)
//! - `upnp` - UPnP IGD and NAT-PMP / PCP port mapping
//! - `services` - Systemd service management
//!
//! All functions use the shared `client` module for HTTP requests,
//! which provides centralized error handling and authentication.

pub mod auth;
pub mod blocky;
pub mod bridges;
pub mod caddy;
pub mod changes;
pub mod client;
pub mod clients;
pub mod dashboard;
pub mod dnsmasq;
pub mod firewall;
pub mod interfaces;
pub mod logs;
pub mod services;
pub mod settings;
pub mod sqm;
pub mod ssh;
pub mod system;
pub mod upnp;
pub mod users;
pub mod vlans;
pub mod wizard;

// Client module provides the HTTP request helpers used by submodules

// Re-export all public functions from submodules for backward compatibility
pub use auth::*;
pub use blocky::*;
pub use bridges::*;
pub use caddy::*;
pub use changes::*;
pub use clients::*;
pub use dashboard::*;
pub use dnsmasq::*;
pub use firewall::*;
pub use interfaces::*;
pub use logs::*;
pub use services::*;
pub use settings::*;
pub use sqm::*;
pub use ssh::*;
pub use system::*;
pub use upnp::*;
pub use users::*;
pub use vlans::*;
pub use wizard::*;
