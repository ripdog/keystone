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
//! - `caddy` - Caddy reverse proxy configuration
//! - `services` - Systemd service management
//!
//! All functions use the shared `client` module for HTTP requests,
//! which provides centralized error handling and authentication.

pub mod auth;
pub mod bridges;
pub mod caddy;
pub mod client;
pub mod dashboard;
pub mod dnsmasq;
pub mod firewall;
pub mod interfaces;
pub mod services;
pub mod settings;
pub mod users;
pub mod vlans;
pub mod wizard;

// Client module provides the HTTP request helpers used by submodules

// Re-export all public functions from submodules for backward compatibility
pub use auth::*;
pub use bridges::*;
pub use caddy::*;
pub use dashboard::*;
pub use dnsmasq::*;
pub use firewall::*;
pub use interfaces::*;
pub use services::*;
pub use settings::*;
pub use users::*;
pub use vlans::*;
pub use wizard::*;
