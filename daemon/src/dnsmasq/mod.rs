//! Dnsmasq module for DNS/DHCP server configuration and management
//!
//! This module provides functionality for:
//! - Managing dnsmasq configuration stored in the database
//! - Generating dnsmasq configuration files
//! - Applying configuration and managing the dnsmasq service
//! - Parsing active DHCP leases from the lease file
//!
//! # Architecture
//!
//! Dnsmasq replaces the old systemd-networkd DHCP server functionality:
//! - Global DNS settings (cache, upstream servers, local domain)
//! - Per-interface DHCP ranges with IPv4 and IPv6 support
//! - Static leases (MAC-to-IP reservations)
//! - Custom DHCP options
//! - DNS host records and CNAMEs
//! - Address overrides for blocking/redirecting domains

mod apply;
mod config;
mod db;
mod leases;
pub mod routes;

pub use apply::*;
pub use config::DNSMASQ_CONFIG_PATH;
pub use db::*;
pub use leases::*;
