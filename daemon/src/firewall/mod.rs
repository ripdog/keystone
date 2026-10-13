//! Firewall module for nftables ruleset generation and management
//!
//! This module provides functionality for:
//! - Generating nftables JSON rulesets from Keystone's firewall configuration
//! - Previewing rulesets in human-readable format
//! - Applying rulesets atomically with rollback support
//!
//! # Architecture
//!
//! The firewall uses a zone-based model similar to pfSense/OpenWrt:
//! - Zones group interfaces with common policies
//! - Zone-to-zone forwarding policies control traffic flow
//! - Input rules control access to the router itself
//! - Forward rules control traffic passing through the router
//! - Port forwards (DNAT) redirect incoming connections
//!
//! # Tables
//!
//! Two dedicated tables are used (family: inet for dual-stack IPv4/IPv6):
//! - `keystone` - Filter rules (input/forward/output chains)
//! - `keystone_nat` - NAT rules (prerouting/postrouting chains)

mod apply;
pub(crate) mod generate;
pub mod routes;
pub mod simple;
pub mod validate;

pub use apply::*;
