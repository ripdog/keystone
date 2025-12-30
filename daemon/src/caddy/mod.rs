//! Caddy module for reverse proxy configuration and management
//!
//! This module provides functionality for:
//! - Managing Caddy configuration stored in the database
//! - Generating Caddyfile configuration
//! - Validating and applying configuration to the Caddy service
//!
//! # Architecture
//!
//! Caddy serves the Keystone web UI over HTTPS on the LAN interface.
//! Configuration supports:
//! - Self-signed certificates (internal TLS)
//! - Custom ACME/DNS challenge configuration for valid certificates
//! - Binding to specific LAN interfaces only

mod apply;
mod db;
pub mod routes;

pub use apply::*;
pub use db::*;
