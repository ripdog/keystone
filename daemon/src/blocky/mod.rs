//! DNS filtering (ad-blocking) and encrypted upstream DNS, served by Blocky.
//!
//! - `config`: validation and the generated `config.yml`, and the dnsmasq link checks.
//! - `db`: the saved configuration.
//! - `apply`: writing the configuration, the service, status and the pending preview.
//! - `api`: a minimal client for Blocky's loopback HTTP API.
//! - `querylog`: reading Blocky's daily CSV query log.
//! - `routes`: the HTTP API.
//!
//! dnsmasq keeps port 53 and forwards to Blocky on loopback when its upstream
//! mode is `blocky`; see `dnsmasq::config`.

pub mod api;
pub mod apply;
pub mod config;
pub mod db;
pub mod querylog;
pub mod routes;

pub use apply::{apply_saved, is_serving, preview_blocky_config};
pub use db::load_blocky_config;
