//! Wi-Fi access point, served by hostapd.
//!
//! - `config`: the generated `hostapd` configuration.
//! - `db`: the saved configuration and the last configuration applied.
//! - `detect`: wireless interfaces, installed tools and the station list.
//! - `apply`: writing the configuration and controlling `hostapd@<interface>`.
//! - `routes`: the HTTP API.

pub mod apply;
pub mod config;
pub mod db;
pub mod detect;
pub mod routes;

pub use apply::{apply_saved, bridge_candidates, preview_wireless_config};
pub use db::load_wireless_config;
