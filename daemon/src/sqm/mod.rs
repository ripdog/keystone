//! Smart Queue Management (SQM): CAKE traffic shaping on the WAN link.
//!
//! - `db`: the saved configuration and the last configuration applied.
//! - `apply`: the `tc`/`ip` plan for a configuration, validation, applying it,
//!   and the reconciler that restores it after a reboot or a WAN link flap.
//! - `status`: live counters parsed from `tc -s -j`.
//! - `routes`: the HTTP API.
//!
//! The reconciler re-applies the last applied configuration (`sqm_applied`),
//! never unsaved edits in `sqm_config`.

mod apply;
mod db;
pub mod routes;
mod status;

pub use apply::{apply_saved, preview_sqm, start_reconciler, validate_config};
pub use db::{load_sqm_config, save_sqm_config};
pub use status::read_status;
