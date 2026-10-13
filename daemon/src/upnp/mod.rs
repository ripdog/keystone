//! UPnP IGD and NAT-PMP / PCP port mapping, served by miniupnpd.
//!
//! - `config`: validation and the generated `miniupnpd.conf`.
//! - `db`: the saved configuration and the last configuration applied.
//! - `detect`: which firewall backend the installed miniupnpd was built with.
//! - `nft`: the nftables table miniupnpd writes its rules into.
//! - `leases`: the mapping list read from miniupnpd's lease file.
//! - `apply`: writing the configuration, the service, status and the reconciler.
//! - `routes`: the HTTP API.
//!
//! Keystone's firewall ruleset carries one accept rule for UPnP mappings while
//! UPnP is enabled; see [`load_forward_accept`].

pub mod apply;
pub mod config;
pub mod db;
pub mod detect;
pub mod leases;
pub mod nft;
pub mod routes;

use anyhow::Result;
use keystone_core::upnp::UpnpForwardAccept;
use sqlx::SqlitePool;

pub use apply::{apply_saved, interface_candidates, preview_upnp_config, start_reconciler};
pub use db::load_upnp_config;

/// The forward-chain accept rule for UPnP mappings, present only while UPnP is
/// enabled. Loaded with the firewall configuration so that apply, preview and
/// rollback all see the same rule.
pub async fn load_forward_accept(pool: &SqlitePool) -> Result<Option<UpnpForwardAccept>> {
    Ok(config::forward_accept(&db::load_upnp_config(pool).await?))
}
