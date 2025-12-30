//! Application pages

mod bridges;
mod caddy;
mod dashboard;
mod dnsmasq;
mod firewall;
mod interface_edit;
mod interfaces;
mod networkd_preview;
mod settings;
mod vlans;

pub use bridges::*;
pub use caddy::*;
pub use dashboard::*;
pub use dnsmasq::*;
pub use firewall::*;
pub use interface_edit::*;
pub use interfaces::*;
pub use networkd_preview::*;
pub use settings::*;
pub use vlans::*;
