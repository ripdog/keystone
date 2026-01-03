//! Chain generation modules for nftables ruleset
//!
//! This module contains separate submodules for each chain type:
//! - `input` - Input chain (traffic destined for the router)
//! - `forward` - Forward chain (traffic passing through the router)
//! - `output` - Output chain (traffic from the router)
//! - `nat` - NAT chains (prerouting/postrouting for DNAT/SNAT)

pub mod forward;
pub mod input;
pub mod nat;
pub mod output;

pub use forward::*;
pub use input::*;
pub use nat::*;
pub use output::*;
