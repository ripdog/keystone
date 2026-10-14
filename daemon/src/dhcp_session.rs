//! Restarting a DHCPv4 link without breaking the ISP's session.
//!
//! Captures from a BNG that keys its routing state on the DHCP lease showed
//! that `networkctl reconfigure` makes networkd forget its lease and send a
//! DISCOVER while the BNG still holds the old one; the BNG answers normally but
//! stops routing, until the lease expires and is cleaned up (about 25 minutes).
//! A brief link bounce makes networkd re-request its old address instead
//! (INIT-REBOOT, option 50), which the BNG accepts and keeps routing.

use std::time::Duration;

use anyhow::Result;
use keystone_core::{DhcpMode, InterfaceConfig};

use crate::interface_rename::run_ip;

/// How long the link stays down. A 3 second bounce is what was verified.
const BOUNCE_DOWN_TIME: Duration = Duration::from_secs(3);

/// Whether the interface runs a DHCPv4 client, whose session an ISP may track.
pub fn uses_dhcpv4(config: &InterfaceConfig) -> bool {
    matches!(config.dhcp_mode, DhcpMode::Yes | DhcpMode::Ipv4)
}

/// Take the link down briefly and bring it back up.
pub async fn bounce_link(name: &str) -> Result<()> {
    keystone_core::validation::interface_name(name).map_err(anyhow::Error::msg)?;
    run_ip(&["link", "set", "dev", name, "down"]).await?;
    tokio::time::sleep(BOUNCE_DOWN_TIME).await;
    run_ip(&["link", "set", "dev", name, "up"]).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(mode: DhcpMode) -> InterfaceConfig {
        InterfaceConfig {
            name: "wan0".into(),
            dhcp_mode: mode,
            ..Default::default()
        }
    }

    #[test]
    fn only_dhcpv4_interfaces_need_the_gentle_restart() {
        assert!(uses_dhcpv4(&config(DhcpMode::Yes)));
        assert!(uses_dhcpv4(&config(DhcpMode::Ipv4)));
        assert!(!uses_dhcpv4(&config(DhcpMode::Ipv6)));
        assert!(!uses_dhcpv4(&config(DhcpMode::No)));
    }
}
