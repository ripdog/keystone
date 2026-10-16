//! Restarting a DHCPv4 link without breaking the ISP's session.
//!
//! Captures from a BNG that keys its routing state on the DHCP lease showed
//! that `networkctl reconfigure` makes networkd forget its lease and send a
//! DISCOVER while the BNG still holds the old one; the BNG answers normally but
//! stops routing, until the lease expires and is cleaned up (about 25 minutes).
//! A brief link bounce makes networkd re-request its old address instead
//! (INIT-REBOOT, option 50), which the BNG accepts and keeps routing.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use keystone_core::{DhcpMode, InterfaceConfig};
use serde_json::Value;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tracing::{error, info, warn};

use crate::interface_rename::run_ip;

/// How long the link stays down. A 3 second bounce is what was verified.
const BOUNCE_DOWN_TIME: Duration = Duration::from_secs(3);

/// How long the link stays down after releasing the lease. One second was
/// enough in testing (the link then needs a few seconds to come up); this adds
/// margin for a slower BNG.
const RESET_DOWN_TIME: Duration = Duration::from_secs(5);

/// If the reset task dies with the link down, this timer brings it back up.
const FAILSAFE_DELAY_SECS: u64 = 120;

const SYS_CLASS_NET: &str = "/sys/class/net";
const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;
const DHCP_MIN_PACKET: usize = 300;

/// Only one reset at a time: two would race on the link state.
static RESET_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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

/// What a DHCPRELEASE needs to know about the current lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseInfo {
    pub address: Ipv4Addr,
    pub server: Ipv4Addr,
    /// The client identifier (option 61) the lease was obtained with.
    pub client_id: Vec<u8>,
}

fn unhex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) || !value.is_ascii() {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).ok())
        .collect()
}

fn ipv4_from_hex(value: &str) -> Option<Ipv4Addr> {
    let bytes: [u8; 4] = unhex(value)?.try_into().ok()?;
    Some(Ipv4Addr::from(bytes))
}

/// Read the lease from `networkctl status <link> --json=short` output, either
/// the whole document or just its `DHCPv4Client` object.
pub fn parse_lease(json: &str) -> Result<LeaseInfo> {
    let document: Value = serde_json::from_str(json).context("Unreadable networkctl output")?;
    let client = document.get("DHCPv4Client").unwrap_or(&document);
    let message = client
        .pointer("/Lease/Message")
        .ok_or_else(|| anyhow!("The link has no DHCPv4 lease"))?;

    let address = message
        .get("yiaddr")
        .and_then(Value::as_str)
        .and_then(ipv4_from_hex)
        .filter(|address| !address.is_unspecified())
        .ok_or_else(|| anyhow!("The DHCPv4 lease has no address"))?;

    // Option 54 (server identifier).
    let server = message
        .get("options")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|option| option.get("tag").and_then(Value::as_u64) == Some(54))
        .and_then(|option| option.get("data")?.as_str())
        .and_then(ipv4_from_hex)
        .ok_or_else(|| anyhow!("The DHCPv4 lease has no server identifier"))?;

    let client_id: Vec<u8> = client
        .get("ClientIdentifier")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("The DHCPv4 client has no client identifier"))?
        .iter()
        .map(|byte| byte.as_u64().and_then(|b| u8::try_from(b).ok()))
        .collect::<Option<_>>()
        .ok_or_else(|| anyhow!("The DHCPv4 client identifier is invalid"))?;
    if client_id.len() < 2 {
        bail!("The DHCPv4 client identifier is too short");
    }

    Ok(LeaseInfo {
        address,
        server,
        client_id,
    })
}

/// A DHCPRELEASE (RFC 2131 section 4.4.4): unicast to the server, with the
/// client's address in ciaddr, the server identifier and the client identifier.
pub fn build_release(lease: &LeaseInfo, mac: [u8; 6], xid: u32) -> Vec<u8> {
    let mut packet = Vec::with_capacity(DHCP_MIN_PACKET);
    packet.extend_from_slice(&[1, 1, 6, 0]); // BOOTREQUEST, Ethernet, hlen 6, hops 0
    packet.extend_from_slice(&xid.to_be_bytes());
    packet.extend_from_slice(&[0; 4]); // secs, flags
    packet.extend_from_slice(&lease.address.octets()); // ciaddr
    packet.extend_from_slice(&[0; 12]); // yiaddr, siaddr, giaddr
    packet.extend_from_slice(&mac);
    packet.extend_from_slice(&[0; 10]); // chaddr padding
    packet.extend_from_slice(&[0; 64 + 128]); // sname, file
    packet.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]); // magic cookie
    packet.extend_from_slice(&[53, 1, 7]); // DHCPRELEASE
    packet.extend_from_slice(&[54, 4]);
    packet.extend_from_slice(&lease.server.octets());
    packet.push(61);
    packet.push(lease.client_id.len() as u8);
    packet.extend_from_slice(&lease.client_id);
    packet.push(255);
    packet.resize(packet.len().max(DHCP_MIN_PACKET), 0);
    packet
}

fn link_mac(name: &str) -> Result<[u8; 6]> {
    let text = std::fs::read_to_string(
        std::path::Path::new(SYS_CLASS_NET)
            .join(name)
            .join("address"),
    )
    .with_context(|| format!("Cannot read the hardware address of {name}"))?;
    let bytes: Vec<u8> = text
        .trim()
        .split(':')
        .map(|pair| u8::from_str_radix(pair, 16))
        .collect::<Result<_, _>>()
        .context("Invalid hardware address")?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("{name} has no 6-byte hardware address"))
}

async fn read_lease(name: &str) -> Result<LeaseInfo> {
    let output = tokio::time::timeout(
        Duration::from_secs(15),
        tokio::process::Command::new("/usr/bin/networkctl")
            .args(["status", "--no-pager", "--json=short", name])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| anyhow!("networkctl status timed out"))?
    .context("Failed to run networkctl")?;
    if !output.status.success() {
        bail!(
            "networkctl status failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    parse_lease(&String::from_utf8_lossy(&output.stdout))
}

/// Send the release from the lease address to the server, through `iface`.
fn send_release(iface: &str, lease: &LeaseInfo, packet: &[u8]) -> Result<()> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.bind_device(Some(iface.as_bytes()))?;
    socket.bind(&SockAddr::from(SocketAddrV4::new(
        lease.address,
        DHCP_CLIENT_PORT,
    )))?;
    socket.send_to(
        packet,
        &SockAddr::from(SocketAddrV4::new(lease.server, DHCP_SERVER_PORT)),
    )?;
    Ok(())
}

fn failsafe_unit(name: &str) -> String {
    format!("keystone-link-up-{name}")
}

async fn run_systemctl_stop(unit: &str) {
    let _ = tokio::process::Command::new("systemctl")
        .args(["stop", unit])
        .output()
        .await;
}

/// Arrange for the link to come back up even if this daemon dies mid-reset.
async fn schedule_failsafe(name: &str) -> Result<()> {
    let unit = failsafe_unit(name);
    // A leftover from an earlier, interrupted reset would block the new one.
    run_systemctl_stop(&format!("{unit}.timer")).await;
    let output = tokio::process::Command::new("systemd-run")
        .arg("--quiet")
        .arg(format!("--on-active={FAILSAFE_DELAY_SECS}"))
        .arg(format!("--unit={unit}"))
        .arg("--collect")
        .args(["/usr/bin/ip", "link", "set", "dev", name, "up"])
        .output()
        .await
        .context("Failed to run systemd-run")?;
    if !output.status.success() {
        bail!(
            "Could not schedule the safety timer that brings {name} back up: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Release the DHCPv4 lease of `name`, take its link down briefly and bring it
/// back up, so the ISP's BNG sees a fresh session instead of a stale one.
///
/// Everything that can fail safely (reading the lease, scheduling the
/// failsafe, sending the release) happens before this returns; the link
/// bounce then continues in the background.
pub async fn start_reset(name: &str) -> Result<String> {
    keystone_core::validation::interface_name(name).map_err(anyhow::Error::msg)?;
    let guard = RESET_LOCK
        .try_lock()
        .map_err(|_| anyhow!("A DHCP session reset is already running"))?;

    let lease = read_lease(name).await?;
    let mac = link_mac(name)?;
    let xid = rand::random::<u32>();
    let packet = build_release(&lease, mac, xid);

    schedule_failsafe(name).await?;
    if let Err(error) =
        send_release(name, &lease, &packet).context("Failed to send the DHCP release")
    {
        // Nothing changed on the link, so the safety timer is not needed.
        run_systemctl_stop(&format!("{}.timer", failsafe_unit(name))).await;
        return Err(error);
    }
    info!(
        "Sent DHCPRELEASE for {} to {} on {name}; bouncing the link",
        lease.address, lease.server
    );

    let link = name.to_string();
    tokio::spawn(async move {
        let _guard = guard;
        if let Err(error) = run_ip(&["link", "set", "dev", &link, "down"]).await {
            warn!("Could not take {link} down: {error:#}");
        }
        tokio::time::sleep(RESET_DOWN_TIME).await;
        if let Err(error) = run_ip(&["link", "set", "dev", &link, "up"]).await {
            // The failsafe timer still brings the link up.
            error!("Could not bring {link} back up: {error:#}");
            return;
        }
        run_systemctl_stop(&format!("{}.timer", failsafe_unit(&link))).await;
        info!("DHCP session reset on {link} complete");
    });

    Ok(format!(
        "Released the DHCP lease of {name} and restarted its link. The connection is down for about {} seconds, then the interface gets a fresh lease.",
        RESET_DOWN_TIME.as_secs() + 7
    ))
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

    /// `networkctl status wan0 --json=short` output from systemd 262.
    const STATUS_JSON: &str = r#"{"DHCPv4Client":{"Lease":{"LeaseTimestampUSec":25600910624,
        "Message":{"op":2,"htype":1,"hops":0,"xid":586376233,"secs":0,"flags":0,
        "ciaddr":"00000000","yiaddr":"67bb0620","siaddr":"67f36620","giaddr":"00000000",
        "chaddr":"00e84c689ed2","options":[{"tag":1,"data":"ffffffff"},
        {"tag":3,"data":"67f36620"},{"tag":51,"data":"000004b0"},{"tag":53,"data":"05"},
        {"tag":54,"data":"67f36620"}]}},"ClientIdentifier":[1,0,232,76,104,158,210]}}"#;

    fn lease() -> LeaseInfo {
        parse_lease(STATUS_JSON).unwrap()
    }

    #[test]
    fn lease_is_read_from_networkctl_json() {
        let lease = lease();
        assert_eq!(lease.address, Ipv4Addr::new(103, 187, 6, 32));
        assert_eq!(lease.server, Ipv4Addr::new(103, 243, 102, 32));
        assert_eq!(lease.client_id, [1, 0, 232, 76, 104, 158, 210]);
        // The bare DHCPv4Client object works too.
        let inner = serde_json::from_str::<Value>(STATUS_JSON).unwrap()["DHCPv4Client"].to_string();
        assert_eq!(parse_lease(&inner).unwrap(), lease);
    }

    #[test]
    fn a_missing_or_partial_lease_is_an_error() {
        assert!(parse_lease("not json").is_err());
        assert!(parse_lease("{}").is_err());
        assert!(parse_lease(r#"{"DHCPv4Client":{}}"#).is_err());
        let no_server = STATUS_JSON.replace(
            r#"{"tag":54,"data":"67f36620"}"#,
            r#"{"tag":3,"data":"67f36620"}"#,
        );
        assert!(parse_lease(&no_server).is_err());
        let no_address = STATUS_JSON.replace(r#""yiaddr":"67bb0620""#, r#""yiaddr":"00000000""#);
        assert!(parse_lease(&no_address).is_err());
        let bad_id = STATUS_JSON.replace("[1,0,232,76,104,158,210]", "[1,999]");
        assert!(parse_lease(&bad_id).is_err());
    }

    #[test]
    fn release_packet_matches_rfc_2131() {
        let mac = [0x00, 0xe8, 0x4c, 0x68, 0x9e, 0xd2];
        let packet = build_release(&lease(), mac, 0x1234_5678);
        assert_eq!(packet.len(), 300);
        assert_eq!(&packet[..4], &[1, 1, 6, 0]); // BOOTREQUEST over Ethernet
        assert_eq!(&packet[4..8], &0x1234_5678u32.to_be_bytes());
        assert_eq!(&packet[12..16], &[103, 187, 6, 32]); // ciaddr
        assert_eq!(&packet[16..28], &[0; 12]); // yiaddr, siaddr, giaddr
        assert_eq!(&packet[28..34], &mac); // chaddr
        assert_eq!(&packet[236..240], &[0x63, 0x82, 0x53, 0x63]);
        let options = &packet[240..];
        assert_eq!(&options[..3], &[53, 1, 7]); // DHCPRELEASE
        assert_eq!(&options[3..9], &[54, 4, 103, 243, 102, 32]); // server id
        assert_eq!(&options[9..11], &[61, 7]); // client id, as the lease used it
        assert_eq!(&options[11..18], &[1, 0, 232, 76, 104, 158, 210]);
        assert_eq!(options[18], 255);
        assert!(options[19..].iter().all(|&b| b == 0));
    }

    /// The reset sends from the DHCP client port bound to the WAN device
    /// (CAP_NET_BIND_SERVICE, CAP_NET_RAW) and takes the link down (CAP_NET_ADMIN).
    /// Tightening the daemon's capabilities must not silently break it.
    #[test]
    fn service_unit_grants_the_capabilities_the_reset_needs() {
        let unit = include_str!("../../packaging/arch/keystone-daemon.service");
        for directive in ["CapabilityBoundingSet=", "AmbientCapabilities="] {
            let caps = unit
                .lines()
                .find_map(|line| line.strip_prefix(directive))
                .unwrap();
            for cap in ["CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_NET_BIND_SERVICE"] {
                assert!(
                    caps.split_ascii_whitespace().any(|c| c == cap),
                    "{directive} missing {cap}"
                );
            }
        }
    }

    #[test]
    fn failsafe_unit_names_are_per_link() {
        assert_eq!(failsafe_unit("wan0"), "keystone-link-up-wan0");
    }

    #[test]
    fn only_dhcpv4_interfaces_need_the_gentle_restart() {
        assert!(uses_dhcpv4(&config(DhcpMode::Yes)));
        assert!(uses_dhcpv4(&config(DhcpMode::Ipv4)));
        assert!(!uses_dhcpv4(&config(DhcpMode::Ipv6)));
        assert!(!uses_dhcpv4(&config(DhcpMode::No)));
    }
}
