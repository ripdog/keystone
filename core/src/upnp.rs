//! UPnP IGD and NAT-PMP / PCP port mapping, served by miniupnpd.
//!
//! Keystone never runs miniupnpd from a shell. It generates
//! `/etc/miniupnpd/miniupnpd.conf`, keeps the nftables tables miniupnpd writes
//! its rules into, and controls `miniupnpd.service`. Only the nftables build of
//! miniupnpd is supported; see [`UpnpBinaryStatus`].

use serde::{Deserialize, Serialize};

/// Default lease ceiling for PCP and NAT-PMP mappings, in seconds (24 hours,
/// the largest value miniupnpd accepts for `max_lifetime`).
pub const UPNP_MAX_LEASE_SECS_LIMIT: u32 = 86_400;
/// Smallest accepted lease ceiling. miniupnpd's minimum lifetime is 120 seconds
/// and it refuses a maximum that is not larger than its minimum.
pub const UPNP_MIN_LEASE_SECS: u32 = 121;
/// Smallest accepted interval between SSDP announcements, in seconds.
pub const UPNP_MIN_NOTIFY_SECS: u32 = 60;
/// Largest accepted interval between SSDP announcements, in seconds.
pub const UPNP_MAX_NOTIFY_SECS: u32 = 86_400;

/// Whether the installed miniupnpd can be used by Keystone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpnpBinaryStatus {
    /// No `miniupnpd` binary in `/usr/bin` or `/usr/sbin`.
    NotInstalled,
    /// Built with the iptables backend (`extra/miniupnpd` on Arch). Unsupported.
    IptablesBuild,
    /// Built with the nftables backend. The only supported build.
    NftablesBuild,
    /// Installed, but its backend could not be recognised from its libraries.
    Unknown,
}

impl UpnpBinaryStatus {
    /// Actionable text for the status, shown in the UI and returned on refusal.
    pub const fn message(self) -> &'static str {
        match self {
            UpnpBinaryStatus::NotInstalled => {
                "miniupnpd is not installed. Install miniupnpd-nft from the AUR (or build miniupnpd with --firewall=nftables)."
            }
            UpnpBinaryStatus::IptablesBuild => {
                "miniupnpd is built with the iptables backend, which Keystone does not support. Install miniupnpd-nft from the AUR (or build miniupnpd with --firewall=nftables)."
            }
            UpnpBinaryStatus::NftablesBuild => "miniupnpd is built with the nftables backend.",
            UpnpBinaryStatus::Unknown => {
                "miniupnpd is installed, but its firewall backend could not be determined. Keystone needs a build with the nftables backend: install miniupnpd-nft from the AUR (or build miniupnpd with --firewall=nftables)."
            }
        }
    }

    /// True only for the build Keystone can drive.
    pub const fn is_supported(self) -> bool {
        matches!(self, UpnpBinaryStatus::NftablesBuild)
    }
}

/// An inclusive range of TCP/UDP ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRange {
    pub min: u16,
    pub max: u16,
}

impl PortRange {
    pub const UNPRIVILEGED: PortRange = PortRange {
        min: 1024,
        max: 65535,
    };
}

impl Default for PortRange {
    fn default() -> Self {
        Self::UNPRIVILEGED
    }
}

/// UPnP / NAT-PMP settings. A single configuration row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UpnpConfig {
    /// Run miniupnpd and let clients on the LAN interfaces map ports.
    pub enabled: bool,
    /// LAN-role interfaces whose clients may request mappings. Never WAN.
    pub lan_interfaces: Vec<String>,
    /// The WAN interface that mappings are created on.
    pub wan_interface: String,
    /// Serve UPnP IGD (the protocol most consumer software uses).
    pub enable_igd: bool,
    /// Serve NAT-PMP and PCP.
    pub enable_natpmp_pcp: bool,
    /// Clients may only map ports to their own address.
    pub secure_mode: bool,
    /// External ports a client may request.
    pub external_ports: PortRange,
    /// Internal (client-side) ports a client may map.
    pub internal_ports: PortRange,
    /// Client subnets allowed to create mappings, as `a.b.c.d/nn`. Empty means
    /// the subnets of the selected LAN interfaces, which must then have static
    /// IPv4 addresses.
    pub allowed_client_subnets: Vec<String>,
    /// Longest lease a client may request, in seconds.
    pub max_lease_secs: u32,
    /// Name shown to clients in the device description.
    pub friendly_name: String,
    /// Seconds between SSDP announcements.
    pub notify_interval_secs: u32,
    /// Report the system uptime instead of the daemon uptime.
    pub system_uptime: bool,
}

impl Default for UpnpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            lan_interfaces: Vec::new(),
            wan_interface: String::new(),
            enable_igd: true,
            enable_natpmp_pcp: true,
            secure_mode: true,
            external_ports: PortRange::UNPRIVILEGED,
            internal_ports: PortRange::UNPRIVILEGED,
            allowed_client_subnets: Vec::new(),
            max_lease_secs: UPNP_MAX_LEASE_SECS_LIMIT,
            friendly_name: "Keystone router".to_string(),
            notify_interval_secs: 900,
            system_uptime: true,
        }
    }
}

/// The accept rule that lets UPnP-created DNAT traffic through the Keystone
/// forward chain. Present in the firewall ruleset only while UPnP is enabled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpnpForwardAccept {
    pub wan_interface: String,
    pub lan_interfaces: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpnpStateResponse {
    pub config: UpnpConfig,
    /// Configured LAN-role interfaces, the only ones that may be selected.
    pub lan_candidates: Vec<String>,
    /// Configured WAN-role interfaces.
    pub wan_candidates: Vec<String>,
    /// First enabled WAN-role interface, pre-selected on a new configuration.
    pub default_wan: Option<String>,
    pub binary: UpnpBinaryStatus,
    /// [`UpnpBinaryStatus::message`] for `binary`.
    pub binary_message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaveUpnpConfigRequest {
    pub config: UpnpConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaveUpnpConfigResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpnpApplyResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum UpnpProtocol {
    Tcp,
    Udp,
}

/// One port mapping, as recorded in miniupnpd's lease file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpnpMapping {
    pub protocol: UpnpProtocol,
    pub external_port: u16,
    pub internal_address: String,
    pub internal_port: u16,
    /// Unix time the mapping expires. `None` for a mapping without a lease.
    pub expires_at: Option<i64>,
    /// Description supplied by the client. Untrusted text: display it as text.
    pub description: String,
}

/// Live state of UPnP: the detected binary, the service and its mappings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpnpStatusResponse {
    pub binary: UpnpBinaryStatus,
    pub binary_message: String,
    pub service_active: bool,
    pub mappings: Vec<UpnpMapping>,
    /// Why the mapping list is incomplete, if it is (for example malformed
    /// lease lines that were skipped).
    pub warnings: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_disabled_and_secure() {
        let config = UpnpConfig::default();
        assert!(!config.enabled);
        assert!(config.secure_mode);
        assert!(config.enable_igd && config.enable_natpmp_pcp);
        assert_eq!(config.external_ports, PortRange::UNPRIVILEGED);
        assert_eq!(config.max_lease_secs, UPNP_MAX_LEASE_SECS_LIMIT);
    }

    #[test]
    fn only_the_nftables_build_is_supported() {
        assert!(UpnpBinaryStatus::NftablesBuild.is_supported());
        for status in [
            UpnpBinaryStatus::NotInstalled,
            UpnpBinaryStatus::IptablesBuild,
            UpnpBinaryStatus::Unknown,
        ] {
            assert!(!status.is_supported());
            assert!(status.message().contains("miniupnpd-nft"));
        }
        assert!(
            UpnpBinaryStatus::IptablesBuild
                .message()
                .contains("iptables backend")
        );
    }

    #[test]
    fn binary_status_serialises_snake_case() {
        let json = serde_json::to_string(&UpnpBinaryStatus::IptablesBuild).unwrap();
        assert_eq!(json, "\"iptables_build\"");
        let json = serde_json::to_string(&UpnpProtocol::Udp).unwrap();
        assert_eq!(json, "\"UDP\"");
    }

    #[test]
    fn config_fills_missing_fields_from_defaults() {
        let config: UpnpConfig = serde_json::from_str(r#"{"enabled": true}"#).unwrap();
        assert!(config.enabled);
        assert_eq!(
            config,
            UpnpConfig {
                enabled: true,
                ..UpnpConfig::default()
            }
        );
    }
}
