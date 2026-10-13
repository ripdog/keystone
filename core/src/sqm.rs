//! Smart Queue Management (SQM): CAKE traffic shaping on the WAN link.
//!
//! Upload is shaped on the WAN interface itself (egress). Download is shaped by
//! redirecting WAN ingress traffic to an IFB device and shaping that device
//! (ingress). A bandwidth of zero leaves that direction unshaped.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Smallest accepted shaper rate, in kbit/s (0 disables a direction).
pub const SQM_MIN_KBIT: u32 = 64;
/// Largest accepted shaper rate, in kbit/s.
pub const SQM_MAX_KBIT: u32 = 100_000_000;
/// Smallest accepted per-packet overhead, in bytes.
pub const SQM_OVERHEAD_MIN: i32 = -64;
/// Largest accepted per-packet overhead, in bytes.
pub const SQM_OVERHEAD_MAX: i32 = 256;
/// Largest accepted minimum packet unit, in bytes.
pub const SQM_MPU_MAX: u32 = 256;

/// Link framing that the shaper compensates for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SqmLinkPreset {
    /// No link-layer compensation.
    None,
    /// Plain Ethernet (fibre ONT, Ethernet handoff, most cable and fibre WANs).
    #[default]
    Ethernet,
    /// DOCSIS cable modem.
    Docsis,
    /// VDSL2 with PPPoE over PTM framing.
    PppoePtm,
    /// VDSL2 with bridged Ethernet over PTM framing.
    BridgedPtm,
    /// ADSL with PPPoE over ATM (VC-MUX framing).
    PppoeVcmux,
}

impl SqmLinkPreset {
    pub const fn as_str(self) -> &'static str {
        match self {
            SqmLinkPreset::None => "none",
            SqmLinkPreset::Ethernet => "ethernet",
            SqmLinkPreset::Docsis => "docsis",
            SqmLinkPreset::PppoePtm => "pppoe-ptm",
            SqmLinkPreset::BridgedPtm => "bridged-ptm",
            SqmLinkPreset::PppoeVcmux => "pppoe-vcmux",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "none" => SqmLinkPreset::None,
            "ethernet" => SqmLinkPreset::Ethernet,
            "docsis" => SqmLinkPreset::Docsis,
            "pppoe-ptm" => SqmLinkPreset::PppoePtm,
            "bridged-ptm" => SqmLinkPreset::BridgedPtm,
            "pppoe-vcmux" => SqmLinkPreset::PppoeVcmux,
            _ => return None,
        })
    }
}

impl fmt::Display for SqmLinkPreset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SqmLinkPreset {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value).ok_or_else(|| format!("unknown link preset {value:?}"))
    }
}

/// CAKE diffserv (priority tin) mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SqmDiffserv {
    /// One tin; DSCP values are ignored.
    Besteffort,
    /// Three tins: bulk, best effort, voice.
    Diffserv3,
    /// Four tins: bulk, best effort, video, voice.
    #[default]
    Diffserv4,
    /// Eight tins.
    Diffserv8,
}

impl SqmDiffserv {
    pub const fn as_str(self) -> &'static str {
        match self {
            SqmDiffserv::Besteffort => "besteffort",
            SqmDiffserv::Diffserv3 => "diffserv3",
            SqmDiffserv::Diffserv4 => "diffserv4",
            SqmDiffserv::Diffserv8 => "diffserv8",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "besteffort" => SqmDiffserv::Besteffort,
            "diffserv3" => SqmDiffserv::Diffserv3,
            "diffserv4" => SqmDiffserv::Diffserv4,
            "diffserv8" => SqmDiffserv::Diffserv8,
            _ => return None,
        })
    }
}

impl fmt::Display for SqmDiffserv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SqmDiffserv {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value).ok_or_else(|| format!("unknown diffserv mode {value:?}"))
    }
}

/// How traffic is split into fairness queues.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SqmIsolation {
    /// Per-host fairness with per-flow fairness inside each host. Upload uses
    /// source-host isolation and download uses destination-host isolation.
    #[default]
    Dual,
    /// Per-flow fairness, with hosts also isolated (`triple-isolate`).
    Triflow,
    /// Per-flow fairness only.
    Flows,
    /// Per-host fairness only.
    Hosts,
}

impl SqmIsolation {
    pub const fn as_str(self) -> &'static str {
        match self {
            SqmIsolation::Dual => "dual",
            SqmIsolation::Triflow => "triflow",
            SqmIsolation::Flows => "flows",
            SqmIsolation::Hosts => "hosts",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "dual" => SqmIsolation::Dual,
            "triflow" => SqmIsolation::Triflow,
            "flows" => SqmIsolation::Flows,
            "hosts" => SqmIsolation::Hosts,
            _ => return None,
        })
    }
}

impl fmt::Display for SqmIsolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SqmIsolation {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value).ok_or_else(|| format!("unknown isolation mode {value:?}"))
    }
}

/// The SQM configuration. Stored as a single row and applied as a whole.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SqmConfig {
    /// Whether shaping is enabled. A disabled configuration removes the
    /// qdiscs this module created.
    pub enabled: bool,
    /// WAN interface whose traffic is shaped.
    pub interface: String,
    /// Download rate in kbit/s (0 leaves download unshaped).
    pub download_kbit: u32,
    /// Upload rate in kbit/s (0 leaves upload unshaped).
    pub upload_kbit: u32,
    pub link_preset: SqmLinkPreset,
    /// Custom per-packet overhead in bytes, applied after the link preset.
    pub overhead: Option<i32>,
    /// Custom minimum packet unit in bytes, applied after the link preset.
    pub mpu: Option<u32>,
    pub diffserv: SqmDiffserv,
    pub isolation: SqmIsolation,
    /// Use NAT-aware flow hashing (`nat`), so fairness sees internal hosts.
    pub nat: bool,
    /// Drop redundant TCP ACKs on upload (`ack-filter`).
    pub ack_filter: bool,
    /// Clear DSCP marks at the shaper (`wash`).
    pub wash: bool,
}

impl Default for SqmConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: String::new(),
            download_kbit: 0,
            upload_kbit: 0,
            link_preset: SqmLinkPreset::default(),
            overhead: None,
            mpu: None,
            diffserv: SqmDiffserv::default(),
            isolation: SqmIsolation::default(),
            nat: true,
            ack_filter: false,
            wash: false,
        }
    }
}

/// Interfaces offered by the SQM page and the default WAN choice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqmStateResponse {
    pub config: SqmConfig,
    /// Names of all configured interfaces.
    pub available_interfaces: Vec<String>,
    /// First enabled WAN-role interface, pre-selected on a new configuration.
    pub default_interface: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaveSqmConfigRequest {
    pub config: SqmConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaveSqmConfigResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqmApplyResponse {
    pub success: bool,
    pub message: String,
}

/// Live state of the shaper, read from the kernel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SqmStatusResponse {
    /// The last applied configuration has shaping enabled and its qdiscs were
    /// found on the system.
    pub active: bool,
    pub interface: Option<String>,
    /// Why the status is incomplete, when it is.
    pub message: Option<String>,
    pub upload: Option<SqmDirectionStatus>,
    pub download: Option<SqmDirectionStatus>,
}

/// Counters for one shaped direction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqmDirectionStatus {
    /// Device carrying the CAKE qdisc: the WAN interface (upload) or the IFB
    /// device (download).
    pub device: String,
    pub bandwidth_kbit: u32,
    pub sent_bytes: u64,
    pub sent_packets: u64,
    pub drops: u64,
    pub backlog_bytes: u64,
    /// Per-tin counters, in tin order. Empty when the kernel reports none.
    pub tins: Vec<SqmTinStatus>,
}

/// Counters for one CAKE priority tin. Fields the kernel omits are `None`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqmTinStatus {
    pub name: String,
    pub sent_bytes: Option<u64>,
    pub sent_packets: Option<u64>,
    pub backlog_bytes: Option<u64>,
    pub drops: Option<u64>,
    /// Packets marked with ECN instead of dropped.
    pub ecn_marks: Option<u64>,
    pub avg_delay_us: Option<u64>,
    pub peak_delay_us: Option<u64>,
    pub base_delay_us: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqm_enums_round_trip_through_their_names() {
        for preset in [
            SqmLinkPreset::None,
            SqmLinkPreset::Ethernet,
            SqmLinkPreset::Docsis,
            SqmLinkPreset::PppoePtm,
            SqmLinkPreset::BridgedPtm,
            SqmLinkPreset::PppoeVcmux,
        ] {
            assert_eq!(SqmLinkPreset::parse(preset.as_str()), Some(preset));
            let json = serde_json::to_string(&preset).unwrap();
            assert_eq!(json, format!("\"{}\"", preset.as_str()));
        }
        for mode in [
            SqmDiffserv::Besteffort,
            SqmDiffserv::Diffserv3,
            SqmDiffserv::Diffserv4,
            SqmDiffserv::Diffserv8,
        ] {
            assert_eq!(SqmDiffserv::parse(mode.as_str()), Some(mode));
            let json = serde_json::to_string(&mode).unwrap();
            assert_eq!(json, format!("\"{}\"", mode.as_str()));
        }
        for isolation in [
            SqmIsolation::Dual,
            SqmIsolation::Triflow,
            SqmIsolation::Flows,
            SqmIsolation::Hosts,
        ] {
            assert_eq!(SqmIsolation::parse(isolation.as_str()), Some(isolation));
            let json = serde_json::to_string(&isolation).unwrap();
            assert_eq!(json, format!("\"{}\"", isolation.as_str()));
        }
        assert!("ethernet ".parse::<SqmLinkPreset>().is_err());
        assert!("diffserv9".parse::<SqmDiffserv>().is_err());
    }

    #[test]
    fn default_config_is_disabled_with_nat_on() {
        let config = SqmConfig::default();
        assert!(!config.enabled);
        assert!(config.nat);
        assert_eq!(config.download_kbit, 0);
        assert_eq!(config.upload_kbit, 0);
        assert_eq!(config.diffserv, SqmDiffserv::Diffserv4);
    }

    #[test]
    fn config_deserializes_with_missing_fields() {
        let config: SqmConfig =
            serde_json::from_str(r#"{"enabled":true,"interface":"enp1s0","download_kbit":90000}"#)
                .unwrap();
        assert!(config.enabled);
        assert_eq!(config.interface, "enp1s0");
        assert_eq!(config.download_kbit, 90_000);
        assert_eq!(config.upload_kbit, 0);
        assert!(config.nat);
    }
}
