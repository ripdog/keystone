//! Wi-Fi access point, served by hostapd.
//!
//! Keystone never runs hostapd from a shell. It generates
//! `/etc/hostapd/<interface>.conf` and controls `hostapd@<interface>.service`.
//! The access point is attached to a Keystone bridge, so wireless clients share
//! the LAN of that bridge: its addressing, DHCP range and firewall zone.
//!
//! Only what the supported hardware is known to do is offered: one WPA2-PSK
//! network on 2.4 GHz with 20 MHz channels. The reverse-engineered brcmsmac
//! driver (Broadcom BCM43224) marks every 5 GHz channel no-initiate-radiation,
//! so it cannot host an access point there, and it supports a single AP
//! interface per radio.

use serde::{Deserialize, Serialize};

use crate::validation;

/// Channels offered on 2.4 GHz. Channels 12 and 13 are limited by regulatory
/// domain (and "no IR" under the driver's default one), so they are left out.
pub const WIRELESS_CHANNELS: std::ops::RangeInclusive<u8> = 1..=11;
/// Longest SSID, in bytes.
pub const SSID_MAX_BYTES: usize = 32;
/// WPA passphrase length limits, in characters.
pub const PASSPHRASE_MIN_LEN: usize = 8;
pub const PASSPHRASE_MAX_LEN: usize = 63;

/// Wi-Fi access point settings. A single configuration row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WirelessConfig {
    /// Run the access point.
    pub enabled: bool,
    /// The wireless interface that hosts the access point, e.g. `wlp4s0b1`.
    pub interface: String,
    /// The Keystone bridge the access point joins. Clients get the LAN of
    /// this bridge.
    pub bridge: String,
    /// Network name, 1 to 32 bytes of UTF-8.
    pub ssid: String,
    /// Do not broadcast the SSID in beacons.
    pub hidden_ssid: bool,
    /// ISO 3166 country code, which sets the allowed channels and power.
    pub country_code: String,
    /// 2.4 GHz channel, 1 to 11.
    pub channel: u8,
    /// WPA2-PSK passphrase, 8 to 63 printable ASCII characters.
    pub passphrase: String,
    /// Stop wireless clients from talking to each other.
    pub client_isolation: bool,
}

impl Default for WirelessConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: String::new(),
            bridge: String::new(),
            ssid: String::new(),
            hidden_ssid: false,
            country_code: String::new(),
            channel: 6,
            passphrase: String::new(),
            client_isolation: false,
        }
    }
}

impl WirelessConfig {
    /// Check the settings, whether or not the access point is enabled.
    /// `bridges` are the names of the configured bridges.
    ///
    /// A disabled configuration may be incomplete (a fresh install has no SSID
    /// yet), so only the fields that are filled in are checked then.
    pub fn validate(&self, bridges: &[String]) -> Result<(), String> {
        validation::single_line_fields(self)?;
        if self.enabled || !self.interface.is_empty() {
            validation::interface_name(&self.interface)?;
        }
        if !self.enabled && self.ssid.is_empty() && self.passphrase.is_empty() {
            return Ok(());
        }
        validate_ssid(&self.ssid)?;
        validate_passphrase(&self.passphrase)?;
        validate_country_code(&self.country_code)?;
        if !WIRELESS_CHANNELS.contains(&self.channel) {
            return Err(format!(
                "Channel must be from {} to {}",
                WIRELESS_CHANNELS.start(),
                WIRELESS_CHANNELS.end()
            ));
        }
        if self.enabled || !self.bridge.is_empty() {
            validation::interface_name(&self.bridge)?;
            if !bridges.iter().any(|bridge| bridge == &self.bridge) {
                return Err(format!(
                    "Bridge {:?} is not configured; create it under Bridges first",
                    self.bridge
                ));
            }
        }
        Ok(())
    }
}

/// An SSID is 1 to 32 bytes of printable UTF-8.
pub fn validate_ssid(ssid: &str) -> Result<(), String> {
    if ssid.is_empty() || ssid.len() > SSID_MAX_BYTES {
        return Err(format!("SSID must be 1 to {SSID_MAX_BYTES} bytes long"));
    }
    if !validation::is_single_line(ssid) {
        return Err("SSID must not contain control characters".to_string());
    }
    Ok(())
}

/// A WPA passphrase is 8 to 63 printable ASCII characters. Spaces are allowed
/// inside it, but not at either end, where hostapd's line parsing could
/// silently drop them.
pub fn validate_passphrase(passphrase: &str) -> Result<(), String> {
    let length = passphrase.chars().count();
    if !(PASSPHRASE_MIN_LEN..=PASSPHRASE_MAX_LEN).contains(&length) {
        return Err(format!(
            "Passphrase must be {PASSPHRASE_MIN_LEN} to {PASSPHRASE_MAX_LEN} characters long"
        ));
    }
    if !passphrase.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return Err("Passphrase must use printable ASCII characters only".to_string());
    }
    if passphrase.starts_with(' ') || passphrase.ends_with(' ') {
        return Err("Passphrase must not start or end with a space".to_string());
    }
    Ok(())
}

/// Two uppercase ASCII letters. The world (`00`) and unset (`99`, `XX`)
/// domains are rejected: an access point needs a real regulatory domain.
pub fn validate_country_code(code: &str) -> Result<(), String> {
    if code.len() != 2 || !code.bytes().all(|b| b.is_ascii_uppercase()) || code == "XX" {
        return Err("Country code must be two uppercase letters, such as NZ or US".to_string());
    }
    Ok(())
}

/// A wireless interface found on this machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WirelessInterface {
    pub name: String,
    /// Kernel driver bound to the device, e.g. `brcmsmac`.
    pub driver: Option<String>,
    pub mac: Option<String>,
    /// Whether the radio can host an access point. `None` when it could not be
    /// determined (`iw` is not installed).
    pub ap_supported: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WirelessStateResponse {
    pub config: WirelessConfig,
    pub interfaces: Vec<WirelessInterface>,
    /// Configured bridges the access point can join.
    pub bridge_candidates: Vec<String>,
    pub hostapd_installed: bool,
    pub iw_installed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaveWirelessConfigRequest {
    pub config: WirelessConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaveWirelessConfigResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WirelessApplyResponse {
    pub success: bool,
    pub message: String,
}

/// A client associated with the access point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WirelessStation {
    pub mac: String,
    pub signal_dbm: Option<i32>,
    /// Milliseconds since the station last sent a frame.
    pub inactive_ms: Option<u64>,
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
    /// Seconds since the station associated.
    pub connected_secs: Option<u64>,
}

/// Live state of the access point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WirelessStatusResponse {
    pub service_active: bool,
    pub stations: Vec<WirelessStation>,
    /// Why the station list is missing or incomplete, if it is.
    pub warnings: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bridges() -> Vec<String> {
        vec!["br-lan".to_string()]
    }

    fn valid() -> WirelessConfig {
        WirelessConfig {
            enabled: true,
            interface: "wlp4s0b1".to_string(),
            bridge: "br-lan".to_string(),
            ssid: "keystone".to_string(),
            country_code: "NZ".to_string(),
            passphrase: "correct horse battery".to_string(),
            ..WirelessConfig::default()
        }
    }

    #[test]
    fn a_complete_configuration_is_valid() {
        assert_eq!(valid().validate(&bridges()), Ok(()));
    }

    #[test]
    fn the_default_configuration_is_disabled_and_valid() {
        let config = WirelessConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.validate(&bridges()), Ok(()));
    }

    #[test]
    fn an_enabled_configuration_needs_every_field() {
        for broken in [
            WirelessConfig {
                interface: String::new(),
                ..valid()
            },
            WirelessConfig {
                ssid: String::new(),
                ..valid()
            },
            WirelessConfig {
                passphrase: String::new(),
                ..valid()
            },
            WirelessConfig {
                country_code: String::new(),
                ..valid()
            },
            WirelessConfig {
                bridge: String::new(),
                ..valid()
            },
        ] {
            assert!(broken.validate(&bridges()).is_err(), "{broken:?}");
        }
    }

    #[test]
    fn the_bridge_must_exist() {
        let error = valid().validate(&[]).unwrap_err();
        assert!(error.contains("br-lan"), "{error}");
    }

    #[test]
    fn ssids_are_bounded_and_single_line() {
        assert!(validate_ssid("a").is_ok());
        assert!(validate_ssid(&"a".repeat(SSID_MAX_BYTES)).is_ok());
        assert!(validate_ssid(&"a".repeat(SSID_MAX_BYTES + 1)).is_err());
        // The limit is in bytes: 11 three-byte characters is 33.
        assert!(validate_ssid(&"é".repeat(16)).is_ok());
        assert!(validate_ssid(&"€".repeat(11)).is_err());
        assert!(validate_ssid("").is_err());
        assert!(validate_ssid("evil\nwpa=0").is_err());
    }

    #[test]
    fn passphrases_are_printable_ascii_of_the_wpa_length() {
        assert!(validate_passphrase("12345678").is_ok());
        assert!(validate_passphrase(&"a".repeat(PASSPHRASE_MAX_LEN)).is_ok());
        assert!(validate_passphrase("short").is_err());
        assert!(validate_passphrase(&"a".repeat(PASSPHRASE_MAX_LEN + 1)).is_err());
        assert!(validate_passphrase("with a space inside").is_ok());
        assert!(validate_passphrase(" leading space").is_err());
        assert!(validate_passphrase("trailing space ").is_err());
        assert!(validate_passphrase("pässword123").is_err());
        assert!(validate_passphrase("line\nbreak123").is_err());
    }

    #[test]
    fn country_codes_are_two_uppercase_letters() {
        assert!(validate_country_code("NZ").is_ok());
        assert!(validate_country_code("nz").is_err());
        assert!(validate_country_code("N").is_err());
        assert!(validate_country_code("NZL").is_err());
        assert!(validate_country_code("00").is_err());
        assert!(validate_country_code("XX").is_err());
    }

    #[test]
    fn only_the_dependable_channels_are_accepted() {
        for channel in WIRELESS_CHANNELS {
            let config = WirelessConfig { channel, ..valid() };
            assert!(config.validate(&bridges()).is_ok(), "channel {channel}");
        }
        for channel in [0, 12, 13, 36, 255] {
            let config = WirelessConfig { channel, ..valid() };
            assert!(config.validate(&bridges()).is_err(), "channel {channel}");
        }
    }

    #[test]
    fn interface_names_cannot_escape_the_config_directory() {
        for name in ["../etc/passwd", "a/b", "wlan 0", ".."] {
            let config = WirelessConfig {
                interface: name.to_string(),
                ..valid()
            };
            assert!(config.validate(&bridges()).is_err(), "{name}");
        }
    }

    #[test]
    fn missing_fields_take_their_defaults() {
        let config: WirelessConfig = serde_json::from_str(r#"{"ssid": "x"}"#).unwrap();
        assert_eq!(
            config,
            WirelessConfig {
                ssid: "x".to_string(),
                ..WirelessConfig::default()
            }
        );
    }
}
