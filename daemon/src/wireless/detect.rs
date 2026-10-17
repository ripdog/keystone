//! What this machine has: wireless interfaces, the tools Keystone drives, and
//! the stations associated with the access point.
//!
//! `iw` is run with fixed arguments and an interface or phy name that came from
//! sysfs or from validated configuration, never through a shell.

use std::fs;
use std::path::Path;
use std::time::Duration;

use keystone_core::validation;
use keystone_core::wireless::{WirelessInterface, WirelessStation};
use tokio::process::Command;
use tokio::time::timeout;

const SYS_CLASS_NET: &str = "/sys/class/net";
const IW_TIMEOUT: Duration = Duration::from_secs(5);

/// Whether `name` is installed in a standard binary directory.
pub fn binary_installed(name: &str) -> bool {
    ["/usr/bin", "/usr/sbin"]
        .iter()
        .any(|dir| Path::new(dir).join(name).is_file())
}

/// Wireless interfaces: network devices with a `phy80211` link in sysfs.
pub async fn list_interfaces() -> Vec<WirelessInterface> {
    let mut found = Vec::new();
    let Ok(entries) = fs::read_dir(SYS_CLASS_NET) else {
        return found;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if validation::interface_name(&name).is_err() {
            continue;
        }
        let dir = entry.path();
        let Ok(phy) = fs::read_link(dir.join("phy80211")) else {
            continue;
        };
        let phy_name = phy
            .file_name()
            .map(|name| name.to_string_lossy().into_owned());
        let driver = fs::read_link(dir.join("device/driver"))
            .ok()
            .and_then(|path| path.file_name().map(|n| n.to_string_lossy().into_owned()));
        let mac = fs::read_to_string(dir.join("address"))
            .ok()
            .map(|mac| mac.trim().to_string());
        let ap_supported = match phy_name {
            Some(phy) => phy_supports_ap(&phy).await,
            None => None,
        };
        found.push(WirelessInterface {
            name,
            driver,
            mac,
            ap_supported,
        });
    }
    found.sort_by(|a, b| a.name.cmp(&b.name));
    found
}

async fn phy_supports_ap(phy: &str) -> Option<bool> {
    if validation::interface_name(phy).is_err() || !binary_installed("iw") {
        return None;
    }
    let output = run_iw(&["phy", phy, "info"]).await.ok()?;
    Some(parse_supports_ap(&output))
}

/// Whether `iw phy <phy> info` lists `AP` among the supported interface modes.
pub fn parse_supports_ap(output: &str) -> bool {
    let mut in_modes = false;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Supported interface modes:") {
            in_modes = true;
            continue;
        }
        if in_modes {
            match trimmed.strip_prefix("* ") {
                Some(mode) if mode.trim() == "AP" => return true,
                Some(_) => {}
                None => in_modes = false,
            }
        }
    }
    false
}

/// Stations associated with `interface`, from `iw dev <interface> station dump`.
pub async fn list_stations(interface: &str) -> Result<Vec<WirelessStation>, String> {
    validation::interface_name(interface)?;
    if !binary_installed("iw") {
        return Err("iw is not installed, so the station list is unavailable".to_string());
    }
    let output = run_iw(&["dev", interface, "station", "dump"]).await?;
    Ok(parse_station_dump(&output))
}

async fn run_iw(args: &[&str]) -> Result<String, String> {
    let mut command = Command::new("/usr/bin/iw");
    command.args(args).kill_on_drop(true);
    let output = timeout(IW_TIMEOUT, command.output())
        .await
        .map_err(|_| "iw timed out".to_string())?
        .map_err(|error| format!("failed to run iw: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "iw failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Parse `iw dev <interface> station dump`. Lines that do not parse are skipped.
pub fn parse_station_dump(output: &str) -> Vec<WirelessStation> {
    let mut stations: Vec<WirelessStation> = Vec::new();
    for line in output.lines() {
        if let Some(rest) = line.strip_prefix("Station ") {
            let mac = rest.split_whitespace().next().unwrap_or_default();
            stations.push(WirelessStation {
                mac: mac.to_ascii_lowercase(),
                signal_dbm: None,
                inactive_ms: None,
                rx_bytes: None,
                tx_bytes: None,
                connected_secs: None,
            });
            continue;
        }
        let Some(station) = stations.last_mut() else {
            continue;
        };
        let Some((key, value)) = line.trim().split_once(':') else {
            continue;
        };
        let first_number = || value.split_whitespace().next();
        match key {
            "signal" => station.signal_dbm = first_number().and_then(|v| v.parse().ok()),
            "inactive time" => station.inactive_ms = first_number().and_then(|v| v.parse().ok()),
            "rx bytes" => station.rx_bytes = first_number().and_then(|v| v.parse().ok()),
            "tx bytes" => station.tx_bytes = first_number().and_then(|v| v.parse().ok()),
            "connected time" => {
                station.connected_secs = first_number().and_then(|v| v.parse().ok())
            }
            _ => {}
        }
    }
    stations
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHY_INFO: &str = "Wiphy phy0\n\tSupported interface modes:\n\t\t * IBSS\n\t\t * managed\n\t\t * AP\n\t\t * AP/VLAN\n\t\t * monitor\n\tBand 1:\n";

    #[test]
    fn ap_support_is_read_from_the_interface_modes() {
        assert!(parse_supports_ap(PHY_INFO));
    }

    #[test]
    fn ap_vlan_alone_is_not_ap_support() {
        let info =
            "\tSupported interface modes:\n\t\t * managed\n\t\t * AP/VLAN\n\tBand 1:\n\t\t * AP\n";
        assert!(!parse_supports_ap(info));
    }

    #[test]
    fn no_modes_section_means_no_ap_support() {
        assert!(!parse_supports_ap("Wiphy phy0\n"));
    }

    #[test]
    fn parses_a_station_dump() {
        let dump = "Station 06:C9:3E:84:A9:47 (on wlp4s0b1)\n\tinactive time:\t1230 ms\n\trx bytes:\t12345\n\trx packets:\t10\n\ttx bytes:\t6789\n\tsignal:  \t-45 [-45, -47] dBm\n\tconnected time:\t120 seconds\nStation aa:bb:cc:dd:ee:ff (on wlp4s0b1)\n\tsignal:  \tnot-a-number dBm\n";
        let stations = parse_station_dump(dump);
        assert_eq!(stations.len(), 2);
        assert_eq!(
            stations[0],
            WirelessStation {
                mac: "06:c9:3e:84:a9:47".to_string(),
                signal_dbm: Some(-45),
                inactive_ms: Some(1230),
                rx_bytes: Some(12345),
                tx_bytes: Some(6789),
                connected_secs: Some(120),
            }
        );
        assert_eq!(stations[1].mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(stations[1].signal_dbm, None);
    }

    #[test]
    fn an_empty_dump_has_no_stations() {
        assert!(parse_station_dump("").is_empty());
    }
}
