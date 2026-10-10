//! System status checks for Keystone
//!
//! Performs various checks to ensure the system is properly configured for Keystone.

use keystone_core::{CheckCategory, CheckSeverity, SystemCheck, SystemStatusResponse};
use std::fs;
use std::path::Path;
use std::process::Command;
use tracing::debug;

/// Interface prefixes that indicate virtual/fake interfaces (not physical NICs)
const VIRTUAL_INTERFACE_PREFIXES: &[&str] = &[
    "lo",        // Loopback
    "docker",    // Docker bridge
    "br-",       // Docker/other bridges (but not br0 etc.)
    "veth",      // Virtual ethernet (containers)
    "virbr",     // libvirt bridge
    "vnet",      // libvirt VMs
    "tun",       // VPN tunnel
    "tap",       // VPN tunnel
    "wg",        // WireGuard
    "tailscale", // Tailscale VPN
    "vlan",      // Our own VLAN interfaces
];

/// Perform all system status checks
pub fn perform_all_checks(setup_complete: bool) -> SystemStatusResponse {
    let checks = vec![
        // Package checks
        check_package_nftables(),
        check_package_iproute2(),
        check_package_dnsmasq(setup_complete),
        check_package_caddy(),
        // Service checks
        check_service_systemd_networkd(),
        check_service_network_manager(),
        check_service_nftables(),
        // Permission checks
        check_permission_networkd_dir(),
        check_permission_dnsmasq_dir(),
        check_permission_keystone_data_dir(),
        // Network checks
        check_network_interfaces(),
        // Configuration checks
        check_daemon_running_as_root(),
    ];

    // Count errors and warnings
    let error_count = checks
        .iter()
        .filter(|c| c.severity == CheckSeverity::Error)
        .count() as u32;
    let warning_count = checks
        .iter()
        .filter(|c| c.severity == CheckSeverity::Warning)
        .count() as u32;

    // All checks pass if there are no errors (warnings are acceptable)
    let all_checks_pass = error_count == 0;

    SystemStatusResponse {
        all_checks_pass,
        setup_complete,
        error_count,
        warning_count,
        checks,
    }
}

/// Check if a command exists in PATH
fn command_exists(cmd: &str) -> bool {
    if cmd.is_empty() {
        return false;
    }

    if cmd.contains('/') {
        return Path::new(cmd).is_file();
    }

    std::env::var_os("PATH")
        .and_then(|path| {
            std::env::split_paths(&path)
                .map(|dir| dir.join(cmd))
                .find(|candidate| candidate.is_file())
        })
        .is_some()
}

/// Check if a systemd service is enabled
fn service_is_enabled(service: &str) -> bool {
    Command::new("systemctl")
        .args(["is-enabled", "--quiet", service])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Check if a systemd service is active
fn service_is_active(service: &str) -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", service])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn can_create_temp_file(dir: &Path) -> bool {
    if !dir.is_dir() {
        return false;
    }

    let path = dir.join(".keystone_write_test");
    let result = fs::write(&path, b"test").is_ok();
    let _ = fs::remove_file(&path);
    result
}

// ============================================================================
// Package Checks
// ============================================================================

fn check_package_nftables() -> SystemCheck {
    let exists = command_exists("nft");
    if !exists {
        return SystemCheck {
            id: "pkg_nftables".to_string(),
            name: "nftables".to_string(),
            category: CheckCategory::Package,
            severity: CheckSeverity::Error,
            message: "nftables is not installed - firewall functionality will not work".to_string(),
            fix_advice: Some("Install nftables: pacman -S nftables".to_string()),
        };
    }

    // Runtime sanity check: ensure nft can talk to kernel/netlink
    let output = Command::new("nft").args(["list", "ruleset"]).output();

    match output {
        Ok(o) if o.status.success() => SystemCheck {
            id: "pkg_nftables".to_string(),
            name: "nftables".to_string(),
            category: CheckCategory::Package,
            severity: CheckSeverity::Pass,
            message: "nftables is installed and working".to_string(),
            fix_advice: None,
        },
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr).trim().to_string();
            SystemCheck {
                id: "pkg_nftables".to_string(),
                name: "nftables".to_string(),
                category: CheckCategory::Package,
                severity: CheckSeverity::Error,
                message: if stderr.is_empty() {
                    "nftables is installed but failed to query the ruleset".to_string()
                } else {
                    format!("nftables failed to query ruleset: {}", stderr)
                },
                fix_advice: Some(
                    "Ensure Keystone daemon runs as root and the kernel supports nftables"
                        .to_string(),
                ),
            }
        }
        Err(e) => SystemCheck {
            id: "pkg_nftables".to_string(),
            name: "nftables".to_string(),
            category: CheckCategory::Package,
            severity: CheckSeverity::Error,
            message: format!("Failed to execute nft: {}", e),
            fix_advice: Some("Check nftables installation and PATH".to_string()),
        },
    }
}

fn check_package_iproute2() -> SystemCheck {
    let exists = command_exists("ip");
    SystemCheck {
        id: "pkg_iproute2".to_string(),
        name: "iproute2".to_string(),
        category: CheckCategory::Package,
        severity: if exists {
            CheckSeverity::Pass
        } else {
            CheckSeverity::Error
        },
        message: if exists {
            "iproute2 is installed".to_string()
        } else {
            "iproute2 (ip command) is not installed - network configuration will not work"
                .to_string()
        },
        fix_advice: if exists {
            None
        } else {
            Some("Install iproute2: pacman -S iproute2".to_string())
        },
    }
}

fn dnsmasq_check_severity(installed: bool, setup_complete: bool) -> CheckSeverity {
    if installed {
        CheckSeverity::Pass
    } else if setup_complete {
        CheckSeverity::Warning
    } else {
        // The initial SOHO wizard always provisions DHCP/DNS.
        CheckSeverity::Error
    }
}

fn check_package_dnsmasq(setup_complete: bool) -> SystemCheck {
    let exists = command_exists("dnsmasq");
    SystemCheck {
        id: "pkg_dnsmasq".to_string(),
        name: "dnsmasq".to_string(),
        category: CheckCategory::Package,
        severity: dnsmasq_check_severity(exists, setup_complete),
        message: if exists {
            "dnsmasq is installed".to_string()
        } else if setup_complete {
            "dnsmasq is not installed - DNS/DHCP server features will not be available".to_string()
        } else {
            "dnsmasq is required to complete initial router setup".to_string()
        },
        fix_advice: if exists {
            None
        } else {
            Some("Install dnsmasq: pacman -S dnsmasq".to_string())
        },
    }
}

fn check_package_caddy() -> SystemCheck {
    let exists = command_exists("caddy");
    SystemCheck {
        id: "pkg_caddy".to_string(),
        name: "Caddy".to_string(),
        category: CheckCategory::Package,
        severity: if exists {
            CheckSeverity::Pass
        } else {
            CheckSeverity::Warning
        },
        message: if exists {
            "Caddy is installed".to_string()
        } else {
            "Caddy is not installed - HTTPS reverse proxy features will not be available"
                .to_string()
        },
        fix_advice: if exists {
            None
        } else {
            Some("Install Caddy if you need HTTPS: pacman -S caddy".to_string())
        },
    }
}

// ============================================================================
// Service Checks
// ============================================================================

fn check_service_systemd_networkd() -> SystemCheck {
    let enabled = service_is_enabled("systemd-networkd.service");
    let active = service_is_active("systemd-networkd.service");

    let (severity, message) = match (enabled, active) {
        (true, true) => (
            CheckSeverity::Pass,
            "systemd-networkd is enabled and running".to_string(),
        ),
        (true, false) => (
            CheckSeverity::Warning,
            "systemd-networkd is enabled but not running".to_string(),
        ),
        (false, true) => (
            CheckSeverity::Warning,
            "systemd-networkd is running but not enabled at boot".to_string(),
        ),
        (false, false) => (
            CheckSeverity::Error,
            "systemd-networkd is not enabled or running - network configuration will not work"
                .to_string(),
        ),
    };

    SystemCheck {
        id: "svc_networkd".to_string(),
        name: "systemd-networkd".to_string(),
        category: CheckCategory::Service,
        severity,
        message,
        fix_advice: if severity == CheckSeverity::Pass {
            None
        } else {
            Some("Enable and start: systemctl enable --now systemd-networkd".to_string())
        },
    }
}

fn check_service_network_manager() -> SystemCheck {
    let active = service_is_active("NetworkManager.service");

    SystemCheck {
        id: "svc_networkmanager".to_string(),
        name: "NetworkManager".to_string(),
        category: CheckCategory::Service,
        severity: if active {
            CheckSeverity::Warning
        } else {
            CheckSeverity::Pass
        },
        message: if active {
            "NetworkManager is running - it may conflict with systemd-networkd".to_string()
        } else {
            "NetworkManager is not running".to_string()
        },
        fix_advice: if active {
            Some("Disable NetworkManager if using systemd-networkd: systemctl disable --now NetworkManager".to_string())
        } else {
            None
        },
    }
}

fn check_service_nftables() -> SystemCheck {
    // nftables service is optional - we apply rules directly
    // But if it exists and is enabled, that's good for persistence
    let enabled = service_is_enabled("nftables.service");

    SystemCheck {
        id: "svc_nftables".to_string(),
        name: "nftables service".to_string(),
        category: CheckCategory::Service,
        severity: if enabled {
            CheckSeverity::Pass
        } else {
            CheckSeverity::Warning
        },
        message: if enabled {
            "nftables service is enabled (rules will persist across reboots)".to_string()
        } else {
            "nftables service is not enabled - firewall rules may not persist across reboots"
                .to_string()
        },
        fix_advice: if enabled {
            None
        } else {
            Some("Enable nftables: systemctl enable nftables".to_string())
        },
    }
}

// ============================================================================
// Permission Checks
// ============================================================================

fn check_permission_networkd_dir() -> SystemCheck {
    let path = Path::new("/etc/systemd/network");
    let exists = path.exists();
    let writable = exists && can_create_temp_file(path);

    let (severity, message) = match (exists, writable) {
        (true, true) => (
            CheckSeverity::Pass,
            "/etc/systemd/network exists and is writable".to_string(),
        ),
        (true, false) => (
            CheckSeverity::Error,
            "/etc/systemd/network exists but is not writable".to_string(),
        ),
        (false, _) => (
            CheckSeverity::Error,
            "/etc/systemd/network does not exist".to_string(),
        ),
    };

    SystemCheck {
        id: "perm_networkd_dir".to_string(),
        name: "networkd config directory".to_string(),
        category: CheckCategory::Permission,
        severity,
        message,
        fix_advice: if severity == CheckSeverity::Pass {
            None
        } else {
            Some("Create directory: mkdir -p /etc/systemd/network".to_string())
        },
    }
}

fn check_permission_dnsmasq_dir() -> SystemCheck {
    let path = Path::new("/etc/dnsmasq.d");
    let exists = path.exists();
    let writable = exists && can_create_temp_file(path);

    // This is only a warning since dnsmasq is optional
    let (severity, message) = match (exists, writable) {
        (true, true) => (
            CheckSeverity::Pass,
            "/etc/dnsmasq.d exists and is writable".to_string(),
        ),
        (true, false) => (
            CheckSeverity::Warning,
            "/etc/dnsmasq.d exists but is not writable".to_string(),
        ),
        (false, _) => (
            CheckSeverity::Warning,
            "/etc/dnsmasq.d does not exist - will be created when dnsmasq is configured"
                .to_string(),
        ),
    };

    SystemCheck {
        id: "perm_dnsmasq_dir".to_string(),
        name: "dnsmasq config directory".to_string(),
        category: CheckCategory::Permission,
        severity,
        message,
        fix_advice: if exists {
            None
        } else {
            Some("Create directory if using dnsmasq: mkdir -p /etc/dnsmasq.d".to_string())
        },
    }
}

fn check_permission_keystone_data_dir() -> SystemCheck {
    let path = Path::new("/var/lib/keystone");
    let exists = path.exists();
    let writable = exists && can_create_temp_file(path);

    let (severity, message) = match (exists, writable) {
        (true, true) => (
            CheckSeverity::Pass,
            "/var/lib/keystone exists and is writable".to_string(),
        ),
        (true, false) => (
            CheckSeverity::Error,
            "/var/lib/keystone exists but is not writable".to_string(),
        ),
        (false, _) => (
            CheckSeverity::Error,
            "/var/lib/keystone does not exist".to_string(),
        ),
    };

    SystemCheck {
        id: "perm_keystone_data".to_string(),
        name: "Keystone data directory".to_string(),
        category: CheckCategory::Permission,
        severity,
        message,
        fix_advice: if severity == CheckSeverity::Pass {
            None
        } else {
            Some(
                "Create directory: mkdir -p /var/lib/keystone && chmod 700 /var/lib/keystone"
                    .to_string(),
            )
        },
    }
}

// ============================================================================
// Network Checks
// ============================================================================

fn check_network_interfaces() -> SystemCheck {
    let interfaces = get_physical_interfaces();
    let count = interfaces.len();

    debug!(
        "Found {} physical network interfaces: {:?}",
        count, interfaces
    );

    let (severity, message) = if count >= 2 {
        (
            CheckSeverity::Pass,
            format!(
                "Found {} physical network interfaces: {}",
                count,
                interfaces.join(", ")
            ),
        )
    } else if count == 1 {
        (
            CheckSeverity::Warning,
            format!(
                "Only 1 physical network interface found ({}). A router typically needs at least 2 interfaces (WAN and LAN).",
                interfaces.first().unwrap_or(&"unknown".to_string())
            ),
        )
    } else {
        (
            CheckSeverity::Error,
            "No physical network interfaces found! Keystone requires at least one network interface.".to_string(),
        )
    };

    SystemCheck {
        id: "net_interfaces".to_string(),
        name: "Network interfaces".to_string(),
        category: CheckCategory::Network,
        severity,
        message,
        fix_advice: if count < 2 {
            Some("Ensure your system has at least 2 physical network interfaces for WAN and LAN. Virtual interfaces like Docker bridges, VPNs, and loopback are filtered out.".to_string())
        } else {
            None
        },
    }
}

/// Get list of physical network interfaces (filtering out virtual ones)
pub(crate) fn get_physical_interfaces() -> Vec<String> {
    let mut interfaces = Vec::new();

    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();

            // Check if this is a virtual interface
            let is_virtual = VIRTUAL_INTERFACE_PREFIXES
                .iter()
                .any(|prefix| name.starts_with(prefix));

            if is_virtual {
                debug!("Filtering out virtual interface: {}", name);
                continue;
            }

            // Additional check: look at the device type
            // Physical NICs typically have a "device" symlink in /sys/class/net/<iface>/
            let device_path = entry.path().join("device");
            if !device_path.exists() && name != "lo" {
                // No device symlink and not loopback - might be virtual
                // But let's also check if it's a bridge we created (starts with br and followed by a digit)
                if name.starts_with("br") && name.chars().nth(2).is_some_and(|c| c.is_ascii_digit())
                {
                    // This is likely a user-created bridge like br0, br1 - include it
                    interfaces.push(name);
                    continue;
                }

                // Check for bond interfaces
                if name.starts_with("bond") {
                    interfaces.push(name);
                    continue;
                }

                debug!("Filtering out interface without device symlink: {}", name);
                continue;
            }

            interfaces.push(name);
        }
    }

    interfaces.sort();
    interfaces
}

// ============================================================================
// Configuration Checks
// ============================================================================

fn check_daemon_running_as_root() -> SystemCheck {
    let is_root = nix::unistd::Uid::effective().is_root();

    SystemCheck {
        id: "cfg_root".to_string(),
        name: "Daemon privileges".to_string(),
        category: CheckCategory::Configuration,
        severity: if is_root {
            CheckSeverity::Pass
        } else {
            CheckSeverity::Error
        },
        message: if is_root {
            "Daemon is running with root privileges".to_string()
        } else {
            "Daemon is not running as root - many operations will fail".to_string()
        },
        fix_advice: if is_root {
            None
        } else {
            Some("Run the daemon as root: sudo keystone-daemon".to_string())
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_dnsmasq_blocks_initial_setup_but_not_other_modes() {
        assert_eq!(dnsmasq_check_severity(false, false), CheckSeverity::Error);
        assert_eq!(dnsmasq_check_severity(false, true), CheckSeverity::Warning);
        assert_eq!(dnsmasq_check_severity(true, false), CheckSeverity::Pass);
    }

    #[test]
    fn test_command_exists() {
        // ls should exist on any Unix system
        assert!(command_exists("ls"));
        // This should not exist
        assert!(!command_exists("nonexistent_command_12345"));
    }

    #[test]
    fn test_command_exists_with_path() {
        assert!(command_exists("/bin/ls") || command_exists("/usr/bin/ls"));
    }

    #[test]
    fn test_virtual_interface_filtering() {
        let test_names = vec![
            ("eth0", false),
            ("enp3s0", false),
            ("wlan0", false),
            ("lo", true),
            ("docker0", true),
            ("br-abc123", true),
            ("br0", false), // User bridge, should be kept
            ("veth123abc", true),
            ("virbr0", true),
            ("tun0", true),
            ("wg0", true),
            ("tailscale0", true),
            ("bond0", false), // Bond should be kept
        ];

        for (name, should_be_virtual) in test_names {
            let is_virtual = VIRTUAL_INTERFACE_PREFIXES
                .iter()
                .any(|prefix| name.starts_with(prefix));
            if should_be_virtual {
                assert!(is_virtual, "{} should be detected as virtual", name);
            } else {
                // For non-virtual, prefix check alone isn't sufficient
                // The real filtering uses device symlink check too
            }
        }
    }
}
