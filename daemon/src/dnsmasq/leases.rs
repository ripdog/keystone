//! Dnsmasq lease file parsing
//!
//! Parses the dnsmasq lease file to get current active DHCP leases.
//! Default location: /var/lib/dnsmasq/dnsmasq.leases

use anyhow::Result;
use keystone_core::DhcpLease;
use std::fs;
use std::path::Path;
use tracing::debug;

use super::config::DNSMASQ_LEASE_FILE;

/// Parse the dnsmasq lease file and return active leases
///
/// The lease file format is:
/// ```text
/// expire_time mac_address ip_address hostname client_id
/// ```
///
/// Where:
/// - expire_time: Unix timestamp when lease expires (0 for infinite)
/// - mac_address: Client MAC address
/// - ip_address: Assigned IP address
/// - hostname: Client hostname (* if not provided)
/// - client_id: Client identifier (optional, * if not provided)
pub fn parse_lease_file() -> Result<Vec<DhcpLease>> {
    parse_lease_file_path(DNSMASQ_LEASE_FILE)
}

/// Parse a lease file from a specific path
pub fn parse_lease_file_path<P: AsRef<Path>>(path: P) -> Result<Vec<DhcpLease>> {
    let path = path.as_ref();

    if !path.exists() {
        debug!("Lease file does not exist: {:?}", path);
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(path)?;
    let mut leases = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(lease) = parse_lease_line(line) {
            leases.push(lease);
        }
    }

    // Sort by IP address for consistent ordering
    leases.sort_by(|a, b| {
        // Parse IP addresses for proper numeric sorting
        let a_parts: Vec<u8> = a
            .ip_address
            .split('.')
            .filter_map(|s| s.parse().ok())
            .collect();
        let b_parts: Vec<u8> = b
            .ip_address
            .split('.')
            .filter_map(|s| s.parse().ok())
            .collect();
        a_parts.cmp(&b_parts)
    });

    debug!("Parsed {} active leases from {:?}", leases.len(), path);
    Ok(leases)
}

/// Parse a single lease line
fn parse_lease_line(line: &str) -> Option<DhcpLease> {
    let parts: Vec<&str> = line.split_whitespace().collect();

    if parts.len() < 4 {
        return None;
    }

    let expires_at: u64 = parts[0].parse().ok()?;
    let mac_address = parts[1].to_string();
    let ip_address = parts[2].to_string();

    // Hostname - * means not provided
    let hostname = if parts[3] == "*" {
        None
    } else {
        Some(parts[3].to_string())
    };

    // Client ID - optional field, * means not provided
    let client_id = parts
        .get(4)
        .and_then(|s| if *s == "*" { None } else { Some(s.to_string()) });

    Some(DhcpLease {
        mac_address,
        ip_address,
        hostname,
        expires_at,
        client_id,
    })
}

/// Get only active (non-expired) leases
pub fn get_active_leases() -> Result<Vec<DhcpLease>> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let leases = parse_lease_file()?;

    Ok(leases
        .into_iter()
        .filter(|l| l.expires_at == 0 || l.expires_at > now) // 0 = infinite
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_lease_line_basic() {
        let line = "1735500000 00:11:22:33:44:55 192.168.1.100 myhost *";
        let lease = parse_lease_line(line).unwrap();

        assert_eq!(lease.expires_at, 1735500000);
        assert_eq!(lease.mac_address, "00:11:22:33:44:55");
        assert_eq!(lease.ip_address, "192.168.1.100");
        assert_eq!(lease.hostname, Some("myhost".to_string()));
        assert_eq!(lease.client_id, None);
    }

    #[test]
    fn test_parse_lease_line_with_client_id() {
        let line = "1735500000 00:11:22:33:44:55 192.168.1.100 myhost 01:00:11:22:33:44:55";
        let lease = parse_lease_line(line).unwrap();

        assert_eq!(lease.expires_at, 1735500000);
        assert_eq!(lease.mac_address, "00:11:22:33:44:55");
        assert_eq!(lease.ip_address, "192.168.1.100");
        assert_eq!(lease.hostname, Some("myhost".to_string()));
        assert_eq!(lease.client_id, Some("01:00:11:22:33:44:55".to_string()));
    }

    #[test]
    fn test_parse_lease_line_no_hostname() {
        let line = "1735500000 00:11:22:33:44:55 192.168.1.100 * *";
        let lease = parse_lease_line(line).unwrap();

        assert_eq!(lease.hostname, None);
        assert_eq!(lease.client_id, None);
    }

    #[test]
    fn test_parse_lease_line_infinite() {
        let line = "0 00:11:22:33:44:55 192.168.1.100 server infinite";
        let lease = parse_lease_line(line).unwrap();

        assert_eq!(lease.expires_at, 0);
        assert_eq!(lease.hostname, Some("server".to_string()));
    }

    #[test]
    fn test_parse_lease_line_invalid() {
        assert!(parse_lease_line("").is_none());
        assert!(parse_lease_line("# comment").is_none());
        assert!(parse_lease_line("invalid line").is_none());
        assert!(parse_lease_line("abc def ghi").is_none()); // expires_at not a number
    }

    #[test]
    fn test_parse_lease_file_content() {
        // Create a temporary file with test content
        let content = r#"
# dnsmasq lease file
1735500000 00:11:22:33:44:55 192.168.1.100 server1 *
1735600000 00:11:22:33:44:56 192.168.1.101 * 01:00:11:22:33:44:56
0 00:11:22:33:44:57 192.168.1.10 static-server *
"#;

        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("test_leases");
        std::fs::write(&temp_file, content).unwrap();

        let leases = parse_lease_file_path(&temp_file).unwrap();

        assert_eq!(leases.len(), 3);

        // Should be sorted by IP
        assert_eq!(leases[0].ip_address, "192.168.1.10");
        assert_eq!(leases[1].ip_address, "192.168.1.100");
        assert_eq!(leases[2].ip_address, "192.168.1.101");

        // Clean up
        let _ = std::fs::remove_file(temp_file);
    }
}
