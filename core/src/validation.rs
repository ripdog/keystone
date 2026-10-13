//! Validation at privileged configuration-generation boundaries.
//! Deserialization alone does not make strings safe to embed in config files.
use ipnet::IpNet;
use serde::Serialize;
use serde_json::Value;
use std::net::IpAddr;

/// True when `value` can sit on one line of a generated configuration file:
/// it has no control characters (newlines, NUL, escapes, and so on) and no
/// Unicode line or paragraph separators.
pub fn is_single_line(value: &str) -> bool {
    !value
        .chars()
        .any(|c| c.is_control() || c == '\u{2028}' || c == '\u{2029}')
}

/// Reject ASCII/Unicode control characters in any string that would become a
/// networkd/dnsmasq configuration value. In particular, a newline must never
/// introduce a second service directive.
pub fn single_line_fields<T: Serialize>(config: &T) -> Result<(), String> {
    fn inspect(value: &Value, location: &str) -> Result<(), String> {
        match value {
            Value::String(s) => {
                if !is_single_line(s) {
                    return Err(format!("{location} contains disallowed control characters"));
                }
                if s.len() > 4096 {
                    return Err(format!("{location} is too long"));
                }
            }
            Value::Object(obj) => {
                for (key, child) in obj {
                    inspect(child, &format!("{location}.{key}"))?;
                }
            }
            Value::Array(items) => {
                for (i, child) in items.iter().enumerate() {
                    inspect(child, &format!("{location}[{i}]"))?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    inspect(
        &serde_json::to_value(config).map_err(|e| e.to_string())?,
        "configuration",
    )
}

/// Kernel network interface names cannot contain path separators, whitespace,
/// colons or config metacharacters. Keep filesystem-derived paths in-tree.
pub fn interface_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 15
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        || name == "."
        || name == ".."
        || name.starts_with('-')
    {
        return Err(format!("Invalid network interface name: {name:?}"));
    }
    Ok(())
}

/// Group names are shared by address and port groups: a lowercase letter, then
/// lowercase letters, digits or underscores, at most 31 characters in total.
pub fn group_name(name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    let starts_well = matches!(chars.next(), Some('a'..='z'));
    if starts_well && name.len() <= 31 && chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_')) {
        return Ok(());
    }
    Err(format!(
        "group name {name:?} must start with a lowercase letter and contain only lowercase letters, digits and underscores (at most 31 characters)"
    ))
}

/// One address-group entry: an IPv4 or IPv6 address, or a CIDR network whose
/// host bits are zero (`10.0.0.0/8`, not `10.1.2.3/8`).
pub fn address_group_entry(entry: &str) -> Result<IpNet, String> {
    let value = entry.trim();
    if let Ok(net) = value.parse::<IpNet>() {
        if net.addr() != net.network() {
            return Err(format!(
                "{value} has host bits set; write the network address {}",
                net.trunc()
            ));
        }
        return Ok(net);
    }
    match value.parse::<IpAddr>() {
        Ok(addr) => IpNet::new(addr, if addr.is_ipv4() { 32 } else { 128 })
            .map_err(|error| format!("{value}: {error}")),
        Err(_) => Err(format!("{value:?} is not an IP address or CIDR network")),
    }
}

/// One port-group entry: a port (`443`) or an inclusive range (`8000-8100`).
/// Returns the inclusive `(start, end)` pair; a single port has `start == end`.
pub fn port_group_entry(entry: &str) -> Result<(u16, u16), String> {
    let value = entry.trim();
    let parse_port = |text: &str| match text.trim().parse::<u16>() {
        Ok(port) if port > 0 => Ok(port),
        _ => Err(format!("{value:?} is not a port between 1 and 65535")),
    };
    match value.split_once('-') {
        Some((start, end)) => {
            let (start, end) = (parse_port(start)?, parse_port(end)?);
            if end < start {
                return Err(format!("{value:?}: the range end is less than its start"));
            }
            Ok((start, end))
        }
        None => {
            let port = parse_port(value)?;
            Ok((port, port))
        }
    }
}

/// A bare host/IP without Caddyfile grammar, whitespace, ports or URI syntax.
pub fn hostname_or_ip(name: &str) -> Result<(), String> {
    if name.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    if name.len() > 253
        || name.is_empty()
        || name.split('.').any(|part| {
            part.is_empty()
                || part.len() > 63
                || part.starts_with('-')
                || part.ends_with('-')
                || !part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err("Expected a single DNS hostname or IP address".to_owned());
    }
    Ok(())
}

/// Restrict custom TLS syntax to supported certificate and DNS-challenge
/// directives instead of treating it as an unrestricted Caddyfile fragment.
pub fn custom_tls_config(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("Custom TLS mode requires a TLS configuration".into());
    }
    let trimmed: Vec<&str> = value
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let valid_files = if let [line] = trimmed.as_slice() {
        let parts: Vec<&str> = line.split_ascii_whitespace().collect();
        parts.len() == 3
            && parts[0] == "tls"
            && parts[1..].iter().all(|path| {
                path.starts_with('/')
                    && path.len() < 1024
                    && path
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
            })
    } else {
        false
    };
    let valid_dns = if let ["tls {", dns, "}"] = trimmed.as_slice() {
        let parts: Vec<&str> = dns.split_ascii_whitespace().collect();
        parts.len() == 3
            && parts[0] == "dns"
            && parts[1] == "cloudflare"
            && parts[2].starts_with("{env.")
            && parts[2].ends_with('}')
            && parts[2][5..parts[2].len() - 1]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    } else {
        false
    };
    if valid_files || valid_dns {
        Ok(())
    } else {
        Err("Only 'tls /absolute/cert /absolute/key' or a Cloudflare DNS challenge block is supported".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cannot_inject_dnsmasq_directive() {
        assert!(
            single_line_fields(&serde_json::json!({
                "hostnames":["example.org\ndhcp-script=/bin/true"]
            }))
            .is_err()
        );
        assert!(single_line_fields(&serde_json::json!({"hostnames":["a.example"]})).is_ok());
    }
    #[test]
    fn interface_cannot_escape_networkd_directory() {
        assert!(interface_name("../evil").is_err());
        assert!(interface_name("eth0\n[Service]").is_err());
        assert!(interface_name("br-lan").is_ok());
    }
    #[test]
    fn caddy_rejects_extra_sites() {
        assert!(hostname_or_ip("router.example\nsite.example").is_err());
        assert!(custom_tls_config("tls {\n dns cloudflare {env.CF_API_TOKEN}\n}").is_ok());
        assert!(
            custom_tls_config("tls {\n dns cloudflare {env.CF_API_TOKEN}\n}\nother.example {")
                .is_err()
        );
    }
}
