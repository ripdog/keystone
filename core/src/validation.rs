//! Validation at privileged configuration-generation boundaries.
//! Deserialization alone does not make strings safe to embed in config files.
use serde::Serialize;
use serde_json::Value;

/// Reject ASCII/Unicode control characters in any string that would become a
/// networkd/dnsmasq configuration value. In particular, a newline must never
/// introduce a second service directive.
pub fn single_line_fields<T: Serialize>(config: &T) -> Result<(), String> {
    fn inspect(value: &Value, location: &str) -> Result<(), String> {
        match value {
            Value::String(s) => {
                if s.chars().any(char::is_control)
                    || s.contains('\u{2028}')
                    || s.contains('\u{2029}')
                {
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
