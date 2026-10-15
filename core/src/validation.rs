//! Validation at privileged configuration-generation boundaries.
//! Deserialization alone does not make strings safe to embed in config files.
use ipnet::IpNet;
use serde::Serialize;
use serde_json::Value;
use std::net::{IpAddr, Ipv6Addr};

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

/// Whether the kernel or udev assigns names like `name` on its own: `eth0`,
/// `wlan0`, the predictable `enp3s0`, `eno1`, `ens1`, `enx<mac>`, `end0` and
/// `wlp2s0` styles, and the `ifb4<wan>` devices Keystone creates for shaping.
fn is_system_assigned_name(name: &str) -> bool {
    const NUMBERED: &[&str] = &["eth", "wlan", "wwan", "usb", "veth", "ifb"];
    const PREDICTABLE: &[&str] = &["en", "wl", "ww"];
    if name == "lo" {
        return true;
    }
    if NUMBERED.iter().any(|prefix| {
        name.strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
    }) {
        return true;
    }
    if name.starts_with("end") && name[3..].starts_with(|c: char| c.is_ascii_digit()) {
        return true;
    }
    PREDICTABLE.iter().any(|prefix| {
        name.strip_prefix(prefix).is_some_and(|rest| {
            rest.len() > 1
                && rest.starts_with(['o', 'p', 's', 'x'])
                && rest[1..].starts_with(|c: char| c.is_ascii_digit() || c.is_ascii_hexdigit())
        })
    })
}

/// A name an administrator may give a physical interface, such as `wan0`.
/// Stricter than [`interface_name`]: dots are left for VLANs, and the names the
/// kernel and udev assign themselves are reserved, because a NIC renamed to a
/// name another device holds while it probes keeps its original name.
pub fn custom_interface_name(name: &str) -> Result<(), String> {
    interface_name(name)?;
    if name.contains('.') {
        return Err(format!(
            "Interface name {name:?} must not contain '.', which is reserved for VLANs"
        ));
    }
    if is_system_assigned_name(name) {
        return Err(format!(
            "Interface name {name:?} looks like a name the kernel or udev assigns itself; choose another name such as wan0 or lan0"
        ));
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

/// An IPv6 interface-identifier suffix such as `::1234` or `::a:b:c:d`: the low
/// 64 bits of an address, with the network half zero. A rule written with a
/// suffix matches any prefix, so it survives the ISP renumbering a delegated
/// prefix.
pub fn ipv6_suffix(text: &str) -> Result<Ipv6Addr, String> {
    let value = text.trim();
    let addr: Ipv6Addr = value
        .parse()
        .map_err(|_| format!("{value:?} is not an IPv6 suffix such as ::1234"))?;
    if addr.to_bits() >> 64 != 0 {
        return Err(format!(
            "{value} has bits set in the network half; a suffix has only the low 64 bits (e.g. ::1234)"
        ));
    }
    if addr.is_unspecified() {
        return Err("an IPv6 suffix cannot be all zeros".to_string());
    }
    Ok(addr)
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
    #[test]
    fn ipv6_suffix_accepts_only_low_64_bits() {
        assert_eq!(super::ipv6_suffix("::1234").unwrap().to_string(), "::1234");
        assert!(super::ipv6_suffix("::a:b:c:d").is_ok());
        assert!(super::ipv6_suffix("::").is_err());
        assert!(super::ipv6_suffix("2001:db8::1").is_err());
        assert!(super::ipv6_suffix("192.168.1.1").is_err());
        assert!(super::ipv6_suffix("::1/64").is_err());
    }

    use super::*;

    #[test]
    fn custom_interface_names_avoid_system_assigned_names() {
        for good in [
            "wan0",
            "lan0",
            "lan-guest",
            "uplink",
            "entry",
            "wifi0",
            "dmz",
        ] {
            assert!(custom_interface_name(good).is_ok(), "{good}");
        }
        for bad in [
            "eth0",
            "eth12",
            "wlan0",
            "enp3s0",
            "eno1",
            "ens1",
            "enx2cf05d3b621a",
            "end0",
            "wlp2s0",
            "wwan0",
            "usb0",
            "ifb4wan0",
            "veth1",
            "lo",
            "wan.10",
            "",
            "wan 0",
            "a_very_long_name_x",
            "-wan",
        ] {
            assert!(custom_interface_name(bad).is_err(), "{bad}");
        }
    }
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
