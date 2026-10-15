//! Console login banner. Gathers host facts locally (procfs, interface
//! addresses, `systemctl is-active`) so it works unprivileged and without a
//! token, and without the daemon being up.

use nix::ifaddrs::getifaddrs;
use std::collections::BTreeMap;
use std::fs;
use std::io::IsTerminal;
use std::net::IpAddr;
use std::process::{Command, Stdio};

const LOGO: [&str; 6] = [
    "██╗  ██╗███████╗██╗   ██╗███████╗████████╗ ██████╗ ███╗   ██╗███████╗",
    "██║ ██╔╝██╔════╝╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔═══██╗████╗  ██║██╔════╝",
    "█████╔╝ █████╗   ╚████╔╝ ███████╗   ██║   ██║   ██║██╔██╗ ██║█████╗",
    "██╔═██╗ ██╔══╝    ╚██╔╝  ╚════██║   ██║   ██║   ██║██║╚██╗██║██╔══╝",
    "██║  ██╗███████╗   ██║   ███████║   ██║   ╚██████╔╝██║ ╚████║███████╗",
    "╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚══════╝",
];

const SERVICES: &[&str] = &["keystone-daemon", "keystone-web-ui"];

pub struct Facts {
    pub hostname: String,
    pub kernel: String,
    pub uptime_secs: u64,
    pub load: String,
    pub mem_used_pct: Option<u8>,
    /// `(interface, addresses)` sorted by name, loopback excluded.
    pub interfaces: Vec<(String, Vec<String>)>,
    pub services: Vec<(String, String)>,
}

pub fn run() {
    let color = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    print!("{}", render(&collect(), color));
}

fn collect() -> Facts {
    let read = |p: &str| fs::read_to_string(p).unwrap_or_default();
    let load = read("/proc/loadavg")
        .split_whitespace()
        .take(3)
        .collect::<Vec<_>>()
        .join(" ");
    Facts {
        hostname: read("/proc/sys/kernel/hostname").trim().to_owned(),
        kernel: read("/proc/sys/kernel/osrelease").trim().to_owned(),
        uptime_secs: read("/proc/uptime")
            .split_whitespace()
            .next()
            .and_then(|s| s.parse::<f64>().ok())
            .map_or(0, |s| s as u64),
        load,
        mem_used_pct: mem_used_pct(&read("/proc/meminfo")),
        interfaces: interface_addresses(),
        services: SERVICES
            .iter()
            .map(|s| ((*s).to_owned(), service_state(s)))
            .collect(),
    }
}

fn service_state(unit: &str) -> String {
    Command::new("systemctl")
        .args(["is-active", unit])
        .stderr(Stdio::null())
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

fn interface_addresses() -> Vec<(String, Vec<String>)> {
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let Ok(addrs) = getifaddrs() else {
        return Vec::new();
    };
    for ifa in addrs {
        if ifa.interface_name == "lo" {
            continue;
        }
        let entry = map.entry(ifa.interface_name.clone()).or_default();
        let Some(addr) = ifa.address else { continue };
        if let Some(v4) = addr.as_sockaddr_in() {
            entry.push(IpAddr::V4(v4.ip()).to_string());
        } else if let Some(v6) = addr.as_sockaddr_in6() {
            let ip = v6.ip();
            // Link-local addresses are noise on a banner.
            if ip.segments()[0] & 0xffc0 != 0xfe80 {
                entry.push(IpAddr::V6(ip).to_string());
            }
        }
    }
    map.into_iter()
        .filter(|(name, _)| !is_virtual(name))
        .collect()
}

/// Container/VM plumbing that would drown the real interfaces.
fn is_virtual(name: &str) -> bool {
    ["veth", "docker", "br-", "virbr", "vnet"]
        .iter()
        .any(|p| name.starts_with(p))
}

fn mem_used_pct(meminfo: &str) -> Option<u8> {
    let field = |key: &str| -> Option<u64> {
        meminfo
            .lines()
            .find_map(|l| l.strip_prefix(key)?.split_whitespace().next()?.parse().ok())
    };
    let total = field("MemTotal:")?;
    let avail = field("MemAvailable:")?;
    (total > 0).then(|| (total.saturating_sub(avail) * 100 / total) as u8)
}

fn format_uptime(secs: u64) -> String {
    let (d, h, m) = (secs / 86_400, secs % 86_400 / 3_600, secs % 3_600 / 60);
    match (d, h) {
        (0, 0) => format!("{m}m"),
        (0, _) => format!("{h}h {m}m"),
        _ => format!("{d}d {h}h"),
    }
}

pub fn render(f: &Facts, color: bool) -> String {
    let mut out = String::from("\n");
    for row in LOGO {
        if color {
            out.push_str(&format!("  \x1b[36m{row}\x1b[0m\n"));
        } else {
            out.push_str(&format!("  {row}\n"));
        }
    }
    out.push_str(&format!("\n  on {}\n  {}\n\n", f.hostname, "─".repeat(69)));
    let mem = f.mem_used_pct.map_or("n/a".into(), |p| format!("{p}%"));
    out.push_str(&format!(
        "  Uptime   {}\n  Load     {}\n  Memory   {}\n  Kernel   {}\n\n",
        format_uptime(f.uptime_secs),
        f.load,
        mem,
        f.kernel
    ));
    for (name, addrs) in &f.interfaces {
        let list = if addrs.is_empty() {
            "no address".to_owned()
        } else {
            addrs.join(", ")
        };
        out.push_str(&format!("  {name:<12} {list}\n"));
    }
    out.push('\n');
    for (name, state) in &f.services {
        let mark = if state == "active" { "●" } else { "○" };
        out.push_str(&format!("  {mark} {name} ({state})\n"));
    }
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> Facts {
        Facts {
            hostname: "gw".into(),
            kernel: "6.1".into(),
            uptime_secs: 90_061,
            load: "0.1 0.2 0.3".into(),
            mem_used_pct: Some(42),
            interfaces: vec![
                ("eth0".into(), vec!["192.0.2.1".into()]),
                ("eth1".into(), vec![]),
            ],
            services: vec![
                ("keystone-daemon".into(), "active".into()),
                ("keystone-web-ui".into(), "failed".into()),
            ],
        }
    }

    #[test]
    fn renders_host_facts_interfaces_and_service_state() {
        let out = render(&facts(), false);
        assert!(out.contains("gw"));
        assert!(out.contains("╚═╝"));
        assert!(!out.contains('\x1b'));
        assert!(render(&facts(), true).contains("\x1b[36m"));
        assert!(out.contains("1d 1h"));
        assert!(out.contains("42%"));
        assert!(out.contains("eth0") && out.contains("192.0.2.1"));
        assert!(out.contains("no address"));
        assert!(out.contains("● keystone-daemon (active)"));
        assert!(out.contains("○ keystone-web-ui (failed)"));
    }

    #[test]
    fn parses_memory_usage() {
        let m = "MemTotal: 1000 kB\nMemAvailable: 250 kB\n";
        assert_eq!(mem_used_pct(m), Some(75));
        assert_eq!(mem_used_pct(""), None);
    }

    #[test]
    fn uptime_formats() {
        assert_eq!(format_uptime(300), "5m");
        assert_eq!(format_uptime(7_500), "2h 5m");
    }

    #[test]
    fn hides_container_interfaces() {
        assert!(is_virtual("veth1234"));
        assert!(!is_virtual("eth0"));
    }
}
