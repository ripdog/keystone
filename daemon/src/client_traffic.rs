//! Per-client internet throughput history.
//!
//! The kernel has no per-host byte counters, so Keystone owns a small nftables
//! table, `inet keystone_acct`, separate from the user-facing firewall tables
//! (a firewall apply never touches it). Its forward hook runs after the main
//! filter chain, so only traffic the firewall accepted is counted. Packets
//! leaving through a WAN interface are counted per source address, and packets
//! arriving from one per destination address, in dynamic sets that carry a
//! counter per element. Forwarding sees addresses between DNAT and SNAT, so
//! both directions are keyed by the LAN client's own address.
//!
//! Once a second the daemon lists the table, turns counter deltas into rates
//! and keeps one minute of history per address. The API sums the addresses of
//! each device. The table is created by the daemon from validated interface
//! names only; no file is written, so the service sandbox is not involved.

use crate::db::Database;
use anyhow::{Context, Result, bail};
use keystone_core::ClientTrafficSample;
use serde_json::Value;
use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    process::Stdio,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{io::AsyncWriteExt, process::Command, sync::RwLock, time};
use tracing::{debug, warn};

pub const TABLE: &str = "keystone_acct";
const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
/// How often the WAN interface list is re-read from the database.
const WAN_REFRESH_TICKS: u64 = 10;
const HISTORY_MS: u64 = 60_000;
const MAX_TICKS: usize = 61;

pub type ClientTrafficSnapshot = Arc<RwLock<Sampler>>;

/// Rates of every address that moved data during one sampling interval.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Tick {
    timestamp_ms: u64,
    /// Address to (download, upload) bytes per second. Idle addresses are omitted.
    rates: HashMap<IpAddr, (u64, u64)>,
}

/// Cumulative per-address byte counters read from the accounting table.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Readings {
    pub down: HashMap<IpAddr, u64>,
    pub up: HashMap<IpAddr, u64>,
}

#[derive(Default)]
pub struct Sampler {
    previous: Readings,
    sampled_at: Option<Instant>,
    ticks: VecDeque<Tick>,
}

impl Sampler {
    fn update(&mut self, readings: Readings, now: Instant, timestamp_ms: u64) {
        let elapsed_ms = self.sampled_at.map(|at| now.duration_since(at).as_millis());
        // Like the interface sampler, never turn a stalled poll into a spike.
        if elapsed_ms.is_some_and(|ms| (250..=3_000).contains(&ms)) {
            let elapsed_ms = elapsed_ms.unwrap_or(1);
            let mut rates: HashMap<IpAddr, (u64, u64)> = HashMap::new();
            for (ip, rate) in rates_between(&self.previous.down, &readings.down, elapsed_ms) {
                rates.entry(ip).or_default().0 = rate;
            }
            for (ip, rate) in rates_between(&self.previous.up, &readings.up, elapsed_ms) {
                rates.entry(ip).or_default().1 = rate;
            }
            self.ticks.push_back(Tick {
                timestamp_ms,
                rates,
            });
        }
        self.previous = readings;
        self.sampled_at = Some(now);
        while self
            .ticks
            .front()
            .is_some_and(|tick| timestamp_ms.saturating_sub(tick.timestamp_ms) > HISTORY_MS)
            || self.ticks.len() > MAX_TICKS
        {
            self.ticks.pop_front();
        }
    }

    /// Forget counters, e.g. after the table was recreated. History is kept.
    fn counters_reset(&mut self) {
        self.previous = Readings::default();
        self.sampled_at = None;
    }

    /// One sample per sampling tick with the addresses' rates added together.
    /// Ticks where none of the addresses moved data are zero, so every device
    /// gets the same evenly spaced timestamps.
    pub fn series_for(&self, addresses: &[IpAddr]) -> Vec<ClientTrafficSample> {
        self.ticks
            .iter()
            .map(|tick| {
                let (download, upload) = addresses
                    .iter()
                    .filter_map(|ip| tick.rates.get(ip))
                    .fold((0u64, 0u64), |(d, u), (rd, ru)| {
                        (d.saturating_add(*rd), u.saturating_add(*ru))
                    });
                ClientTrafficSample {
                    timestamp_ms: tick.timestamp_ms,
                    download_bytes_per_sec: download,
                    upload_bytes_per_sec: upload,
                }
            })
            .collect()
    }
}

/// Rates for addresses that were also present at the previous reading with a
/// counter that did not go backwards (an expired and re-added set element
/// restarts at zero). A first sighting has no baseline and produces no rate.
fn rates_between(
    previous: &HashMap<IpAddr, u64>,
    current: &HashMap<IpAddr, u64>,
    elapsed_ms: u128,
) -> impl Iterator<Item = (IpAddr, u64)> {
    current.iter().filter_map(move |(ip, bytes)| {
        let before = previous.get(ip)?;
        let delta = bytes.checked_sub(*before).filter(|delta| *delta > 0)?;
        let rate = (u128::from(delta) * 1_000 / elapsed_ms).min(u128::from(u64::MAX)) as u64;
        Some((*ip, rate))
    })
}

/// Interface names come from the database, but this script goes to nft, so
/// only the characters Linux interface names realistically use are accepted.
fn valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// nft script that atomically (re)creates the accounting table.
pub fn ruleset(wan_interfaces: &[String]) -> String {
    let wan: Vec<String> = wan_interfaces
        .iter()
        .filter(|name| valid_interface_name(name))
        .map(|name| format!("\"{name}\""))
        .collect();
    let wan_elements = if wan.is_empty() {
        String::new()
    } else {
        format!("elements = {{ {} }}", wan.join(", "))
    };
    // Elements expire after five idle minutes so departed devices drop out.
    format!(
        "add table inet {TABLE}\n\
         delete table inet {TABLE}\n\
         table inet {TABLE} {{\n\
         \tset wan_interfaces {{ type ifname; {wan_elements} }}\n\
         \tset down4 {{ type ipv4_addr; flags dynamic; counter; size 4096; timeout 5m; }}\n\
         \tset up4 {{ type ipv4_addr; flags dynamic; counter; size 4096; timeout 5m; }}\n\
         \tset down6 {{ type ipv6_addr; flags dynamic; counter; size 4096; timeout 5m; }}\n\
         \tset up6 {{ type ipv6_addr; flags dynamic; counter; size 4096; timeout 5m; }}\n\
         \tchain forward {{\n\
         \t\ttype filter hook forward priority filter + 10; policy accept;\n\
         \t\tiifname @wan_interfaces add @down4 {{ ip daddr counter }}\n\
         \t\toifname @wan_interfaces add @up4 {{ ip saddr counter }}\n\
         \t\tiifname @wan_interfaces add @down6 {{ ip6 daddr counter }}\n\
         \t\toifname @wan_interfaces add @up6 {{ ip6 saddr counter }}\n\
         \t}}\n\
         }}\n"
    )
}

/// Parse `nft -j list table inet keystone_acct` into per-address byte counters.
/// Elements that do not parse are skipped.
pub fn parse_readings(table: &Value) -> Readings {
    let mut readings = Readings::default();
    let objects = table
        .get("nftables")
        .and_then(Value::as_array)
        .into_iter()
        .flatten();
    for set in objects.filter_map(|object| object.get("set")) {
        let target = match set.get("name").and_then(Value::as_str) {
            Some("down4" | "down6") => &mut readings.down,
            Some("up4" | "up6") => &mut readings.up,
            _ => continue,
        };
        let elements = set.get("elem").and_then(Value::as_array);
        for element in elements.into_iter().flatten() {
            let Some(element) = element.get("elem") else {
                continue;
            };
            let address = element
                .get("val")
                .and_then(Value::as_str)
                .and_then(|text| text.parse::<IpAddr>().ok());
            let bytes = element
                .get("counter")
                .and_then(|counter| counter.get("bytes"))
                .and_then(Value::as_u64);
            if let (Some(address), Some(bytes)) = (address, bytes) {
                let total = target.entry(address).or_insert(0);
                *total = total.saturating_add(bytes);
            }
        }
    }
    readings
}

/// `None` when the table is not installed.
async fn read_table() -> Result<Option<Readings>> {
    let output = Command::new("nft")
        .args(["-j", "list", "table", "inet", TABLE])
        .stdin(Stdio::null())
        .output()
        .await
        .context("Failed to run nft")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("No such file or directory") {
            return Ok(None);
        }
        bail!("nft could not list {TABLE}: {}", stderr.trim());
    }
    let value: Value = serde_json::from_slice(&output.stdout).context("nft returned bad JSON")?;
    Ok(Some(parse_readings(&value)))
}

async fn install(wan_interfaces: &[String]) -> Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to run nft")?;
    let mut stdin = child.stdin.take().context("nft has no stdin")?;
    stdin.write_all(ruleset(wan_interfaces).as_bytes()).await?;
    drop(stdin);
    let output = child.wait_with_output().await?;
    if !output.status.success() {
        bail!(
            "nft rejected the accounting table: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

async fn wan_interfaces(db: &Database) -> Result<Vec<String>> {
    let mut names: Vec<String> = db
        .get_firewall_zones()
        .await?
        .into_iter()
        .filter(|zone| zone.is_wan)
        .flat_map(|zone| zone.interfaces)
        .filter(|name| valid_interface_name(name))
        .collect();
    names.sort();
    names.dedup();
    Ok(names)
}

/// Sampling starts once at daemon startup, independent of who has the page open.
pub fn start(db: Database) -> ClientTrafficSnapshot {
    let snapshot: ClientTrafficSnapshot = Arc::new(RwLock::new(Sampler::default()));
    let output = Arc::clone(&snapshot);
    tokio::spawn(async move {
        let mut installed_for: Option<Vec<String>> = None;
        let mut ticker = time::interval(SAMPLE_INTERVAL);
        ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        let mut tick_count: u64 = 0;
        loop {
            ticker.tick().await;
            if installed_for.is_none() || tick_count % WAN_REFRESH_TICKS == 0 {
                match wan_interfaces(&db).await {
                    Ok(wan) if installed_for.as_ref() != Some(&wan) => match install(&wan).await {
                        Ok(()) => {
                            debug!("Client traffic accounting installed for {wan:?}");
                            output.write().await.counters_reset();
                            installed_for = Some(wan);
                        }
                        Err(err) => warn!("Unable to set up client traffic accounting: {err:#}"),
                    },
                    Ok(_) => {}
                    Err(err) => warn!("Unable to read WAN interfaces for accounting: {err:#}"),
                }
            }
            tick_count += 1;
            if installed_for.is_none() {
                continue;
            }
            let now = Instant::now();
            let timestamp_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            match read_table().await {
                Ok(Some(readings)) => output.write().await.update(readings, now, timestamp_ms),
                // Removed behind our back (e.g. `nft flush ruleset`): recreate it.
                Ok(None) => installed_for = None,
                Err(err) => warn!("Unable to sample client traffic: {err:#}"),
            }
        }
    });
    snapshot
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn readings(down: &[(&str, u64)], up: &[(&str, u64)]) -> Readings {
        Readings {
            down: down.iter().map(|(a, b)| (ip(a), *b)).collect(),
            up: up.iter().map(|(a, b)| (ip(a), *b)).collect(),
        }
    }

    #[test]
    fn parses_counters_from_nft_json() {
        let table = json!({"nftables": [
            {"metainfo": {"version": "1.1.7"}},
            {"set": {"family": "inet", "name": "wan_interfaces", "elem": ["eth0"]}},
            {"set": {"name": "down4", "elem": [
                {"elem": {"val": "192.168.1.20", "expires": 299,
                          "counter": {"packets": 3, "bytes": 4500}}},
                {"elem": {"val": "not-an-address", "counter": {"packets": 1, "bytes": 9}}},
                {"elem": {"val": "192.168.1.21"}},
            ]}},
            {"set": {"name": "up6", "elem": [
                {"elem": {"val": "2001:db8::20", "counter": {"packets": 1, "bytes": 77}}},
            ]}},
            {"set": {"name": "up4"}},
        ]});
        let parsed = parse_readings(&table);
        assert_eq!(
            parsed,
            readings(&[("192.168.1.20", 4500)], &[("2001:db8::20", 77)])
        );
    }

    #[test]
    fn rates_come_from_counter_deltas_over_elapsed_time() {
        let mut sampler = Sampler::default();
        let t = Instant::now();
        sampler.update(
            readings(&[("10.0.0.2", 1_000)], &[("10.0.0.2", 100)]),
            t,
            1_000,
        );
        assert!(
            sampler.series_for(&[ip("10.0.0.2")]).is_empty(),
            "needs a baseline"
        );
        sampler.update(
            readings(&[("10.0.0.2", 3_000)], &[("10.0.0.2", 600)]),
            t + Duration::from_millis(500),
            1_500,
        );
        let series = sampler.series_for(&[ip("10.0.0.2")]);
        assert_eq!(series.len(), 1);
        assert_eq!(series[0].timestamp_ms, 1_500);
        assert_eq!(series[0].download_bytes_per_sec, 4_000);
        assert_eq!(series[0].upload_bytes_per_sec, 1_000);
    }

    #[test]
    fn a_device_sums_all_its_addresses_and_idle_ticks_are_zero() {
        let mut sampler = Sampler::default();
        let t = Instant::now();
        sampler.update(
            readings(&[("10.0.0.2", 0), ("2001:db8::2", 0)], &[]),
            t,
            1_000,
        );
        sampler.update(
            readings(&[("10.0.0.2", 1_000), ("2001:db8::2", 500)], &[]),
            t + Duration::from_secs(1),
            2_000,
        );
        sampler.update(
            readings(&[("10.0.0.2", 1_000), ("2001:db8::2", 500)], &[]),
            t + Duration::from_secs(2),
            3_000,
        );
        let series = sampler.series_for(&[ip("10.0.0.2"), ip("2001:db8::2")]);
        assert_eq!(
            series
                .iter()
                .map(|s| s.download_bytes_per_sec)
                .collect::<Vec<_>>(),
            vec![1_500, 0]
        );
        let other = sampler.series_for(&[ip("10.0.0.9")]);
        assert_eq!(
            other.len(),
            2,
            "unknown devices still get the shared timestamps"
        );
        assert!(other.iter().all(|s| s.download_bytes_per_sec == 0));
    }

    #[test]
    fn restarted_counters_and_long_gaps_do_not_invent_traffic() {
        let mut sampler = Sampler::default();
        let t = Instant::now();
        sampler.update(readings(&[("10.0.0.2", 9_000)], &[]), t, 1_000);
        // Element expired and came back from zero.
        sampler.update(
            readings(&[("10.0.0.2", 40)], &[]),
            t + Duration::from_secs(1),
            2_000,
        );
        // The poll stalled for ten seconds.
        sampler.update(
            readings(&[("10.0.0.2", 90_000)], &[]),
            t + Duration::from_secs(11),
            12_000,
        );
        assert!(
            sampler
                .series_for(&[ip("10.0.0.2")])
                .iter()
                .all(|s| s.download_bytes_per_sec == 0)
        );
        sampler.update(
            readings(&[("10.0.0.2", 90_100)], &[]),
            t + Duration::from_secs(12),
            13_000,
        );
        let series = sampler.series_for(&[ip("10.0.0.2")]);
        assert_eq!(series.last().unwrap().download_bytes_per_sec, 100);
    }

    #[test]
    fn history_rolls_at_one_minute() {
        let mut sampler = Sampler::default();
        let t = Instant::now();
        for i in 0..=120u64 {
            sampler.update(
                readings(&[("10.0.0.2", i * 10)], &[]),
                t + Duration::from_secs(i),
                1_000 + i * 1_000,
            );
        }
        let series = sampler.series_for(&[ip("10.0.0.2")]);
        assert!(series.len() <= MAX_TICKS);
        let last = series.last().unwrap().timestamp_ms;
        assert!(series.first().unwrap().timestamp_ms >= last - HISTORY_MS);
    }

    #[test]
    fn ruleset_quotes_only_valid_interface_names() {
        let script = ruleset(&[
            "eth0".into(),
            "ppp0.100".into(),
            "bad\"; flush ruleset".into(),
        ]);
        assert!(script.contains("elements = { \"eth0\", \"ppp0.100\" }"));
        assert!(!script.contains("flush ruleset"));
        let empty = ruleset(&[]);
        assert!(!empty.contains("elements"));
        assert!(
            empty.starts_with("add table inet keystone_acct\ndelete table inet keystone_acct\n")
        );
    }

    /// The generated script must be accepted by the real nft in a throwaway
    /// network namespace. Skipped where unshare or nft is unavailable.
    #[test]
    fn ruleset_is_accepted_by_nft() {
        use std::io::Write;
        let spawned = std::process::Command::new("unshare")
            .args(["-rn", "nft", "-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn();
        let Ok(mut child) = spawned else {
            return;
        };
        child
            .stdin
            .take()
            .unwrap()
            .write_all(ruleset(&["eth0".into()]).as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("Operation not permitted") || stderr.contains("unshare:") {
            return;
        }
        assert!(output.status.success(), "nft rejected the script: {stderr}");
    }
}
