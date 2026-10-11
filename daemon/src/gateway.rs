//! Continuous WAN gateway reachability monitoring. Routing data comes from the
//! kernel; probes and rolling history are owned by the daemon, not HTTP requests.

use crate::db::Database;
use keystone_core::{GatewayFamily, GatewaySample, GatewayStatus, InterfaceRole};
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{process::Command, sync::RwLock, task::JoinSet, time};
use tracing::warn;

const INTERVAL: Duration = Duration::from_secs(5);
const HISTORY_LEN: usize = 60; // Five minutes, including unsuccessful probes.

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Target {
    interface: String,
    address: IpAddr,
}

impl Target {
    fn family(&self) -> GatewayFamily {
        match self.address {
            IpAddr::V4(_) => GatewayFamily::Ipv4,
            IpAddr::V6(_) => GatewayFamily::Ipv6,
        }
    }
}

pub type GatewaySnapshot = Arc<RwLock<Vec<GatewayStatus>>>;

/// Start a single sampler at daemon startup. It outlives dashboard visitors.
pub fn start(db: Database) -> GatewaySnapshot {
    let snapshot: GatewaySnapshot = Arc::new(RwLock::new(Vec::new()));
    let output = Arc::clone(&snapshot);
    tokio::spawn(async move {
        let mut ticker = time::interval(INTERVAL);
        ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let configs = match db.get_interface_configs().await {
                Ok(configs) => configs,
                Err(err) => {
                    warn!("Unable to discover WAN interfaces for gateway monitor: {err}");
                    continue;
                }
            };
            let wans: HashSet<String> = configs
                .into_iter()
                .filter(|cfg| {
                    cfg.enabled
                        && cfg.role == InterfaceRole::WAN
                        && keystone_core::validation::interface_name(&cfg.name).is_ok()
                })
                .map(|cfg| cfg.name)
                .collect();
            let targets = discover_gateways(&wans);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;

            // Each probe is independent: one unresponsive family must not block
            // its counterpart. Bound the number of spawned commands to observed
            // WAN default routes.
            let mut jobs = JoinSet::new();
            for target in targets.iter().cloned() {
                jobs.spawn(async move {
                    let latency = ping(&target).await;
                    (target, latency)
                });
            }
            let mut results = Vec::new();
            while let Some(result) = jobs.join_next().await {
                if let Ok(item) = result {
                    results.push(item);
                }
            }

            let mut statuses = output.write().await;
            // Retain a lost gateway as red until its route returns. Forget it
            // when a new default gateway replaces it on the same interface.
            statuses.retain(|status| {
                wans.contains(&status.interface)
                    && (targets.iter().any(|target| {
                        target.interface == status.interface
                            && target.family() == status.family
                            && target.address.to_string() == status.gateway
                    }) || !targets.iter().any(|target| {
                        target.interface == status.interface && target.family() == status.family
                    }))
            });

            for status in statuses.iter_mut() {
                status.active_route = false;
            }
            for (target, latency) in results {
                let gateway = target.address.to_string();
                let family = target.family();
                let status = if let Some(status) = statuses.iter_mut().find(|s| {
                    s.interface == target.interface && s.gateway == gateway && s.family == family
                }) {
                    status
                } else {
                    statuses.push(GatewayStatus {
                        interface: target.interface.clone(),
                        gateway: gateway.clone(),
                        family,
                        active_route: true,
                        latest_latency_ms: None,
                        average_latency_ms: None,
                        packet_loss_percent: 0.0,
                        history: Vec::new(),
                    });
                    statuses.last_mut().expect("just inserted")
                };
                status.active_route = true;
                add_sample(status, now, latency);
            }
            for status in statuses.iter_mut().filter(|s| !s.active_route) {
                add_sample(status, now, None);
            }
            statuses.sort_by(|a, b| {
                (a.interface.as_str(), a.family, a.gateway.as_str()).cmp(&(
                    b.interface.as_str(),
                    b.family,
                    b.gateway.as_str(),
                ))
            });
        }
    });
    snapshot
}

fn add_sample(status: &mut GatewayStatus, timestamp_ms: u64, latency_ms: Option<f64>) {
    status.history.push(GatewaySample {
        timestamp_ms,
        latency_ms,
    });
    if status.history.len() > HISTORY_LEN {
        status.history.remove(0);
    }
    status.latest_latency_ms = latency_ms;
    let good: Vec<f64> = status
        .history
        .iter()
        .filter_map(|sample| sample.latency_ms)
        .collect();
    status.average_latency_ms =
        (!good.is_empty()).then(|| good.iter().sum::<f64>() / good.len() as f64);
    status.packet_loss_percent =
        100.0 * (status.history.len() - good.len()) as f64 / status.history.len() as f64;
}

fn discover_gateways(wans: &HashSet<String>) -> Vec<Target> {
    let mut targets = Vec::new();
    if let Ok(routes) = std::fs::read_to_string("/proc/net/route") {
        targets.extend(parse_ipv4_routes(&routes, wans));
    }
    if let Ok(routes) = std::fs::read_to_string("/proc/net/ipv6_route") {
        targets.extend(parse_ipv6_routes(&routes, wans));
    }
    // ECMP and duplicate default routes must not cause duplicate probes.
    targets.sort_by(|a, b| {
        (a.interface.as_str(), a.address.to_string())
            .cmp(&(b.interface.as_str(), b.address.to_string()))
    });
    targets.dedup();
    targets
}

fn parse_ipv4_routes(routes: &str, wans: &HashSet<String>) -> Vec<Target> {
    routes
        .lines()
        .filter_map(|line| {
            let parts: Vec<_> = line.split_whitespace().collect();
            if parts.len() < 8
                || !wans.contains(parts[0])
                || parts[1] != "00000000"
                || parts[7] != "00000000"
            {
                return None;
            }
            let flags = u32::from_str_radix(parts[3], 16).ok()?;
            if flags & 0x3 != 0x3 {
                // Up and Gateway
                return None;
            }
            let value = u32::from_str_radix(parts[2], 16).ok()?;
            (value != 0).then(|| Target {
                interface: parts[0].to_owned(),
                address: IpAddr::V4(Ipv4Addr::from(value.to_le_bytes())),
            })
        })
        .collect()
}

fn parse_ipv6_routes(routes: &str, wans: &HashSet<String>) -> Vec<Target> {
    routes
        .lines()
        .filter_map(|line| {
            let parts: Vec<_> = line.split_whitespace().collect();
            if parts.len() < 10
                || !wans.contains(parts[9])
                || parts[0] != "0".repeat(32)
                || parts[1] != "00"
            {
                return None;
            }
            let raw = parts[4];
            if raw.len() != 32 {
                return None;
            }
            let value = u128::from_str_radix(raw, 16).ok()?;
            (value != 0).then(|| Target {
                interface: parts[9].to_owned(),
                address: IpAddr::V6(Ipv6Addr::from(value)),
            })
        })
        .collect()
}

/// All executable arguments come from validated kernel routes and numeric IPs;
/// never interpolate addresses or interface names through a shell.
async fn ping(target: &Target) -> Option<f64> {
    let family = match target.address {
        IpAddr::V4(_) => "-4",
        IpAddr::V6(_) => "-6",
    };
    let output = time::timeout(
        Duration::from_secs(3),
        Command::new("/usr/bin/ping")
            .args(["-n", "-c", "1", "-W", "1", "-I", &target.interface, family])
            .arg(target.address.to_string())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_latency(&String::from_utf8_lossy(&output.stdout))
}

/// iputils uses 'time=0.42 ms', and sometimes 'time<1 ms'.
fn parse_latency(output: &str) -> Option<f64> {
    output.split_whitespace().find_map(|token| {
        token
            .strip_prefix("time=")
            .or_else(|| token.strip_prefix("time<"))
            .and_then(|value| value.parse::<f64>().ok())
            .filter(|value| value.is_finite() && *value >= 0.0)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_only_from_wan_and_both_families() {
        let wans = HashSet::from(["enp3s0".to_owned()]);
        let v4 = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\nenp3s0 00000000 0101A8C0 0003 0 0 100 00000000 0 0 0\nenp2s0 00000000 0101A8C0 0003 0 0 100 00000000 0 0 0\nenp3s0 00A8C0C0 00000000 0001 0 0 100 00FFFFFF 0 0 0";
        assert_eq!(
            parse_ipv4_routes(v4, &wans),
            vec![Target {
                interface: "enp3s0".to_owned(),
                address: "192.168.1.1".parse().unwrap(),
            }]
        );
        let v6 = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000064 00000000 00000000 00000003 enp3s0\n00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000064 00000000 00000000 00000003 enp2s0";
        assert_eq!(
            parse_ipv6_routes(v6, &wans),
            vec![Target {
                interface: "enp3s0".to_owned(),
                address: "fe80::1".parse().unwrap(),
            }]
        );
    }

    #[test]
    fn statistics_roll_over_and_recover() {
        let mut status = GatewayStatus {
            interface: "wan".into(),
            gateway: "1.1.1.1".into(),
            family: GatewayFamily::Ipv4,
            active_route: true,
            latest_latency_ms: None,
            average_latency_ms: None,
            packet_loss_percent: 0.0,
            history: vec![],
        };
        add_sample(&mut status, 1, Some(12.0));
        add_sample(&mut status, 2, None);
        assert_eq!(status.packet_loss_percent, 50.0);
        assert_eq!(status.latest_latency_ms, None);
        assert_eq!(status.average_latency_ms, Some(12.0));
        for i in 3..100 {
            add_sample(&mut status, i, Some(10.0));
        }
        assert_eq!(status.history.len(), HISTORY_LEN);
        assert_eq!(status.packet_loss_percent, 0.0);
    }

    #[test]
    fn parses_iputils_rtt() {
        assert_eq!(
            parse_latency("64 bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=0.482 ms"),
            Some(0.482)
        );
        assert_eq!(
            parse_latency("64 bytes from ::1: icmp_seq=1 ttl=64 time<1 ms"),
            Some(1.0)
        );
        assert_eq!(parse_latency("100% packet loss"), None);
    }
}
