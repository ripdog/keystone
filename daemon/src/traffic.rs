//! One-second interface throughput history, sampled independently of dashboard visitors.
//! Byte counters come from the kernel and rates use monotonic elapsed time.

use keystone_core::{InterfaceCounters, InterfaceTraffic, TrafficSample};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::RwLock, time};
use tracing::warn;

const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
const HISTORY_MS: u64 = 60_000;
const MAX_SAMPLES: usize = 61;

pub type TrafficSnapshot = Arc<RwLock<Vec<InterfaceTraffic>>>;

#[derive(Default)]
struct Sampler {
    previous: HashMap<String, (InterfaceCounters, Instant)>,
    history: HashMap<String, VecDeque<TrafficSample>>,
}

impl Sampler {
    fn update(
        &mut self,
        counters: Vec<InterfaceCounters>,
        now: Instant,
        timestamp_ms: u64,
    ) -> Vec<InterfaceTraffic> {
        let mut next_previous = HashMap::new();
        for counter in counters {
            let name = counter.name.clone();
            if let Some((previous, sampled_at)) = self.previous.get(&name) {
                let elapsed_ms = now.duration_since(*sampled_at).as_millis();
                // Do not turn missed polls, interface resets or counter wraparounds
                // into giant misleading traffic spikes.
                if (250..=3_000).contains(&elapsed_ms)
                    && counter.rx_bytes >= previous.rx_bytes
                    && counter.tx_bytes >= previous.tx_bytes
                {
                    let rate = |delta: u64| {
                        (u128::from(delta) * 1_000 / elapsed_ms).min(u128::from(u64::MAX)) as u64
                    };
                    let entry = self.history.entry(name.clone()).or_default();
                    entry.push_back(TrafficSample {
                        timestamp_ms,
                        rx_bytes_per_sec: rate(counter.rx_bytes - previous.rx_bytes),
                        tx_bytes_per_sec: rate(counter.tx_bytes - previous.tx_bytes),
                    });
                }
            }
            next_previous.insert(name, (counter, now));
        }
        self.previous = next_previous;
        self.history.retain(|name, samples| {
            if !self.previous.contains_key(name) {
                return false;
            }
            while samples
                .front()
                .is_some_and(|sample| timestamp_ms.saturating_sub(sample.timestamp_ms) > HISTORY_MS)
            {
                samples.pop_front();
            }
            while samples.len() > MAX_SAMPLES {
                samples.pop_front();
            }
            !samples.is_empty()
        });
        let mut snapshot: Vec<_> = self
            .history
            .iter()
            .map(|(name, samples)| InterfaceTraffic {
                name: name.clone(),
                role: None,
                samples: samples.iter().cloned().collect(),
            })
            .collect();
        snapshot.sort_by(|a, b| a.name.cmp(&b.name));
        snapshot
    }
}

/// Sampling is started once at daemon startup and survives dashboard navigation.
pub fn start() -> TrafficSnapshot {
    let snapshot: TrafficSnapshot = Arc::new(RwLock::new(Vec::new()));
    let output = Arc::clone(&snapshot);
    tokio::spawn(async move {
        let mut sampler = Sampler::default();
        let mut ticker = time::interval(SAMPLE_INTERVAL);
        ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let now = Instant::now();
            let timestamp_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            match super::read_interface_counters() {
                Ok(counters) => {
                    *output.write().await = sampler.update(counters, now, timestamp_ms);
                }
                Err(err) => warn!("Unable to sample network traffic: {err}"),
            }
        }
    });
    snapshot
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counter(name: &str, rx: u64, tx: u64) -> InterfaceCounters {
        InterfaceCounters {
            name: name.into(),
            rx_bytes: rx,
            tx_bytes: tx,
            ..Default::default()
        }
    }

    #[test]
    fn rates_use_actual_elapsed_time_and_timestamps() {
        let mut sampler = Sampler::default();
        let now = Instant::now();
        assert!(
            sampler
                .update(vec![counter("wan", 1_000, 2_000)], now, 1_000)
                .is_empty()
        );
        let sample = sampler.update(
            vec![counter("wan", 3_000, 5_000)],
            now + Duration::from_millis(500),
            1_500,
        );
        assert_eq!(sample[0].samples[0].rx_bytes_per_sec, 4_000);
        assert_eq!(sample[0].samples[0].tx_bytes_per_sec, 6_000);
        assert_eq!(sample[0].samples[0].timestamp_ms, 1_500);
    }

    #[test]
    fn counter_reset_and_long_gap_do_not_invent_traffic() {
        let mut sampler = Sampler::default();
        let t = Instant::now();
        sampler.update(vec![counter("wan", 100, 100)], t, 1_000);
        assert!(
            sampler
                .update(
                    vec![counter("wan", 2, 2)],
                    t + Duration::from_secs(1),
                    2_000
                )
                .is_empty()
        );
        assert!(
            sampler
                .update(
                    vec![counter("wan", 100, 100)],
                    t + Duration::from_secs(10),
                    11_000
                )
                .is_empty()
        );
        let samples = sampler.update(
            vec![counter("wan", 150, 175)],
            t + Duration::from_secs(11),
            12_000,
        );
        assert_eq!(samples[0].samples[0].tx_bytes_per_sec, 75);
    }

    #[test]
    fn history_rolls_at_one_minute_and_forgets_removed_interfaces() {
        let mut sampler = Sampler::default();
        let t = Instant::now();
        sampler.update(vec![counter("wan", 0, 0)], t, 1_000);
        for i in 1..=90 {
            let samples = sampler.update(
                vec![counter("wan", i * 100, i * 20)],
                t + Duration::from_secs(i),
                1_000 + i * 1_000,
            );
            assert!(samples[0].samples.len() <= MAX_SAMPLES);
        }
        let last = sampler.history["wan"].back().unwrap().timestamp_ms;
        assert!(sampler.history["wan"].front().unwrap().timestamp_ms >= last - HISTORY_MS);
        assert!(
            sampler
                .update(vec![], t + Duration::from_secs(91), 92_000)
                .is_empty()
        );
    }
}
