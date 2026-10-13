//! Live shaper counters, read from `tc -s -j qdisc show`.
//!
//! The JSON is parsed defensively: every field is optional, and a value the
//! kernel does not report becomes `None` or zero rather than an error.

use anyhow::Result;
use keystone_core::sqm::{SqmDiffserv, SqmDirectionStatus, SqmStatusResponse, SqmTinStatus};
use serde_json::Value;
use sqlx::SqlitePool;

use super::apply::{ifb_name, is_root_cake, qdisc_list};
use super::db::load_applied;

/// Names of the priority tins of a diffserv mode, in tin order.
fn tin_names(mode: SqmDiffserv) -> &'static [&'static str] {
    match mode {
        SqmDiffserv::Besteffort => &["Best Effort"],
        SqmDiffserv::Diffserv3 => &["Bulk", "Best Effort", "Voice"],
        SqmDiffserv::Diffserv4 => &["Bulk", "Best Effort", "Video", "Voice"],
        SqmDiffserv::Diffserv8 => &[],
    }
}

fn unsigned(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

fn tin_status(index: usize, tin: &Value, names: &[&str]) -> SqmTinStatus {
    let name = names
        .get(index)
        .map_or_else(|| format!("Tin {}", index + 1), |name| (*name).to_string());
    SqmTinStatus {
        name,
        sent_bytes: unsigned(tin, "sent_bytes"),
        sent_packets: unsigned(tin, "sent_packets"),
        backlog_bytes: unsigned(tin, "backlog_bytes"),
        drops: unsigned(tin, "drops"),
        ecn_marks: unsigned(tin, "ecn_mark").or_else(|| unsigned(tin, "ecn_marks")),
        avg_delay_us: unsigned(tin, "avg_delay_us"),
        peak_delay_us: unsigned(tin, "peak_delay_us"),
        base_delay_us: unsigned(tin, "base_delay_us"),
    }
}

/// Counters of the root CAKE qdisc among `qdiscs`, if there is one.
pub fn parse_direction(
    qdiscs: &[Value],
    device: &str,
    bandwidth_kbit: u32,
    diffserv: SqmDiffserv,
) -> Option<SqmDirectionStatus> {
    let cake = qdiscs.iter().find(|qdisc| is_root_cake(qdisc))?;
    let names = tin_names(diffserv);
    let tins = cake
        .get("tins")
        .and_then(Value::as_array)
        .map(|tins| {
            tins.iter()
                .enumerate()
                .map(|(index, tin)| tin_status(index, tin, names))
                .collect()
        })
        .unwrap_or_default();
    Some(SqmDirectionStatus {
        device: device.to_string(),
        bandwidth_kbit,
        sent_bytes: unsigned(cake, "bytes").unwrap_or(0),
        sent_packets: unsigned(cake, "packets").unwrap_or(0),
        drops: unsigned(cake, "drops").unwrap_or(0),
        backlog_bytes: unsigned(cake, "backlog").unwrap_or(0),
        tins,
    })
}

/// Read the shaper counters for the last applied configuration.
pub async fn read_status(pool: &SqlitePool) -> Result<SqmStatusResponse> {
    let Some(applied) = load_applied(pool).await? else {
        return Ok(SqmStatusResponse {
            message: Some("Traffic shaping has not been applied yet.".to_string()),
            ..SqmStatusResponse::default()
        });
    };
    let interface = (!applied.interface.is_empty()).then(|| applied.interface.clone());
    if !applied.enabled {
        return Ok(SqmStatusResponse {
            interface,
            message: Some("Traffic shaping is disabled.".to_string()),
            ..SqmStatusResponse::default()
        });
    }

    let wan = applied.interface.as_str();
    let mut missing = Vec::new();
    let upload = if applied.upload_kbit > 0 {
        let status = match qdisc_list(wan).await {
            Some(qdiscs) => parse_direction(&qdiscs, wan, applied.upload_kbit, applied.diffserv),
            None => None,
        };
        if status.is_none() {
            missing.push(format!("no CAKE qdisc on {wan}"));
        }
        status
    } else {
        None
    };

    let ifb = ifb_name(wan);
    let download = if applied.download_kbit > 0 {
        let status = match qdisc_list(&ifb).await {
            Some(qdiscs) => parse_direction(&qdiscs, &ifb, applied.download_kbit, applied.diffserv),
            None => None,
        };
        if status.is_none() {
            missing.push(format!("no CAKE qdisc on {ifb}"));
        }
        status
    } else {
        None
    };

    let active = (applied.upload_kbit == 0 || upload.is_some())
        && (applied.download_kbit == 0 || download.is_some());
    Ok(SqmStatusResponse {
        active,
        interface,
        message: (!missing.is_empty()).then(|| {
            format!(
                "{}; the reconciler re-applies the configuration when the link returns",
                missing.join(", ")
            )
        }),
        upload,
        download,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Captured shape of `tc -s -j qdisc show dev eth0` for a CAKE root qdisc
    /// with diffserv4 and four tins, plus a child class from another qdisc.
    const CAKE_SAMPLE: &str = r#"[
      {
        "kind": "cake",
        "handle": "8001:",
        "dev": "eth0",
        "root": true,
        "refcnt": 2,
        "options": {
          "bandwidth": 2500000,
          "diffserv": "diffserv4",
          "triple-isolate": true,
          "nat": true,
          "wash": false,
          "rtt": 100000,
          "raw": true,
          "overhead": 38,
          "mpu": 84
        },
        "bytes": 918273645,
        "packets": 1203344,
        "drops": 1532,
        "overlimits": 4410,
        "requeues": 0,
        "backlog": 12288,
        "qlen": 9,
        "memory_used": 1048576,
        "memory_limit": 33554432,
        "capacity_estimate": 2500000,
        "min_network_size": 32,
        "max_network_size": 32,
        "min_adj_size": 84,
        "max_adj_size": 1538,
        "avg_hdr_offset": 14,
        "tins": [
          {
            "threshold_rate": 156250,
            "sent_bytes": 10485760,
            "backlog_bytes": 0,
            "target_us": 5000,
            "interval_us": 100000,
            "peak_delay_us": 1200,
            "avg_delay_us": 310,
            "base_delay_us": 220,
            "sent_packets": 9001,
            "way_inds": 12,
            "way_miss": 900,
            "way_collisions": 0,
            "drops": 3,
            "ecn_mark": 0,
            "ack_drops": 0,
            "sparse_flows": 2,
            "bulk_flows": 0,
            "unresponsive_flows": 0,
            "max_skblen": 1514,
            "flow_quantum": 1514
          },
          {
            "threshold_rate": 2500000,
            "sent_bytes": 884000000,
            "backlog_bytes": 8192,
            "target_us": 5000,
            "interval_us": 100000,
            "peak_delay_us": 18750,
            "avg_delay_us": 4210,
            "base_delay_us": 2900,
            "sent_packets": 1150000,
            "way_inds": 880,
            "way_miss": 40210,
            "way_collisions": 2,
            "drops": 1420,
            "ecn_mark": 75,
            "ack_drops": 0,
            "sparse_flows": 18,
            "bulk_flows": 3,
            "unresponsive_flows": 0,
            "max_skblen": 1514,
            "flow_quantum": 1514
          },
          {
            "threshold_rate": 2500000,
            "sent_bytes": 0,
            "backlog_bytes": 0,
            "sent_packets": 0,
            "drops": 0,
            "ecn_mark": 0
          },
          {
            "threshold_rate": 2500000,
            "sent_bytes": 24000000,
            "backlog_bytes": 0,
            "sent_packets": 42000,
            "drops": 109,
            "ecn_mark": 0
          }
        ]
      },
      {
        "kind": "pfifo_fast",
        "handle": "0:",
        "parent": "8001:1",
        "bytes": 0,
        "packets": 0,
        "drops": 0,
        "backlog": 0,
        "qlen": 0
      }
    ]"#;

    fn sample() -> Vec<Value> {
        serde_json::from_str(CAKE_SAMPLE).unwrap()
    }

    #[test]
    fn parses_root_cake_counters_and_tins() {
        let status = parse_direction(&sample(), "eth0", 2_500, SqmDiffserv::Diffserv4)
            .expect("root cake present");
        assert_eq!(status.device, "eth0");
        assert_eq!(status.bandwidth_kbit, 2_500);
        assert_eq!(status.sent_bytes, 918_273_645);
        assert_eq!(status.sent_packets, 1_203_344);
        assert_eq!(status.drops, 1_532);
        assert_eq!(status.backlog_bytes, 12_288);

        let names: Vec<&str> = status.tins.iter().map(|tin| tin.name.as_str()).collect();
        assert_eq!(names, ["Bulk", "Best Effort", "Video", "Voice"]);

        let best_effort = &status.tins[1];
        assert_eq!(best_effort.avg_delay_us, Some(4_210));
        assert_eq!(best_effort.peak_delay_us, Some(18_750));
        assert_eq!(best_effort.base_delay_us, Some(2_900));
        assert_eq!(best_effort.drops, Some(1_420));
        assert_eq!(best_effort.ecn_marks, Some(75));
        assert_eq!(best_effort.backlog_bytes, Some(8_192));
    }

    #[test]
    fn child_qdiscs_are_not_mistaken_for_the_shaper() {
        let only_child: Vec<Value> = sample().into_iter().skip(1).collect();
        assert!(parse_direction(&only_child, "eth0", 2_500, SqmDiffserv::Diffserv4).is_none());
    }

    #[test]
    fn missing_fields_are_tolerated() {
        let minimal: Vec<Value> = serde_json::from_str(
            r#"[{"kind":"cake","root":true,"bytes":10,"tins":[{"drops":2},{"ecn_marks":5}]}]"#,
        )
        .unwrap();
        let status = parse_direction(&minimal, "ifb4eth0", 9_000, SqmDiffserv::Besteffort).unwrap();
        assert_eq!(status.sent_bytes, 10);
        assert_eq!(status.sent_packets, 0);
        assert_eq!(status.drops, 0);
        assert_eq!(status.tins.len(), 2);
        assert_eq!(status.tins[0].name, "Best Effort");
        assert_eq!(status.tins[0].drops, Some(2));
        assert_eq!(status.tins[0].avg_delay_us, None);
        assert_eq!(status.tins[1].name, "Tin 2");
        assert_eq!(status.tins[1].ecn_marks, Some(5));
    }

    #[test]
    fn a_non_cake_root_yields_no_status() {
        let fq: Vec<Value> =
            serde_json::from_str(r#"[{"kind":"fq_codel","root":true,"bytes":1}]"#).unwrap();
        assert!(parse_direction(&fq, "eth0", 1_000, SqmDiffserv::Diffserv4).is_none());
    }
}
