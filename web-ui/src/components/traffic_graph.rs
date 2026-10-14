//! Real-time, shaded SVG traffic charts backed by daemon-owned one-minute history.

use forge_charts::{AreaChart, Series, TooltipSlot, YFormat};
use keystone_core::{ClientTrafficSample, InterfaceRole, InterfaceTraffic, TrafficSample};
use leptos::prelude::*;
use std::sync::Arc;

/// Kernel counters are bytes; network throughput is conventionally shown
/// in decimal bits per second. Both axes and hover values use the same units.
pub fn format_rate(bytes_per_second: f64) -> String {
    let bits = bytes_per_second * 8.0;
    let (scaled, unit) = if bits >= 1_000_000_000.0 {
        (bits / 1_000_000_000.0, "Gbit/s")
    } else if bits >= 1_000_000.0 {
        (bits / 1_000_000.0, "Mbit/s")
    } else if bits >= 1_000.0 {
        (bits / 1_000.0, "kbit/s")
    } else {
        (bits, "bit/s")
    };
    if scaled >= 100.0 || unit == "bit/s" {
        format!("{scaled:.0} {unit}")
    } else if scaled >= 10.0 {
        format!("{scaled:.1} {unit}")
    } else {
        format!("{scaled:.2} {unit}")
    }
}

/// Interpret ingress/egress from the perspective of LAN clients.
/// On WAN, received traffic is download; on LAN, transmitted traffic is download.
fn download_upload(role: InterfaceRole, sample: &TrafficSample) -> (u64, u64) {
    match role {
        InterfaceRole::WAN => (sample.rx_bytes_per_sec, sample.tx_bytes_per_sec),
        InterfaceRole::LAN => (sample.tx_bytes_per_sec, sample.rx_bytes_per_sec),
    }
}

/// Chart styling shared by every page that draws a `RateChart`.
pub const TRAFFIC_GRAPH_CSS: &str = r#"
    .keystone-traffic-graph .charts-tooltip {
        background: rgba(13, 23, 39, 0.97);
        color: #f1f5f9;
        border: 1px solid rgba(148, 163, 184, 0.25);
    }
    .keystone-traffic-graph .charts-line {
        stroke-width: 2.25;
        stroke-linejoin: round;
        stroke-linecap: round;
        vector-effect: non-scaling-stroke;
    }
"#;

/// One point of a download/upload chart, from the LAN side's point of view.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RatePoint {
    timestamp_ms: u64,
    download: u64,
    upload: u64,
}

#[component]
pub fn TrafficGraph(
    name: String,
    role: InterfaceRole,
    history: ReadSignal<Vec<InterfaceTraffic>>,
) -> impl IntoView {
    let data: Signal<Vec<RatePoint>> = Signal::derive(move || {
        history
            .get()
            .into_iter()
            .find(|item| item.name == name)
            .map(|item| {
                item.samples
                    .iter()
                    .map(|sample| {
                        let (download, upload) = download_upload(role, sample);
                        RatePoint {
                            timestamp_ms: sample.timestamp_ms,
                            download,
                            upload,
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    });
    view! {
        <section class="min-w-0 bg-[#121f30] rounded-xl border border-slate-700/60 p-4 sm:p-5 space-y-3">
            <h3 class="text-sm font-semibold text-slate-100">{role.to_string()}</h3>
            <RateChart data=data height=250 />
        </section>
    }
}

/// A device's WAN throughput over the daemon's last minute of samples.
#[component]
pub fn ClientTrafficGraph(samples: Signal<Vec<ClientTrafficSample>>) -> impl IntoView {
    let data: Signal<Vec<RatePoint>> = Signal::derive(move || {
        samples
            .get()
            .into_iter()
            .map(|sample| RatePoint {
                timestamp_ms: sample.timestamp_ms,
                download: sample.download_bytes_per_sec,
                upload: sample.upload_bytes_per_sec,
            })
            .collect()
    });
    view! { <RateChart data=data height=160 /> }
}

/// Download/upload area chart with a legend, hover tooltip and rate-scaled axis.
#[component]
fn RateChart(data: Signal<Vec<RatePoint>>, height: u32) -> impl IntoView {
    let most_recent =
        Signal::derive(move || data.get().last().map(|p| p.timestamp_ms).unwrap_or(0));
    let tooltip: TooltipSlot = Arc::new(move |index| {
        let Some(point) = data.get_untracked().get(index).cloned() else {
            return view! { <span>"No sample"</span> }.into_any();
        };
        view! {
            <div class="min-w-48 space-y-2 text-xs text-slate-100">
                <div class="font-medium text-slate-300">
                    {format!("At {:02}:{:02}:{:02} UTC", (point.timestamp_ms / 3_600_000) % 24, (point.timestamp_ms / 60_000) % 60, (point.timestamp_ms / 1_000) % 60)}
                </div>
                <div class="flex justify-between gap-5">
                    <span class="text-sky-300">"↓ Download"</span>
                    <span class="font-mono">{format_rate(point.download as f64)}</span>
                </div>
                <div class="flex justify-between gap-5">
                    <span class="text-emerald-300">"↑ Upload"</span>
                    <span class="font-mono">{format_rate(point.upload as f64)}</span>
                </div>
            </div>
        }.into_any()
    });
    let y_format: YFormat = Arc::new(format_rate);
    view! {
        <div class="space-y-3">
            <div class="flex items-center justify-end gap-4 text-xs font-medium">
                <span class="text-sky-300 flex items-center gap-1.5"><span class="w-2.5 h-2.5 rounded-full bg-sky-400"></span>"Download"</span>
                <span class="text-emerald-300 flex items-center gap-1.5"><span class="w-2.5 h-2.5 rounded-full bg-emerald-400"></span>"Upload"</span>
            </div>
            <Show when=move || !data.get().is_empty() fallback=move || view! {
                <div class="flex items-center justify-center text-slate-500 text-sm" style=format!("height: {}px", height - 20)>"Collecting traffic samples..."</div>
            }>
                <div class="keystone-traffic-graph" style="--charts-fg: #cbd5e1; --charts-fg-muted: #94a3b8; --charts-grid-color: rgba(148,163,184,0.15); --charts-series-opened: #38bdf8; --charts-series-opened-soft: rgba(56,189,248,0.33); --charts-series-closed: #34d399; --charts-series-closed-soft: rgba(52,211,153,0.25);">
                    <AreaChart
                        data=data
                        x_label=move |item: &RatePoint| {
                            let age = most_recent.get_untracked().saturating_sub(item.timestamp_ms) / 1_000;
                            if age == 0 { "now".to_owned() } else { format!("-{age}s") }
                        }
                        y_values=move |item: &RatePoint| vec![item.download as f64, item.upload as f64]
                        series=vec![Series::area("Download", "opened"), Series::area("Upload", "closed")]
                        legend=false
                        tooltip=tooltip.clone()
                        y_format=y_format.clone()
                        height=height
                    />
                </div>
            </Show>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_have_scaled_axes_and_exact_tooltip_values() {
        assert_eq!(format_rate(0.0), "0 bit/s");
        assert_eq!(format_rate(10.0), "80 bit/s");
        assert_eq!(format_rate(125.0), "1.00 kbit/s");
        assert_eq!(format_rate(125_000.0), "1.00 Mbit/s");
        assert_eq!(format_rate(1_500_000.0), "12.0 Mbit/s");
        assert_eq!(format_rate(187_500_000.0), "1.50 Gbit/s");
        assert_eq!(format_rate(125_000_000.0), "1.00 Gbit/s");
    }

    #[test]
    fn download_and_upload_are_relative_to_lan_clients() {
        let sample = TrafficSample {
            timestamp_ms: 1000,
            rx_bytes_per_sec: 125_000,
            tx_bytes_per_sec: 62_500,
        };
        assert_eq!(
            download_upload(InterfaceRole::WAN, &sample),
            (125_000, 62_500)
        );
        assert_eq!(
            download_upload(InterfaceRole::LAN, &sample),
            (62_500, 125_000)
        );
    }
}
