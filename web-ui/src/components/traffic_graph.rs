//! Real-time, shaded SVG traffic charts backed by daemon-owned one-minute history.

use forge_charts::{AreaChart, Series, TooltipSlot, YFormat};
use keystone_core::{InterfaceTraffic, TrafficSample};
use leptos::prelude::*;
use std::sync::Arc;

fn short_rate(value: f64) -> String {
    if value >= 1_000_000_000.0 {
        format!("{:.1} GB/s", value / 1_000_000_000.0)
    } else if value >= 1_000_000.0 {
        format!("{:.1} MB/s", value / 1_000_000.0)
    } else if value >= 1_000.0 {
        format!("{:.1} kB/s", value / 1_000.0)
    } else {
        format!("{value:.0} B/s")
    }
}

fn exact_rate(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::new();
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    format!("{out} B/s")
}

#[component]
pub fn TrafficGraph(name: String, history: ReadSignal<Vec<InterfaceTraffic>>) -> impl IntoView {
    let selected_name = name.clone();
    let data: Signal<Vec<TrafficSample>> = Signal::derive(move || {
        history
            .get()
            .into_iter()
            .find(|item| item.name == selected_name)
            .map(|item| item.samples)
            .unwrap_or_default()
    });
    let current = data;
    let most_recent =
        Signal::derive(move || data.get().last().map(|p| p.timestamp_ms).unwrap_or(0));
    let tooltip: TooltipSlot = Arc::new(move |index| {
        let Some(sample) = current.get_untracked().get(index).cloned() else {
            return view! { <span>"No sample"</span> }.into_any();
        };
        view! {
            <div class="min-w-48 space-y-2 text-xs text-slate-100">
                <div class="font-medium text-slate-300">
                    {format!("At {:02}:{:02}:{:02} UTC", (sample.timestamp_ms / 3_600_000) % 24, (sample.timestamp_ms / 60_000) % 60, (sample.timestamp_ms / 1_000) % 60)}
                </div>
                <div class="flex justify-between gap-5">
                    <span class="text-sky-300">"↓ Download"</span>
                    <span class="font-mono">{exact_rate(sample.rx_bytes_per_sec)}</span>
                </div>
                <div class="flex justify-between gap-5">
                    <span class="text-emerald-300">"↑ Upload"</span>
                    <span class="font-mono">{exact_rate(sample.tx_bytes_per_sec)}</span>
                </div>
            </div>
        }.into_any()
    });
    let y_format: YFormat = Arc::new(short_rate);
    view! {
        <section class="min-w-0 bg-[#121f30] rounded-xl border border-slate-700/60 p-4 sm:p-5 space-y-3">
            <div class="flex flex-wrap justify-between items-start gap-3">
                <div class="min-w-0">
                    <h3 class="text-sm font-semibold text-slate-100 break-all">{name}</h3>
                    <p class="text-xs text-slate-500">"Last 60 seconds · sampled by daemon"</p>
                </div>
                <div class="flex items-center gap-4 text-xs font-medium">
                    <span class="text-sky-300 flex items-center gap-1.5"><span class="w-2.5 h-2.5 rounded-full bg-sky-400"></span>"Download"</span>
                    <span class="text-emerald-300 flex items-center gap-1.5"><span class="w-2.5 h-2.5 rounded-full bg-emerald-400"></span>"Upload"</span>
                </div>
            </div>
            <Show when=move || !data.get().is_empty() fallback=|| view! {
                <div class="h-[230px] flex items-center justify-center text-slate-500 text-sm">"Collecting traffic samples..."</div>
            }>
                <div class="keystone-traffic-graph" style="--charts-fg: #cbd5e1; --charts-fg-muted: #94a3b8; --charts-grid-color: rgba(148,163,184,0.15); --charts-series-opened: #38bdf8; --charts-series-opened-soft: rgba(56,189,248,0.33); --charts-series-closed: #34d399; --charts-series-closed-soft: rgba(52,211,153,0.25);">
                    <AreaChart
                        data=data
                        x_label=move |item: &TrafficSample| {
                            let age = most_recent.get_untracked().saturating_sub(item.timestamp_ms) / 1_000;
                            if age == 0 { "now".to_owned() } else { format!("-{age}s") }
                        }
                        y_values=|item: &TrafficSample| vec![item.rx_bytes_per_sec as f64, item.tx_bytes_per_sec as f64]
                        series=vec![Series::area("Download", "opened"), Series::area("Upload", "closed")]
                        legend=false
                        tooltip=tooltip.clone()
                        y_format=y_format.clone()
                        height=250
                    />
                </div>
            </Show>
        </section>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_have_scaled_axes_and_exact_tooltip_values() {
        assert_eq!(short_rate(1_500_000.0), "1.5 MB/s");
        assert_eq!(short_rate(0.0), "0 B/s");
        assert_eq!(exact_rate(123_456_789), "123,456,789 B/s");
    }
}
