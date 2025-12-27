//! Dashboard page with live network status

use gloo_timers::callback::Interval;
use keystone_core::{InterfaceCounters, InterfaceRole, SystemState};
use leptos::prelude::*;
use leptos::task::spawn_local;
use std::collections::HashMap;

use crate::api;

#[derive(Clone, Debug, Default)]
struct InterfaceRate {
    name: String,
    rx_bps: u64,
    tx_bps: u64,
}

#[component]
pub fn DashboardPage(
    auth_token: ReadSignal<Option<String>>,
    state: ReadSignal<SystemState>,
    set_state: WriteSignal<SystemState>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let (rates, set_rates) = signal(Vec::<InterfaceRate>::new());
    let (prev_counters, set_prev_counters) = signal(Vec::<InterfaceCounters>::new());
    let (error_msg, set_error_msg) = signal(Option::<String>::None);

    let do_poll = move || {
        let Some(token) = auth_token.get_untracked() else {
            return;
        };

        spawn_local(async move {
            match api::fetch_dashboard(&token).await {
                Ok(resp) => {
                    set_error_msg.set(None);
                    set_state.set(resp.state.clone());

                    let prev = prev_counters.get_untracked();
                    let mut prev_map: HashMap<String, (u64, u64)> = HashMap::new();
                    for c in prev {
                        prev_map.insert(c.name, (c.rx_bytes, c.tx_bytes));
                    }

                    let mut new_rates = Vec::new();
                    for c in resp.interface_counters.iter() {
                        let (rx_bps, tx_bps) = prev_map
                            .get(&c.name)
                            .map(|(rx, tx)| {
                                (
                                    c.rx_bytes.saturating_sub(*rx),
                                    c.tx_bytes.saturating_sub(*tx),
                                )
                            })
                            .unwrap_or((0, 0));

                        new_rates.push(InterfaceRate {
                            name: c.name.clone(),
                            rx_bps,
                            tx_bps,
                        });
                    }

                    set_prev_counters.set(resp.interface_counters.clone());
                    set_rates.set(new_rates);
                }
                Err(e) => {
                    if e == "Unauthorized" {
                        on_unauthorized.run(());
                        return;
                    }
                    set_error_msg.set(Some(e));
                }
            }
        });
    };

    // Start polling (and also do an immediate poll).
    Effect::new(move |_| {
        if auth_token.get().is_some() {
            do_poll();
            let interval = Interval::new(1000, move || do_poll());
            std::mem::forget(interval);
        }
    });

    let format_rate = |bps: u64| -> String {
        if bps > 1024 * 1024 {
            format!("{:.1} MiB/s", (bps as f64) / (1024.0 * 1024.0))
        } else if bps > 1024 {
            format!("{:.1} KiB/s", (bps as f64) / 1024.0)
        } else {
            format!("{} B/s", bps)
        }
    };

    view! {
        <div class="space-y-6">
            <div>
                <h1 class="text-2xl font-semibold text-blue-300">"Dashboard"</h1>
                <p class="text-gray-400">"Live network status (updates every second)"</p>
            </div>

            <Show when=move || error_msg.get().is_some()>
                <div class="p-3 bg-red-900/50 border border-red-500 rounded text-red-200 text-sm">
                    {move || error_msg.get().unwrap_or_default()}
                </div>
            </Show>

            <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
                <div class="bg-gray-800 rounded-lg p-5 shadow-lg">
                    <div class="text-sm text-gray-400 mb-1">"WAN IP"</div>
                    <div class="text-lg font-medium">
                        {move || {
                            state
                                .get()
                                .interfaces
                                .iter()
                                .find(|i| i.role == InterfaceRole::WAN)
                                .and_then(|i| i.address.clone())
                                .unwrap_or_else(|| "—".to_string())
                        }}
                    </div>
                </div>

                <div class="bg-gray-800 rounded-lg p-5 shadow-lg">
                    <div class="text-sm text-gray-400 mb-1">"LAN IPs"</div>
                    <div class="text-sm text-gray-200 space-y-1">
                        <For
                            each=move || {
                                state
                                    .get()
                                    .interfaces
                                    .iter()
                                    .filter(|i| i.role == InterfaceRole::LAN)
                                    .filter_map(|i| i.address.clone().map(|a| (i.name.clone(), a)))
                                    .collect::<Vec<_>>()
                            }
                            key=|(name, _)| name.clone()
                            children=|(name, addr)| view! { <div><span class="text-gray-400">{name} ": "</span>{addr}</div> }
                        />
                        <Show when=move || {
                            !state
                                .get()
                                .interfaces
                                .iter()
                                .any(|i| i.role == InterfaceRole::LAN && i.address.is_some())
                        }>
                            <div class="text-gray-500">"—"</div>
                        </Show>
                    </div>
                </div>
            </div>

            <div class="bg-gray-800 rounded-lg p-6 shadow-lg">
                <h2 class="text-xl font-semibold text-blue-300 mb-4">"Network Activity"</h2>

                <div class="overflow-x-auto">
                    <table class="w-full text-sm">
                        <thead>
                            <tr class="text-left text-gray-400 border-b border-gray-700">
                                <th class="py-2 pr-4">"Interface"</th>
                                <th class="py-2 pr-4">"RX"</th>
                                <th class="py-2 pr-4">"TX"</th>
                            </tr>
                        </thead>
                        <tbody>
                            <For
                                each=move || rates.get()
                                key=|r| r.name.clone()
                                children=move |r| {
                                    let rx = format_rate(r.rx_bps);
                                    let tx = format_rate(r.tx_bps);
                                    view! {
                                        <tr class="border-b border-gray-700/50">
                                            <td class="py-2 pr-4 font-medium">{r.name}</td>
                                            <td class="py-2 pr-4 text-gray-200">{rx}</td>
                                            <td class="py-2 pr-4 text-gray-200">{tx}</td>
                                        </tr>
                                    }
                                }
                            />
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    }
}
