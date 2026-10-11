//! Dashboard page with live network status

use crate::api;
use crate::components::TrafficGraph;
use gloo_timers::callback::Interval;
use keystone_core::{GatewayFamily, GatewayStatus, InterfaceRole, InterfaceTraffic, SystemState};
use leptos::prelude::*;
use leptos::task::spawn_local;

#[component]
pub fn DashboardPage(
    auth_token: ReadSignal<Option<String>>,
    state: ReadSignal<SystemState>,
    set_state: WriteSignal<SystemState>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let (traffic, set_traffic) = signal(Vec::<InterfaceTraffic>::new());
    let (gateways, set_gateways) = signal(Vec::<GatewayStatus>::new());
    let (renewing, set_renewing) = signal::<Option<String>>(None);
    let (renew_message, set_renew_message) = signal::<Option<String>>(None);
    let (error_msg, set_error_msg) = signal(Option::<String>::None);
    let (status_error, set_status_error) = signal(Option::<(u32, String)>::None); // (error_count, short_message)

    let do_poll = move || {
        let Some(token) = auth_token.get_untracked() else {
            return;
        };

        spawn_local(async move {
            match api::fetch_dashboard(&token).await {
                Ok(resp) => {
                    set_error_msg.set(None);
                    set_state.set(resp.state.clone());
                    set_gateways.set(resp.gateways);
                    set_traffic.set(resp.traffic);
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

    let renew_link = move |name: String| {
        let Some(token) = auth_token.get_untracked() else {
            return;
        };
        set_renewing.set(Some(name.clone()));
        set_renew_message.set(None);
        spawn_local(async move {
            let result = api::renew_interface(&token, &name).await;
            match result {
                Ok(response) => set_renew_message.set(Some(response.message)),
                Err(e) if e == "Unauthorized" => on_unauthorized.run(()),
                Err(e) => set_renew_message.set(Some(format!("Failed to renew {name}: {e}"))),
            }
            set_renewing.set(None);
        });
    };

    // Start polling (and also do an immediate poll).
    // The Effect stores the returned Interval, which is dropped when the component unmounts,
    // stopping the polling automatically.
    Effect::new(move |_prev_interval: Option<Option<Interval>>| {
        if auth_token.get().is_some() {
            do_poll();
            Some(Interval::new(1000, do_poll))
        } else {
            None
        }
    });

    // Async system status banner (loads after main content)
    Effect::new(move || {
        leptos::task::spawn_local(async move {
            match api::fetch_system_status().await {
                Ok(status) => {
                    if status.error_count > 0 {
                        set_status_error.set(Some((
                            status.error_count,
                            format!("{} system status error(s) detected", status.error_count),
                        )));
                    } else {
                        set_status_error.set(None);
                    }
                }
                Err(_) => {
                    // Don't spam the dashboard if status can't be loaded
                    set_status_error.set(None);
                }
            }
        });
    });

    view! {
        <div class="space-y-6">
            <style>{forge_charts::CHART_CSS}</style>
            <style>{r#"
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
            "#}</style>
            <div>
                <h1 class="text-2xl font-semibold text-blue-300">"Dashboard"</h1>
                <p class="text-gray-400">"Live network status"</p>
            </div>

            <Show when=move || status_error.get().is_some()>
                <div class="p-3 bg-yellow-900/50 border border-yellow-600 rounded text-yellow-200 text-sm">
                    <div class="flex items-center justify-between gap-3">
                        <div>
                            {move || status_error.get().map(|(_, msg)| msg).unwrap_or_default()}
                            " · "
                            <a class="underline hover:text-yellow-100" href="/status">"View details"</a>
                        </div>
                        <button
                            class="text-yellow-200/70 hover:text-yellow-100"
                            on:click=move |_| set_status_error.set(None)
                        >
                            "×"
                        </button>
                    </div>
                </div>
            </Show>

            <Show when=move || error_msg.get().is_some()>
                <div class="p-3 bg-red-900/50 border border-red-500 rounded text-red-200 text-sm">
                    {move || error_msg.get().unwrap_or_default()}
                </div>
            </Show>

            <div class="bg-gray-800 rounded-lg p-5 shadow-lg space-y-3">
                <h2 class="text-blue-300 font-medium">"WAN Gateway Health"</h2>
                <p class="text-xs text-gray-400">"ICMP samples every 5 seconds · 5-minute rolling window · monitored by daemon"</p>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {move || [GatewayFamily::Ipv4, GatewayFamily::Ipv6].into_iter().map(|family| {
                        let relevant: Vec<_> = gateways.get().into_iter().filter(|g| g.family == family).collect();
                        let label = if family == GatewayFamily::Ipv4 { "IPv4" } else { "IPv6" };
                        let unhealthy = relevant.iter().any(|g| !g.active_route || g.latest_latency_ms.is_none());
                        let card_class = if unhealthy {
                            "bg-red-950/50 border border-red-700 rounded p-4 space-y-3 min-w-0"
                        } else {
                            "bg-gray-900/60 border border-gray-700 rounded p-4 space-y-3 min-w-0"
                        };
                        view! {
                            <div class=card_class>
                                <div class="font-medium text-gray-200">{label}</div>
                                {if relevant.is_empty() {
                                    view! { <div class="text-sm text-gray-500">"No WAN default gateway detected"</div> }.into_any()
                                } else {
                                    view! {
                                        <div class="space-y-4">
                                            {relevant.into_iter().map(|g| {
                                                let sample_count = g.history.len();
                                                let failed = !g.active_route || g.latest_latency_ms.is_none();
                                                let status_class = if failed { "text-red-400" } else { "text-green-400" };
                                                let loss_class = if g.packet_loss_percent > 0.0 { "text-red-400" } else { "text-gray-300" };
                                                let status_text = if !g.active_route {
                                                    "Route missing".to_owned()
                                                } else if failed {
                                                    "No response".to_owned()
                                                } else {
                                                    format!("{:.1} ms", g.latest_latency_ms.unwrap_or_default())
                                                };
                                                let mean = g.average_latency_ms.map(|ms| format!("{ms:.1} ms"))
                                                    .unwrap_or_else(|| "—".to_owned());
                                                view! {
                                                    <div class="space-y-2">
                                                        <div class="flex justify-between items-baseline gap-2 flex-wrap">
                                                            <span class="text-xs text-gray-400 break-all">{g.interface.clone()} ": " {g.gateway.clone()}</span>
                                                            <span class=format!("text-sm font-semibold {}", status_class)>{status_text}</span>
                                                        </div>
                                                        <div class="flex justify-between text-xs gap-3">
                                                            <span class="text-gray-400">"Mean RTT: " <span class="text-gray-200">{mean}</span></span>
                                                            <span class=loss_class>
                                                                {format!("{:.1}% loss", g.packet_loss_percent)}
                                                            </span>
                                                        </div>
                                                        <div class="flex items-end gap-px h-8" aria-label="Recent ICMP samples: blue means reply, red means loss">
                                                            {g.history.into_iter().map(|sample| {
                                                                let success = sample.latency_ms.is_some();
                                                                let height = sample.latency_ms.map(|ms| (5.0 + ms.min(100.0) * 0.26) as u32).unwrap_or(30);
                                                                view! {
                                                                    <div
                                                                        class=if success { "bg-blue-400 flex-1 min-w-px rounded-t-sm" } else { "bg-red-500 flex-1 min-w-px rounded-t-sm" }
                                                                        style=format!("height: {height}px")
                                                                        title=if let Some(ms) = sample.latency_ms { format!("{ms:.2} ms") } else { "Packet loss".to_owned() }
                                                                    ></div>
                                                                }
                                                            }).collect_view()}
                                                        </div>
                                                        <div class="text-xs text-gray-500">{format!("{} samples", sample_count)}</div>
                                                    </div>
                                                }
                                            }).collect_view()}
                                        </div>
                                    }.into_any()
                                }}
                            </div>
                        }
                    }).collect_view()}
                </div>
            </div>

            <Show when=move || renew_message.get().is_some()>
                <div class="text-sm text-gray-200 bg-gray-800 rounded p-3">{move || renew_message.get().unwrap_or_default()}</div>
            </Show>
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {move || {
                    [InterfaceRole::WAN, InterfaceRole::LAN].into_iter().map(|role| {
                        let relevant = state.get().interfaces.into_iter()
                            .filter(|iface| iface.role == role).collect::<Vec<_>>();
                        let ipv4 = relevant.iter().flat_map(|iface| iface.ipv4_addresses.iter()
                            .filter(|address| !address.starts_with("169.254."))
                            .map(|address| (iface.name.clone(), address.clone())))
                            .collect::<Vec<_>>();
                        let ipv6 = relevant.iter().flat_map(|iface| iface.ipv6_addresses.iter()
                            .filter(|address| !address.starts_with("fe80:"))
                            .map(|address| (iface.name.clone(), address.clone())))
                            .collect::<Vec<_>>();
                        let link_local = relevant.iter().flat_map(|iface| iface.ipv6_addresses.iter()
                            .filter(|address| address.starts_with("fe80:"))
                            .map(|address| (iface.name.clone(), address.clone())))
                            .collect::<Vec<_>>();
                        let link_local_text = link_local.into_iter()
                            .map(|(name, address)| format!("{name}: {address} (link-local)"))
                            .collect::<Vec<_>>().join(" · ");
                        view! {
                            <div class="bg-gray-800 rounded-lg p-5 shadow-lg space-y-4 min-w-0">
                                <div class="flex items-center justify-between gap-3">
                                    <h2 class="text-blue-300 font-medium">{role.to_string()}</h2>
                                    <div class="flex flex-wrap gap-2">
                                        {relevant.iter().map(|iface| {
                                            let name = iface.name.clone();
                                            let check_name = name.clone();
                                            view! {
                                                <button
                                                    class="text-xs px-2 py-1 rounded bg-gray-700 hover:bg-gray-600 disabled:opacity-50 text-gray-200"
                                                    disabled=move || renewing.get().is_some()
                                                    on:click=move |_| renew_link(name.clone())
                                                    title="Renew interface via systemd-networkd"
                                                >
                                                    {move || if renewing.get().as_deref() == Some(check_name.as_str()) {
                                                        format!("Renewing {}...", check_name)
                                                    } else {
                                                        format!("Renew {}", check_name)
                                                    }}
                                                </button>
                                            }
                                        }).collect_view()}
                                    </div>
                                </div>
                                <div>
                                    <div class="text-sm text-gray-400 mb-1">"IPv4"</div>
                                    {if ipv4.is_empty() { view! { <div class="text-gray-500">"—"</div> }.into_any() }
                                    else { view! { <div class="space-y-1">{ipv4.into_iter().map(|(name, address)| view! {
                                        <div class="text-sm text-gray-200 break-all"><span class="text-gray-400">{name} ": "</span>{address}</div>
                                    }).collect_view()}</div> }.into_any() }}
                                </div>
                                <div>
                                    <div class="text-sm text-gray-400 mb-1">"IPv6"</div>
                                    {if ipv6.is_empty() { view! { <div class="text-gray-500">"No global address"</div> }.into_any() }
                                    else { view! { <div class="space-y-1">{ipv6.into_iter().map(|(name, address)| view! {
                                        <div class="text-sm text-gray-200 break-all"><span class="text-gray-400">{name} ": "</span>{address}</div>
                                    }).collect_view()}</div> }.into_any() }}
                                    <div class="text-xs text-gray-500 mt-1 break-all">{link_local_text}</div>
                                </div>
                            </div>
                        }
                    }).collect_view()
                }}
            </div>

            <div class="bg-gray-800 rounded-xl p-5 sm:p-6 shadow-lg space-y-4">
                <div class="flex flex-wrap justify-between items-baseline gap-2">
                    <h2 class="text-xl font-semibold text-blue-300">"Network Activity"</h2>
                    <span class="text-xs text-gray-400">"Live · one-minute rolling history · bytes per second"</span>
                </div>
                <div class="grid grid-cols-1 2xl:grid-cols-2 gap-4">
                    <For
                        each=move || { traffic.get().into_iter().map(|entry| entry.name).collect::<Vec<String>>() }
                        key=|name| name.clone()
                        children=move |name| {
                            view! { <TrafficGraph name=name history=traffic /> }
                        }
                    />
                </div>
                <Show when=move || traffic.get().is_empty()>
                    <p class="text-sm text-gray-500 py-8 text-center">"Collecting interface traffic history..."</p>
                </Show>
            </div>
        </div>
    }
}
