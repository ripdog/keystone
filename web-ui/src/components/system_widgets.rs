//! Dashboard widgets: host resource summary and a compact service control list.

use crate::api;
use crate::components::use_toasts;
use gloo_timers::callback::Interval;
use keystone_core::{SystemInfo, SystemdActiveState, SystemdUnit};
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::components::A;

/// Services whose stop would cut the operator off from Keystone itself.
const NO_STOP_UNITS: &[&str] = &["keystone-daemon.service", "keystone-web-ui.service"];

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit < 3 {
        format!("{value:.0} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn format_uptime(secs: u64) -> String {
    let (days, hours, minutes) = (secs / 86_400, secs / 3_600 % 24, secs / 60 % 60);
    match (days, hours) {
        (0, 0) => format!("{minutes}m"),
        (0, _) => format!("{hours}h {minutes}m"),
        _ => format!("{days}d {hours}h"),
    }
}

fn percent(used: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        used as f64 / total as f64 * 100.0
    }
}

fn bar_color(percent: f64) -> &'static str {
    if percent >= 90.0 {
        "bg-red-500"
    } else if percent >= 75.0 {
        "bg-yellow-500"
    } else {
        "bg-blue-400"
    }
}

/// A labelled usage bar: `label` on the left, `detail` on the right.
#[component]
fn Meter(label: String, detail: String, percent: f64) -> impl IntoView {
    let width = percent.clamp(0.0, 100.0);
    view! {
        <div class="space-y-1">
            <div class="flex justify-between gap-3 text-xs">
                <span class="text-gray-400 truncate">{label}</span>
                <span class="text-gray-200 whitespace-nowrap">{detail}</span>
            </div>
            <div class="h-1.5 rounded bg-gray-700 overflow-hidden">
                <div class=format!("h-full rounded {}", bar_color(percent)) style=format!("width: {width:.0}%")></div>
            </div>
        </div>
    }
}

#[component]
pub fn SystemInfoCard(
    auth_token: ReadSignal<Option<String>>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let (info, set_info) = signal(Option::<SystemInfo>::None);
    let (error, set_error) = signal(Option::<String>::None);

    let poll = move || {
        let Some(token) = auth_token.get_untracked() else {
            return;
        };
        spawn_local(async move {
            match api::fetch_system_info(&token).await {
                Ok(next) => {
                    set_error.set(None);
                    set_info.set(Some(next));
                }
                Err(e) if e == "Unauthorized" => on_unauthorized.run(()),
                Err(e) => set_error.set(Some(e)),
            }
        });
    };

    // The Interval is dropped with the effect's previous value, stopping polling on unmount.
    Effect::new(move |_prev: Option<Option<Interval>>| {
        if auth_token.get().is_some() {
            poll();
            Some(Interval::new(2000, poll))
        } else {
            None
        }
    });

    view! {
        <div class="bg-gray-800 rounded-lg p-5 shadow-lg space-y-4 min-w-0 h-full flex flex-col">
            <h2 class="text-blue-300 font-medium">"System"</h2>
            <Show when=move || error.get().is_some()>
                <div class="text-xs text-red-300">{move || error.get().unwrap_or_default()}</div>
            </Show>
            {move || match info.get() {
                None => view! { <div class="text-sm text-gray-500">"Loading..."</div> }.into_any(),
                Some(i) => {
                    let cpu = i.cpu_usage_percent;
                    let cpu_detail = match cpu {
                        Some(p) => format!("{p:.0}% · {} cores", i.cpu_count),
                        None => format!("— · {} cores", i.cpu_count),
                    };
                    let mem_pct = percent(i.memory_used_bytes, i.memory_total_bytes);
                    let swap_pct = percent(i.swap_used_bytes, i.swap_total_bytes);
                    view! {
                        <div class="flex flex-col justify-between gap-3 flex-1">
                            <div class="text-xs text-gray-400 space-y-0.5">
                                <div class="flex justify-between gap-3">
                                    <span class="text-gray-200 font-medium truncate">{i.hostname.clone()}</span>
                                    <span class="whitespace-nowrap">"up " {format_uptime(i.uptime_secs)}</span>
                                </div>
                                {i.cpu_model.clone().map(|m| view! { <div class="truncate" title=m.clone()>{m.clone()}</div> })}
                                <div class="truncate">"Linux " {i.kernel.clone()}</div>
                            </div>
                            <Meter label="CPU".to_owned() detail=cpu_detail percent=cpu.unwrap_or(0.0) />
                            <Meter
                                label="Memory".to_owned()
                                detail=format!("{} / {}", format_bytes(i.memory_used_bytes), format_bytes(i.memory_total_bytes))
                                percent=mem_pct
                            />
                            {(i.swap_total_bytes > 0).then(|| view! {
                                <Meter
                                    label="Swap".to_owned()
                                    detail=format!("{} / {}", format_bytes(i.swap_used_bytes), format_bytes(i.swap_total_bytes))
                                    percent=swap_pct
                                />
                            })}
                            {i.disks.iter().map(|d| view! {
                                <Meter
                                    label=format!("Disk {}", d.mount_point)
                                    detail=format!("{} / {}", format_bytes(d.used_bytes), format_bytes(d.total_bytes))
                                    percent=percent(d.used_bytes, d.total_bytes)
                                />
                            }).collect_view()}
                            <div class="flex justify-between gap-3 text-xs text-gray-400 pt-1">
                                <span>
                                    "Load "
                                    <span class="text-gray-200">
                                        {format!("{:.2} {:.2} {:.2}", i.load_average[0], i.load_average[1], i.load_average[2])}
                                    </span>
                                </span>
                                {i.cpu_temperature_c.map(|t| view! {
                                    <span>"CPU " <span class="text-gray-200">{format!("{t:.0} °C")}</span></span>
                                })}
                            </div>
                        </div>
                    }.into_any()
                }
            }}
        </div>
    }
}

fn state_dot_class(state: SystemdActiveState) -> &'static str {
    match state {
        SystemdActiveState::Active => "bg-green-400",
        SystemdActiveState::Activating
        | SystemdActiveState::Deactivating
        | SystemdActiveState::Reloading => "bg-yellow-400 animate-pulse",
        SystemdActiveState::Inactive => "bg-gray-500",
        SystemdActiveState::Failed => "bg-red-500",
    }
}

#[derive(Clone, Copy, PartialEq)]
enum ServiceAction {
    Start,
    Stop,
    Restart,
}

impl ServiceAction {
    fn label(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
        }
    }
}

#[component]
pub fn ServicesCard(
    auth_token: ReadSignal<Option<String>>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let toasts = use_toasts();
    let (units, set_units) = signal(Vec::<SystemdUnit>::new());
    let (error, set_error) = signal(Option::<String>::None);
    let (busy, set_busy) = signal(Option::<String>::None);

    let poll = move || {
        let Some(token) = auth_token.get_untracked() else {
            return;
        };
        spawn_local(async move {
            match api::fetch_units(&token, true).await {
                Ok(list) => set_units.set(list),
                Err(e) if e.contains("Unauthorized") => on_unauthorized.run(()),
                Err(e) => set_error.set(Some(format!("Failed to load services: {e}"))),
            }
        });
    };

    Effect::new(move |_prev: Option<Option<Interval>>| {
        if auth_token.get().is_some() {
            poll();
            Some(Interval::new(3000, poll))
        } else {
            None
        }
    });

    let run_action = move |name: String, action: ServiceAction| {
        let Some(token) = auth_token.get_untracked() else {
            return;
        };
        if action == ServiceAction::Stop {
            let confirmed = web_sys::window()
                .and_then(|w| w.confirm_with_message(&format!("Stop {name}?")).ok())
                .unwrap_or(false);
            if !confirmed {
                return;
            }
        }
        set_busy.set(Some(name.clone()));
        set_error.set(None);
        spawn_local(async move {
            let result = match action {
                ServiceAction::Start => api::start_unit(&token, &name).await,
                ServiceAction::Stop => api::stop_unit(&token, &name).await,
                ServiceAction::Restart => api::restart_unit(&token, &name).await,
            };
            match result {
                Ok(r) if r.success => toasts.success(r.message),
                Ok(r) => set_error.set(Some(r.message)),
                Err(e) if e.contains("Unauthorized") => on_unauthorized.run(()),
                Err(e) => set_error.set(Some(format!("Failed to {} {name}: {e}", action.label()))),
            }
            set_busy.set(None);
            poll();
        });
    };

    let button = "text-xs px-2 py-0.5 rounded bg-gray-700 hover:bg-gray-600 disabled:opacity-40 disabled:cursor-not-allowed text-gray-200";

    view! {
        <div class="bg-gray-800 rounded-lg p-5 shadow-lg space-y-3 min-w-0">
            <div class="flex items-center justify-between gap-3">
                <h2 class="text-blue-300 font-medium">"Services"</h2>
                <A href="/services" attr:class="text-xs text-gray-400 hover:text-gray-200">"Manage"</A>
            </div>
            <Show when=move || error.get().is_some()>
                <div class="text-xs text-red-300 break-words">{move || error.get().unwrap_or_default()}</div>
            </Show>
            <Show when=move || units.get().is_empty() && error.get().is_none()>
                <div class="text-sm text-gray-500">"Loading..."</div>
            </Show>
            <ul class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-x-8">
                <For
                    each=move || units.get()
                    key=|u| (u.name.clone(), u.active_state)
                    children=move |unit: SystemdUnit| {
                        let name = unit.name.clone();
                        let short = name.trim_end_matches(".service").to_owned();
                        let state = unit.active_state;
                        let running = state == SystemdActiveState::Active;
                        let protected = NO_STOP_UNITS.contains(&name.as_str());
                        let href = format!("/services/{}", urlencoding::encode(&name));
                        let (n_restart, n_toggle) = (name.clone(), name.clone());
                        let toggle_action = if running { ServiceAction::Stop } else { ServiceAction::Start };
                        view! {
                            <li class="flex items-center justify-between gap-3 py-1.5 border-b border-gray-700/70">
                                <div class="flex items-center gap-2 min-w-0">
                                    <span
                                        class=format!("w-2 h-2 rounded-full shrink-0 {}", state_dot_class(state))
                                        title=format!("{} ({})", state, unit.sub_state)
                                    ></span>
                                    <A href=href attr:class="text-sm text-gray-200 hover:text-blue-300 truncate" attr:title=unit.description.clone()>
                                        {short}
                                    </A>
                                </div>
                                <div class="flex gap-1.5 shrink-0">
                                    <button
                                        class=button
                                        title="Restart"
                                        disabled=move || busy.get().is_some() || !running
                                        on:click=move |_| run_action(n_restart.clone(), ServiceAction::Restart)
                                    >"Restart"</button>
                                    <button
                                        class=button
                                        title=if protected && running { "Keystone's own services can't be stopped from the dashboard" } else { "" }
                                        disabled=move || busy.get().is_some() || (protected && running)
                                        on:click=move |_| run_action(n_toggle.clone(), toggle_action)
                                    >{if running { "Stop" } else { "Start" }}</button>
                                </div>
                            </li>
                        }
                    }
                />
            </ul>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_scale_to_readable_units() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(8 * 1024 * 1024 * 1024), "8.0 GiB");
        assert_eq!(format_bytes(300 * 1024 * 1024), "300 MiB");
    }

    #[test]
    fn uptime_uses_the_two_largest_units() {
        assert_eq!(format_uptime(59), "0m");
        assert_eq!(format_uptime(3 * 3600 + 5 * 60), "3h 5m");
        assert_eq!(format_uptime(2 * 86_400 + 4 * 3600), "2d 4h");
    }

    #[test]
    fn percent_handles_empty_totals() {
        assert_eq!(percent(1, 0), 0.0);
        assert_eq!(percent(1, 4), 25.0);
    }
}
