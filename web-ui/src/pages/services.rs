//! Systemd services page - list and manage system services

use keystone_core::{SystemdActiveState, SystemdUnit};
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::components::A;

use crate::api;

/// Returns CSS classes for the status badge based on active state
fn status_badge_class(state: SystemdActiveState) -> &'static str {
    match state {
        SystemdActiveState::Active => "bg-green-600 text-green-100",
        SystemdActiveState::Activating | SystemdActiveState::Reloading => {
            "bg-yellow-600 text-yellow-100"
        }
        SystemdActiveState::Deactivating => "bg-yellow-600 text-yellow-100",
        SystemdActiveState::Inactive => "bg-gray-600 text-gray-200",
        SystemdActiveState::Failed => "bg-red-600 text-red-100",
    }
}

/// Returns the display text for an active state
fn status_text(state: SystemdActiveState) -> &'static str {
    match state {
        SystemdActiveState::Active => "Running",
        SystemdActiveState::Activating => "Starting",
        SystemdActiveState::Deactivating => "Stopping",
        SystemdActiveState::Inactive => "Stopped",
        SystemdActiveState::Failed => "Failed",
        SystemdActiveState::Reloading => "Reloading",
    }
}

#[component]
pub fn ServicesPage(
    auth_token: ReadSignal<Option<String>>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let (units, set_units) = signal(Vec::<SystemdUnit>::new());
    let (loading, set_loading) = signal(true);
    let (error_msg, set_error_msg) = signal(Option::<String>::None);
    let (success_msg, set_success_msg) = signal(Option::<String>::None);
    let (show_all, set_show_all) = signal(false);
    let (action_in_progress, set_action_in_progress) = signal(Option::<String>::None);

    // Load units function
    let load_units = move || {
        let keystone_only = !show_all.get();
        if let Some(token) = auth_token.get() {
            set_loading.set(true);
            spawn_local(async move {
                match api::fetch_units(&token, keystone_only).await {
                    Ok(units_list) => {
                        set_units.set(units_list);
                        set_error_msg.set(None);
                    }
                    Err(e) => {
                        if e.contains("Unauthorized") {
                            on_unauthorized.run(());
                        } else {
                            set_error_msg.set(Some(format!("Failed to load units: {}", e)));
                        }
                    }
                }
                set_loading.set(false);
            });
        }
    };

    // Load on mount
    Effect::new(move || {
        load_units();
    });

    // Reload when show_all changes
    Effect::new(move || {
        let _ = show_all.get();
        load_units();
    });

    let start_unit = move |unit_name: String| {
        let token = match auth_token.get() {
            Some(t) => t,
            None => return,
        };
        set_action_in_progress.set(Some(unit_name.clone()));
        set_success_msg.set(None);
        set_error_msg.set(None);

        spawn_local(async move {
            match api::start_unit(&token, &unit_name).await {
                Ok(response) => {
                    if response.success {
                        set_success_msg.set(Some(response.message));
                    } else {
                        set_error_msg.set(Some(response.message));
                    }
                    load_units();
                }
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        set_error_msg.set(Some(format!("Failed to start unit: {}", e)));
                    }
                }
            }
            set_action_in_progress.set(None);
        });
    };

    let stop_unit = move |unit_name: String| {
        let token = match auth_token.get() {
            Some(t) => t,
            None => return,
        };
        set_action_in_progress.set(Some(unit_name.clone()));
        set_success_msg.set(None);
        set_error_msg.set(None);

        spawn_local(async move {
            match api::stop_unit(&token, &unit_name).await {
                Ok(response) => {
                    if response.success {
                        set_success_msg.set(Some(response.message));
                    } else {
                        set_error_msg.set(Some(response.message));
                    }
                    load_units();
                }
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        set_error_msg.set(Some(format!("Failed to stop unit: {}", e)));
                    }
                }
            }
            set_action_in_progress.set(None);
        });
    };

    let restart_unit = move |unit_name: String| {
        let token = match auth_token.get() {
            Some(t) => t,
            None => return,
        };
        set_action_in_progress.set(Some(unit_name.clone()));
        set_success_msg.set(None);
        set_error_msg.set(None);

        spawn_local(async move {
            match api::restart_unit(&token, &unit_name).await {
                Ok(response) => {
                    if response.success {
                        set_success_msg.set(Some(response.message));
                    } else {
                        set_error_msg.set(Some(response.message));
                    }
                    load_units();
                }
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        set_error_msg.set(Some(format!("Failed to restart unit: {}", e)));
                    }
                }
            }
            set_action_in_progress.set(None);
        });
    };

    view! {
        <div class="space-y-6">
            <div>
                <h1 class="text-2xl font-semibold text-blue-300">"System Services"</h1>
                <p class="text-gray-400">"Manage systemd services"</p>
            </div>

            // Success message
            <Show when=move || success_msg.get().is_some()>
                <div class="bg-green-900/50 border border-green-500 rounded p-4 text-green-200">
                    {move || success_msg.get().unwrap_or_default()}
                </div>
            </Show>

            // Error message
            <Show when=move || error_msg.get().is_some()>
                <div class="bg-red-900/50 border border-red-500 rounded p-4 text-red-200">
                    {move || error_msg.get().unwrap_or_default()}
                </div>
            </Show>

            // Controls
            <div class="bg-gray-800 rounded-lg p-4 shadow-lg">
                <div class="flex items-center justify-between">
                    <label class="flex items-center cursor-pointer">
                        <input
                            type="checkbox"
                            prop:checked=move || show_all.get()
                            on:change=move |ev| set_show_all.set(event_target_checked(&ev))
                            class="w-5 h-5 rounded border-gray-500 bg-gray-600 text-blue-500"
                        />
                        <span class="ml-3 text-gray-300">
                            "Show all system services"
                        </span>
                    </label>
                    <button
                        on:click=move |_| load_units()
                        class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
                        disabled=move || loading.get()
                    >
                        {move || if loading.get() { "Loading..." } else { "Refresh" }}
                    </button>
                </div>
            </div>

            // Loading state
            <Show when=move || loading.get() && units.get().is_empty()>
                <div class="bg-gray-800 rounded-lg p-8 shadow-lg text-center">
                    <div class="text-gray-400">"Loading services..."</div>
                </div>
            </Show>

            // Units list
            <Show when=move || !loading.get() || !units.get().is_empty()>
                <div class="bg-gray-800 rounded-lg shadow-lg overflow-hidden">
                    <div class="divide-y divide-gray-700">
                        <For
                            each=move || units.get()
                            key=|unit| (unit.name.clone(), unit.active_state, unit.enabled)
                            children=move |unit: SystemdUnit| {
                                let unit_name_for_link = unit.name.clone();
                                let unit_name_for_start = unit.name.clone();
                                let unit_name_for_stop = unit.name.clone();
                                let unit_name_for_restart = unit.name.clone();
                                let description = unit.description.clone();
                                let active_state = unit.active_state;
                                let sub_state = unit.sub_state.clone();
                                let enabled = unit.enabled;
                                let is_active = matches!(active_state, SystemdActiveState::Active);

                                view! {
                                    <div class="p-4 hover:bg-gray-700/50">
                                        <div class="flex items-center justify-between">
                                            <div class="flex-1 min-w-0">
                                                <div class="flex items-center gap-3">
                                                    <A
                                                        href=format!("/services/{}", urlencoding::encode(&unit_name_for_link))
                                                        attr:class="text-blue-400 hover:text-blue-300 font-medium truncate"
                                                    >
                                                        {unit_name_for_link}
                                                    </A>
                                                    <span class=format!(
                                                        "px-2 py-0.5 rounded text-xs font-medium {}",
                                                        status_badge_class(active_state)
                                                    )>
                                                        {status_text(active_state)}
                                                    </span>
                                                    <Show when=move || enabled>
                                                        <span class="px-2 py-0.5 rounded text-xs font-medium bg-blue-900 text-blue-200">
                                                            "Enabled"
                                                        </span>
                                                    </Show>
                                                </div>
                                                <p class="text-sm text-gray-400 mt-1 truncate">
                                                    {description}
                                                </p>
                                                <p class="text-xs text-gray-500 mt-0.5">
                                                    {sub_state}
                                                </p>
                                            </div>
                                            <div class="flex gap-2 ml-4">
                                                <Show when=move || !is_active>
                                                    {
                                                        let name_for_click = unit_name_for_start.clone();
                                                        view! {
                                                            <button
                                                                on:click=move |_| start_unit(name_for_click.clone())
                                                                class="bg-green-600 hover:bg-green-700 disabled:bg-green-800 disabled:cursor-not-allowed text-white px-3 py-1 rounded text-sm"
                                                                disabled=move || action_in_progress.get().is_some()
                                                            >
                                                                "Start"
                                                            </button>
                                                        }
                                                    }
                                                </Show>
                                                <Show when=move || is_active>
                                                    {
                                                        let name_restart = unit_name_for_restart.clone();
                                                        let name_stop = unit_name_for_stop.clone();
                                                        view! {
                                                            <button
                                                                on:click=move |_| restart_unit(name_restart.clone())
                                                                class="bg-yellow-600 hover:bg-yellow-700 disabled:bg-yellow-800 disabled:cursor-not-allowed text-white px-3 py-1 rounded text-sm"
                                                                disabled=move || action_in_progress.get().is_some()
                                                            >
                                                                "Restart"
                                                            </button>
                                                            <button
                                                                on:click=move |_| stop_unit(name_stop.clone())
                                                                class="bg-red-600 hover:bg-red-700 disabled:bg-red-800 disabled:cursor-not-allowed text-white px-3 py-1 rounded text-sm"
                                                                disabled=move || action_in_progress.get().is_some()
                                                            >
                                                                "Stop"
                                                            </button>
                                                        }
                                                    }
                                                </Show>
                                            </div>
                                        </div>
                                    </div>
                                }
                            }
                        />
                    </div>
                </div>
            </Show>

            // Empty state
            <Show when=move || !loading.get() && units.get().is_empty()>
                <div class="bg-gray-800 rounded-lg p-8 shadow-lg text-center">
                    <p class="text-gray-400">"No services found"</p>
                </div>
            </Show>
        </div>
    }
}
