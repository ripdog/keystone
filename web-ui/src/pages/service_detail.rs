//! Service detail page - view details and logs for a specific systemd unit

use crate::components::use_toasts;
use keystone_core::{SystemdActiveState, SystemdUnitDetail};
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::components::A;
use leptos_router::hooks::use_params_map;

use crate::api;

/// Format bytes to human-readable string
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Format Unix timestamp to human-readable string
fn format_timestamp(timestamp: u64) -> String {
    // Convert microseconds to seconds if needed (systemd often uses microseconds)
    let secs = if timestamp > 1_000_000_000_000 {
        timestamp / 1_000_000
    } else {
        timestamp
    };

    // Use JavaScript Date for formatting in WASM
    let date = js_sys::Date::new(&(secs as f64 * 1000.0).into());
    format!(
        "{}-{:02}-{:02} {:02}:{:02}:{:02}",
        date.get_full_year(),
        date.get_month() + 1,
        date.get_date(),
        date.get_hours(),
        date.get_minutes(),
        date.get_seconds()
    )
}

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
pub fn ServiceDetailPage(
    auth_token: ReadSignal<Option<String>>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let toasts = use_toasts();
    let params = use_params_map();

    let (unit_detail, set_unit_detail) = signal(Option::<SystemdUnitDetail>::None);
    let (loading, set_loading) = signal(true);
    let (error_msg, set_error_msg) = signal(Option::<String>::None);
    let (action_in_progress, set_action_in_progress) = signal(false);

    // Get the unit name from URL params
    let unit_name = move || params.get().get("name").unwrap_or_default();

    // Load unit details
    let load_unit = move || {
        let name = unit_name();
        if name.is_empty() {
            return;
        }

        if let Some(token) = auth_token.get() {
            set_loading.set(true);
            spawn_local(async move {
                match api::fetch_unit_detail(&token, &name).await {
                    Ok(detail) => {
                        set_unit_detail.set(detail);
                        set_error_msg.set(None);
                    }
                    Err(e) => {
                        if e.contains("Unauthorized") {
                            on_unauthorized.run(());
                        } else {
                            set_error_msg.set(Some(format!("Failed to load unit: {}", e)));
                        }
                    }
                }
                set_loading.set(false);
            });
        }
    };

    // Load on mount
    Effect::new(move || {
        load_unit();
    });

    // Action handlers
    let start_unit_action = move |_| {
        let name = unit_name();
        let token = match auth_token.get() {
            Some(t) => t,
            None => return,
        };
        set_action_in_progress.set(true);
        set_error_msg.set(None);

        spawn_local(async move {
            match api::start_unit(&token, &name).await {
                Ok(response) => {
                    if response.success {
                        toasts.success(response.message);
                    } else {
                        set_error_msg.set(Some(response.message));
                    }
                    load_unit();
                }
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        set_error_msg.set(Some(format!("Failed to start unit: {}", e)));
                    }
                }
            }
            set_action_in_progress.set(false);
        });
    };

    let stop_unit_action = move |_| {
        let name = unit_name();
        let token = match auth_token.get() {
            Some(t) => t,
            None => return,
        };
        set_action_in_progress.set(true);
        set_error_msg.set(None);

        spawn_local(async move {
            match api::stop_unit(&token, &name).await {
                Ok(response) => {
                    if response.success {
                        toasts.success(response.message);
                    } else {
                        set_error_msg.set(Some(response.message));
                    }
                    load_unit();
                }
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        set_error_msg.set(Some(format!("Failed to stop unit: {}", e)));
                    }
                }
            }
            set_action_in_progress.set(false);
        });
    };

    let restart_unit_action = move |_| {
        let name = unit_name();
        let token = match auth_token.get() {
            Some(t) => t,
            None => return,
        };
        set_action_in_progress.set(true);
        set_error_msg.set(None);

        spawn_local(async move {
            match api::restart_unit(&token, &name).await {
                Ok(response) => {
                    if response.success {
                        toasts.success(response.message);
                    } else {
                        set_error_msg.set(Some(response.message));
                    }
                    load_unit();
                }
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        set_error_msg.set(Some(format!("Failed to restart unit: {}", e)));
                    }
                }
            }
            set_action_in_progress.set(false);
        });
    };

    let enable_unit_action = move |_| {
        let name = unit_name();
        let token = match auth_token.get() {
            Some(t) => t,
            None => return,
        };
        set_action_in_progress.set(true);
        set_error_msg.set(None);

        spawn_local(async move {
            match api::enable_unit(&token, &name).await {
                Ok(response) => {
                    if response.success {
                        toasts.success(response.message);
                    } else {
                        set_error_msg.set(Some(response.message));
                    }
                    load_unit();
                }
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        set_error_msg.set(Some(format!("Failed to enable unit: {}", e)));
                    }
                }
            }
            set_action_in_progress.set(false);
        });
    };

    let disable_unit_action = move |_| {
        let name = unit_name();
        let token = match auth_token.get() {
            Some(t) => t,
            None => return,
        };
        set_action_in_progress.set(true);
        set_error_msg.set(None);

        spawn_local(async move {
            match api::disable_unit(&token, &name).await {
                Ok(response) => {
                    if response.success {
                        toasts.success(response.message);
                    } else {
                        set_error_msg.set(Some(response.message));
                    }
                    load_unit();
                }
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        set_error_msg.set(Some(format!("Failed to disable unit: {}", e)));
                    }
                }
            }
            set_action_in_progress.set(false);
        });
    };

    view! {
        <div class="space-y-6">
            // Header with back link
            <div class="flex items-center gap-4">
                <A
                    href="/services"
                    attr:class="text-gray-400 hover:text-white"
                >
                    "<- Back to Services"
                </A>
            </div>

            <div>
                <h1 class="text-2xl font-semibold text-blue-300">{move || unit_name()}</h1>
                <p class="text-gray-400">"Service Details"</p>
            </div>

            // Success message

            // Error message
            <Show when=move || error_msg.get().is_some()>
                <div class="bg-red-900/50 border border-red-500 rounded p-4 text-red-200">
                    {move || error_msg.get().unwrap_or_default()}
                </div>
            </Show>

            // Loading state
            <Show when=move || loading.get() && unit_detail.get().is_none()>
                <div class="bg-gray-800 rounded-lg p-8 shadow-lg text-center">
                    <div class="text-gray-400">"Loading service details..."</div>
                </div>
            </Show>

            // Unit not found
            <Show when=move || !loading.get() && unit_detail.get().is_none()>
                <div class="bg-gray-800 rounded-lg p-8 shadow-lg text-center">
                    <p class="text-red-400">"Service not found"</p>
                </div>
            </Show>

            // Unit details
            <Show when=move || unit_detail.get().is_some()>
                {move || {
                    let detail = unit_detail.get().unwrap();
                    let unit = detail.unit.clone();
                    let is_active = matches!(unit.active_state, SystemdActiveState::Active);
                    let logs = detail.recent_logs.clone();
                    let unit_enabled = unit.enabled;

                    // Clone values that will be used in nested closures
                    let result_for_class = detail.result.clone();
                    let result_for_display = detail.result.clone();
                    let logs_for_check = logs.clone();
                    let logs_for_iter = logs.clone();

                    view! {
                        // Status and Actions
                        <div class="bg-gray-800 rounded-lg p-6 shadow-lg">
                            <div class="flex items-center justify-between mb-4">
                                <div class="flex items-center gap-3">
                                    <span class=format!(
                                        "px-3 py-1 rounded text-sm font-medium {}",
                                        status_badge_class(unit.active_state)
                                    )>
                                        {status_text(unit.active_state)}
                                    </span>
                                    <Show when=move || unit_enabled>
                                        <span class="px-3 py-1 rounded text-sm font-medium bg-blue-900 text-blue-200">
                                            "Enabled"
                                        </span>
                                    </Show>
                                </div>
                                <div class="flex gap-2">
                                    <Show when=move || !is_active>
                                        <button
                                            on:click=start_unit_action
                                            class="bg-green-600 hover:bg-green-700 disabled:bg-green-800 disabled:cursor-not-allowed text-white px-4 py-2 rounded"
                                            disabled=move || action_in_progress.get()
                                        >
                                            {move || if action_in_progress.get() { "..." } else { "Start" }}
                                        </button>
                                    </Show>
                                    <Show when=move || is_active>
                                        <button
                                            on:click=restart_unit_action
                                            class="bg-yellow-600 hover:bg-yellow-700 disabled:bg-yellow-800 disabled:cursor-not-allowed text-white px-4 py-2 rounded"
                                            disabled=move || action_in_progress.get()
                                        >
                                            {move || if action_in_progress.get() { "..." } else { "Restart" }}
                                        </button>
                                        <button
                                            on:click=stop_unit_action
                                            class="bg-red-600 hover:bg-red-700 disabled:bg-red-800 disabled:cursor-not-allowed text-white px-4 py-2 rounded"
                                            disabled=move || action_in_progress.get()
                                        >
                                            {move || if action_in_progress.get() { "..." } else { "Stop" }}
                                        </button>
                                    </Show>
                                    <Show when=move || !unit_enabled>
                                        <button
                                            on:click=enable_unit_action
                                            class="bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 disabled:cursor-not-allowed text-white px-4 py-2 rounded"
                                            disabled=move || action_in_progress.get()
                                        >
                                            {move || if action_in_progress.get() { "..." } else { "Enable" }}
                                        </button>
                                    </Show>
                                    <Show when=move || unit_enabled>
                                        <button
                                            on:click=disable_unit_action
                                            class="bg-gray-600 hover:bg-gray-700 disabled:bg-gray-800 disabled:cursor-not-allowed text-white px-4 py-2 rounded"
                                            disabled=move || action_in_progress.get()
                                        >
                                            {move || if action_in_progress.get() { "..." } else { "Disable" }}
                                        </button>
                                    </Show>
                                    <button
                                        on:click=move |_| load_unit()
                                        class="bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded"
                                        disabled=move || loading.get()
                                    >
                                        {move || if loading.get() { "..." } else { "Refresh" }}
                                    </button>
                                </div>
                            </div>

                            <p class="text-gray-300">{unit.description.clone()}</p>
                        </div>

                        // Unit Info
                        <div class="bg-gray-800 rounded-lg p-6 shadow-lg">
                            <h2 class="text-lg font-medium text-white mb-4">"Unit Information"</h2>
                            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                                <div class="bg-gray-700 rounded p-4">
                                    <h3 class="text-sm text-gray-400 mb-1">"Load State"</h3>
                                    <p class="text-white">{unit.load_state.to_string()}</p>
                                </div>
                                <div class="bg-gray-700 rounded p-4">
                                    <h3 class="text-sm text-gray-400 mb-1">"Sub State"</h3>
                                    <p class="text-white">{unit.sub_state.clone()}</p>
                                </div>
                                <Show when=move || detail.main_pid.is_some()>
                                    <div class="bg-gray-700 rounded p-4">
                                        <h3 class="text-sm text-gray-400 mb-1">"Main PID"</h3>
                                        <p class="text-white">{detail.main_pid.unwrap_or(0)}</p>
                                    </div>
                                </Show>
                                <Show when=move || detail.memory_bytes.is_some()>
                                    <div class="bg-gray-700 rounded p-4">
                                        <h3 class="text-sm text-gray-400 mb-1">"Memory Usage"</h3>
                                        <p class="text-white">{format_bytes(detail.memory_bytes.unwrap_or(0))}</p>
                                    </div>
                                </Show>
                                <Show when=move || detail.active_enter_timestamp.is_some()>
                                    <div class="bg-gray-700 rounded p-4">
                                        <h3 class="text-sm text-gray-400 mb-1">"Started At"</h3>
                                        <p class="text-white">{format_timestamp(detail.active_enter_timestamp.unwrap_or(0))}</p>
                                    </div>
                                </Show>
                                <Show when=move || detail.inactive_enter_timestamp.is_some()>
                                    <div class="bg-gray-700 rounded p-4">
                                        <h3 class="text-sm text-gray-400 mb-1">"Stopped At"</h3>
                                        <p class="text-white">{format_timestamp(detail.inactive_enter_timestamp.unwrap_or(0))}</p>
                                    </div>
                                </Show>
                                <Show when=move || detail.result.is_some()>
                                    <div class="bg-gray-700 rounded p-4">
                                        <h3 class="text-sm text-gray-400 mb-1">"Result"</h3>
                                        <p class={
                                            let result = result_for_class.clone().unwrap_or_default();
                                            if result == "success" {
                                                "text-green-400"
                                            } else {
                                                "text-red-400"
                                            }
                                        }>
                                            {result_for_display.clone().unwrap_or_default()}
                                        </p>
                                    </div>
                                </Show>
                            </div>
                        </div>

                        // Logs
                        <div class="bg-gray-800 rounded-lg p-6 shadow-lg">
                            <h2 class="text-lg font-medium text-white mb-4">"Recent Logs"</h2>
                            <Show
                                when=move || !logs_for_check.is_empty()
                                fallback=|| view! {
                                    <p class="text-gray-400">"No recent log entries"</p>
                                }
                            >
                                {
                                    let logs_inner = logs_for_iter.clone();
                                    view! {
                                        <div class="bg-gray-900 rounded p-4 font-mono text-sm overflow-x-auto max-h-96 overflow-y-auto">
                                            <For
                                                each=move || logs_inner.clone().into_iter().enumerate()
                                                key=|(idx, _)| *idx
                                                children=|(_, line)| {
                                                    view! {
                                                        <div class="text-gray-300 whitespace-pre-wrap border-b border-gray-800 py-1">
                                                            {line}
                                                        </div>
                                                    }
                                                }
                                            />
                                        </div>
                                    }
                                }
                            </Show>
                        </div>
                    }
                }}
            </Show>
        </div>
    }
}
