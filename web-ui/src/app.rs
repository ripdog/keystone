//! Keystone Web UI - Leptos Frontend (WASM)
//!
//! This module contains the Leptos components that compile to WASM
//! and run in the browser as a Single Page Application.

use gloo_timers::callback::Interval;
use keystone_core::{
    DashboardResponse, FirewallRule, InterfaceCounters, InterfaceRole, LoginRequest,
    LoginResponse, ManagedInterface, ManagedInterfacesResponse, SaveManagedInterfacesRequest,
    SaveManagedInterfacesResponse, SystemState,
};
use leptos::prelude::*;
use leptos::task::spawn_local;
use std::collections::HashMap;

const TOKEN_KEY: &str = "keystone_auth_token";

fn get_stored_token() -> Option<String> {
    let window = web_sys::window()?;
    let storage = window.local_storage().ok()??;
    storage.get_item(TOKEN_KEY).ok()?
}

fn set_stored_token(token: &str) {
    if let Some(window) = web_sys::window()
        && let Ok(Some(storage)) = window.local_storage()
    {
        let _ = storage.set_item(TOKEN_KEY, token);
    }
}

fn clear_stored_token() {
    if let Some(window) = web_sys::window()
        && let Ok(Some(storage)) = window.local_storage()
    {
        let _ = storage.remove_item(TOKEN_KEY);
    }
}

#[component]
pub fn App() -> impl IntoView {
    let (auth_token, set_auth_token) = signal(get_stored_token());
    let (state, set_state) = signal(SystemState::default());

    let logout = Callback::new(move |()| {
        clear_stored_token();
        set_auth_token.set(None);
    });

    view! {
        <Show
            when=move || auth_token.get().is_some()
            fallback=move || view! { <LoginPage on_login=set_auth_token/> }
        >
            <LoggedInLayout
                auth_token=auth_token
                set_auth_token=set_auth_token
                state=state
                set_state=set_state
                on_logout=logout
            />
        </Show>
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AppPage {
    Dashboard,
    Interfaces,
    Firewall,
    Settings,
}

#[component]
fn LoggedInLayout(
    auth_token: ReadSignal<Option<String>>,
    set_auth_token: WriteSignal<Option<String>>,
    state: ReadSignal<SystemState>,
    set_state: WriteSignal<SystemState>,
    on_logout: Callback<()>,
) -> impl IntoView {
    let (sidebar_open, set_sidebar_open) = signal(false);
    let (page, set_page) = signal(AppPage::Dashboard);

    let logout_click = move |_| on_logout.run(());

    let on_unauthorized = Callback::new(move |()| {
        clear_stored_token();
        set_auth_token.set(None);
    });

    let nav_item = move |label: &'static str, target: AppPage| {
        let set_page = set_page.clone();
        let set_sidebar_open = set_sidebar_open.clone();
        view! {
            <button
                class="w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200"
                on:click=move |_| {
                    set_page.set(target);
                    set_sidebar_open.set(false);
                }
            >
                {label}
            </button>
        }
    };

    let sidebar = move || {
        view! {
            <div class="h-full flex flex-col">
                <div class="mb-6">
                    <div class="text-xl font-semibold text-blue-400">"Keystone"</div>
                    <div class="text-sm text-gray-400">"Router Manager"</div>
                </div>

                <nav class="space-y-1">
                    {nav_item("Dashboard", AppPage::Dashboard)}
                    {nav_item("Interfaces", AppPage::Interfaces)}
                    {nav_item("Firewall", AppPage::Firewall)}
                    {nav_item("Settings", AppPage::Settings)}
                </nav>

                <div class="mt-auto pt-6">
                    <button
                        class="w-full bg-red-600 hover:bg-red-700 text-white px-3 py-2 rounded"
                        on:click=logout_click
                    >
                        "Logout"
                    </button>
                </div>
            </div>
        }
    };

    view! {
        <div class="min-h-screen bg-gray-900 text-gray-100">
            <header class="lg:hidden flex items-center justify-between p-4 border-b border-gray-800">
                <button
                    class="bg-gray-800 hover:bg-gray-700 px-3 py-2 rounded"
                    on:click=move |_| set_sidebar_open.set(true)
                >
                    "Menu"
                </button>
                <div class="font-semibold text-blue-400">"Keystone"</div>
                <button
                    class="bg-red-600 hover:bg-red-700 text-white px-3 py-2 rounded"
                    on:click=logout_click
                >
                    "Logout"
                </button>
            </header>

            <Show when=move || sidebar_open.get()>
                <div class="lg:hidden fixed inset-0 z-40">
                    <div
                        class="absolute inset-0 bg-black/60"
                        on:click=move |_| set_sidebar_open.set(false)
                    ></div>
                    <aside class="absolute left-0 top-0 bottom-0 w-72 bg-gray-800 p-4 shadow-xl">
                        {sidebar}
                    </aside>
                </div>
            </Show>

            <div class="flex">
                <aside class="hidden lg:block w-64 bg-gray-800 p-6 min-h-screen border-r border-gray-800">
                    {sidebar}
                </aside>

                <main class="flex-1 p-4 lg:p-8">
                    <Show when=move || page.get() == AppPage::Dashboard>
                        <DashboardPage
                            auth_token=auth_token
                            state=state
                            set_state=set_state
                            on_unauthorized=on_unauthorized
                        />
                    </Show>

                    <Show when=move || page.get() == AppPage::Interfaces>
                        <InterfacesPanel
                            auth_token=auth_token
                            state=state
                            on_unauthorized=on_unauthorized
                        />
                    </Show>

                    <Show when=move || page.get() == AppPage::Firewall>
                        <FirewallPanel state=state/>
                    </Show>

                    <Show when=move || page.get() == AppPage::Settings>
                        <SystemSettingsPanel state=state/>
                    </Show>
                </main>
            </div>
        </div>
    }
}

#[derive(Clone, Debug, Default)]
struct InterfaceRate {
    name: String,
    rx_bps: u64,
    tx_bps: u64,
}

#[component]
fn DashboardPage(
    auth_token: ReadSignal<Option<String>>,
    state: ReadSignal<SystemState>,
    set_state: WriteSignal<SystemState>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let (_dashboard, set_dashboard) = signal(Option::<DashboardResponse>::None);
    let (rates, set_rates) = signal(Vec::<InterfaceRate>::new());
    let (prev_counters, set_prev_counters) = signal(Vec::<InterfaceCounters>::new());
    let (error_msg, set_error_msg) = signal(Option::<String>::None);

    let do_poll = move || {
        let Some(token) = auth_token.get_untracked() else {
            return;
        };

        spawn_local(async move {
            match dashboard_api(&token).await {
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
                    set_dashboard.set(Some(resp));
                }
                Err(e) => {
                    if e == "unauthorized" {
                        on_unauthorized.run(());
                        return;
                    }
                    set_error_msg.set(Some(e));
                }
            }
        });
    };

    // Start polling (and also do an immediate poll).
    // Note: we intentionally "forget" the interval handle; the callback reads the token
    // untracked and becomes a no-op after logout.
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

async fn dashboard_api(token: &str) -> Result<DashboardResponse, String> {
    let response = gloo_net::http::Request::get("/api/dashboard")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {}", e))?;

    if response.status() == 401 {
        return Err("unauthorized".to_string());
    }

    if response.ok() {
        response
            .json::<DashboardResponse>()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

#[component]
fn LoginPage(on_login: WriteSignal<Option<String>>) -> impl IntoView {
    let (username, set_username) = signal(String::from("admin"));
    let (password, set_password) = signal(String::new());
    let (error_msg, set_error_msg) = signal(Option::<String>::None);
    let (loading, set_loading) = signal(false);

    let handle_submit = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();

        let password_value = password.get();
        set_loading.set(true);
        set_error_msg.set(None);

        spawn_local(async move {
            match login_api(&password_value).await {
                Ok(response) => {
                    if response.success {
                        if let Some(token) = &response.token {
                            set_stored_token(token);
                            on_login.set(Some(token.clone()));
                        }
                    } else {
                        set_error_msg.set(Some(response.message));
                        set_loading.set(false);
                    }
                }
                Err(e) => {
                    set_error_msg.set(Some(format!("Login failed: {}", e)));
                    set_loading.set(false);
                }
            }
        });
    };

    view! {
        <div class="min-h-screen bg-gray-900 flex items-center justify-center p-4">
            <div class="bg-gray-800 rounded-lg p-8 shadow-2xl max-w-md w-full">
                <div class="text-center mb-8">
                    <h1 class="text-3xl font-bold text-blue-400 mb-2">
                        "🔐 Keystone"
                    </h1>
                    <p class="text-gray-400">"Router Manager"</p>
                </div>

                <form on:submit=handle_submit>
                    <div class="mb-4">
                        <label class="block text-gray-300 mb-2 font-medium">
                            "Username"
                        </label>
                        <input
                            type="text"
                            prop:value=move || username.get()
                            on:input=move |ev| set_username.set(event_target_value(&ev))
                            placeholder="admin"
                            class="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded focus:outline-none focus:border-blue-500 text-white"
                            disabled=move || loading.get()
                        />
                    </div>

                    <div class="mb-6">
                        <label class="block text-gray-300 mb-2 font-medium">
                            "Password"
                        </label>
                        <input
                            type="password"
                            prop:value=move || password.get()
                            on:input=move |ev| set_password.set(event_target_value(&ev))
                            placeholder="Enter admin password"
                            class="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded focus:outline-none focus:border-blue-500 text-white"
                            disabled=move || loading.get()
                        />
                    </div>

                    <Show when=move || error_msg.get().is_some()>
                        <div class="mb-4 p-3 bg-red-900/50 border border-red-500 rounded text-red-200 text-sm">
                            {move || error_msg.get().unwrap_or_default()}
                        </div>
                    </Show>

                    <button
                        type="submit"
                        class="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 text-white font-medium py-3 rounded transition-colors"
                        disabled=move || loading.get()
                    >
                        {move || if loading.get() { "Logging in..." } else { "Login" }}
                    </button>
                </form>

                <div class="mt-6 text-center text-sm text-gray-400">
                    <p>"Default credentials: " <code class="bg-gray-700 px-2 py-1 rounded">"admin / admin"</code></p>
                </div>
            </div>
        </div>
    }
}

async fn login_api(password: &str) -> Result<LoginResponse, String> {
    let request = LoginRequest {
        password: password.to_string(),
    };

    let response = gloo_net::http::Request::post("/api/login")
        .json(&request)
        .map_err(|e| format!("Failed to build request: {}", e))?
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {}", e))?;

    if response.ok() {
        response
            .json::<LoginResponse>()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Fetch managed interfaces from the API
async fn fetch_managed_interfaces(token: &str) -> Result<Vec<ManagedInterface>, String> {
    let response = gloo_net::http::Request::get("/api/managed-interfaces")
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        let data: ManagedInterfacesResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;
        Ok(data.interfaces)
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

/// Save managed interfaces to the API
async fn save_managed_interfaces(
    token: &str,
    interfaces: Vec<ManagedInterface>,
) -> Result<SaveManagedInterfacesResponse, String> {
    let request = SaveManagedInterfacesRequest { interfaces };

    let response = gloo_net::http::Request::post("/api/managed-interfaces")
        .header("Authorization", &format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&request).unwrap())
        .map_err(|e| format!("Failed to build request: {}", e))?
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    } else {
        Err(format!("Server error: {}", response.status()))
    }
}

#[component]
fn InterfacesPanel(
    auth_token: ReadSignal<Option<String>>,
    state: ReadSignal<SystemState>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    // Managed interfaces from the database
    let (managed_interfaces, set_managed_interfaces) = signal::<Vec<ManagedInterface>>(vec![]);
    // Local edits (interface name -> Option<role>, None means not managed)
    let (pending_changes, set_pending_changes) =
        signal::<HashMap<String, Option<InterfaceRole>>>(HashMap::new());
    let (loading, set_loading) = signal(true);
    let (saving, set_saving) = signal(false);
    let (error, set_error) = signal::<Option<String>>(None);
    let (success, set_success) = signal::<Option<String>>(None);

    // Load managed interfaces on mount
    {
        let auth_token = auth_token.clone();
        let set_managed_interfaces = set_managed_interfaces.clone();
        let set_loading = set_loading.clone();
        let set_error = set_error.clone();
        let on_unauthorized = on_unauthorized.clone();

        spawn_local(async move {
            if let Some(token) = auth_token.get() {
                match fetch_managed_interfaces(&token).await {
                    Ok(interfaces) => {
                        set_managed_interfaces.set(interfaces);
                    }
                    Err(e) => {
                        if e == "Unauthorized" {
                            on_unauthorized.run(());
                        } else {
                            set_error.set(Some(e));
                        }
                    }
                }
            }
            set_loading.set(false);
        });
    }

    // Get current managed state for an interface (checking pending changes first)
    let get_interface_role = move |name: &str| -> Option<InterfaceRole> {
        let changes = pending_changes.get();
        if let Some(role) = changes.get(name) {
            return *role;
        }
        // Check saved managed interfaces
        managed_interfaces
            .get()
            .iter()
            .find(|m| m.name == name)
            .map(|m| m.role)
    };

    // Check if there are unsaved changes
    let has_changes = move || !pending_changes.get().is_empty();

    // Handle toggling interface management
    let toggle_interface = move |name: String, current_role: Option<InterfaceRole>| {
        set_pending_changes.update(|changes| {
            let new_role = match current_role {
                None => Some(InterfaceRole::LAN), // Default to LAN when enabling
                Some(_) => None,                  // Disable management
            };
            changes.insert(name, new_role);
        });
        set_success.set(None);
    };

    // Handle changing role
    let change_role = move |name: String, role: InterfaceRole| {
        set_pending_changes.update(|changes| {
            changes.insert(name, Some(role));
        });
        set_success.set(None);
    };

    // Save changes
    let save_changes = move |_| {
        let auth_token = auth_token.clone();
        let managed_interfaces = managed_interfaces.clone();
        let pending_changes = pending_changes.clone();
        let set_managed_interfaces = set_managed_interfaces.clone();
        let set_pending_changes = set_pending_changes.clone();
        let set_saving = set_saving.clone();
        let set_error = set_error.clone();
        let set_success = set_success.clone();
        let on_unauthorized = on_unauthorized.clone();

        spawn_local(async move {
            set_saving.set(true);
            set_error.set(None);

            if let Some(token) = auth_token.get() {
                // Build new managed interfaces list
                let mut new_managed: HashMap<String, ManagedInterface> = managed_interfaces
                    .get()
                    .iter()
                    .map(|m| (m.name.clone(), m.clone()))
                    .collect();

                // Apply pending changes
                for (name, role) in pending_changes.get().iter() {
                    match role {
                        Some(r) => {
                            new_managed.insert(
                                name.clone(),
                                ManagedInterface {
                                    name: name.clone(),
                                    role: *r,
                                    static_ip: None,
                                    enabled: true,
                                },
                            );
                        }
                        None => {
                            new_managed.remove(name);
                        }
                    }
                }

                let interfaces: Vec<ManagedInterface> = new_managed.into_values().collect();

                match save_managed_interfaces(&token, interfaces.clone()).await {
                    Ok(response) => {
                        if response.success {
                            set_managed_interfaces.set(interfaces);
                            set_pending_changes.set(HashMap::new());
                            set_success.set(Some(response.message));
                        } else {
                            set_error.set(Some(response.message));
                        }
                    }
                    Err(e) => {
                        if e == "Unauthorized" {
                            on_unauthorized.run(());
                        } else {
                            set_error.set(Some(e));
                        }
                    }
                }
            }
            set_saving.set(false);
        });
    };

    // Discard changes
    let discard_changes = move |_| {
        set_pending_changes.set(HashMap::new());
        set_error.set(None);
        set_success.set(None);
    };

    view! {
        <div class="bg-gray-800 rounded-lg p-6 shadow-lg">
            <div class="flex justify-between items-center mb-4">
                <h2 class="text-2xl font-semibold text-blue-300">
                    "Interface Management"
                </h2>
                <Show when=move || has_changes()>
                    <span class="text-yellow-400 text-sm">"Unsaved changes"</span>
                </Show>
            </div>

            <p class="text-gray-400 mb-6">
                "Select which interfaces Keystone should manage and assign them a role (LAN or WAN)."
            </p>

            // Error/Success messages
            <Show when=move || error.get().is_some()>
                <div class="bg-red-900/50 border border-red-500 text-red-200 px-4 py-2 rounded mb-4">
                    {move || error.get().unwrap_or_default()}
                </div>
            </Show>
            <Show when=move || success.get().is_some()>
                <div class="bg-green-900/50 border border-green-500 text-green-200 px-4 py-2 rounded mb-4">
                    {move || success.get().unwrap_or_default()}
                </div>
            </Show>

            <Show
                when=move || !loading.get()
                fallback=|| view! {
                    <div class="text-gray-400">"Loading interfaces..."</div>
                }
            >
                <div class="space-y-3">
                    <For
                        each=move || state.get().interfaces.clone()
                        key=|iface| iface.name.clone()
                        children=move |iface| {
                            let name = iface.name.clone();
                            let name2 = iface.name.clone();
                            let name3 = iface.name.clone();
                            let name4 = iface.name.clone();
                            let name5 = iface.name.clone();
                            let name6 = iface.name.clone();
                            let name7 = iface.name.clone();
                            let address = iface.address.clone().unwrap_or_else(|| "No IP".to_string());

                            let is_managed = move || get_interface_role(&name3).is_some();
                            let role_section_class = move || {
                                if is_managed() {
                                    "flex items-center gap-2"
                                } else {
                                    "hidden"
                                }
                            };

                            view! {
                                <div class="bg-gray-700 rounded p-4 flex items-center justify-between">
                                    <div class="flex items-center gap-4">
                                        // Checkbox to toggle management
                                        <input
                                            type="checkbox"
                                            checked=move || get_interface_role(&name).is_some()
                                            class="w-5 h-5 rounded border-gray-500 bg-gray-600 text-blue-500 focus:ring-blue-500"
                                            on:change=move |_| {
                                                let n = name2.clone();
                                                toggle_interface(n.clone(), get_interface_role(&n))
                                            }
                                        />
                                        <div>
                                            <div class="font-medium text-white">{name4.clone()}</div>
                                            <div class="text-sm text-gray-400">{address}</div>
                                        </div>
                                    </div>

                                    // Role selector (hidden when not managed via CSS)
                                    <div class=role_section_class>
                                        <span class="text-gray-400 text-sm">"Role:"</span>
                                        <select
                                            class="bg-gray-600 text-white rounded px-3 py-1 border border-gray-500 focus:border-blue-500 focus:outline-none"
                                            on:change=move |ev| {
                                                let value = event_target_value(&ev);
                                                let role = match value.as_str() {
                                                    "WAN" => InterfaceRole::WAN,
                                                    _ => InterfaceRole::LAN,
                                                };
                                                change_role(name5.clone(), role);
                                            }
                                        >
                                            <option
                                                value="LAN"
                                                selected=move || get_interface_role(&name6) == Some(InterfaceRole::LAN)
                                            >
                                                "LAN"
                                            </option>
                                            <option
                                                value="WAN"
                                                selected=move || get_interface_role(&name7) == Some(InterfaceRole::WAN)
                                            >
                                                "WAN"
                                            </option>
                                        </select>
                                    </div>
                                </div>
                            }
                        }
                    />
                </div>

                // Save/Discard buttons
                <Show when=move || has_changes()>
                    <div class="mt-6 flex gap-3">
                        <button
                            class="bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 disabled:cursor-not-allowed text-white px-4 py-2 rounded font-medium"
                            disabled=move || saving.get()
                            on:click=save_changes
                        >
                            {move || if saving.get() { "Saving..." } else { "Save Changes" }}
                        </button>
                        <button
                            class="bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded"
                            disabled=move || saving.get()
                            on:click=discard_changes
                        >
                            "Discard"
                        </button>
                    </div>
                </Show>
            </Show>
        </div>
    }
}

#[component]
fn FirewallPanel(state: ReadSignal<SystemState>) -> impl IntoView {
    view! {
        <div class="bg-gray-800 rounded-lg p-6 shadow-lg">
            <h2 class="text-2xl font-semibold text-blue-300 mb-4">
                "Firewall Rules"
            </h2>

            <div class="space-y-3">
                <Show
                    when=move || !state.get().firewall_rules.is_empty()
                    fallback=|| view! {
                        <p class="text-gray-500 italic">"No firewall rules configured"</p>
                    }
                >
                    <For
                        each=move || state.get().firewall_rules.clone()
                        key=|rule| rule.id.clone()
                        children=|rule| view! { <FirewallRuleCard rule=rule/> }
                    />
                </Show>
            </div>

            <button class="mt-4 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded">
                "+ Add Rule"
            </button>
        </div>
    }
}

#[component]
fn FirewallRuleCard(rule: FirewallRule) -> impl IntoView {
    let action_color = match rule.action {
        keystone_core::FirewallAction::Accept => "text-green-400",
        keystone_core::FirewallAction::Drop => "text-red-400",
        keystone_core::FirewallAction::Reject => "text-yellow-400",
    };

    let description = rule.description.clone();
    let action_str = format!("{:?}", rule.action);
    let port = rule.port;
    let protocol_str = format!("{:?}", rule.protocol);
    let enabled_status = if rule.enabled { "On" } else { "Off" };
    let status_class = if rule.enabled {
        "bg-green-600 text-white px-2 py-1 rounded text-xs"
    } else {
        "bg-gray-600 text-white px-2 py-1 rounded text-xs"
    };

    view! {
        <div class="bg-gray-700 rounded p-3 text-sm">
            <div class="flex justify-between items-start mb-2">
                <div>
                    <span class="font-medium">{description}</span>
                    <span class={format!("ml-2 {}", action_color)}>
                        {action_str}
                    </span>
                </div>
                <span class={status_class}>
                    {enabled_status}
                </span>
            </div>

            <div class="text-gray-300 space-y-1">
                <div>
                    <span class="text-gray-400">"Port: "</span>
                    {port}
                    " | "
                    <span class="text-gray-400">"Protocol: "</span>
                    {protocol_str}
                </div>
            </div>
        </div>
    }
}

#[component]
fn SystemSettingsPanel(state: ReadSignal<SystemState>) -> impl IntoView {
    view! {
        <div class="bg-gray-800 rounded-lg p-6 shadow-lg mt-6">
            <h2 class="text-2xl font-semibold text-blue-300 mb-4">
                "System Settings"
            </h2>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div class="bg-gray-700 rounded p-4">
                    <h3 class="font-medium mb-2">"IP Forwarding"</h3>
                    <label class="flex items-center cursor-pointer">
                        <input
                            type="checkbox"
                            prop:checked=move || state.get().ip_forwarding_enabled
                            class="form-checkbox h-5 w-5 text-blue-600"
                        />
                        <span class="ml-2 text-gray-300">
                            {move || if state.get().ip_forwarding_enabled {
                                "Enabled"
                            } else {
                                "Disabled"
                            }}
                        </span>
                    </label>
                </div>

                <div class="bg-gray-700 rounded p-4">
                    <h3 class="font-medium mb-2">"NAT / Masquerading"</h3>
                    <label class="flex items-center cursor-pointer">
                        <input
                            type="checkbox"
                            prop:checked=move || state.get().nat_enabled
                            class="form-checkbox h-5 w-5 text-blue-600"
                        />
                        <span class="ml-2 text-gray-300">
                            {move || if state.get().nat_enabled {
                                "Enabled"
                            } else {
                                "Disabled"
                            }}
                        </span>
                    </label>
                </div>
            </div>

            <button class="mt-6 bg-green-600 hover:bg-green-700 text-white px-6 py-2 rounded font-medium">
                "💾 Apply Configuration"
            </button>
        </div>
    }
}
