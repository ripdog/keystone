//! UPnP / NAT-PMP page: port mapping that lets LAN clients open ports on the
//! WAN, served by miniupnpd, with the live mapping list.
//!
//! Saving writes the configuration to the database. The daemon applies it as a
//! separate step, so this page has no apply button of its own.

use crate::api;
use crate::components::form_utils::{event_target_checked, event_target_value};
use crate::components::use_config_changed;
use gloo_timers::callback::Interval;
use keystone_core::Client;
use keystone_core::upnp::{
    PortRange, UpnpConfig, UpnpMapping, UpnpProtocol, UpnpStateResponse, UpnpStatusResponse,
};
use leptos::prelude::*;
use leptos::task::spawn_local;

/// How often the mapping list is refreshed.
const STATUS_REFRESH_MS: u32 = 5_000;
/// How often the LAN client list is refreshed, to name the mapped hosts.
const CLIENTS_REFRESH_MS: u32 = 30_000;

const LABEL: &str = "block text-gray-300 mb-2";
const HELP: &str = "text-sm text-gray-500 mt-1";
const INPUT: &str = "w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white";
const CHECKBOX_LABEL: &str = "flex items-start gap-3 text-gray-200";

// ============================================================================
// Pure helpers
// ============================================================================

fn parse_port(label: &str, value: &str) -> Result<u16, String> {
    value
        .trim()
        .parse::<u16>()
        .map_err(|_| format!("{label} must be a port number from 0 to 65535"))
}

fn parse_number(label: &str, value: &str) -> Result<u32, String> {
    value
        .trim()
        .parse::<u32>()
        .map_err(|_| format!("{label} must be a whole number"))
}

/// Subnets are typed one per line. Blank lines are ignored.
fn subnets_from_text(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

fn protocol_label(protocol: UpnpProtocol) -> &'static str {
    match protocol {
        UpnpProtocol::Tcp => "TCP",
        UpnpProtocol::Udp => "UDP",
    }
}

/// How long until a lease ends, as text. `now` is Unix seconds.
fn expiry_text(expires_at: Option<i64>, now: i64) -> String {
    match expires_at {
        None => "No lease".to_string(),
        Some(end) if end <= now => "Expired".to_string(),
        Some(end) => {
            let remaining = end - now;
            if remaining >= 3600 {
                format!("in {}h {}m", remaining / 3600, (remaining % 3600) / 60)
            } else if remaining >= 60 {
                format!("in {}m", remaining / 60)
            } else {
                format!("in {remaining}s")
            }
        }
    }
}

/// The LAN client that holds `address`, named by its hostname or MAC address.
fn client_name(clients: &[Client], address: &str) -> Option<String> {
    clients
        .iter()
        .find(|client| client.ipv4.iter().any(|ip| ip == address))
        .map(|client| {
            client
                .hostname
                .clone()
                .unwrap_or_else(|| client.mac.clone())
        })
}

// ============================================================================
// Form state
// ============================================================================

/// Every field of the settings form, each a signal so that the form keeps what
/// the user typed while the page re-renders.
#[derive(Clone, Copy)]
struct FormState {
    enabled: RwSignal<bool>,
    lan: RwSignal<Vec<String>>,
    wan: RwSignal<String>,
    igd: RwSignal<bool>,
    natpmp: RwSignal<bool>,
    secure: RwSignal<bool>,
    external_min: RwSignal<String>,
    external_max: RwSignal<String>,
    internal_min: RwSignal<String>,
    internal_max: RwSignal<String>,
    subnets: RwSignal<String>,
    max_lease: RwSignal<String>,
    friendly_name: RwSignal<String>,
    notify: RwSignal<String>,
    uptime: RwSignal<bool>,
}

impl FormState {
    fn new() -> Self {
        let defaults = UpnpConfig::default();
        Self {
            enabled: RwSignal::new(defaults.enabled),
            lan: RwSignal::new(Vec::new()),
            wan: RwSignal::new(String::new()),
            igd: RwSignal::new(defaults.enable_igd),
            natpmp: RwSignal::new(defaults.enable_natpmp_pcp),
            secure: RwSignal::new(defaults.secure_mode),
            external_min: RwSignal::new(defaults.external_ports.min.to_string()),
            external_max: RwSignal::new(defaults.external_ports.max.to_string()),
            internal_min: RwSignal::new(defaults.internal_ports.min.to_string()),
            internal_max: RwSignal::new(defaults.internal_ports.max.to_string()),
            subnets: RwSignal::new(String::new()),
            max_lease: RwSignal::new(defaults.max_lease_secs.to_string()),
            friendly_name: RwSignal::new(defaults.friendly_name),
            notify: RwSignal::new(defaults.notify_interval_secs.to_string()),
            uptime: RwSignal::new(defaults.system_uptime),
        }
    }

    fn load(&self, config: &UpnpConfig, default_wan: Option<&str>) {
        self.enabled.set(config.enabled);
        self.lan.set(config.lan_interfaces.clone());
        let wan = if config.wan_interface.is_empty() {
            default_wan.unwrap_or_default().to_string()
        } else {
            config.wan_interface.clone()
        };
        self.wan.set(wan);
        self.igd.set(config.enable_igd);
        self.natpmp.set(config.enable_natpmp_pcp);
        self.secure.set(config.secure_mode);
        self.external_min.set(config.external_ports.min.to_string());
        self.external_max.set(config.external_ports.max.to_string());
        self.internal_min.set(config.internal_ports.min.to_string());
        self.internal_max.set(config.internal_ports.max.to_string());
        self.subnets.set(config.allowed_client_subnets.join("\n"));
        self.max_lease.set(config.max_lease_secs.to_string());
        self.friendly_name.set(config.friendly_name.clone());
        self.notify.set(config.notify_interval_secs.to_string());
        self.uptime.set(config.system_uptime);
    }

    fn to_config(self) -> Result<UpnpConfig, String> {
        let max_lease = parse_number("Maximum lease", &self.max_lease.get())?;
        let notify = parse_number("Announcement interval", &self.notify.get())?;
        Ok(UpnpConfig {
            enabled: self.enabled.get(),
            lan_interfaces: self.lan.get(),
            wan_interface: self.wan.get(),
            enable_igd: self.igd.get(),
            enable_natpmp_pcp: self.natpmp.get(),
            secure_mode: self.secure.get(),
            external_ports: PortRange {
                min: parse_port("External port (from)", &self.external_min.get())?,
                max: parse_port("External port (to)", &self.external_max.get())?,
            },
            internal_ports: PortRange {
                min: parse_port("Internal port (from)", &self.internal_min.get())?,
                max: parse_port("Internal port (to)", &self.internal_max.get())?,
            },
            allowed_client_subnets: subnets_from_text(&self.subnets.get()),
            max_lease_secs: max_lease,
            friendly_name: self.friendly_name.get(),
            notify_interval_secs: notify,
            system_uptime: self.uptime.get(),
        })
    }
}

// ============================================================================
// Page
// ============================================================================

#[component]
pub fn UpnpPage(
    auth_token: ReadSignal<Option<String>>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let token = Signal::derive(move || auth_token.get().unwrap_or_default());
    let form = FormState::new();
    let state = RwSignal::new(Option::<UpnpStateResponse>::None);

    let loading = RwSignal::new(true);
    let saving = RwSignal::new(false);
    let error_msg = RwSignal::new(Option::<String>::None);
    let success_msg = RwSignal::new(Option::<String>::None);

    // Load the saved configuration once the token is known.
    Effect::new(move || {
        let token_val = token.get();
        if token_val.is_empty() {
            return;
        }
        spawn_local(async move {
            match api::fetch_upnp_state(&token_val).await {
                Ok(next) => {
                    form.load(&next.config, next.default_wan.as_deref());
                    state.set(Some(next));
                    loading.set(false);
                }
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        error_msg.set(Some(e));
                        loading.set(false);
                    }
                }
            }
        });
    });

    let config_changed = use_config_changed();
    let save = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();
        error_msg.set(None);
        success_msg.set(None);
        let config = match form.to_config() {
            Ok(config) => config,
            Err(message) => {
                error_msg.set(Some(message));
                return;
            }
        };
        saving.set(true);
        let token_val = token.get();
        spawn_local(async move {
            match api::save_upnp_config(&token_val, config).await {
                Ok(()) => {
                    success_msg.set(Some(
                        "UPnP settings saved. They take effect once the configuration is applied."
                            .to_string(),
                    ));
                    config_changed.run(());
                }
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        error_msg.set(Some(format!("Error: {e}")));
                    }
                }
            }
            saving.set(false);
        });
    };

    let binary_unsupported = move || state.get().is_some_and(|s| !s.binary.is_supported());

    view! {
        <div class="space-y-6">
            <div>
                <h1 class="text-2xl font-semibold text-blue-300">"UPnP / NAT-PMP"</h1>
                <p class="text-gray-400">"Let devices on the LAN open ports on the WAN, without manual port forwards"</p>
            </div>

            <Show when=binary_unsupported>
                <div class="bg-red-900/60 border border-red-500 rounded-lg p-4 text-red-100 space-y-1">
                    <p class="font-semibold">"miniupnpd is not usable by Keystone"</p>
                    <p>{move || state.get().map(|s| s.binary_message).unwrap_or_default()}</p>
                    <p class="text-sm text-red-200">
                        "Keystone needs the nftables build of miniupnpd. The package in the official repositories uses iptables and is not supported."
                    </p>
                </div>
            </Show>

            <div class="bg-amber-900/40 border border-amber-500/60 rounded-lg p-4 text-amber-100">
                <p>
                    <span class="font-semibold">"Security: "</span>
                    "UPnP lets any device on the selected networks open ports. Keep secure mode on, so that clients can only map ports to their own address."
                </p>
            </div>

            <Show when=move || success_msg.get().is_some()>
                <div class="bg-green-900/50 border border-green-500 rounded p-4 text-green-200">
                    {move || success_msg.get().unwrap_or_default()}
                </div>
            </Show>

            <Show when=move || error_msg.get().is_some()>
                <div class="bg-red-900/50 border border-red-500 rounded p-4 text-red-200">
                    {move || error_msg.get().unwrap_or_default()}
                </div>
            </Show>

            <Show when=move || loading.get()>
                <div class="text-center py-8 text-gray-400">"Loading UPnP settings..."</div>
            </Show>

            <Show when=move || !loading.get()>
                <form on:submit=save class="bg-gray-800 rounded-lg shadow-lg p-6 space-y-6">
                    <label class=CHECKBOX_LABEL>
                        <input
                            type="checkbox"
                            class="mt-1 w-4 h-4"
                            prop:checked=move || form.enabled.get()
                            on:change=move |ev| form.enabled.set(event_target_checked(&ev))
                        />
                        <span>"Enable UPnP and NAT-PMP port mapping"</span>
                    </label>

                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                        // LAN interfaces
                        <div>
                            <span class=LABEL>"LAN interfaces"</span>
                            <div class="space-y-2">
                                {move || {
                                    state
                                        .get()
                                        .map(|s| s.lan_candidates)
                                        .unwrap_or_default()
                                        .into_iter()
                                        .map(|name| {
                                            let checked_name = name.clone();
                                            let toggled_name = name.clone();
                                            view! {
                                                <label class=CHECKBOX_LABEL>
                                                    <input
                                                        type="checkbox"
                                                        class="mt-1 w-4 h-4"
                                                        prop:checked=move || form.lan.get().contains(&checked_name)
                                                        on:change=move |ev| {
                                                            let on = event_target_checked(&ev);
                                                            let name = toggled_name.clone();
                                                            form.lan.update(|list| {
                                                                list.retain(|item| item != &name);
                                                                if on {
                                                                    list.push(name);
                                                                }
                                                            });
                                                        }
                                                    />
                                                    <span>{name}</span>
                                                </label>
                                            }
                                        })
                                        .collect_view()
                                }}
                            </div>
                            <p class=HELP>"Clients on these interfaces may request port mappings. Never select the WAN interface."</p>
                        </div>

                        // WAN interface
                        <div>
                            <label class=LABEL>"WAN interface"</label>
                            <select
                                class=INPUT
                                prop:value=move || form.wan.get()
                                on:change=move |ev| form.wan.set(event_target_value(&ev))
                            >
                                <option value="">"Choose an interface"</option>
                                {move || {
                                    state
                                        .get()
                                        .map(|s| s.wan_candidates)
                                        .unwrap_or_default()
                                        .into_iter()
                                        .map(|name| {
                                            let value = name.clone();
                                            view! { <option value=value>{name}</option> }
                                        })
                                        .collect_view()
                                }}
                            </select>
                            <p class=HELP>"Mappings are made on this interface."</p>
                        </div>
                    </div>

                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div class="space-y-3">
                            <span class=LABEL>"Protocols"</span>
                            <label class=CHECKBOX_LABEL>
                                <input
                                    type="checkbox"
                                    class="mt-1 w-4 h-4"
                                    prop:checked=move || form.igd.get()
                                    on:change=move |ev| form.igd.set(event_target_checked(&ev))
                                />
                                <span>"UPnP IGD (most games, consoles and media software)"</span>
                            </label>
                            <label class=CHECKBOX_LABEL>
                                <input
                                    type="checkbox"
                                    class="mt-1 w-4 h-4"
                                    prop:checked=move || form.natpmp.get()
                                    on:change=move |ev| form.natpmp.set(event_target_checked(&ev))
                                />
                                <span>"NAT-PMP and PCP (Apple and some other devices)"</span>
                            </label>
                        </div>

                        <div class="space-y-3">
                            <span class=LABEL>"Options"</span>
                            <label class=CHECKBOX_LABEL>
                                <input
                                    type="checkbox"
                                    class="mt-1 w-4 h-4"
                                    prop:checked=move || form.secure.get()
                                    on:change=move |ev| form.secure.set(event_target_checked(&ev))
                                />
                                <span>"Secure mode: clients may only map ports to their own address"</span>
                            </label>
                            <label class=CHECKBOX_LABEL>
                                <input
                                    type="checkbox"
                                    class="mt-1 w-4 h-4"
                                    prop:checked=move || form.uptime.get()
                                    on:change=move |ev| form.uptime.set(event_target_checked(&ev))
                                />
                                <span>"Report system uptime instead of the daemon's uptime"</span>
                            </label>
                        </div>
                    </div>

                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div>
                            <span class=LABEL>"External ports allowed"</span>
                            <div class="flex items-center gap-2">
                                <input
                                    type="number" min="0" max="65535" class=INPUT
                                    prop:value=move || form.external_min.get()
                                    on:input=move |ev| form.external_min.set(event_target_value(&ev))
                                />
                                <span class="text-gray-400">"to"</span>
                                <input
                                    type="number" min="0" max="65535" class=INPUT
                                    prop:value=move || form.external_max.get()
                                    on:input=move |ev| form.external_max.set(event_target_value(&ev))
                                />
                            </div>
                            <p class=HELP>"Ports 1024 and above are recommended."</p>
                        </div>

                        <div>
                            <span class=LABEL>"Internal ports allowed"</span>
                            <div class="flex items-center gap-2">
                                <input
                                    type="number" min="0" max="65535" class=INPUT
                                    prop:value=move || form.internal_min.get()
                                    on:input=move |ev| form.internal_min.set(event_target_value(&ev))
                                />
                                <span class="text-gray-400">"to"</span>
                                <input
                                    type="number" min="0" max="65535" class=INPUT
                                    prop:value=move || form.internal_max.get()
                                    on:input=move |ev| form.internal_max.set(event_target_value(&ev))
                                />
                            </div>
                        </div>
                    </div>

                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div>
                            <label class=LABEL>"Client subnets allowed to map ports"</label>
                            <textarea
                                class=INPUT
                                rows="4"
                                placeholder="Leave empty to use the subnets of the LAN interfaces"
                                prop:value=move || form.subnets.get()
                                on:input=move |ev| form.subnets.set(event_target_value(&ev))
                            ></textarea>
                            <p class=HELP>"One network per line, for example 192.168.1.0/24."</p>
                        </div>

                        <div class="space-y-4">
                            <div>
                                <label class=LABEL>"Longest lease (seconds)"</label>
                                <input
                                    type="number" min="121" max="86400" class=INPUT
                                    prop:value=move || form.max_lease.get()
                                    on:input=move |ev| form.max_lease.set(event_target_value(&ev))
                                />
                                <p class=HELP>"Between 121 and 86400 (24 hours)."</p>
                            </div>
                            <div>
                                <label class=LABEL>"Name shown to clients"</label>
                                <input
                                    type="text" maxlength="64" class=INPUT
                                    prop:value=move || form.friendly_name.get()
                                    on:input=move |ev| form.friendly_name.set(event_target_value(&ev))
                                />
                            </div>
                            <div>
                                <label class=LABEL>"Announcement interval (seconds)"</label>
                                <input
                                    type="number" min="60" max="86400" class=INPUT
                                    prop:value=move || form.notify.get()
                                    on:input=move |ev| form.notify.set(event_target_value(&ev))
                                />
                            </div>
                        </div>
                    </div>

                    <div class="flex justify-end">
                        <button
                            type="submit"
                            class="px-6 py-2 bg-blue-600 hover:bg-blue-500 rounded text-white disabled:opacity-50"
                            disabled=move || saving.get()
                        >
                            {move || if saving.get() { "Saving..." } else { "Save settings" }}
                        </button>
                    </div>
                </form>
            </Show>

            <UpnpMappingsPanel token=token on_unauthorized=on_unauthorized />
        </div>
    }
}

// ============================================================================
// Live mappings
// ============================================================================

#[component]
fn UpnpMappingsPanel(token: Signal<String>, on_unauthorized: Callback<()>) -> impl IntoView {
    let status = RwSignal::new(Option::<UpnpStatusResponse>::None);
    let clients = RwSignal::new(Vec::<Client>::new());
    let load_error = RwSignal::new(Option::<String>::None);
    // Tick used to recompute "expires in" text between refreshes.
    let now = RwSignal::new(js_sys::Date::now() as i64 / 1000);

    let poll_status = move || {
        let token_val = token.get_untracked();
        if token_val.is_empty() {
            return;
        }
        spawn_local(async move {
            match api::fetch_upnp_status(&token_val).await {
                Ok(next) => {
                    now.set(js_sys::Date::now() as i64 / 1000);
                    status.set(Some(next));
                    load_error.set(None);
                }
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        load_error.set(Some(e));
                    }
                }
            }
        });
    };

    let poll_clients = move || {
        let token_val = token.get_untracked();
        if token_val.is_empty() {
            return;
        }
        spawn_local(async move {
            if let Ok(list) = api::fetch_clients(&token_val).await {
                clients.set(list);
            }
        });
    };

    // The Effects keep the Intervals alive; dropping them on unmount stops polling.
    Effect::new(move |_prev: Option<Option<Interval>>| {
        if token.get().is_empty() {
            None
        } else {
            poll_status();
            Some(Interval::new(STATUS_REFRESH_MS, poll_status))
        }
    });
    Effect::new(move |_prev: Option<Option<Interval>>| {
        if token.get().is_empty() {
            None
        } else {
            poll_clients();
            Some(Interval::new(CLIENTS_REFRESH_MS, poll_clients))
        }
    });

    view! {
        <div class="bg-gray-800 rounded-lg shadow-lg p-6 space-y-4">
            <div class="flex flex-wrap justify-between items-start gap-3">
                <div>
                    <h2 class="text-xl font-semibold text-blue-300">"Active port mappings"</h2>
                    <p class=HELP>"Mappings that clients have requested. Refreshes every 5 seconds."</p>
                </div>
                {move || status.get().map(|s| if s.service_active {
                    view! {
                        <span class="inline-flex items-center gap-2 rounded-full bg-green-900/50 px-3 py-1 text-sm text-green-200 ring-1 ring-inset ring-green-500/40">
                            <span class="w-2 h-2 rounded-full bg-green-400"></span>"miniupnpd running"
                        </span>
                    }.into_any()
                } else {
                    view! {
                        <span class="inline-flex items-center gap-2 rounded-full bg-gray-700 px-3 py-1 text-sm text-gray-300 ring-1 ring-inset ring-gray-500/40">
                            <span class="w-2 h-2 rounded-full bg-gray-400"></span>"miniupnpd not running"
                        </span>
                    }.into_any()
                })}
            </div>

            <Show when=move || load_error.get().is_some()>
                <div class="bg-red-900/50 border border-red-500 rounded p-3 text-red-200 text-sm">
                    {move || load_error.get().unwrap_or_default()}
                </div>
            </Show>

            {move || {
                status
                    .get()
                    .map(|s| s.warnings)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|warning| {
                        view! {
                            <div class="bg-amber-900/40 border border-amber-500/60 rounded p-3 text-amber-100 text-sm">
                                {warning}
                            </div>
                        }
                    })
                    .collect_view()
            }}

            <div class="overflow-x-auto">
                <table class="min-w-full text-sm text-left text-gray-200">
                    <thead class="text-gray-400 border-b border-gray-700">
                        <tr>
                            <th class="py-2 pr-4 font-medium">"Protocol"</th>
                            <th class="py-2 pr-4 font-medium">"External port"</th>
                            <th class="py-2 pr-4 font-medium">"Internal address"</th>
                            <th class="py-2 pr-4 font-medium">"Client"</th>
                            <th class="py-2 pr-4 font-medium">"Description"</th>
                            <th class="py-2 pr-4 font-medium">"Expires"</th>
                        </tr>
                    </thead>
                    <tbody>
                        {move || {
                            let mappings: Vec<UpnpMapping> = status
                                .get()
                                .map(|s| s.mappings)
                                .unwrap_or_default();
                            if mappings.is_empty() {
                                return view! {
                                    <tr>
                                        <td colspan="6" class="py-4 text-center text-gray-500">
                                            "No active mappings"
                                        </td>
                                    </tr>
                                }
                                .into_any();
                            }
                            let known = clients.get();
                            let current = now.get();
                            mappings
                                .into_iter()
                                .map(|mapping| {
                                    let client = client_name(&known, &mapping.internal_address)
                                        .unwrap_or_else(|| "—".to_string());
                                    let internal = format!(
                                        "{}:{}",
                                        mapping.internal_address, mapping.internal_port
                                    );
                                    let expires = expiry_text(mapping.expires_at, current);
                                    view! {
                                        <tr class="border-b border-gray-700/60">
                                            <td class="py-2 pr-4">{protocol_label(mapping.protocol)}</td>
                                            <td class="py-2 pr-4 font-mono">{mapping.external_port}</td>
                                            <td class="py-2 pr-4 font-mono">{internal}</td>
                                            <td class="py-2 pr-4">{client}</td>
                                            <td class="py-2 pr-4 break-all">{mapping.description}</td>
                                            <td class="py-2 pr-4 whitespace-nowrap">{expires}</td>
                                        </tr>
                                    }
                                })
                                .collect_view()
                                .into_any()
                        }}
                    </tbody>
                </table>
            </div>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_fields_reject_non_numbers_and_out_of_range_values() {
        assert_eq!(parse_port("Port", " 1024 "), Ok(1024));
        assert!(parse_port("Port", "65536").is_err());
        assert!(parse_port("Port", "-1").is_err());
        assert!(parse_port("Port", "").is_err());
    }

    #[test]
    fn subnets_are_read_one_per_line() {
        assert_eq!(
            subnets_from_text(" 192.168.1.0/24 \n\n10.0.0.0/8\n"),
            vec!["192.168.1.0/24".to_string(), "10.0.0.0/8".to_string()]
        );
        assert!(subnets_from_text("  \n").is_empty());
    }

    #[test]
    fn expiry_text_counts_down_in_the_largest_unit() {
        assert_eq!(expiry_text(None, 100), "No lease");
        assert_eq!(expiry_text(Some(100), 100), "Expired");
        assert_eq!(expiry_text(Some(130), 100), "in 30s");
        assert_eq!(expiry_text(Some(100 + 150), 100), "in 2m");
        assert_eq!(expiry_text(Some(100 + 3600 + 120), 100), "in 1h 2m");
    }
}
