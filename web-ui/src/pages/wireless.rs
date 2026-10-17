//! Wi-Fi page: a WPA2 access point served by hostapd and attached to a bridge,
//! with the list of associated stations.
//!
//! Saving writes the configuration to the database. The daemon applies it as a
//! separate step, so this page has no apply button of its own.

use crate::api;
use crate::components::form_utils::{event_target_checked, event_target_value};
use crate::components::rule_table::format_bytes;
use crate::components::use_config_changed;
use crate::components::use_toasts;
use gloo_timers::callback::Interval;
use keystone_core::wireless::{
    WIRELESS_CHANNELS, WirelessConfig, WirelessStateResponse, WirelessStation,
    WirelessStatusResponse,
};
use leptos::prelude::*;
use leptos::task::spawn_local;

/// How often the station list is refreshed.
const STATUS_REFRESH_MS: u32 = 5_000;

const LABEL: &str = "block text-gray-300 mb-2";
const HELP: &str = "text-sm text-gray-500 mt-1";
const INPUT: &str = "w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white";
const CHECKBOX_LABEL: &str = "flex items-start gap-3 text-gray-200";

// ============================================================================
// Pure helpers
// ============================================================================

/// Signal strength as text, or a dash when the driver did not report it.
fn signal_text(signal_dbm: Option<i32>) -> String {
    signal_dbm.map_or_else(|| "—".to_string(), |dbm| format!("{dbm} dBm"))
}

/// How long ago a station was last heard, as text.
fn inactive_text(inactive_ms: Option<u64>) -> String {
    match inactive_ms {
        None => "—".to_string(),
        Some(ms) if ms < 1000 => "just now".to_string(),
        Some(ms) => format!("{}s ago", ms / 1000),
    }
}

/// A connection time in seconds as text, using the largest useful unit.
fn connected_text(connected_secs: Option<u64>) -> String {
    match connected_secs {
        None => "—".to_string(),
        Some(secs) if secs >= 3600 => format!("{}h {}m", secs / 3600, (secs % 3600) / 60),
        Some(secs) if secs >= 60 => format!("{}m", secs / 60),
        Some(secs) => format!("{secs}s"),
    }
}

fn bytes_text(bytes: Option<u64>) -> String {
    bytes.map_or_else(|| "—".to_string(), format_bytes)
}

// ============================================================================
// Form state
// ============================================================================

/// Every field of the settings form, each a signal so that the form keeps what
/// the user typed while the page re-renders.
#[derive(Clone, Copy)]
struct FormState {
    enabled: RwSignal<bool>,
    interface: RwSignal<String>,
    bridge: RwSignal<String>,
    ssid: RwSignal<String>,
    hidden: RwSignal<bool>,
    country: RwSignal<String>,
    channel: RwSignal<String>,
    passphrase: RwSignal<String>,
    show_passphrase: RwSignal<bool>,
    isolation: RwSignal<bool>,
}

impl FormState {
    fn new() -> Self {
        let defaults = WirelessConfig::default();
        Self {
            enabled: RwSignal::new(defaults.enabled),
            interface: RwSignal::new(String::new()),
            bridge: RwSignal::new(String::new()),
            ssid: RwSignal::new(String::new()),
            hidden: RwSignal::new(defaults.hidden_ssid),
            country: RwSignal::new(String::new()),
            channel: RwSignal::new(defaults.channel.to_string()),
            passphrase: RwSignal::new(String::new()),
            show_passphrase: RwSignal::new(false),
            isolation: RwSignal::new(defaults.client_isolation),
        }
    }

    fn load(&self, config: &WirelessConfig, interfaces: &[String], bridges: &[String]) {
        self.enabled.set(config.enabled);
        // A new configuration starts on the only radio and the only bridge.
        let pick = |saved: &str, only: &[String]| match (saved.is_empty(), only) {
            (true, [one]) => one.clone(),
            _ => saved.to_string(),
        };
        self.interface.set(pick(&config.interface, interfaces));
        self.bridge.set(pick(&config.bridge, bridges));
        self.ssid.set(config.ssid.clone());
        self.hidden.set(config.hidden_ssid);
        self.country.set(config.country_code.clone());
        self.channel.set(config.channel.to_string());
        self.passphrase.set(config.passphrase.clone());
        self.isolation.set(config.client_isolation);
    }

    fn to_config(self) -> Result<WirelessConfig, String> {
        let channel = self
            .channel
            .get()
            .trim()
            .parse::<u8>()
            .map_err(|_| "Channel must be a number".to_string())?;
        Ok(WirelessConfig {
            enabled: self.enabled.get(),
            interface: self.interface.get(),
            bridge: self.bridge.get(),
            ssid: self.ssid.get(),
            hidden_ssid: self.hidden.get(),
            country_code: self.country.get().trim().to_ascii_uppercase(),
            channel,
            passphrase: self.passphrase.get(),
            client_isolation: self.isolation.get(),
        })
    }
}

// ============================================================================
// Page
// ============================================================================

#[component]
pub fn WirelessPage(
    auth_token: ReadSignal<Option<String>>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let toasts = use_toasts();
    let token = Signal::derive(move || auth_token.get().unwrap_or_default());
    let form = FormState::new();
    let state = RwSignal::new(Option::<WirelessStateResponse>::None);

    let loading = RwSignal::new(true);
    let saving = RwSignal::new(false);
    let error_msg = RwSignal::new(Option::<String>::None);

    // Load the saved configuration once the token is known.
    Effect::new(move || {
        let token_val = token.get();
        if token_val.is_empty() {
            return;
        }
        spawn_local(async move {
            match api::fetch_wireless_state(&token_val).await {
                Ok(next) => {
                    let interfaces: Vec<String> =
                        next.interfaces.iter().map(|i| i.name.clone()).collect();
                    form.load(&next.config, &interfaces, &next.bridge_candidates);
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
            match api::save_wireless_config(&token_val, config).await {
                Ok(()) => {
                    toasts.success(
                        "Wi-Fi settings saved. They take effect once the configuration is applied."
                            .to_string(),
                    );
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

    let missing_tool = move || {
        state
            .get()
            .filter(|s| !s.hostapd_installed)
            .map(|_| "hostapd is not installed. Install it with: pacman -S hostapd".to_string())
    };
    let no_radio = move || state.get().is_some_and(|s| s.interfaces.is_empty());
    let no_bridge = move || state.get().is_some_and(|s| s.bridge_candidates.is_empty());

    view! {
        <div class="space-y-6">
            <div>
                <h1 class="text-2xl font-semibold text-blue-300">"Wi-Fi"</h1>
            </div>

            <Show when=move || missing_tool().is_some()>
                <div class="bg-red-900/60 border border-red-500 rounded-lg p-4 text-red-100">
                    {move || missing_tool().unwrap_or_default()}
                </div>
            </Show>

            <Show when=move || !loading.get() && no_radio()>
                <div class="bg-amber-900/40 border border-amber-500/60 rounded-lg p-4 text-amber-100">
                    "No wireless interface was found on this machine."
                </div>
            </Show>

            <Show when=move || !loading.get() && no_bridge()>
                <div class="bg-amber-900/40 border border-amber-500/60 rounded-lg p-4 text-amber-100">
                    "The access point joins a bridge, so Wi-Fi clients share its LAN. "
                    "Create a bridge first, with your LAN port as a member, and move the LAN address, DHCP range and firewall zone onto it."
                </div>
            </Show>

            <div class="bg-gray-800 rounded-lg p-4 text-gray-300 text-sm">
                "Wi-Fi is limited by the radio: one network, WPA2-PSK, 2.4 GHz with 20 MHz channels. "
                "Not every adapter can host an access point on 5 GHz."
            </div>

            <Show when=move || error_msg.get().is_some()>
                <div class="bg-red-900/50 border border-red-500 rounded p-4 text-red-200">
                    {move || error_msg.get().unwrap_or_default()}
                </div>
            </Show>

            <Show when=move || loading.get()>
                <div class="text-center py-8 text-gray-400">"Loading Wi-Fi settings..."</div>
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
                        <span>"Enable the Wi-Fi access point"</span>
                    </label>

                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div>
                            <label class=LABEL>"Wireless interface"</label>
                            <select
                                class=INPUT
                                prop:value=move || form.interface.get()
                                on:change=move |ev| form.interface.set(event_target_value(&ev))
                            >
                                <option value="">"Choose an interface"</option>
                                {move || {
                                    state
                                        .get()
                                        .map(|s| s.interfaces)
                                        .unwrap_or_default()
                                        .into_iter()
                                        .map(|iface| {
                                            let note = match iface.ap_supported {
                                                Some(false) => " (cannot host an access point)",
                                                _ => "",
                                            };
                                            let label = match &iface.driver {
                                                Some(driver) => format!("{} — {driver}{note}", iface.name),
                                                None => format!("{}{note}", iface.name),
                                            };
                                            let value = iface.name.clone();
                                            view! { <option value=value>{label}</option> }
                                        })
                                        .collect_view()
                                }}
                            </select>
                        </div>

                        <div>
                            <label class=LABEL>"Bridge"</label>
                            <select
                                class=INPUT
                                prop:value=move || form.bridge.get()
                                on:change=move |ev| form.bridge.set(event_target_value(&ev))
                            >
                                <option value="">"Choose a bridge"</option>
                                {move || {
                                    state
                                        .get()
                                        .map(|s| s.bridge_candidates)
                                        .unwrap_or_default()
                                        .into_iter()
                                        .map(|name| {
                                            let value = name.clone();
                                            view! { <option value=value>{name}</option> }
                                        })
                                        .collect_view()
                                }}
                            </select>
                            <p class=HELP>"Wi-Fi clients get this bridge's addresses and DHCP range."</p>
                        </div>

                        <div>
                            <label class=LABEL>"Network name (SSID)"</label>
                            <input
                                type="text"
                                maxlength="32"
                                class=INPUT
                                prop:value=move || form.ssid.get()
                                on:input=move |ev| form.ssid.set(event_target_value(&ev))
                            />
                        </div>

                        <div>
                            <label class=LABEL>"Passphrase"</label>
                            <input
                                class=INPUT
                                type=move || if form.show_passphrase.get() { "text" } else { "password" }
                                autocomplete="new-password"
                                minlength="8"
                                maxlength="63"
                                prop:value=move || form.passphrase.get()
                                on:input=move |ev| form.passphrase.set(event_target_value(&ev))
                            />
                            <label class="flex items-center gap-2 mt-2 text-sm text-gray-400">
                                <input
                                    type="checkbox"
                                    class="w-4 h-4"
                                    prop:checked=move || form.show_passphrase.get()
                                    on:change=move |ev| form.show_passphrase.set(event_target_checked(&ev))
                                />
                                "Show passphrase"
                            </label>
                            <p class=HELP>"8 to 63 characters (WPA2-PSK)."</p>
                        </div>

                        <div>
                            <label class=LABEL>"Country code"</label>
                            <input
                                type="text"
                                maxlength="2"
                                placeholder="NZ"
                                class=INPUT
                                prop:value=move || form.country.get()
                                on:input=move |ev| form.country.set(event_target_value(&ev))
                            />
                            <p class=HELP>"Two letters. It sets the channels and power the radio may use."</p>
                        </div>

                        <div>
                            <label class=LABEL>"Channel (2.4 GHz)"</label>
                            <select
                                class=INPUT
                                prop:value=move || form.channel.get()
                                on:change=move |ev| form.channel.set(event_target_value(&ev))
                            >
                                {WIRELESS_CHANNELS
                                    .map(|channel| {
                                        let label = channel.to_string();
                                        let value = label.clone();
                                        view! { <option value=value>{label}</option> }
                                    })
                                    .collect_view()}
                            </select>
                            <p class=HELP>"Channels 1, 6 and 11 do not overlap."</p>
                        </div>
                    </div>

                    <div class="space-y-3">
                        <span class=LABEL>"Options"</span>
                        <label class=CHECKBOX_LABEL>
                            <input
                                type="checkbox"
                                class="mt-1 w-4 h-4"
                                prop:checked=move || form.hidden.get()
                                on:change=move |ev| form.hidden.set(event_target_checked(&ev))
                            />
                            <span>"Hide the network name (not a security measure)"</span>
                        </label>
                        <label class=CHECKBOX_LABEL>
                            <input
                                type="checkbox"
                                class="mt-1 w-4 h-4"
                                prop:checked=move || form.isolation.get()
                                on:change=move |ev| form.isolation.set(event_target_checked(&ev))
                            />
                            <span>"Client isolation: Wi-Fi clients cannot talk to each other"</span>
                        </label>
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

            <WirelessStationsPanel token=token on_unauthorized=on_unauthorized />
        </div>
    }
}

// ============================================================================
// Associated stations
// ============================================================================

#[component]
fn WirelessStationsPanel(token: Signal<String>, on_unauthorized: Callback<()>) -> impl IntoView {
    let status = RwSignal::new(Option::<WirelessStatusResponse>::None);
    let load_error = RwSignal::new(Option::<String>::None);

    let poll_status = move || {
        let token_val = token.get_untracked();
        if token_val.is_empty() {
            return;
        }
        spawn_local(async move {
            match api::fetch_wireless_status(&token_val).await {
                Ok(next) => {
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

    // The Effect keeps the Interval alive; dropping it on unmount stops polling.
    Effect::new(move |_prev: Option<Option<Interval>>| {
        if token.get().is_empty() {
            None
        } else {
            poll_status();
            Some(Interval::new(STATUS_REFRESH_MS, poll_status))
        }
    });

    view! {
        <div class="bg-gray-800 rounded-lg shadow-lg p-6 space-y-4">
            <div class="flex flex-wrap justify-between items-start gap-3">
                <h2 class="text-xl font-semibold text-blue-300">"Connected devices"</h2>
                {move || status.get().map(|s| if s.service_active {
                    view! {
                        <span class="inline-flex items-center gap-2 rounded-full bg-green-900/50 px-3 py-1 text-sm text-green-200 ring-1 ring-inset ring-green-500/40">
                            <span class="w-2 h-2 rounded-full bg-green-400"></span>"Access point running"
                        </span>
                    }.into_any()
                } else {
                    view! {
                        <span class="inline-flex items-center gap-2 rounded-full bg-gray-700 px-3 py-1 text-sm text-gray-300 ring-1 ring-inset ring-gray-500/40">
                            <span class="w-2 h-2 rounded-full bg-gray-400"></span>"Access point not running"
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
                            <th class="py-2 pr-4 font-medium">"MAC address"</th>
                            <th class="py-2 pr-4 font-medium">"Signal"</th>
                            <th class="py-2 pr-4 font-medium">"Last heard"</th>
                            <th class="py-2 pr-4 font-medium">"Received"</th>
                            <th class="py-2 pr-4 font-medium">"Sent"</th>
                            <th class="py-2 pr-4 font-medium">"Connected"</th>
                        </tr>
                    </thead>
                    <tbody>
                        {move || {
                            let stations: Vec<WirelessStation> = status
                                .get()
                                .map(|s| s.stations)
                                .unwrap_or_default();
                            if stations.is_empty() {
                                return view! {
                                    <tr>
                                        <td colspan="6" class="py-4 text-center text-gray-500">
                                            "No devices connected"
                                        </td>
                                    </tr>
                                }
                                .into_any();
                            }
                            stations
                                .into_iter()
                                .map(|station| {
                                    view! {
                                        <tr class="border-b border-gray-700/60">
                                            <td class="py-2 pr-4 font-mono">{station.mac}</td>
                                            <td class="py-2 pr-4">{signal_text(station.signal_dbm)}</td>
                                            <td class="py-2 pr-4">{inactive_text(station.inactive_ms)}</td>
                                            <td class="py-2 pr-4">{bytes_text(station.rx_bytes)}</td>
                                            <td class="py-2 pr-4">{bytes_text(station.tx_bytes)}</td>
                                            <td class="py-2 pr-4 whitespace-nowrap">{connected_text(station.connected_secs)}</td>
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
    fn signal_and_activity_text_handle_missing_values() {
        assert_eq!(signal_text(Some(-45)), "-45 dBm");
        assert_eq!(signal_text(None), "—");
        assert_eq!(inactive_text(None), "—");
        assert_eq!(inactive_text(Some(300)), "just now");
        assert_eq!(inactive_text(Some(4_200)), "4s ago");
    }

    #[test]
    fn connection_time_uses_the_largest_unit() {
        assert_eq!(connected_text(None), "—");
        assert_eq!(connected_text(Some(42)), "42s");
        assert_eq!(connected_text(Some(125)), "2m");
        assert_eq!(connected_text(Some(3_725)), "1h 2m");
    }
}
