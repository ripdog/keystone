//! Traffic shaping (SQM) page: CAKE shaping of the WAN link in both directions,
//! with live counters.
//!
//! Saving writes the configuration to the database. The daemon applies it as a
//! separate step, so this page has no apply button of its own.

use crate::api;
use crate::components::form_utils::{event_target_checked, event_target_value};
use crate::components::format_rate;
use crate::components::use_config_changed;
use gloo_timers::callback::Interval;
use keystone_core::sqm::{
    SqmConfig, SqmDiffserv, SqmDirectionStatus, SqmIsolation, SqmLinkPreset, SqmStatusResponse,
};
use leptos::prelude::*;
use leptos::task::spawn_local;

/// How often the live counters are refreshed.
const STATS_REFRESH_MS: u32 = 2_000;

const LABEL: &str = "block text-gray-300 mb-2";
const HELP: &str = "text-sm text-gray-500 mt-1";
const INPUT: &str = "w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white";
const CHECKBOX_LABEL: &str = "flex items-start gap-3 text-gray-200";

// ============================================================================
// Pure helpers
// ============================================================================

/// Parse a rate typed in Mbit/s into kbit/s. An empty field means 0, which
/// leaves that direction unshaped.
pub fn parse_mbit(text: &str) -> Result<u32, String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(0);
    }
    let mbit: f64 = trimmed
        .parse()
        .map_err(|_| format!("{trimmed:?} is not a rate in Mbit/s"))?;
    if !mbit.is_finite() || mbit < 0.0 {
        return Err("rates cannot be negative".to_string());
    }
    let kbit = (mbit * 1000.0).round();
    if kbit > f64::from(u32::MAX) {
        return Err("rate is too large".to_string());
    }
    Ok(kbit as u32)
}

/// Show a kbit/s rate in Mbit/s without trailing zeros. Zero shows as an
/// empty field.
pub fn format_mbit(kbit: u32) -> String {
    if kbit == 0 {
        String::new()
    } else {
        format!("{}", f64::from(kbit) / 1000.0)
    }
}

/// Parse an optional number field. An empty field means "not set".
fn parse_optional<T: std::str::FromStr>(text: &str, label: &str) -> Result<Option<T>, String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    trimmed
        .parse()
        .map(Some)
        .map_err(|_| format!("{label} must be a whole number"))
}

/// Bytes per second between two readings of a counter, taken `(milliseconds,
/// bytes)`. `None` when no time has passed or the counter went backwards, which
/// happens when the shaper is re-applied.
pub fn rate_between(previous: (f64, u64), current: (f64, u64)) -> Option<f64> {
    let elapsed = (current.0 - previous.0) / 1000.0;
    if elapsed <= 0.0 || current.1 < previous.1 {
        return None;
    }
    Some((current.1 - previous.1) as f64 / elapsed)
}

/// What the link type means, in one line.
fn preset_help(preset: SqmLinkPreset) -> &'static str {
    match preset {
        SqmLinkPreset::None => {
            "No link-layer compensation: packets are counted as Linux reports them."
        }
        SqmLinkPreset::Ethernet => {
            "Plain Ethernet framing, such as a fibre ONT or an Ethernet handoff."
        }
        SqmLinkPreset::Docsis => "Cable modem (DOCSIS) framing.",
        SqmLinkPreset::PppoePtm => "VDSL2 with PPPoE: PTM framing plus PPPoE encapsulation.",
        SqmLinkPreset::BridgedPtm => "VDSL2 with bridged Ethernet over PTM framing, without PPPoE.",
        SqmLinkPreset::PppoeVcmux => "ADSL with PPPoE over ATM (VC-MUX) framing.",
    }
}

fn diffserv_help(mode: SqmDiffserv) -> &'static str {
    match mode {
        SqmDiffserv::Besteffort => "One queue: DSCP priority marks are ignored.",
        SqmDiffserv::Diffserv3 => "Three tiers: bulk, best effort and voice.",
        SqmDiffserv::Diffserv4 => "Four tiers: bulk, best effort, video and voice. Recommended.",
        SqmDiffserv::Diffserv8 => "Eight tiers, for networks that use fine-grained DSCP marks.",
    }
}

fn isolation_help(mode: SqmIsolation) -> &'static str {
    match mode {
        SqmIsolation::Dual => {
            "Fair per host, then per flow: source hosts on upload, destination hosts on download. Recommended."
        }
        SqmIsolation::Triflow => "Fair per flow, with hosts also isolated.",
        SqmIsolation::Flows => "Fair per flow only.",
        SqmIsolation::Hosts => "Fair per host only.",
    }
}

fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let value = bytes as f64;
    if value >= GB {
        format!("{:.2} GB", value / GB)
    } else if value >= MB {
        format!("{:.2} MB", value / MB)
    } else if value >= KB {
        format!("{:.1} KB", value / KB)
    } else {
        format!("{bytes} B")
    }
}

fn format_delay(microseconds: Option<u64>) -> String {
    match microseconds {
        Some(us) => format!("{:.1} ms", us as f64 / 1000.0),
        None => "—".to_string(),
    }
}

fn format_count(value: Option<u64>) -> String {
    value.map_or_else(|| "—".to_string(), |count| count.to_string())
}

// ============================================================================
// Form state
// ============================================================================

/// Every field of the settings form. Each is a signal, so the form keeps what
/// the user typed while the page re-renders.
#[derive(Clone, Copy)]
struct FormState {
    enabled: RwSignal<bool>,
    interface: RwSignal<String>,
    download: RwSignal<String>,
    upload: RwSignal<String>,
    preset: RwSignal<SqmLinkPreset>,
    overhead: RwSignal<String>,
    mpu: RwSignal<String>,
    diffserv: RwSignal<SqmDiffserv>,
    isolation: RwSignal<SqmIsolation>,
    nat: RwSignal<bool>,
    ack_filter: RwSignal<bool>,
    wash: RwSignal<bool>,
}

impl FormState {
    fn new() -> Self {
        Self {
            enabled: RwSignal::new(false),
            interface: RwSignal::new(String::new()),
            download: RwSignal::new(String::new()),
            upload: RwSignal::new(String::new()),
            preset: RwSignal::new(SqmLinkPreset::default()),
            overhead: RwSignal::new(String::new()),
            mpu: RwSignal::new(String::new()),
            diffserv: RwSignal::new(SqmDiffserv::default()),
            isolation: RwSignal::new(SqmIsolation::default()),
            nat: RwSignal::new(true),
            ack_filter: RwSignal::new(false),
            wash: RwSignal::new(false),
        }
    }

    /// Fill the form from the saved configuration. A new configuration starts
    /// with the WAN interface the daemon found.
    fn load(&self, config: &SqmConfig, default_interface: Option<&str>) {
        self.enabled.set(config.enabled);
        let interface = if config.interface.is_empty() {
            default_interface.unwrap_or_default()
        } else {
            config.interface.as_str()
        };
        self.interface.set(interface.to_string());
        self.download.set(format_mbit(config.download_kbit));
        self.upload.set(format_mbit(config.upload_kbit));
        self.preset.set(config.link_preset);
        self.overhead
            .set(config.overhead.map(|v| v.to_string()).unwrap_or_default());
        self.mpu
            .set(config.mpu.map(|v| v.to_string()).unwrap_or_default());
        self.diffserv.set(config.diffserv);
        self.isolation.set(config.isolation);
        self.nat.set(config.nat);
        self.ack_filter.set(config.ack_filter);
        self.wash.set(config.wash);
    }

    /// Read the form into a configuration, or say which field is wrong.
    fn to_config(self) -> Result<SqmConfig, String> {
        Ok(SqmConfig {
            enabled: self.enabled.get_untracked(),
            interface: self.interface.get_untracked(),
            download_kbit: parse_mbit(&self.download.get_untracked())
                .map_err(|e| format!("Download: {e}"))?,
            upload_kbit: parse_mbit(&self.upload.get_untracked())
                .map_err(|e| format!("Upload: {e}"))?,
            link_preset: self.preset.get_untracked(),
            overhead: parse_optional(&self.overhead.get_untracked(), "Overhead")?,
            mpu: parse_optional(&self.mpu.get_untracked(), "Minimum packet size")?,
            diffserv: self.diffserv.get_untracked(),
            isolation: self.isolation.get_untracked(),
            nat: self.nat.get_untracked(),
            ack_filter: self.ack_filter.get_untracked(),
            wash: self.wash.get_untracked(),
        })
    }
}

// ============================================================================
// Page
// ============================================================================

#[component]
pub fn SqmPage(
    auth_token: ReadSignal<Option<String>>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let token = Signal::derive(move || auth_token.get().unwrap_or_default());
    let form = FormState::new();
    let interfaces = RwSignal::new(Vec::<String>::new());
    let show_advanced = RwSignal::new(false);

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
            match api::fetch_sqm_state(&token_val).await {
                Ok(state) => {
                    form.load(&state.config, state.default_interface.as_deref());
                    interfaces.set(state.available_interfaces);
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
            match api::save_sqm_config(&token_val, config).await {
                Ok(()) => {
                    success_msg.set(Some(
                        "Traffic shaping settings saved. They take effect once the configuration is applied."
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

    view! {
        <div class="space-y-6">
            <div>
                <h1 class="text-2xl font-semibold text-blue-300">"Traffic Shaping (SQM)"</h1>
                <p class="text-gray-400">"CAKE shaping on the WAN link keeps latency low under load, in both directions"</p>
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
                <div class="text-center py-8 text-gray-400">"Loading traffic shaping settings..."</div>
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
                        <span>"Enable traffic shaping on the WAN link"</span>
                    </label>

                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                        // WAN interface
                        <div>
                            <label class=LABEL>"WAN interface"</label>
                            <select
                                class=INPUT
                                prop:value=move || form.interface.get()
                                on:change=move |ev| form.interface.set(event_target_value(&ev))
                            >
                                <option value="">"Choose an interface"</option>
                                <For
                                    each=move || interfaces.get()
                                    key=|name| name.clone()
                                    children=move |name: String| {
                                        let value = name.clone();
                                        view! { <option value=value>{name}</option> }
                                    }
                                />
                            </select>
                            <p class=HELP>"The interface whose traffic leaves and enters the internet."</p>
                        </div>

                        // Link type
                        <div>
                            <label class=LABEL>"Link type"</label>
                            <select
                                class=INPUT
                                prop:value=move || form.preset.get().as_str()
                                on:change=move |ev| {
                                    let value = event_target_value(&ev);
                                    form.preset.set(SqmLinkPreset::parse(&value).unwrap_or_default());
                                }
                            >
                                <option value="ethernet">"Ethernet (fibre, Ethernet handoff)"</option>
                                <option value="docsis">"DOCSIS (cable modem)"</option>
                                <option value="pppoe-ptm">"VDSL2 with PPPoE (PTM)"</option>
                                <option value="bridged-ptm">"VDSL2 bridged (PTM)"</option>
                                <option value="pppoe-vcmux">"ADSL with PPPoE over ATM"</option>
                                <option value="none">"None (raw packet sizes)"</option>
                            </select>
                            <p class=HELP>{move || preset_help(form.preset.get())}</p>
                        </div>

                        // Download
                        <div>
                            <label class=LABEL>"Download (Mbit/s)"</label>
                            <input
                                type="text"
                                inputmode="decimal"
                                placeholder="e.g. 90 or 93.5; empty leaves download unshaped"
                                class=INPUT
                                prop:value=move || form.download.get()
                                on:input=move |ev| form.download.set(event_target_value(&ev))
                            />
                        </div>

                        // Upload
                        <div>
                            <label class=LABEL>"Upload (Mbit/s)"</label>
                            <input
                                type="text"
                                inputmode="decimal"
                                placeholder="e.g. 18 or 18.5; empty leaves upload unshaped"
                                class=INPUT
                                prop:value=move || form.upload.get()
                                on:input=move |ev| form.upload.set(event_target_value(&ev))
                            />
                        </div>
                    </div>

                    <p class="text-sm text-gray-400">
                        "Set each rate to about 90 to 95% of the speed you measure on the line. Check the result with a bufferbloat test such as "
                        <a
                            href="https://www.waveform.com/tools/bufferbloat"
                            target="_blank"
                            rel="noopener noreferrer"
                            class="text-blue-300 hover:underline"
                        >"waveform.com/tools/bufferbloat"</a>
                        "."
                    </p>

                    // Advanced options
                    <div class="border border-gray-600 rounded-lg overflow-hidden">
                        <button
                            type="button"
                            class="w-full flex items-center justify-between px-4 py-3 bg-gray-700/50 hover:bg-gray-700 text-left"
                            on:click=move |_| show_advanced.update(|v| *v = !*v)
                        >
                            <span class="text-gray-200 font-medium">"Advanced options"</span>
                            <svg
                                class="w-5 h-5 text-gray-400 transition-transform"
                                class:rotate-180=move || show_advanced.get()
                                fill="none"
                                stroke="currentColor"
                                viewBox="0 0 24 24"
                            >
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
                            </svg>
                        </button>
                        <Show when=move || show_advanced.get()>
                            <div class="p-4 space-y-6 border-t border-gray-600">
                                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                                    <div>
                                        <label class=LABEL>"Priority tiers"</label>
                                        <select
                                            class=INPUT
                                            prop:value=move || form.diffserv.get().as_str()
                                            on:change=move |ev| {
                                                let value = event_target_value(&ev);
                                                form.diffserv.set(SqmDiffserv::parse(&value).unwrap_or_default());
                                            }
                                        >
                                            <option value="diffserv4">"Four tiers (diffserv4)"</option>
                                            <option value="diffserv3">"Three tiers (diffserv3)"</option>
                                            <option value="diffserv8">"Eight tiers (diffserv8)"</option>
                                            <option value="besteffort">"Single queue (besteffort)"</option>
                                        </select>
                                        <p class=HELP>{move || diffserv_help(form.diffserv.get())}</p>
                                    </div>

                                    <div>
                                        <label class=LABEL>"Flow isolation"</label>
                                        <select
                                            class=INPUT
                                            prop:value=move || form.isolation.get().as_str()
                                            on:change=move |ev| {
                                                let value = event_target_value(&ev);
                                                form.isolation.set(SqmIsolation::parse(&value).unwrap_or_default());
                                            }
                                        >
                                            <option value="dual">"Per host, then per flow (dual)"</option>
                                            <option value="triflow">"Per flow, hosts isolated (triflow)"</option>
                                            <option value="flows">"Per flow (flows)"</option>
                                            <option value="hosts">"Per host (hosts)"</option>
                                        </select>
                                        <p class=HELP>{move || isolation_help(form.isolation.get())}</p>
                                    </div>

                                    <div>
                                        <label class=LABEL>"Overhead (bytes)"</label>
                                        <input
                                            type="text"
                                            inputmode="numeric"
                                            placeholder="Empty keeps the link type's value"
                                            class=INPUT
                                            prop:value=move || form.overhead.get()
                                            on:input=move |ev| form.overhead.set(event_target_value(&ev))
                                        />
                                        <p class=HELP>"Between -64 and 256. Overrides the link type's overhead."</p>
                                    </div>

                                    <div>
                                        <label class=LABEL>"Minimum packet size (bytes)"</label>
                                        <input
                                            type="text"
                                            inputmode="numeric"
                                            placeholder="Empty keeps the link type's value"
                                            class=INPUT
                                            prop:value=move || form.mpu.get()
                                            on:input=move |ev| form.mpu.set(event_target_value(&ev))
                                        />
                                        <p class=HELP>"Between 0 and 256."</p>
                                    </div>
                                </div>

                                <div class="space-y-3">
                                    <label class=CHECKBOX_LABEL>
                                        <input
                                            type="checkbox"
                                            class="mt-1 w-4 h-4"
                                            prop:checked=move || form.nat.get()
                                            on:change=move |ev| form.nat.set(event_target_checked(&ev))
                                        />
                                        <span>"NAT-aware fairness: share bandwidth per device behind the router, not per translated address"</span>
                                    </label>
                                    <label class=CHECKBOX_LABEL>
                                        <input
                                            type="checkbox"
                                            class="mt-1 w-4 h-4"
                                            prop:checked=move || form.ack_filter.get()
                                            on:change=move |ev| form.ack_filter.set(event_target_checked(&ev))
                                        />
                                        <span>"Drop redundant TCP ACKs on upload: helps asymmetric links, can hurt some uploads"</span>
                                    </label>
                                    <label class=CHECKBOX_LABEL>
                                        <input
                                            type="checkbox"
                                            class="mt-1 w-4 h-4"
                                            prop:checked=move || form.wash.get()
                                            on:change=move |ev| form.wash.set(event_target_checked(&ev))
                                        />
                                        <span>"Clear DSCP marks at the shaper: use when the ISP rewrites or ignores priority marks"</span>
                                    </label>
                                </div>
                            </div>
                        </Show>
                    </div>

                    <div class="pt-2">
                        <button
                            type="submit"
                            class="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded disabled:opacity-50"
                            disabled=move || saving.get()
                        >
                            {move || if saving.get() { "Saving..." } else { "Save Settings" }}
                        </button>
                    </div>
                </form>

                <SqmStatsPanel token=token on_unauthorized=on_unauthorized />
            </Show>
        </div>
    }
}

// ============================================================================
// Live counters
// ============================================================================

/// One reading of the two byte counters, taken at `at_ms`.
#[derive(Clone, Copy)]
struct Sample {
    at_ms: f64,
    upload: Option<u64>,
    download: Option<u64>,
}

/// Throughput per direction in bytes per second, derived from two readings.
#[derive(Clone, Copy, Default)]
struct Rates {
    upload: Option<f64>,
    download: Option<f64>,
}

#[component]
fn SqmStatsPanel(token: Signal<String>, on_unauthorized: Callback<()>) -> impl IntoView {
    let status = RwSignal::new(Option::<SqmStatusResponse>::None);
    let rates = RwSignal::new(Rates::default());
    let last = RwSignal::new(Option::<Sample>::None);
    let load_error = RwSignal::new(Option::<String>::None);

    let poll = move || {
        let token_val = token.get_untracked();
        if token_val.is_empty() {
            return;
        }
        spawn_local(async move {
            match api::fetch_sqm_status(&token_val).await {
                Ok(next) => {
                    let sample = Sample {
                        at_ms: js_sys::Date::now(),
                        upload: next.upload.as_ref().map(|d| d.sent_bytes),
                        download: next.download.as_ref().map(|d| d.sent_bytes),
                    };
                    let previous = last.get_untracked();
                    rates.set(Rates {
                        upload: direction_rate(previous, sample, |s| s.upload),
                        download: direction_rate(previous, sample, |s| s.download),
                    });
                    last.set(Some(sample));
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
            poll();
            Some(Interval::new(STATS_REFRESH_MS, poll))
        }
    });

    view! {
        <div class="bg-gray-800 rounded-lg shadow-lg p-6 space-y-4">
            <div class="flex flex-wrap justify-between items-start gap-3">
                <div>
                    <h2 class="text-xl font-semibold text-blue-300">"Live shaping"</h2>
                    <p class=HELP>"Counters of the applied configuration. Refreshes every 2 seconds."</p>
                </div>
                {move || status.get().map(|s| if s.active {
                    view! {
                        <span class="inline-flex items-center gap-2 rounded-full bg-green-900/50 px-3 py-1 text-sm text-green-200 ring-1 ring-inset ring-green-500/40">
                            <span class="w-2 h-2 rounded-full bg-green-400"></span>"Shaping active"
                        </span>
                    }.into_any()
                } else {
                    view! {
                        <span class="inline-flex items-center rounded-full bg-gray-700 px-3 py-1 text-sm text-gray-300">"Not active"</span>
                    }.into_any()
                })}
            </div>

            {move || load_error.get().map(|text| view! {
                <div class="bg-red-900/50 border border-red-500 rounded p-3 text-red-200 text-sm">
                    {format!("Failed to load counters: {text}")}
                </div>
            })}

            {move || status.get().and_then(|s| s.message).map(|text| view! {
                <p class="text-sm text-yellow-200 bg-yellow-900/30 border border-yellow-600 rounded p-3">{text}</p>
            })}

            {move || status.get().map(|s| {
                let current = rates.get();
                let download = s.download.map(|d| direction_view("Download", d, current.download));
                let upload = s.upload.map(|d| direction_view("Upload", d, current.upload));
                view! {
                    <div class="grid grid-cols-1 xl:grid-cols-2 gap-4">
                        {download}
                        {upload}
                    </div>
                }
            })}
        </div>
    }
}

/// The rate of one direction, from the previous reading to the current one.
fn direction_rate(
    previous: Option<Sample>,
    current: Sample,
    pick: fn(Sample) -> Option<u64>,
) -> Option<f64> {
    let previous = previous?;
    rate_between(
        (previous.at_ms, pick(previous)?),
        (current.at_ms, pick(current)?),
    )
}

fn direction_view(
    title: &'static str,
    direction: SqmDirectionStatus,
    rate: Option<f64>,
) -> impl IntoView {
    let shaped = format!("Shaped to {} Mbit/s", format_mbit(direction.bandwidth_kbit));
    let rate_text = rate.map_or_else(|| "measuring...".to_string(), format_rate);
    let device = direction.device.clone();
    let tins = direction.tins.clone();
    view! {
        <div class="rounded-lg bg-gray-900/60 ring-1 ring-inset ring-gray-700 p-4 space-y-4">
            <div class="flex flex-wrap justify-between items-baseline gap-2">
                <h3 class="text-lg font-medium text-gray-100">{title}</h3>
                <span class="text-xs text-gray-500">{format!("{shaped} on {device}")}</span>
            </div>
            <div class="grid grid-cols-2 gap-3 text-sm">
                <div>
                    <p class="text-gray-500">"Throughput"</p>
                    <p class="text-lg font-semibold text-white">{rate_text}</p>
                </div>
                <div>
                    <p class="text-gray-500">"Sent"</p>
                    <p class="text-lg font-semibold text-white">{format_bytes(direction.sent_bytes)}</p>
                    <p class="text-xs text-gray-500">{format!("{} packets", direction.sent_packets)}</p>
                </div>
                <div>
                    <p class="text-gray-500">"Drops"</p>
                    <p class="text-lg font-semibold text-white">{direction.drops.to_string()}</p>
                </div>
                <div>
                    <p class="text-gray-500">"Backlog"</p>
                    <p class="text-lg font-semibold text-white">{format_bytes(direction.backlog_bytes)}</p>
                </div>
            </div>
            {if tins.is_empty() {
                view! {
                    <p class="text-sm text-gray-500">"The kernel reported no per-tier counters."</p>
                }.into_any()
            } else {
                view! {
                    <div class="overflow-x-auto">
                        <table class="w-full text-sm">
                            <thead>
                                <tr class="text-left text-gray-400 border-b border-gray-700">
                                    <th class="py-2 pr-3 font-medium">"Tier"</th>
                                    <th class="py-2 pr-3 font-medium text-right">"Avg delay"</th>
                                    <th class="py-2 pr-3 font-medium text-right">"Peak delay"</th>
                                    <th class="py-2 pr-3 font-medium text-right">"Drops"</th>
                                    <th class="py-2 font-medium text-right">"Marks"</th>
                                </tr>
                            </thead>
                            <tbody>
                                {tins.into_iter().map(|tin| view! {
                                    <tr class="border-b border-gray-800 text-gray-200">
                                        <td class="py-2 pr-3">{tin.name}</td>
                                        <td class="py-2 pr-3 text-right">{format_delay(tin.avg_delay_us)}</td>
                                        <td class="py-2 pr-3 text-right">{format_delay(tin.peak_delay_us)}</td>
                                        <td class="py-2 pr-3 text-right">{format_count(tin.drops)}</td>
                                        <td class="py-2 text-right">{format_count(tin.ecn_marks)}</td>
                                    </tr>
                                }).collect_view()}
                            </tbody>
                        </table>
                    </div>
                }.into_any()
            }}
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mbit_fields_convert_to_kbit_and_back() {
        assert_eq!(parse_mbit("").unwrap(), 0);
        assert_eq!(parse_mbit("  ").unwrap(), 0);
        assert_eq!(parse_mbit("90").unwrap(), 90_000);
        assert_eq!(parse_mbit("93.5").unwrap(), 93_500);
        assert_eq!(parse_mbit("0.064").unwrap(), 64);
        assert!(parse_mbit("-1").is_err());
        assert!(parse_mbit("fast").is_err());
        assert!(parse_mbit("NaN").is_err());
        assert!(parse_mbit("1e12").is_err());

        assert_eq!(format_mbit(0), "");
        assert_eq!(format_mbit(90_000), "90");
        assert_eq!(format_mbit(93_500), "93.5");
    }

    #[test]
    fn optional_numbers_are_empty_or_parsed() {
        assert_eq!(parse_optional::<i32>("", "Overhead").unwrap(), None);
        assert_eq!(parse_optional::<i32>("-8", "Overhead").unwrap(), Some(-8));
        assert!(parse_optional::<u32>("x", "Minimum packet size").is_err());
    }

    #[test]
    fn rates_come_from_counter_deltas() {
        assert_eq!(rate_between((0.0, 1_000), (2_000.0, 3_000)), Some(1_000.0));
        assert_eq!(rate_between((0.0, 1_000), (0.0, 3_000)), None);
        assert_eq!(rate_between((0.0, 5_000), (2_000.0, 3_000)), None);
    }

    #[test]
    fn direction_rate_needs_both_readings() {
        let first = Sample {
            at_ms: 0.0,
            upload: Some(100),
            download: None,
        };
        let second = Sample {
            at_ms: 2_000.0,
            upload: Some(2_100),
            download: Some(4_000),
        };
        assert_eq!(
            direction_rate(Some(first), second, |s| s.upload),
            Some(1_000.0)
        );
        assert_eq!(direction_rate(Some(first), second, |s| s.download), None);
        assert_eq!(direction_rate(None, second, |s| s.upload), None);
    }
}
