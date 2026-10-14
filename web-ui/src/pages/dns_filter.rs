//! DNS filtering page: ad-blocking and encrypted upstream DNS served by Blocky.
//!
//! The page has four tabs (settings, groups, clients and the query log) and a
//! status panel that refreshes itself. Saving writes the configuration to the
//! database. The daemon applies it as a separate step, as on the UPnP page, so
//! there is no apply button here.

use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::api;
use crate::api::QueryLogQuery;
use crate::components::form_utils::{event_target_checked, event_target_value};
use crate::components::use_config_changed;
use crate::components::use_toasts;
use gloo_timers::callback::Interval;
use keystone_core::blocky::{
    BLOCKY_DEFAULT_SELECTOR, BlockyBlockType, BlockyClientGroups, BlockyConfig, BlockyGroup,
    BlockyQueryLogEntry, BlockyQueryLogResponse, BlockyStateResponse, BlockyStatusResponse,
    BlockyUpstreamStrategy,
};
use keystone_core::{Client, DnsmasqUpstreamMode};
use leptos::prelude::*;
use leptos::task::spawn_local;

/// How often the status panel is refreshed.
const STATUS_REFRESH_MS: u32 = 5_000;
/// How often the LAN client list is refreshed, to name clients.
const CLIENTS_REFRESH_MS: u32 = 30_000;

const LABEL: &str = "block text-gray-300 mb-2";
const HELP: &str = "text-sm text-gray-500 mt-1";
const INPUT: &str = "w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white";
const CHECKBOX_LABEL: &str = "flex items-start gap-3 text-gray-200";
const BUTTON: &str =
    "px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded text-white disabled:opacity-50";
const PRIMARY: &str =
    "px-6 py-2 bg-blue-600 hover:bg-blue-500 rounded text-white disabled:opacity-50";

// ============================================================================
// Pure helpers
// ============================================================================

/// Text areas hold one entry per line. Blank lines are ignored.
fn text_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

fn parse_strategy(value: &str) -> BlockyUpstreamStrategy {
    match value {
        "strict" => BlockyUpstreamStrategy::Strict,
        "random" => BlockyUpstreamStrategy::Random,
        _ => BlockyUpstreamStrategy::ParallelBest,
    }
}

fn parse_block_type(value: &str) -> BlockyBlockType {
    match value {
        "nx_domain" => BlockyBlockType::NxDomain,
        _ => BlockyBlockType::ZeroIp,
    }
}

fn parse_count(label: &str, value: &str, min: u32, max: u32) -> Result<u32, String> {
    let number = value
        .trim()
        .parse::<u32>()
        .map_err(|_| format!("{label} must be a whole number"))?;
    if (min..=max).contains(&number) {
        Ok(number)
    } else {
        Err(format!("{label} must be between {min} and {max}"))
    }
}

/// Time left in a pause, as text.
fn remaining_text(seconds: u64) -> String {
    if seconds >= 3600 {
        format!("{}h {}m", seconds / 3600, (seconds % 3600) / 60)
    } else if seconds >= 60 {
        format!("{}m {}s", seconds / 60, seconds % 60)
    } else {
        format!("{seconds}s")
    }
}

/// A warning when the DNS filtering switch and dnsmasq's upstream mode disagree.
fn mismatch_message(blocky_enabled: bool, mode: DnsmasqUpstreamMode) -> Option<&'static str> {
    match (blocky_enabled, mode == DnsmasqUpstreamMode::Blocky) {
        (true, false) => Some(
            "DNS filtering is enabled, but DNS & DHCP does not send queries to Blocky, so no ads are blocked. Choose \"Blocky\" as the upstream mode on the DNS settings page.",
        ),
        (false, true) => Some(
            "DNS & DHCP uses Blocky as its upstream, but DNS filtering is disabled. Enable DNS filtering, or choose another upstream mode on the DNS settings page.",
        ),
        _ => None,
    }
}

/// Add `domain` to the custom allowlist of the first group that `client` uses:
/// its own entry when it has one, otherwise the `default` entry. Returns the
/// group's name. Client selectors that are networks are not matched here, so a
/// client covered only by a network entry gets the `default` group.
fn allow_domain(config: &mut BlockyConfig, client: &str, domain: &str) -> Result<String, String> {
    let domain = domain.trim();
    if domain.is_empty() || domain.contains(char::is_whitespace) {
        return Err("the domain must not be empty or contain spaces".to_string());
    }
    let assignment = config
        .client_groups
        .iter()
        .find(|assignment| assignment.selector == client)
        .or_else(|| {
            config
                .client_groups
                .iter()
                .find(|assignment| assignment.selector == BLOCKY_DEFAULT_SELECTOR)
        })
        .ok_or_else(|| "no filtering group applies to this client".to_string())?;
    let group_name = assignment
        .groups
        .first()
        .cloned()
        .ok_or_else(|| "this client has no filtering group".to_string())?;
    let group = config
        .groups
        .iter_mut()
        .find(|group| group.name == group_name)
        .ok_or_else(|| format!("group {group_name:?} does not exist"))?;
    if !group.custom_allow.iter().any(|entry| entry == domain) {
        group.custom_allow.push(domain.to_string());
    }
    Ok(group_name)
}

// ============================================================================
// Form state
// ============================================================================

/// A fresh identity for a row, so that list rows keep their own signals when
/// another row is removed.
fn next_row_id() -> usize {
    static NEXT: AtomicUsize = AtomicUsize::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// One filtering group, each field a signal so typing survives re-renders.
#[derive(Clone, Copy)]
struct GroupDraft {
    id: usize,
    name: RwSignal<String>,
    denylists: RwSignal<String>,
    allowlists: RwSignal<String>,
    custom_deny: RwSignal<String>,
    custom_allow: RwSignal<String>,
}

impl GroupDraft {
    fn new(group: &BlockyGroup) -> Self {
        Self {
            id: next_row_id(),
            name: RwSignal::new(group.name.clone()),
            denylists: RwSignal::new(group.denylists.join("\n")),
            allowlists: RwSignal::new(group.allowlists.join("\n")),
            custom_deny: RwSignal::new(group.custom_deny.join("\n")),
            custom_allow: RwSignal::new(group.custom_allow.join("\n")),
        }
    }

    fn to_group(self) -> BlockyGroup {
        BlockyGroup {
            name: self.name.get().trim().to_string(),
            denylists: text_lines(&self.denylists.get()),
            allowlists: text_lines(&self.allowlists.get()),
            custom_deny: text_lines(&self.custom_deny.get()),
            custom_allow: text_lines(&self.custom_allow.get()),
        }
    }
}

/// One client selector and the groups that apply to it.
#[derive(Clone, Copy)]
struct ClientDraft {
    id: usize,
    selector: RwSignal<String>,
    groups: RwSignal<Vec<String>>,
}

impl ClientDraft {
    fn new(assignment: &BlockyClientGroups) -> Self {
        Self {
            id: next_row_id(),
            selector: RwSignal::new(assignment.selector.clone()),
            groups: RwSignal::new(assignment.groups.clone()),
        }
    }
}

/// Every field of the settings, groups and clients forms.
#[derive(Clone, Copy)]
struct FormState {
    enabled: RwSignal<bool>,
    upstreams: RwSignal<String>,
    bootstrap: RwSignal<String>,
    strategy: RwSignal<String>,
    block_type: RwSignal<String>,
    refresh_hours: RwSignal<String>,
    prefetching: RwSignal<bool>,
    min_cache: RwSignal<String>,
    query_log: RwSignal<bool>,
    retention: RwSignal<String>,
    groups: RwSignal<Vec<GroupDraft>>,
    clients: RwSignal<Vec<ClientDraft>>,
}

impl FormState {
    fn new() -> Self {
        let defaults = BlockyConfig::default();
        Self {
            enabled: RwSignal::new(defaults.enabled),
            upstreams: RwSignal::new(defaults.upstreams.join("\n")),
            bootstrap: RwSignal::new(
                defaults
                    .bootstrap
                    .iter()
                    .map(IpAddr::to_string)
                    .collect::<Vec<_>>()
                    .join("\n"),
            ),
            strategy: RwSignal::new(defaults.upstream_strategy.blocky_value().to_string()),
            block_type: RwSignal::new(defaults.block_type.blocky_value().to_string()),
            refresh_hours: RwSignal::new(defaults.refresh_hours.to_string()),
            prefetching: RwSignal::new(defaults.prefetching),
            min_cache: RwSignal::new(defaults.min_cache_minutes.to_string()),
            query_log: RwSignal::new(defaults.query_log_enabled),
            retention: RwSignal::new(defaults.query_log_retention_days.to_string()),
            groups: RwSignal::new(Vec::new()),
            clients: RwSignal::new(Vec::new()),
        }
    }

    fn load(&self, config: &BlockyConfig) {
        self.enabled.set(config.enabled);
        self.upstreams.set(config.upstreams.join("\n"));
        self.bootstrap.set(
            config
                .bootstrap
                .iter()
                .map(IpAddr::to_string)
                .collect::<Vec<_>>()
                .join("\n"),
        );
        self.strategy
            .set(config.upstream_strategy.blocky_value().to_string());
        self.block_type
            .set(config.block_type.blocky_value().to_string());
        self.refresh_hours.set(config.refresh_hours.to_string());
        self.prefetching.set(config.prefetching);
        self.min_cache.set(config.min_cache_minutes.to_string());
        self.query_log.set(config.query_log_enabled);
        self.retention
            .set(config.query_log_retention_days.to_string());
        self.groups
            .set(config.groups.iter().map(GroupDraft::new).collect());
        self.clients
            .set(config.client_groups.iter().map(ClientDraft::new).collect());
    }

    /// Names of the groups on the groups tab, for the client checkboxes.
    fn group_names(&self) -> Vec<String> {
        self.groups
            .get()
            .into_iter()
            .map(|group| group.name.get().trim().to_string())
            .filter(|name| !name.is_empty())
            .collect()
    }

    fn to_config(self) -> Result<BlockyConfig, String> {
        let bootstrap = text_lines(&self.bootstrap.get())
            .into_iter()
            .map(|line| {
                line.parse::<IpAddr>()
                    .map_err(|_| format!("bootstrap resolver {line:?} is not an IP address"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(BlockyConfig {
            enabled: self.enabled.get(),
            upstreams: text_lines(&self.upstreams.get()),
            bootstrap,
            upstream_strategy: parse_strategy(&self.strategy.get()),
            block_type: parse_block_type(&self.block_type.get()),
            refresh_hours: parse_count("List refresh", &self.refresh_hours.get(), 1, 168)?,
            prefetching: self.prefetching.get(),
            min_cache_minutes: parse_count("Minimum cache time", &self.min_cache.get(), 0, 60)?,
            query_log_enabled: self.query_log.get(),
            query_log_retention_days: parse_count(
                "Query log retention",
                &self.retention.get(),
                1,
                90,
            )?,
            groups: self
                .groups
                .get()
                .into_iter()
                .map(GroupDraft::to_group)
                .collect(),
            client_groups: self
                .clients
                .get()
                .into_iter()
                .map(|client| BlockyClientGroups {
                    selector: client.selector.get().trim().to_string(),
                    groups: client.groups.get(),
                })
                .collect(),
        })
    }
}

/// The tabs of the page.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Settings,
    Groups,
    Clients,
    QueryLog,
}

// ============================================================================
// Page
// ============================================================================

#[component]
pub fn DnsFilterPage(
    auth_token: ReadSignal<Option<String>>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let toasts = use_toasts();
    let token = Signal::derive(move || auth_token.get().unwrap_or_default());
    let form = FormState::new();
    let state = RwSignal::new(Option::<BlockyStateResponse>::None);
    let dnsmasq_mode = RwSignal::new(Option::<DnsmasqUpstreamMode>::None);
    let tab = RwSignal::new(Tab::Settings);

    let loading = RwSignal::new(true);
    let saving = RwSignal::new(false);
    let error_msg = RwSignal::new(Option::<String>::None);

    let load = move || {
        let token_val = token.get_untracked();
        if token_val.is_empty() {
            return;
        }
        spawn_local(async move {
            match api::fetch_blocky_state(&token_val).await {
                Ok(next) => {
                    form.load(&next.config);
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
            if let Ok(dnsmasq) = api::fetch_dnsmasq_state(&token_val).await {
                dnsmasq_mode.set(Some(dnsmasq.config.upstream_mode));
            }
        });
    };

    // Load the saved configuration once the token is known.
    Effect::new(move || {
        if !token.get().is_empty() {
            load();
        }
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
            match api::save_blocky_config(&token_val, config).await {
                Ok(()) => {
                    toasts.success(
                        "DNS filtering settings saved. They take effect once the configuration is applied.",
                    );
                    config_changed.run(());
                    load();
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

    let mismatch = move || {
        let saved = state.get()?;
        let mode = dnsmasq_mode.get()?;
        mismatch_message(saved.config.enabled, mode)
    };
    let binary_missing = move || state.get().is_some_and(|s| !s.installed);

    view! {
        <div class="space-y-6">
            <div>
                <h1 class="text-2xl font-semibold text-blue-300">"DNS filtering"</h1>
            </div>

            <Show when=binary_missing>
                <div class="bg-red-900/60 border border-red-500 rounded-lg p-4 text-red-100 space-y-1">
                    <p class="font-semibold">"Blocky is not installed"</p>
                    <p>{move || state.get().map(|s| s.binary_message).unwrap_or_default()}</p>
                </div>
            </Show>

            <Show when=move || mismatch().is_some()>
                <div class="bg-amber-900/40 border border-amber-500/60 rounded-lg p-4 text-amber-100 flex flex-wrap justify-between gap-3">
                    <p>{move || mismatch().unwrap_or_default()}</p>
                    <a href="/dnsmasq/dns-settings" class="underline text-amber-200 whitespace-nowrap">"Open DNS settings"</a>
                </div>
            </Show>

            <Show when=move || error_msg.get().is_some()>
                <div class="bg-red-900/50 border border-red-500 rounded p-4 text-red-200">
                    {move || error_msg.get().unwrap_or_default()}
                </div>
            </Show>

            <StatusPanel token=token on_unauthorized=on_unauthorized />

            <div class="flex flex-wrap gap-2 border-b border-gray-700 pb-2">
                <TabButton tab=tab value=Tab::Settings label="Settings" />
                <TabButton tab=tab value=Tab::Groups label="Filter groups" />
                <TabButton tab=tab value=Tab::Clients label="Clients" />
                <TabButton tab=tab value=Tab::QueryLog label="Query log" />
            </div>

            <Show when=move || loading.get()>
                <div class="text-center py-8 text-gray-400">"Loading DNS filtering settings..."</div>
            </Show>

            <Show when=move || !loading.get() && tab.get() != Tab::QueryLog>
                <form on:submit=save class="bg-gray-800 rounded-lg shadow-lg p-6 space-y-6">
                    <Show when=move || tab.get() == Tab::Settings>
                        <SettingsTab form=form />
                    </Show>
                    <Show when=move || tab.get() == Tab::Groups>
                        <GroupsTab form=form />
                    </Show>
                    <Show when=move || tab.get() == Tab::Clients>
                        <ClientsTab form=form token=token on_unauthorized=on_unauthorized />
                    </Show>
                    <div class="flex justify-end">
                        <button
                            type="submit"
                            class=PRIMARY
                            disabled=move || saving.get()
                        >
                            {move || if saving.get() { "Saving..." } else { "Save settings" }}
                        </button>
                    </div>
                </form>
            </Show>

            <Show when=move || !loading.get() && tab.get() == Tab::QueryLog>
                <QueryLogPanel token=token on_unauthorized=on_unauthorized reload=Callback::new(move |()| load()) />
            </Show>
        </div>
    }
}

#[component]
fn TabButton(tab: RwSignal<Tab>, value: Tab, label: &'static str) -> impl IntoView {
    view! {
        <button
            type="button"
            class=move || {
                if tab.get() == value {
                    "px-4 py-2 rounded-t bg-gray-800 text-blue-300 font-semibold"
                } else {
                    "px-4 py-2 rounded-t text-gray-400 hover:text-gray-200"
                }
            }
            on:click=move |_| tab.set(value)
        >
            {label}
        </button>
    }
}

// ============================================================================
// Settings tab
// ============================================================================

#[component]
fn SettingsTab(form: FormState) -> impl IntoView {
    view! {
        <label class=CHECKBOX_LABEL>
            <input
                type="checkbox"
                class="mt-1 w-4 h-4"
                prop:checked=move || form.enabled.get()
                on:change=move |ev| form.enabled.set(event_target_checked(&ev))
            />
            <span>"Enable DNS filtering. Blocky runs on this router, and DNS & DHCP sends its queries to it when Blocky is chosen as the upstream mode."</span>
        </label>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
                <label class=LABEL>"Upstream resolvers"</label>
                <textarea
                    class=INPUT
                    rows="4"
                    prop:value=move || form.upstreams.get()
                    on:input=move |ev| form.upstreams.set(event_target_value(&ev))
                ></textarea>
                <p class=HELP>"One per line: an IP address, tcp-tls:host (DNS over TLS), or https://host/path (DNS over HTTPS). Up to 8."</p>
            </div>
            <div>
                <label class=LABEL>"Bootstrap resolvers"</label>
                <textarea
                    class=INPUT
                    rows="4"
                    prop:value=move || form.bootstrap.get()
                    on:input=move |ev| form.bootstrap.set(event_target_value(&ev))
                ></textarea>
                <p class=HELP>"Plain IP resolvers that look up the upstream host names and list downloads. Not this router. Up to 4."</p>
            </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div>
                <label class=LABEL>"Upstream strategy"</label>
                <select
                    class=INPUT
                    prop:value=move || form.strategy.get()
                    on:change=move |ev| form.strategy.set(event_target_value(&ev))
                >
                    <option value="parallel_best">"Fastest of all upstreams"</option>
                    <option value="strict">"In order, next on failure"</option>
                    <option value="random">"Random upstream per query"</option>
                </select>
            </div>
            <div>
                <label class=LABEL>"Blocked answer"</label>
                <select
                    class=INPUT
                    prop:value=move || form.block_type.get()
                    on:change=move |ev| form.block_type.set(event_target_value(&ev))
                >
                    <option value="zero_ip">"0.0.0.0 / ::"</option>
                    <option value="nx_domain">"NXDOMAIN"</option>
                </select>
            </div>
            <div>
                <label class=LABEL>"List refresh (hours)"</label>
                <input
                    type="number" min="1" max="168" class=INPUT
                    prop:value=move || form.refresh_hours.get()
                    on:input=move |ev| form.refresh_hours.set(event_target_value(&ev))
                />
            </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div>
                <label class=LABEL>"Minimum cache time (minutes)"</label>
                <input
                    type="number" min="0" max="60" class=INPUT
                    prop:value=move || form.min_cache.get()
                    on:input=move |ev| form.min_cache.set(event_target_value(&ev))
                />
            </div>
            <div class="space-y-3">
                <span class=LABEL>"Caching"</span>
                <label class=CHECKBOX_LABEL>
                    <input
                        type="checkbox"
                        class="mt-1 w-4 h-4"
                        prop:checked=move || form.prefetching.get()
                        on:change=move |ev| form.prefetching.set(event_target_checked(&ev))
                    />
                    <span>"Refresh popular names before they expire"</span>
                </label>
            </div>
            <div class="space-y-3">
                <span class=LABEL>"Query log"</span>
                <label class=CHECKBOX_LABEL>
                    <input
                        type="checkbox"
                        class="mt-1 w-4 h-4"
                        prop:checked=move || form.query_log.get()
                        on:change=move |ev| form.query_log.set(event_target_checked(&ev))
                    />
                    <span>"Keep a log of every query"</span>
                </label>
                <div>
                    <label class=LABEL>"Keep for (days)"</label>
                    <input
                        type="number" min="1" max="90" class=INPUT
                        prop:value=move || form.retention.get()
                        on:input=move |ev| form.retention.set(event_target_value(&ev))
                    />
                </div>
            </div>
        </div>
    }
}

// ============================================================================
// Groups tab
// ============================================================================

#[component]
fn GroupsTab(form: FormState) -> impl IntoView {
    let add_group = move |_| {
        form.groups
            .update(|groups| groups.push(GroupDraft::new(&BlockyGroup::default())));
    };

    view! {
        <p class=HELP>
            "A group holds block lists (one URL per line) and hand-written entries: a domain such as example.com, a wildcard such as *.example.com, or a regular expression between slashes. An allowlist overrides the blocked domains of its group, and a group with allowlists also needs a denylist."
        </p>
        <div class="space-y-6">
            <For
                each=move || form.groups.get()
                key=|group| group.id
                children=move |group| {
                    let id = group.id;
                    view! {
                        <div class="border border-gray-700 rounded-lg p-4 space-y-4">
                            <div class="flex flex-wrap items-end gap-4">
                                <div class="flex-1 min-w-48">
                                    <label class=LABEL>"Group name"</label>
                                    <input
                                        type="text" maxlength="32" class=INPUT
                                        prop:value=move || group.name.get()
                                        on:input=move |ev| group.name.set(event_target_value(&ev))
                                    />
                                    <p class=HELP>"Lowercase letters, digits, - and _. Clients are assigned to groups by this name."</p>
                                </div>
                                <button
                                    type="button"
                                    class="px-4 py-2 bg-red-900/60 hover:bg-red-800 rounded text-red-100"
                                    on:click=move |_| form.groups.update(|groups| {
                                        groups.retain(|item| item.id != id);
                                    })
                                >
                                    "Remove group"
                                </button>
                            </div>
                            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                                <TextAreaField label="Block lists (URLs)" value=group.denylists />
                                <TextAreaField label="Allow lists (URLs)" value=group.allowlists />
                                <TextAreaField label="Blocked domains" value=group.custom_deny />
                                <TextAreaField label="Allowed domains" value=group.custom_allow />
                            </div>
                        </div>
                    }
                }
            />
            <button type="button" class=BUTTON on:click=add_group>"Add group"</button>
        </div>
    }
}

#[component]
fn TextAreaField(label: &'static str, value: RwSignal<String>) -> impl IntoView {
    view! {
        <div>
            <label class=LABEL>{label}</label>
            <textarea
                class=INPUT
                rows="4"
                prop:value=move || value.get()
                on:input=move |ev| value.set(event_target_value(&ev))
            ></textarea>
        </div>
    }
}

// ============================================================================
// Clients tab
// ============================================================================

#[component]
fn ClientsTab(
    form: FormState,
    token: Signal<String>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let known = RwSignal::new(Vec::<Client>::new());
    let poll_clients = move || {
        let token_val = token.get_untracked();
        if token_val.is_empty() {
            return;
        }
        spawn_local(async move {
            match api::fetch_clients(&token_val).await {
                Ok(list) => known.set(list),
                Err(e) if e.contains("Unauthorized") => on_unauthorized.run(()),
                Err(_) => {}
            }
        });
    };
    Effect::new(move |_prev: Option<Option<Interval>>| {
        if token.get().is_empty() {
            None
        } else {
            poll_clients();
            Some(Interval::new(CLIENTS_REFRESH_MS, poll_clients))
        }
    });

    let add_client = move |_| {
        let first = form.group_names().into_iter().take(1).collect::<Vec<_>>();
        form.clients.update(|clients| {
            clients.push(ClientDraft {
                id: next_row_id(),
                selector: RwSignal::new(String::new()),
                groups: RwSignal::new(first),
            })
        });
    };

    view! {
        <p class=HELP>
            "Each row applies its groups to one client: \"default\" for every client without its own row, an IP address, or a network such as 192.168.1.0/24."
        </p>
        <datalist id="known-clients">
            {move || {
                known
                    .get()
                    .into_iter()
                    .flat_map(|client| {
                        let label = client
                            .hostname
                            .clone()
                            .unwrap_or_else(|| client.mac.clone());
                        client
                            .ipv4
                            .into_iter()
                            .map(move |ip| view! { <option value=ip.clone()>{label.clone()}</option> })
                            .collect::<Vec<_>>()
                    })
                    .collect_view()
            }}
        </datalist>
        <div class="space-y-4">
            <For
                each=move || form.clients.get()
                key=|client| client.id
                children=move |client| {
                    let id = client.id;
                    view! {
                        <div class="border border-gray-700 rounded-lg p-4 flex flex-wrap items-start gap-4">
                            <div class="min-w-56">
                                <label class=LABEL>"Client"</label>
                                <input
                                    type="text" list="known-clients" class=INPUT
                                    placeholder="default"
                                    prop:value=move || client.selector.get()
                                    on:input=move |ev| client.selector.set(event_target_value(&ev))
                                />
                            </div>
                            <div class="flex-1 min-w-48">
                                <span class=LABEL>"Groups"</span>
                                <div class="flex flex-wrap gap-3">
                                    {move || {
                                        form.group_names()
                                            .into_iter()
                                            .map(|name| {
                                                let checked_name = name.clone();
                                                let toggled_name = name.clone();
                                                view! {
                                                    <label class=CHECKBOX_LABEL>
                                                        <input
                                                            type="checkbox"
                                                            class="mt-1 w-4 h-4"
                                                            prop:checked=move || client.groups.get().contains(&checked_name)
                                                            on:change=move |ev| {
                                                                let on = event_target_checked(&ev);
                                                                let name = toggled_name.clone();
                                                                client.groups.update(|groups| {
                                                                    groups.retain(|item| item != &name);
                                                                    if on {
                                                                        groups.push(name);
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
                            </div>
                            <button
                                type="button"
                                class="px-4 py-2 bg-red-900/60 hover:bg-red-800 rounded text-red-100"
                                on:click=move |_| form.clients.update(|clients| {
                                    clients.retain(|item| item.id != id);
                                })
                            >
                                "Remove"
                            </button>
                        </div>
                    }
                }
            />
            <button type="button" class=BUTTON on:click=add_client>"Add client"</button>
        </div>
    }
}

// ============================================================================
// Status panel
// ============================================================================

/// A runtime action on the running Blocky service.
#[derive(Clone, Copy)]
enum RuntimeAction {
    /// Pause for some minutes, or resume when `None`.
    Pause(Option<u32>),
    RefreshLists,
    FlushCache,
}

#[component]
fn StatusPanel(token: Signal<String>, on_unauthorized: Callback<()>) -> impl IntoView {
    let status = RwSignal::new(Option::<BlockyStatusResponse>::None);
    let action_error = RwSignal::new(Option::<String>::None);
    let action_message = RwSignal::new(Option::<String>::None);
    let busy = RwSignal::new(false);

    let poll = move || {
        let token_val = token.get_untracked();
        if token_val.is_empty() {
            return;
        }
        spawn_local(async move {
            match api::fetch_blocky_status(&token_val).await {
                Ok(next) => status.set(Some(next)),
                Err(e) if e.contains("Unauthorized") => on_unauthorized.run(()),
                Err(e) => action_error.set(Some(e)),
            }
        });
    };
    Effect::new(move |_prev: Option<Option<Interval>>| {
        if token.get().is_empty() {
            None
        } else {
            poll();
            Some(Interval::new(STATUS_REFRESH_MS, poll))
        }
    });

    // Runs a runtime action and shows its result. Runtime actions are not
    // configuration: they take effect at once and create no snapshot.
    let run_action = move |action: RuntimeAction| {
        let token_val = token.get_untracked();
        busy.set(true);
        action_error.set(None);
        action_message.set(None);
        spawn_local(async move {
            let result = match action {
                RuntimeAction::Pause(minutes) => api::set_blocking_pause(&token_val, minutes).await,
                RuntimeAction::RefreshLists => api::refresh_blocky_lists(&token_val).await,
                RuntimeAction::FlushCache => api::flush_blocky_cache(&token_val).await,
            };
            match result {
                Ok(response) if response.success => action_message.set(Some(response.message)),
                Ok(response) => action_error.set(Some(response.message)),
                Err(e) if e.contains("Unauthorized") => on_unauthorized.run(()),
                Err(e) => action_error.set(Some(e)),
            }
            busy.set(false);
            poll();
        });
    };

    view! {
        <div class="bg-gray-800 rounded-lg shadow-lg p-6 space-y-4">
            <div class="flex flex-wrap justify-between items-start gap-3">
                <div>
                    <h2 class="text-xl font-semibold text-blue-300">"Status"</h2>
                    <p class=HELP>"Refreshes every 5 seconds. Saved settings take effect after they are applied."</p>
                </div>
                {move || status.get().map(|s| {
                    if !s.service_active {
                        view! {
                            <span class="inline-flex items-center gap-2 rounded-full bg-gray-700 px-3 py-1 text-sm text-gray-300 ring-1 ring-inset ring-gray-500/40">
                                <span class="w-2 h-2 rounded-full bg-gray-400"></span>"Not running"
                            </span>
                        }.into_any()
                    } else if s.blocking.is_some_and(|b| b.enabled) {
                        view! {
                            <span class="inline-flex items-center gap-2 rounded-full bg-green-900/50 px-3 py-1 text-sm text-green-200 ring-1 ring-inset ring-green-500/40">
                                <span class="w-2 h-2 rounded-full bg-green-400"></span>"Blocking"
                            </span>
                        }.into_any()
                    } else {
                        view! {
                            <span class="inline-flex items-center gap-2 rounded-full bg-amber-900/50 px-3 py-1 text-sm text-amber-200 ring-1 ring-inset ring-amber-500/40">
                                <span class="w-2 h-2 rounded-full bg-amber-400"></span>"Paused"
                            </span>
                        }.into_any()
                    }
                })}
            </div>

            {move || status.get().map(|s| {
                let paused_for = s
                    .blocking
                    .filter(|b| !b.enabled && b.auto_enable_in_secs > 0)
                    .map(|b| format!("Blocking resumes in {}.", remaining_text(b.auto_enable_in_secs)));
                view! {
                    <div class="text-sm text-gray-300 space-y-1">
                        <p>{s.binary_message}</p>
                        {paused_for.map(|text| view! { <p>{text}</p> })}
                        {s.warnings.into_iter().map(|w| view! { <p class="text-amber-300">{w}</p> }).collect_view()}
                    </div>
                }
            })}

            <Show when=move || action_error.get().is_some()>
                <div class="bg-red-900/50 border border-red-500 rounded p-3 text-red-200">
                    {move || action_error.get().unwrap_or_default()}
                </div>
            </Show>
            <Show when=move || action_message.get().is_some()>
                <div class="bg-green-900/40 border border-green-500/60 rounded p-3 text-green-200">
                    {move || action_message.get().unwrap_or_default()}
                </div>
            </Show>

            <div class="flex flex-wrap gap-2">
                <button type="button" class=BUTTON disabled=move || busy.get() on:click=move |_| run_action(RuntimeAction::Pause(Some(5)))>"Pause 5 min"</button>
                <button type="button" class=BUTTON disabled=move || busy.get() on:click=move |_| run_action(RuntimeAction::Pause(Some(30)))>"Pause 30 min"</button>
                <button type="button" class=BUTTON disabled=move || busy.get() on:click=move |_| run_action(RuntimeAction::Pause(Some(60)))>"Pause 1 hour"</button>
                <button type="button" class=BUTTON disabled=move || busy.get() on:click=move |_| run_action(RuntimeAction::Pause(None))>"Resume"</button>
                <button type="button" class=BUTTON disabled=move || busy.get() on:click=move |_| run_action(RuntimeAction::RefreshLists)>"Refresh lists"</button>
                <button type="button" class=BUTTON disabled=move || busy.get() on:click=move |_| run_action(RuntimeAction::FlushCache)>"Flush cache"</button>
            </div>
        </div>
    }
}

// ============================================================================
// Query log
// ============================================================================

#[component]
fn QueryLogPanel(
    token: Signal<String>,
    on_unauthorized: Callback<()>,
    reload: Callback<()>,
) -> impl IntoView {
    let toasts = use_toasts();
    let client_filter = RwSignal::new(String::new());
    let domain_filter = RwSignal::new(String::new());
    let blocked_only = RwSignal::new(false);
    let log = RwSignal::new(Option::<BlockyQueryLogResponse>::None);
    let error_msg = RwSignal::new(Option::<String>::None);
    let loading = RwSignal::new(false);
    let config_changed = use_config_changed();

    let search = move || {
        let token_val = token.get_untracked();
        if token_val.is_empty() {
            return;
        }
        let query = QueryLogQuery {
            client: client_filter.get_untracked(),
            domain: domain_filter.get_untracked(),
            blocked_only: blocked_only.get_untracked(),
        };
        loading.set(true);
        error_msg.set(None);
        spawn_local(async move {
            match api::fetch_query_log(&token_val, &query).await {
                Ok(response) => log.set(Some(response)),
                Err(e) if e.contains("Unauthorized") => on_unauthorized.run(()),
                Err(e) => error_msg.set(Some(e)),
            }
            loading.set(false);
        });
    };

    // The first search runs when the tab opens.
    search();

    // Adds the domain to the saved configuration, so that the change is
    // pending like any other. The saved configuration is read again first, and
    // the settings form is reloaded from it.
    let allow = move |client: String, domain: String| {
        let token_val = token.get_untracked();
        error_msg.set(None);
        spawn_local(async move {
            let result = async {
                let mut current = api::fetch_blocky_state(&token_val).await?.config;
                let group = allow_domain(&mut current, &client, &domain)?;
                api::save_blocky_config(&token_val, current).await?;
                Ok::<String, String>(group)
            }
            .await;
            match result {
                Ok(group) => {
                    toasts.success(format!(
                        "{domain} is allowed in group {group:?}. The change is pending until it is applied."
                    ));
                    config_changed.run(());
                    reload.run(());
                }
                Err(e) if e.contains("Unauthorized") => on_unauthorized.run(()),
                Err(e) => error_msg.set(Some(e)),
            }
        });
    };

    view! {
        <div class="bg-gray-800 rounded-lg shadow-lg p-6 space-y-4">
            <form
                class="flex flex-wrap items-end gap-4"
                on:submit=move |ev: web_sys::SubmitEvent| {
                    ev.prevent_default();
                    search();
                }
            >
                <div class="min-w-48">
                    <label class=LABEL>"Client address"</label>
                    <input
                        type="text" class=INPUT placeholder="192.168.1.20"
                        prop:value=move || client_filter.get()
                        on:input=move |ev| client_filter.set(event_target_value(&ev))
                    />
                </div>
                <div class="min-w-48">
                    <label class=LABEL>"Domain contains"</label>
                    <input
                        type="text" class=INPUT placeholder="example.com"
                        prop:value=move || domain_filter.get()
                        on:input=move |ev| domain_filter.set(event_target_value(&ev))
                    />
                </div>
                <label class=CHECKBOX_LABEL>
                    <input
                        type="checkbox"
                        class="mt-1 w-4 h-4"
                        prop:checked=move || blocked_only.get()
                        on:change=move |ev| blocked_only.set(event_target_checked(&ev))
                    />
                    <span>"Blocked only"</span>
                </label>
                <button type="submit" class=PRIMARY disabled=move || loading.get()>
                    {move || if loading.get() { "Searching..." } else { "Search" }}
                </button>
            </form>

            <p class=HELP>
                "Up to 1000 of the most recent matching queries are shown. \"Allow\" adds the domain to the allowed list of the client's first group; it is saved as a pending change, and it replaces unsaved edits on the other tabs."
            </p>

            <Show when=move || error_msg.get().is_some()>
                <div class="bg-red-900/50 border border-red-500 rounded p-3 text-red-200">
                    {move || error_msg.get().unwrap_or_default()}
                </div>
            </Show>

            {move || log.get().map(|response| {
                let truncated = response.truncated;
                let warnings = response.warnings.clone();
                view! {
                    <div class="space-y-2">
                        {warnings.into_iter().map(|w| view! { <p class="text-sm text-amber-300">{w}</p> }).collect_view()}
                        {truncated.then(|| view! {
                            <p class="text-sm text-gray-400">"Only the most recent results are shown. Narrow the filters to see older queries."</p>
                        })}
                        <QueryLogTable entries=response.entries allow=allow />
                    </div>
                }
            })}
        </div>
    }
}

#[component]
fn QueryLogTable(
    entries: Vec<BlockyQueryLogEntry>,
    allow: impl Fn(String, String) + Copy + 'static,
) -> impl IntoView {
    if entries.is_empty() {
        return view! { <p class="text-gray-400">"No queries match these filters."</p> }.into_any();
    }
    view! {
        <div class="overflow-x-auto">
            <table class="min-w-full text-sm text-left">
                <thead class="text-gray-400 border-b border-gray-700">
                    <tr>
                        <th class="py-2 pr-4">"Time"</th>
                        <th class="py-2 pr-4">"Client"</th>
                        <th class="py-2 pr-4">"Domain"</th>
                        <th class="py-2 pr-4">"Type"</th>
                        <th class="py-2 pr-4">"Result"</th>
                        <th class="py-2 pr-4">"ms"</th>
                        <th class="py-2"></th>
                    </tr>
                </thead>
                <tbody class="text-gray-200">
                    {entries
                        .into_iter()
                        .map(|entry| {
                            let blocked = entry.blocked;
                            let client_ip = entry.client_ip.clone();
                            let domain = entry.domain.clone();
                            let client_label = match &entry.client_name {
                                Some(name) => format!("{name} ({})", entry.client_ip),
                                None => entry.client_ip.clone(),
                            };
                            view! {
                                <tr class="border-b border-gray-700/60">
                                    <td class="py-2 pr-4 whitespace-nowrap">{entry.time}</td>
                                    <td class="py-2 pr-4">{client_label}</td>
                                    <td class="py-2 pr-4 break-all">{entry.domain}</td>
                                    <td class="py-2 pr-4">{entry.question_type}</td>
                                    <td class="py-2 pr-4">
                                        {if blocked {
                                            view! { <span class="text-red-300 font-semibold">"Blocked"</span> }.into_any()
                                        } else {
                                            view! { <span class="text-gray-400">{entry.response_type}</span> }.into_any()
                                        }}
                                    </td>
                                    <td class="py-2 pr-4">{entry.duration_ms}</td>
                                    <td class="py-2">
                                        {blocked.then(|| view! {
                                            <button
                                                type="button"
                                                class="px-3 py-1 bg-gray-700 hover:bg-gray-600 rounded text-white"
                                                on:click=move |_| allow(client_ip.clone(), domain.clone())
                                            >
                                                "Allow"
                                            </button>
                                        })}
                                    </td>
                                </tr>
                            }
                        })
                        .collect_view()}
                </tbody>
            </table>
        </div>
    }
    .into_any()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_areas_hold_one_entry_per_line() {
        assert_eq!(
            text_lines("  https://a.example/list.txt \n\n ads.example\r\n"),
            vec![
                "https://a.example/list.txt".to_string(),
                "ads.example".to_string()
            ]
        );
    }

    #[test]
    fn counts_are_checked_against_their_range() {
        assert_eq!(parse_count("Refresh", " 24 ", 1, 168), Ok(24));
        assert!(
            parse_count("Refresh", "0", 1, 168)
                .unwrap_err()
                .contains("between 1 and 168")
        );
        assert!(
            parse_count("Refresh", "a day", 1, 168)
                .unwrap_err()
                .contains("whole number")
        );
    }

    #[test]
    fn remaining_pause_time_uses_the_largest_unit() {
        assert_eq!(remaining_text(45), "45s");
        assert_eq!(remaining_text(125), "2m 5s");
        assert_eq!(remaining_text(3725), "1h 2m");
    }

    #[test]
    fn a_mismatch_between_blocky_and_dnsmasq_is_reported_both_ways() {
        assert!(mismatch_message(true, DnsmasqUpstreamMode::System).is_some());
        assert!(mismatch_message(false, DnsmasqUpstreamMode::Blocky).is_some());
        assert!(mismatch_message(true, DnsmasqUpstreamMode::Blocky).is_none());
        assert!(mismatch_message(false, DnsmasqUpstreamMode::System).is_none());
    }

    #[test]
    fn allowing_a_domain_uses_the_client_entry_then_the_default() {
        let mut config = BlockyConfig {
            groups: vec![
                BlockyGroup {
                    name: "ads".to_string(),
                    denylists: vec!["https://lists.example/ads.txt".to_string()],
                    ..BlockyGroup::default()
                },
                BlockyGroup {
                    name: "kids".to_string(),
                    denylists: vec!["https://lists.example/adult.txt".to_string()],
                    ..BlockyGroup::default()
                },
            ],
            client_groups: vec![
                BlockyClientGroups {
                    selector: "default".to_string(),
                    groups: vec!["ads".to_string()],
                },
                BlockyClientGroups {
                    selector: "192.168.1.20".to_string(),
                    groups: vec!["kids".to_string()],
                },
            ],
            ..BlockyConfig::default()
        };

        assert_eq!(
            allow_domain(&mut config, "192.168.1.20", " tracker.example ").unwrap(),
            "kids"
        );
        assert_eq!(
            config.groups[1].custom_allow,
            vec!["tracker.example".to_string()]
        );

        // Adding the same domain again does not duplicate it.
        allow_domain(&mut config, "192.168.1.20", "tracker.example").unwrap();
        assert_eq!(config.groups[1].custom_allow.len(), 1);

        assert_eq!(
            allow_domain(&mut config, "10.0.0.9", "news.example").unwrap(),
            "ads"
        );
        assert_eq!(
            config.groups[0].custom_allow,
            vec!["news.example".to_string()]
        );
    }

    #[test]
    fn allowing_refuses_an_unusable_domain_or_missing_group() {
        let mut config = BlockyConfig::default();
        assert!(allow_domain(&mut config, "10.0.0.9", "two words").is_err());
        assert!(allow_domain(&mut config, "10.0.0.9", "  ").is_err());

        config.client_groups.clear();
        assert!(allow_domain(&mut config, "10.0.0.9", "news.example").is_err());
    }
}
