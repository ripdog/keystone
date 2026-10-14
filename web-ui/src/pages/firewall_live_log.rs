//! Live firewall log: the packets logging rules have written to the kernel log.
//!
//! The page polls with the journal cursor, so each poll returns only what is
//! new. It keeps the most recent rows and scrolls to the newest one while it is
//! not paused. The kernel line does not carry the rule's action, so the action
//! is looked up in the rule's configuration.

use super::firewall_packet_tester::rule_page;
use crate::api;
use crate::components::rule_table::{FilterBox, matches_filter};
use gloo_timers::callback::Interval;
use keystone_core::FirewallLogEntry;
use leptos::html;
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::components::A;

/// Rows kept in the page. Older rows are dropped as new ones arrive.
const MAX_ROWS: usize = 500;
/// Lines requested per poll.
const POLL_LIMIT: usize = 200;
const POLL_MS: u32 = 2000;

/// Rule actions by `(kind, id)`, from the input and forward rules.
#[derive(Clone, PartialEq, Eq)]
struct RuleInfo {
    kind: &'static str,
    id: i64,
    action: String,
}

fn action_for(rules: &[RuleInfo], entry: &FirewallLogEntry) -> String {
    let (Some(kind), Some(id)) = (entry.rule_kind.as_deref(), entry.rule_id) else {
        return "-".to_string();
    };
    rules
        .iter()
        .find(|rule| rule.kind == kind && rule.id == id)
        .map(|rule| rule.action.clone())
        .unwrap_or_else(|| "deleted".to_string())
}

/// Local time of a kernel timestamp (microseconds since the epoch).
fn time_of(realtime_us: u64) -> String {
    let date = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(
        (realtime_us / 1000) as f64,
    ));
    String::from(date.to_locale_time_string("en-GB"))
}

fn ports(entry: &FirewallLogEntry) -> String {
    match (entry.source_port, entry.destination_port) {
        (Some(source), Some(destination)) => format!("{source} -> {destination}"),
        (None, Some(destination)) => format!("-> {destination}"),
        (Some(source), None) => format!("{source} ->"),
        (None, None) => "-".to_string(),
    }
}

#[component]
pub fn LiveLogTab(token: Signal<String>, on_unauthorized: Callback<()>) -> impl IntoView {
    let entries = RwSignal::new(Vec::<FirewallLogEntry>::new());
    let cursor = RwSignal::new(None::<String>);
    let paused = RwSignal::new(false);
    let filter = RwSignal::new(String::new());
    let error = RwSignal::new(None::<String>);
    let cursor_reset = RwSignal::new(false);
    let rules = RwSignal::new(Vec::<RuleInfo>::new());
    let logging_enabled = RwSignal::new(None::<bool>);
    let scroll_ref = NodeRef::<html::Div>::new();

    // The rules give each row its action, and tell whether any rule logs.
    let load_rules = move || {
        let token_value = token.get_untracked();
        if token_value.is_empty() {
            return;
        }
        spawn_local(async move {
            let inputs = api::fetch_input_rules(&token_value).await;
            let forwards = api::fetch_forward_rules(&token_value).await;
            let mut infos = Vec::new();
            let mut any_logging = false;
            if let Ok(list) = inputs {
                for rule in list {
                    any_logging |= rule.log_enabled;
                    if let Some(id) = rule.id {
                        infos.push(RuleInfo {
                            kind: "input",
                            id,
                            action: rule.action.to_string(),
                        });
                    }
                }
            }
            if let Ok(list) = forwards {
                for rule in list {
                    any_logging |= rule.log_enabled;
                    if let Some(id) = rule.id {
                        infos.push(RuleInfo {
                            kind: "forward",
                            id,
                            action: rule.action.to_string(),
                        });
                    }
                }
            }
            rules.set(infos);
            logging_enabled.set(Some(any_logging));
        });
    };

    let poll = move || {
        if paused.get_untracked() {
            return;
        }
        let token_value = token.get_untracked();
        if token_value.is_empty() {
            return;
        }
        let current = cursor.get_untracked();
        spawn_local(async move {
            match api::fetch_firewall_log(&token_value, current.as_deref(), POLL_LIMIT).await {
                Ok(response) => {
                    entries.update(|rows| {
                        rows.extend(response.entries);
                        let excess = rows.len().saturating_sub(MAX_ROWS);
                        rows.drain(..excess);
                    });
                    cursor.set(response.next_cursor);
                    cursor_reset.set(response.cursor_reset);
                    error.set(None);
                }
                Err(message) => {
                    if message.contains("Unauthorized") {
                        on_unauthorized.run(());
                    }
                    error.set(Some(message));
                }
            }
        });
    };

    // The Effect keeps the Interval alive for as long as the tab is shown, and
    // drops it on unmount. It polls at once when the token is available.
    Effect::new(move |_prev: Option<Option<Interval>>| {
        if token.get().is_empty() {
            None
        } else {
            load_rules();
            poll();
            Some(Interval::new(POLL_MS, move || {
                poll();
            }))
        }
    });

    // Keep the newest row in view while the log is not paused.
    Effect::new(move |_| {
        let _ = entries.get();
        if !paused.get_untracked()
            && let Some(element) = scroll_ref.get()
        {
            element.set_scroll_top(element.scroll_height());
        }
    });

    let row_fields = move |entry: &FirewallLogEntry, action: &str| -> Vec<String> {
        vec![
            entry.prefix.clone(),
            entry.rule_kind.clone().unwrap_or_default(),
            action.to_string(),
            entry.in_interface.clone().unwrap_or_default(),
            entry.out_interface.clone().unwrap_or_default(),
            entry.source.clone().unwrap_or_default(),
            entry.destination.clone().unwrap_or_default(),
            entry.protocol.clone().unwrap_or_default(),
            entry.message.clone(),
        ]
    };

    view! {
        <div class="space-y-4">
            <div class="flex flex-wrap items-center justify-between gap-3">
                <div>
                    <h2 class="text-lg font-medium text-gray-200">"Live Log"</h2>
                    <p class="text-gray-400 text-sm">
                        "Packets matched by logging rules, newest last."
                    </p>
                </div>
                <div class="flex items-center gap-2">
                    <FilterBox query=filter placeholder="Filter lines" />
                    <button
                        class="px-3 py-1.5 bg-gray-600 hover:bg-gray-500 text-white rounded text-sm"
                        on:click=move |_| paused.update(|value| *value = !*value)
                    >
                        {move || if paused.get() { "Resume" } else { "Pause" }}
                    </button>
                    <button
                        class="px-3 py-1.5 bg-gray-600 hover:bg-gray-500 text-white rounded text-sm"
                        on:click=move |_| entries.set(Vec::new())
                    >
                        "Clear"
                    </button>
                </div>
            </div>

            {move || (logging_enabled.get() == Some(false)).then(|| view! {
                <p class="text-amber-300 text-sm bg-amber-950/40 border border-amber-800 rounded p-3">
                    "No input or forward rule has logging enabled. Turn on logging in a rule to see its packets here."
                </p>
            })}
            {move || cursor_reset.get().then(|| view! {
                <p class="text-gray-400 text-xs">
                    "The previous position in the log is no longer available, so the most recent lines are shown."
                </p>
            })}
            {move || error.get().map(|message| view! {
                <p class="text-red-400 text-sm">"Could not read the log: "{message}</p>
            })}

            <div node_ref=scroll_ref class="overflow-auto max-h-[600px] border border-gray-700 rounded">
                <table class="min-w-full text-sm">
                    <thead class="bg-gray-900 text-gray-400 text-left sticky top-0">
                        <tr>
                            <th class="px-3 py-2 font-medium">"Time"</th>
                            <th class="px-3 py-2 font-medium">"Rule"</th>
                            <th class="px-3 py-2 font-medium">"Action"</th>
                            <th class="px-3 py-2 font-medium">"In"</th>
                            <th class="px-3 py-2 font-medium">"Out"</th>
                            <th class="px-3 py-2 font-medium">"Source → destination"</th>
                            <th class="px-3 py-2 font-medium">"Protocol"</th>
                            <th class="px-3 py-2 font-medium">"Ports"</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-800">
                        {move || {
                            let query = filter.get();
                            let rule_list = rules.get();
                            entries
                                .get()
                                .into_iter()
                                .filter_map(|entry| {
                                    let action = action_for(&rule_list, &entry);
                                    let fields = row_fields(&entry, &action);
                                    matches_filter(&query, &fields).then_some((entry, action))
                                })
                                .map(|(entry, action)| render_row(entry, action))
                                .collect_view()
                        }}
                    </tbody>
                </table>
            </div>
        </div>
    }
}

fn render_row(entry: FirewallLogEntry, action: String) -> impl IntoView {
    let time = time_of(entry.realtime_us);
    let ports_text = ports(&entry);
    let rule = if entry.parsed {
        let text = match (&entry.prefix, entry.rule_id) {
            (prefix, Some(id)) if !prefix.is_empty() => format!("#{id} {prefix}"),
            (_, Some(id)) => format!("#{id}"),
            _ => entry.prefix.clone(),
        };
        match entry.rule_kind.as_deref() {
            Some(kind) => {
                let path = rule_page(kind);
                view! { <A href=path>{text}</A> }.into_any()
            }
            None => view! { <span>{text}</span> }.into_any(),
        }
    } else {
        // Unknown layout: the raw message is all there is.
        view! { <span class="text-gray-400 break-all">{entry.message.clone()}</span> }.into_any()
    };
    let source_destination = match (&entry.source, &entry.destination) {
        (Some(source), Some(destination)) => format!("{source} → {destination}"),
        _ => "-".to_string(),
    };
    view! {
        <tr class="text-gray-300">
            <td class="px-3 py-1.5 whitespace-nowrap text-gray-400">{time}</td>
            <td class="px-3 py-1.5">{rule}</td>
            <td class="px-3 py-1.5">{action}</td>
            <td class="px-3 py-1.5 font-mono">{entry.in_interface.clone().unwrap_or_default()}</td>
            <td class="px-3 py-1.5 font-mono">{entry.out_interface.clone().unwrap_or_default()}</td>
            <td class="px-3 py-1.5 font-mono whitespace-nowrap">{source_destination}</td>
            <td class="px-3 py-1.5">{entry.protocol.clone().unwrap_or_default()}</td>
            <td class="px-3 py-1.5 font-mono whitespace-nowrap">{ports_text}</td>
        </tr>
    }
}
