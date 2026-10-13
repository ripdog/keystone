//! Connection tracking table: the connections the router is holding, with
//! counts by protocol and state, grouping by LAN client, and auto-refresh.

use crate::api;
use crate::components::rule_table::{FilterBox, format_bytes, format_count, matches_filter};
use gloo_timers::callback::Interval;
use keystone_core::{Client, ConnectionEntry, ConnectionsResponse};
use leptos::prelude::*;
use std::collections::BTreeMap;

const AUTO_REFRESH_MS: u32 = 5000;

/// `address:port`, with IPv6 addresses bracketed. A missing port is shown as
/// the bare address.
fn endpoint(address: &str, port: Option<u16>) -> String {
    match (port, address.contains(':')) {
        (Some(port), true) => format!("[{address}]:{port}"),
        (Some(port), false) => format!("{address}:{port}"),
        (None, _) => address.to_string(),
    }
}

fn state_of(entry: &ConnectionEntry) -> &str {
    entry.state.as_deref().unwrap_or("-")
}

/// Name of the LAN client that owns a connection's original source: its
/// hostname, else its MAC address, else the address itself.
fn client_label(clients: &[Client], source: &str) -> String {
    clients
        .iter()
        .find(|client| client.ipv4.iter().any(|address| address == source))
        .map(|client| {
            client
                .hostname
                .clone()
                .unwrap_or_else(|| client.mac.clone())
        })
        .unwrap_or_else(|| source.to_string())
}

/// Count of each key, in key order.
fn counts<'a>(entries: impl Iterator<Item = &'a str>) -> Vec<(String, usize)> {
    let mut map: BTreeMap<String, usize> = BTreeMap::new();
    for key in entries {
        *map.entry(key.to_string()).or_default() += 1;
    }
    map.into_iter().collect()
}

#[component]
pub fn ConnectionsTab(token: Signal<String>, on_unauthorized: Callback<()>) -> impl IntoView {
    let reload = RwSignal::new(0);
    let auto_refresh = RwSignal::new(false);
    let group_by_client = RwSignal::new(false);
    let filter = RwSignal::new(String::new());

    let connections = LocalResource::new(move || {
        let token = token.get();
        let _ = reload.get();
        async move { api::fetch_connections(&token).await }
    });
    let clients = LocalResource::new(move || {
        let token = token.get();
        let _ = reload.get();
        async move { api::fetch_clients(&token).await }
    });

    // Auto-refresh: the Effect owns the interval, so turning the option off
    // (or leaving the page) stops it.
    Effect::new(move |_prev: Option<Option<Interval>>| {
        if auto_refresh.get() {
            Some(Interval::new(AUTO_REFRESH_MS, move || {
                reload.update(|value| *value += 1);
            }))
        } else {
            None
        }
    });

    view! {
        <div class="space-y-4">
            <div class="flex flex-wrap items-center justify-between gap-3">
                <div>
                    <h2 class="text-lg font-medium text-gray-200">"Connections"</h2>
                    <p class="text-gray-400 text-sm">"Connections tracked by the router, as the kernel holds them."</p>
                </div>
                <div class="flex flex-wrap items-center gap-3">
                    <FilterBox query=filter placeholder="Filter connections" />
                    <label class="flex items-center gap-1.5 text-sm text-gray-300">
                        <input type="checkbox" class="rounded"
                            prop:checked=move || group_by_client.get()
                            on:change=move |ev| group_by_client.set(event_checked(&ev)) />
                        "Group by LAN client"
                    </label>
                    <label class="flex items-center gap-1.5 text-sm text-gray-300">
                        <input type="checkbox" class="rounded"
                            prop:checked=move || auto_refresh.get()
                            on:change=move |ev| auto_refresh.set(event_checked(&ev)) />
                        "Refresh every 5 s"
                    </label>
                    <button
                        class="px-3 py-1.5 bg-gray-600 hover:bg-gray-500 text-white rounded text-sm"
                        on:click=move |_| reload.update(|value| *value += 1)
                    >
                        "Refresh"
                    </button>
                </div>
            </div>

            <Suspense fallback=move || view! { <p class="text-gray-400">"Reading the connection table..."</p> }>
                {move || {
                    connections.get().map(|result| match result {
                        Ok(response) => {
                            // Names are optional: without them rows show addresses.
                            let client_list = clients.get().and_then(Result::ok).unwrap_or_default();
                            view! { <ConnectionsBody response=response clients=client_list filter=filter group=group_by_client /> }.into_any()
                        }
                        Err(message) => {
                            if message.contains("Unauthorized") {
                                on_unauthorized.run(());
                            }
                            view! { <p class="text-red-400 text-sm">"Could not read connections: "{message}</p> }.into_any()
                        }
                    })
                }}
            </Suspense>
        </div>
    }
}

#[component]
fn ConnectionsBody(
    response: ConnectionsResponse,
    clients: Vec<Client>,
    filter: RwSignal<String>,
    group: RwSignal<bool>,
) -> impl IntoView {
    let protocol_counts = counts(response.connections.iter().map(|c| c.protocol.as_str()));
    let state_counts = counts(response.connections.iter().map(state_of));
    let total = response.connections.len();
    let truncated = response.truncated;
    let limit = response.limit;
    let connections = response.connections;
    let clients = std::sync::Arc::new(clients);
    let rows_source = std::sync::Arc::new(connections);

    let chip = |label: String, count: usize| {
        view! {
            <span class="px-2 py-0.5 rounded bg-gray-700 text-gray-200 text-xs">
                {label}" "<span class="text-gray-400">{count.to_string()}</span>
            </span>
        }
    };

    view! {
        <div class="space-y-3">
            {truncated.then(|| view! {
                <p class="text-amber-300 text-sm bg-amber-950/40 border border-amber-800 rounded p-3">
                    "The table holds more than " {limit} " connections. The first " {limit} " are shown; narrow the filter or refresh later."
                </p>
            })}
            <div class="flex flex-wrap gap-2 items-center text-sm">
                <span class="text-gray-400">{format!("{total} connections")}</span>
                {protocol_counts.into_iter().map(|(name, count)| chip(name, count)).collect_view()}
                <span class="text-gray-600">"|"</span>
                {state_counts.into_iter().map(|(name, count)| chip(name, count)).collect_view()}
            </div>

            <div class="overflow-auto max-h-[600px] border border-gray-700 rounded">
                <table class="min-w-full text-sm">
                    <thead class="bg-gray-900 text-gray-400 text-left sticky top-0">
                        <tr>
                            <th class="px-3 py-2 font-medium">"Proto"</th>
                            <th class="px-3 py-2 font-medium">"State"</th>
                            <th class="px-3 py-2 font-medium">"Original"</th>
                            <th class="px-3 py-2 font-medium">"Reply"</th>
                            <th class="px-3 py-2 font-medium">"NAT"</th>
                            <th class="px-3 py-2 font-medium">"Mark"</th>
                            <th class="px-3 py-2 font-medium">"Timeout"</th>
                            <th class="px-3 py-2 font-medium">"Packets / bytes"</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-800">
                        {move || {
                            let query = filter.get();
                            let visible: Vec<(String, ConnectionEntry)> = rows_source
                                .iter()
                                .map(|entry| (client_label(&clients, &entry.original_source), entry.clone()))
                                .filter(|(owner, entry)| {
                                    matches_filter(
                                        &query,
                                        &[
                                            owner.clone(),
                                            entry.protocol.clone(),
                                            state_of(entry).to_string(),
                                            endpoint(&entry.original_source, entry.original_source_port),
                                            endpoint(&entry.original_destination, entry.original_destination_port),
                                        ],
                                    )
                                })
                                .collect();
                            if group.get() {
                                let mut groups: BTreeMap<String, Vec<ConnectionEntry>> = BTreeMap::new();
                                for (owner, entry) in visible {
                                    groups.entry(owner).or_default().push(entry);
                                }
                                groups
                                    .into_iter()
                                    .map(|(owner, entries)| {
                                        let header = format!("{owner} ({})", entries.len());
                                        view! {
                                            <tr class="bg-gray-800/70">
                                                <td colspan="8" class="px-3 py-1.5 text-gray-200 font-medium">{header}</td>
                                            </tr>
                                            {entries.into_iter().map(connection_row).collect_view()}
                                        }
                                    })
                                    .collect_view()
                                    .into_any()
                            } else {
                                visible
                                    .into_iter()
                                    .map(|(_, entry)| connection_row(entry))
                                    .collect_view()
                                    .into_any()
                            }
                        }}
                    </tbody>
                </table>
            </div>
        </div>
    }
}

fn connection_row(entry: ConnectionEntry) -> impl IntoView {
    let original = format!(
        "{} → {}",
        endpoint(&entry.original_source, entry.original_source_port),
        endpoint(&entry.original_destination, entry.original_destination_port)
    );
    let reply = format!(
        "{} → {}",
        endpoint(&entry.reply_source, entry.reply_source_port),
        endpoint(&entry.reply_destination, entry.reply_destination_port)
    );
    let packets = match (entry.packets, entry.bytes) {
        (Some(packets), Some(bytes)) => {
            format!("{} / {}", format_count(packets), format_bytes(bytes))
        }
        _ => "not accounted".to_string(),
    };
    view! {
        <tr class="text-gray-300">
            <td class="px-3 py-1.5 font-mono">{entry.protocol.clone()}</td>
            <td class="px-3 py-1.5">{state_of(&entry).to_string()}</td>
            <td class="px-3 py-1.5 font-mono whitespace-nowrap">{original}</td>
            <td class="px-3 py-1.5 font-mono whitespace-nowrap">{reply}</td>
            <td class="px-3 py-1.5">{if entry.nat { "yes" } else { "no" }}</td>
            <td class="px-3 py-1.5 font-mono">{entry.mark.to_string()}</td>
            <td class="px-3 py-1.5">{entry.timeout.map(|t| format!("{t} s")).unwrap_or_else(|| "-".to_string())}</td>
            <td class="px-3 py-1.5 whitespace-nowrap">{packets}</td>
        </tr>
    }
}

fn event_checked(ev: &leptos::ev::Event) -> bool {
    use wasm_bindgen::JsCast;
    ev.target()
        .and_then(|target| target.dyn_into::<web_sys::HtmlInputElement>().ok())
        .map(|input| input.checked())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_endpoints_are_bracketed() {
        assert_eq!(endpoint("203.0.113.5", Some(443)), "203.0.113.5:443");
        assert_eq!(endpoint("2001:db8::1", Some(443)), "[2001:db8::1]:443");
        assert_eq!(endpoint("1.1.1.1", None), "1.1.1.1");
    }

    #[test]
    fn counts_group_equal_keys() {
        let keys = ["tcp", "udp", "tcp"];
        let counted = counts(keys.iter().copied());
        let tcp = counted
            .iter()
            .find(|(name, _)| name == "tcp")
            .map(|(_, c)| *c);
        assert_eq!(tcp, Some(2));
        assert_eq!(counted.iter().map(|(_, c)| c).sum::<usize>(), keys.len());
    }
}
