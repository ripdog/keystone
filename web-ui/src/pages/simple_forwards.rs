//! A device-oriented WAN forwarding editor. It writes ordinary firewall rules.
use crate::api;
use crate::components::rule_table::{FilterBox, RuleHits, matches_filter, use_rule_counters};
use crate::components::use_config_changed;
use crate::components::use_toasts;
use keystone_core::{
    CreateSimplePortForwardRequest, LanDevice, PortForward, RuleProtocol, SimplePortForward,
};
use leptos::prelude::*;
use leptos_router::hooks::use_query_map;

/// Counter kinds of a simple forward: its allow rules, one per family.
const SIMPLE_HIT_KINDS: &[&str] = &["forward"];
/// Counter kinds of a raw port forward: external and LAN (hairpin) DNAT.
const RAW_HIT_KINDS: &[&str] = &["portfwd", "portfwd-hairpin"];

/// Text a search matches against for a simple forward.
fn simple_fields(forward: &SimplePortForward) -> Vec<String> {
    vec![
        forward.name.clone(),
        forward.description.clone().unwrap_or_default(),
        forward.protocol.to_string(),
        forward.external_port.to_string(),
        forward.destination_port.to_string(),
        forward.ipv4.clone().unwrap_or_default(),
        forward.ipv6.clone().unwrap_or_default(),
        forward.source_zone.clone().unwrap_or_default(),
        forward.source_ip.clone().unwrap_or_default(),
    ]
}

/// Text a search matches against for a raw port forward.
fn raw_fields(pf: &PortForward) -> Vec<String> {
    vec![
        pf.name.clone(),
        pf.description.clone().unwrap_or_default(),
        pf.protocol.to_string(),
        pf.external_port_start.to_string(),
        pf.dest_ip.clone(),
        pf.dest_ipv6_suffix.clone().unwrap_or_default(),
        pf.source_zone.clone().unwrap_or_default(),
        pf.source_ip.clone().unwrap_or_default(),
        pf.source_group.clone().unwrap_or_default(),
    ]
}

/// The simple forwards that match a search.
fn filter_simple(items: &[SimplePortForward], query: &str) -> Vec<SimplePortForward> {
    items
        .iter()
        .filter(|forward| matches_filter(query, &simple_fields(forward)))
        .cloned()
        .collect()
}

/// The raw port forwards that match a search.
fn filter_raw(items: &[PortForward], query: &str) -> Vec<PortForward> {
    items
        .iter()
        .filter(|pf| matches_filter(query, &raw_fields(pf)))
        .cloned()
        .collect()
}

/// Where a raw port forward accepts traffic from, for display.
fn raw_source(pf: &PortForward) -> String {
    let zone = pf.source_zone.clone().unwrap_or_else(|| "Any".into());
    match (pf.source_group.as_deref(), pf.source_ip.as_deref()) {
        (Some(group), _) => format!("{zone}, group {group}"),
        (None, Some(ip)) => format!("{zone}, {ip}"),
        (None, None) => zone,
    }
}

#[component]
pub(super) fn SimpleForwardsTab(
    token: Signal<String>,
    reload_trigger: RwSignal<i32>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let config_changed = use_config_changed();
    let toasts = use_toasts();
    let forwards = LocalResource::new(move || {
        let token = token.get();
        let _ = reload_trigger.get();
        async move { api::fetch_simple_forwards(&token).await }
    });
    let other_forwards = LocalResource::new(move || {
        let token = token.get();
        let _ = reload_trigger.get();
        async move { api::fetch_other_port_forwards(&token).await }
    });
    let devices = LocalResource::new(move || {
        let token = token.get();
        let _ = reload_trigger.get();
        async move { api::fetch_lan_devices(&token).await }
    });
    let counters = use_rule_counters(token, on_unauthorized);
    let filter = RwSignal::new(String::new());
    let editing = RwSignal::new(false);
    let edit_id = RwSignal::new(None::<i64>);
    let manual = RwSignal::new(false);
    let selected = RwSignal::new(String::new());
    let ipv4 = RwSignal::new(String::new());
    let ipv6 = RwSignal::new(String::new());
    let tcp = RwSignal::new(true);
    let udp = RwSignal::new(false);
    let port = RwSignal::new(String::new());
    let destination_port = RwSignal::new(String::new());
    let description = RwSignal::new(String::new());
    let saving = RwSignal::new(false);
    let error = RwSignal::new(String::new());

    // Opened from the Clients page as /firewall/port-forwards?mac=...: start a
    // new forward for that device. Applied once per requested MAC, and only
    // when the MAC is in the discovered device list, so refreshes or a
    // cancelled editor do not reopen it.
    let query = use_query_map();
    let applied_mac = RwSignal::new(None::<String>);
    Effect::new(move || {
        let Some(requested) = query
            .with(|q| q.get("mac"))
            .map(|mac| mac.to_ascii_lowercase())
        else {
            return;
        };
        if applied_mac.get_untracked().as_deref() == Some(requested.as_str()) {
            return;
        }
        let Some(Ok(items)) = devices.get() else {
            return;
        };
        if !items.iter().any(|d| d.mac == requested) {
            return;
        }
        applied_mac.set(Some(requested.clone()));
        edit_id.set(None);
        manual.set(false);
        selected.set(requested);
        error.set(String::new());
        editing.set(true);
    });

    let save = move |_| {
        if saving.get_untracked() {
            return;
        }
        let external = port.get_untracked().parse::<u16>().ok().filter(|p| *p > 0);
        let internal = if destination_port.get_untracked().is_empty() {
            Some(None)
        } else {
            destination_port
                .get_untracked()
                .parse::<u16>()
                .ok()
                .filter(|p| *p > 0)
                .map(Some)
        };
        let (Some(external), Some(internal)) = (external, internal) else {
            error.set("Enter valid port numbers between 1 and 65535".into());
            return;
        };
        if !tcp.get_untracked() && !udp.get_untracked() {
            error.set("Select TCP and/or UDP".into());
            return;
        }
        let addresses = if manual.get_untracked() {
            (ipv4.get_untracked(), ipv6.get_untracked())
        } else {
            let device = devices
                .get_untracked()
                .and_then(|res| res.ok())
                .and_then(|items| {
                    items
                        .into_iter()
                        .find(|d| d.mac == selected.get_untracked())
                });
            match device {
                Some(d) => (
                    d.ipv4.first().cloned().unwrap_or_default(),
                    d.ipv6.first().cloned().unwrap_or_default(),
                ),
                None => {
                    error.set("Choose a LAN device, or use Advanced to enter addresses".into());
                    return;
                }
            }
        };
        if addresses.0.is_empty() && addresses.1.is_empty() {
            error.set("Enter at least one destination address".into());
            return;
        }
        error.set(String::new());
        saving.set(true);
        let token = token.get_untracked();
        let req = CreateSimplePortForwardRequest {
            tcp: tcp.get_untracked(),
            udp: udp.get_untracked(),
            ipv4: (!addresses.0.trim().is_empty()).then_some(addresses.0),
            ipv6: (!addresses.1.trim().is_empty()).then_some(addresses.1),
            port: external,
            destination_port: internal,
            description: (!description.get_untracked().trim().is_empty())
                .then(|| description.get_untracked().trim().to_owned()),
        };
        leptos::task::spawn_local(async move {
            let outcome = match edit_id.get_untracked() {
                Some(id) => api::update_simple_forward(&token, id, req).await,
                None => api::create_simple_forward(&token, req).await,
            };
            match outcome {
                Ok(()) => {
                    editing.set(false);
                    edit_id.set(None);
                    toasts.success(
                        "Forward saved. Use Apply all in the pending changes bar to activate it.",
                    );
                    config_changed.run(());
                    reload_trigger.update(|v| *v += 1);
                }
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    }
                    error.set(e);
                }
            }
            saving.set(false);
        });
    };

    view! {
        <div class="space-y-4">
            <div class="flex flex-wrap justify-between items-center gap-3">
                <div>
                    <h2 class="text-lg font-medium text-gray-200">"Port Forwards"</h2>
                    <p class="text-gray-400 text-sm">"WAN access to LAN devices — IPv4 DNAT + firewall allow, or native IPv6 routing."</p>
                </div>
                <div class="flex flex-wrap items-center gap-2">
                <FilterBox query=filter placeholder="Search name, ports, addresses, zone" />
                <button class="px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm"
                    on:click=move |_| {
                        error.set(String::new());
                        if editing.get_untracked() { editing.set(false); edit_id.set(None); }
                        else {
                            edit_id.set(None); manual.set(false); selected.set(String::new());
                            ipv4.set(String::new()); ipv6.set(String::new());
                            tcp.set(true); udp.set(false); port.set(String::new());
                            destination_port.set(String::new()); description.set(String::new());
                            editing.set(true);
                        }
                    }>
                    {move || if editing.get() { "Cancel" } else { "+ Add Port Forward" }}
                </button>
                </div>
            </div>
            {move || (!error.get().is_empty()).then(|| view! {
                <div class="bg-red-900/50 border border-red-700 text-red-200 px-4 py-2 rounded text-sm">{error.get()}</div>
            })}

            {move || editing.get().then(|| view! {
                <div class="bg-gray-700 p-4 rounded-lg space-y-4">
                    <h3 class="font-medium text-gray-100">{move || if edit_id.get().is_some() { "Edit Port Forward" } else { "New Port Forward" }}</h3>
                    <div class="flex gap-5">
                        <label class="flex gap-2 items-center text-gray-200">
                            <input type="checkbox" prop:checked=move || tcp.get() on:change=move |ev| tcp.set(event_target_checked(&ev)) />"TCP"
                        </label>
                        <label class="flex gap-2 items-center text-gray-200">
                            <input type="checkbox" prop:checked=move || udp.get() on:change=move |ev| udp.set(event_target_checked(&ev)) />"UDP"
                        </label>
                    </div>
                    <div class="flex items-center justify-between">
                        <label class="block text-sm text-gray-300">"Destination"</label>
                        <label class="flex gap-2 items-center text-sm text-gray-300">
                            <input type="checkbox" prop:checked=move || manual.get() on:change=move |ev| manual.set(event_target_checked(&ev)) />
                            "Advanced: enter addresses manually"
                        </label>
                    </div>
                    {move || if manual.get() {
                        view! {
                            <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                                <div>
                                    <label class="block text-sm text-gray-400 mb-1">"IPv4 (optional)"</label>
                                    <input type="text" placeholder="192.168.1.100" class="w-full px-3 py-2 bg-gray-600 text-gray-100 rounded border border-gray-500"
                                        prop:value=move || ipv4.get() on:input=move |ev| ipv4.set(event_target_value(&ev)) />
                                </div>
                                <div>
                                    <label class="block text-sm text-gray-400 mb-1">"IPv6 (optional)"</label>
                                    <input type="text" placeholder="2001:db8::100" class="w-full px-3 py-2 bg-gray-600 text-gray-100 rounded border border-gray-500"
                                        prop:value=move || ipv6.get() on:input=move |ev| ipv6.set(event_target_value(&ev)) />
                                </div>
                            </div>
                        }.into_any()
                    } else {
                        view! {
                            <div>
                                <select class="w-full px-3 py-2 bg-gray-600 text-gray-100 rounded border border-gray-500"
                                    prop:value=move || selected.get() on:change=move |ev| selected.set(event_target_value(&ev))>
                                    <option value="">"Select a discovered LAN device"</option>
                                    {move || devices.get().map(|res| match res {
                                        Ok(items) => view! {
                                            <For each=move || items.clone() key=|d| d.mac.clone() children=move |d: LanDevice| {
                                                let label = format!("{} ({})  IPv4: {}  IPv6: {}",
                                                    d.hostname.as_deref().unwrap_or("Unknown"),
                                                    d.mac, if d.ipv4.is_empty() { "—".into() } else { d.ipv4.join(", ") },
                                                    if d.ipv6.is_empty() { "—".into() } else { d.ipv6.join(", ") });
                                                view! { <option value=d.mac.clone()>{label}</option> }
                                            } />
                                        }.into_any(),
                                        Err(e) => view! { <option disabled=true>{format!("Neighbour scan failed: {e}")}</option> }.into_any(),
                                    })}
                                </select>
                                <p class="text-xs text-gray-400 mt-1">
                                    "Devices found via LAN neighbours and DHCP leases. Only known IPv6 global/ULA addresses are offered; a device may have more than one address."
                                </p>
                                <button class="text-xs px-2 py-1 mt-2 bg-gray-600 hover:bg-gray-500 text-gray-200 rounded border border-gray-500"
                                    on:click=move |_| reload_trigger.update(|v| *v += 1)>
                                    "↻ Refresh devices"
                                </button>
                            </div>
                        }.into_any()
                    }}
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div>
                            <label class="block text-sm text-gray-400 mb-1">"Port"</label>
                            <input type="number" min="1" max="65535" placeholder="443"
                                class="w-full px-3 py-2 bg-gray-600 text-gray-100 rounded border border-gray-500"
                                prop:value=move || port.get() on:input=move |ev| port.set(event_target_value(&ev)) />
                        </div>
                        <div>
                            <label class="block text-sm text-gray-400 mb-1">"Destination Port (optional; IPv4 remapping only)"</label>
                            <input type="number" min="1" max="65535" placeholder="Same as port"
                                class="w-full px-3 py-2 bg-gray-600 text-gray-100 rounded border border-gray-500"
                                prop:value=move || destination_port.get() on:input=move |ev| destination_port.set(event_target_value(&ev)) />
                        </div>
                    </div>
                    <div>
                        <label class="block text-sm text-gray-400 mb-1">"Comment (optional)"</label>
                        <input type="text" placeholder="e.g. Game server, Nextcloud, remote access"
                            class="w-full px-3 py-2 bg-gray-600 text-gray-100 rounded border border-gray-500"
                            prop:value=move || description.get() on:input=move |ev| description.set(event_target_value(&ev)) />
                    </div>
                    <button on:click=save disabled=move || saving.get()
                        class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded disabled:opacity-50">
                        {move || if saving.get() { "Saving..." } else { "Save" }}
                    </button>
                </div>
            })}

            <Suspense fallback=|| view! { <p class="text-gray-400">"Loading forwards..."</p> }>
                {move || forwards.get().map(|res| match res {
                    Ok(items) => {
                        let empty = items.is_empty();
                        view! {
                            <div class="overflow-x-auto">
                                <table class="w-full text-sm">
                                    <thead class="text-gray-400 border-b border-gray-600">
                                        <tr>
                                            <th class="text-left px-2 py-2">"Forward / Comment"</th>
                                            <th class="text-left px-2 py-2">"Families"</th>
                                            <th class="text-left px-2 py-2">"Protocol"</th>
                                            <th class="text-left px-2 py-2">"WAN port"</th>
                                            <th class="text-left px-2 py-2">"Source"</th>
                                            <th class="text-left px-2 py-2">"Destination(s)"</th>
                                            <th class="text-left px-2 py-2">"Enabled"</th>
                                            <th class="text-left px-2 py-2">"Hits"</th>
                                            <th class="text-right px-2 py-2">"Action"</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <For each=move || filter_simple(&items, &filter.get()) key=|f| f.rule_id children=move |f| {
                                            let id = f.rule_id;
                                            let to_edit = f.clone();
                                            let forward_ids: Vec<i64> = [f.ipv4_rule_id, f.ipv6_rule_id].into_iter().flatten().collect();
                                            view! {
                                                <tr class="border-b border-gray-700 text-gray-200">
                                                    <td class="px-2 py-2">
                                                        <div>{format!("{} {}:{}", f.source_zone.as_deref().unwrap_or("WAN"), f.protocol, f.external_port)}</div>
                                                        {f.description.clone().map(|s| view! { <div class="text-xs text-gray-400 mt-1">{s}</div> })}
                                                    </td>
                                                    <td class="px-2 py-2">{match (f.ipv4.is_some(), f.ipv6.is_some()) {
                                                        (true, true) => "IPv4 + IPv6 (paired)",
                                                        (true, false) => "IPv4",
                                                        (false, true) => "IPv6",
                                                        _ => "—",
                                                    }}</td>
                                                    <td class="px-2 py-2">{f.protocol.to_string()}</td>
                                                    <td class="px-2 py-2">{f.external_port}</td>
                                                    <td class="px-2 py-2">{f.source_ip.unwrap_or_else(|| "Any".into())}</td>
                                                    <td class="px-2 py-2">
                                                        {f.ipv4.clone().map(|ip| view! { <div>{format!("IPv4: {ip}:{}", f.destination_port)}</div> })}
                                                        {f.ipv6.clone().map(|ip| view! { <div>{format!("IPv6: [{ip}]:{}", f.destination_port)}</div> })}
                                                    </td>
                                                    <td class="px-2 py-2">{if f.enabled { "Yes" } else { "No" }}</td>
                                                    <td class="px-2 py-2 whitespace-nowrap"><RuleHits counters=counters kinds=SIMPLE_HIT_KINDS rule_ids=forward_ids /></td>
                                                    <td class="px-2 py-2 text-right whitespace-nowrap">
                                                        <button class="text-blue-300 hover:text-blue-200 mr-3" on:click=move |_| {
                                                            edit_id.set(Some(id));
                                                            tcp.set(matches!(to_edit.protocol, RuleProtocol::Tcp | RuleProtocol::TcpUdp));
                                                            udp.set(matches!(to_edit.protocol, RuleProtocol::Udp | RuleProtocol::TcpUdp));
                                                            ipv4.set(to_edit.ipv4.clone().unwrap_or_default());
                                                            ipv6.set(to_edit.ipv6.clone().unwrap_or_default());
                                                            port.set(to_edit.external_port.to_string());
                                                            destination_port.set(if to_edit.destination_port == to_edit.external_port { String::new() } else { to_edit.destination_port.to_string() });
                                                            description.set(to_edit.description.clone().unwrap_or_default());
                                                            // Show both addresses explicitly even when the discovery list has changed.
                                                            manual.set(true);
                                                            selected.set(String::new());
                                                            error.set(String::new());
                                                            editing.set(true);
                                                        }>"Edit"</button>
                                                        <button class="text-red-400 hover:text-red-300" on:click=move |_| {
                                                            error.set(String::new());
                                                            let token = token.get_untracked();
                                                            leptos::task::spawn_local(async move {
                                                                match api::delete_simple_forward(&token, id).await {
                                                                    Ok(resp) if resp.success => {
                                                                        toasts.success("Forward removed. Use Apply all in the pending changes bar to activate it.");
                                                                        config_changed.run(());
                                                                        reload_trigger.update(|v| *v += 1);
                                                                    }
                                                                    Ok(resp) => error.set(resp.message),
                                                                    Err(e) => {
                                                                        if e.contains("Unauthorized") { on_unauthorized.run(()); }
                                                                        error.set(e);
                                                                    }
                                                                }
                                                            });
                                                        }>"Delete"</button>
                                                    </td>
                                                </tr>
                                            }
                                        } />
                                    </tbody>
                                </table>
                                {empty.then(|| view! { <p class="text-gray-400 text-center py-4">"No WAN-to-host forwards configured."</p> })}
                            </div>
                        }.into_any()
                    }
                    Err(e) => {
                        if e.contains("Unauthorized") { on_unauthorized.run(()); }
                        view! { <p class="text-red-400">{format!("Failed to load forwards: {e}")}</p> }.into_any()
                    }
                })}
            </Suspense>
            <Suspense fallback=|| view! { <p class="text-gray-400">"Loading other port forwards..."</p> }>
                {move || other_forwards.get().and_then(|res| res.ok()).filter(|items| !items.is_empty()).map(|items| view! {
                    <div class="space-y-2 pt-4">
                        <h3 class="text-base font-medium text-gray-200">"Other port forwards (created via CLI/API)"</h3>
                        <p class="text-gray-400 text-sm">"These DNAT rules are not part of a simple forward above. They are live once applied."</p>
                        <div class="overflow-x-auto">
                            <table class="w-full text-sm">
                                <thead class="text-gray-400 border-b border-gray-600">
                                    <tr>
                                        <th class="text-left px-2 py-2">"Name"</th>
                                        <th class="text-left px-2 py-2">"Protocol"</th>
                                        <th class="text-left px-2 py-2">"External port(s)"</th>
                                        <th class="text-left px-2 py-2">"Destination"</th>
                                        <th class="text-left px-2 py-2">"Source zone"</th>
                                        <th class="text-left px-2 py-2">"Enabled"</th>
                                        <th class="text-left px-2 py-2">"Hits"</th>
                                        <th class="text-right px-2 py-2">"Action"</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <For each=move || filter_raw(&items, &filter.get()) key=|pf| pf.id children=move |pf| {
                                        let id = pf.id;
                                        let hit_ids: Vec<i64> = id.into_iter().collect();
                                        let source = raw_source(&pf);
                                        let ports = match pf.external_port_end {
                                            Some(end) if end > pf.external_port_start => format!("{}-{}", pf.external_port_start, end),
                                            _ => pf.external_port_start.to_string(),
                                        };
                                        let mut destination = match (pf.dest_ip.is_empty(), pf.dest_port) {
                                            (true, _) => String::new(),
                                            (false, Some(port)) => format!("{}:{}", pf.dest_ip, port),
                                            (false, None) => pf.dest_ip.clone(),
                                        };
                                        if let Some(suffix) = &pf.dest_ipv6_suffix {
                                            if !destination.is_empty() {
                                                destination.push_str(", ");
                                            }
                                            destination.push_str(&format!("*{suffix}"));
                                        }
                                        view! {
                                            <tr class="border-b border-gray-700 text-gray-200">
                                                <td class="px-2 py-2">{pf.name.clone()}</td>
                                                <td class="px-2 py-2">{pf.protocol.to_string()}</td>
                                                <td class="px-2 py-2">{ports}</td>
                                                <td class="px-2 py-2">{destination}</td>
                                                <td class="px-2 py-2">{source}</td>
                                                <td class="px-2 py-2">{if pf.enabled { "Yes" } else { "No" }}</td>
                                                <td class="px-2 py-2 whitespace-nowrap"><RuleHits counters=counters kinds=RAW_HIT_KINDS rule_ids=hit_ids /></td>
                                                <td class="px-2 py-2 text-right">
                                                    <button class="text-red-400 hover:text-red-300" on:click=move |_| {
                                                        let Some(id) = id else { return };
                                                        error.set(String::new());
                                                        let token = token.get_untracked();
                                                        leptos::task::spawn_local(async move {
                                                            match api::delete_port_forward(&token, id).await {
                                                                Ok(resp) if resp.success => {
                                                                    toasts.success("Port forward removed. Use Apply all in the pending changes bar to activate it.");
                                                                    config_changed.run(());
                                                                    reload_trigger.update(|v| *v += 1);
                                                                }
                                                                Ok(resp) => error.set(resp.message),
                                                                Err(e) => {
                                                                    if e.contains("Unauthorized") { on_unauthorized.run(()); }
                                                                    error.set(e);
                                                                }
                                                            }
                                                        });
                                                    }>"Delete"</button>
                                                </td>
                                            </tr>
                                        }
                                    } />
                                </tbody>
                            </table>
                        </div>
                    </div>
                })}
            </Suspense>
        </div>
    }
}
