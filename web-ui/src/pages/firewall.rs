//! Firewall configuration page
//!
//! Zone-based firewall section routes:
//! - Zones (define interface groups with default policies)
//! - Groups (named address and port sets used by rules)
//! - Zone Forwards (zone-to-zone forwarding policies)
//! - Port Forwards (DNAT rules)
//! - Input Rules (traffic to the router)
//! - Forward Rules (traffic through the router)
//! - Preview (see generated nftables rules)

use super::firewall_connections::ConnectionsTab;
use super::firewall_groups::GroupsTab;
use super::firewall_live_log::LiveLogTab;
use super::firewall_packet_tester::PacketTesterTab;
use super::firewall_rules::{ForwardRulesTab, InputRulesTab};
use super::simple_forwards::SimpleForwardsTab;
use crate::api;
use crate::components::rule_table::{FilterBox, matches_filter};
use crate::components::use_config_changed;
use keystone_core::{
    FirewallAction, FirewallGlobalSettings, FirewallPolicy, FirewallZone, ZoneForwardPolicy,
};
use leptos::prelude::*;
use leptos_router::hooks::use_location;

/// Active firewall section selected by URL
#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum FirewallTab {
    #[default]
    Zones,
    Groups,
    ZoneForwards,
    PortForwards,
    InputRules,
    ForwardRules,
    Settings,
    Preview,
    PacketTester,
    LiveLog,
    Connections,
}

impl FirewallTab {
    fn from_path(path: &str) -> Self {
        match path.rsplit('/').next().unwrap_or_default() {
            "groups" => Self::Groups,
            "zone-forwards" => Self::ZoneForwards,
            "port-forwards" => Self::PortForwards,
            "input-rules" => Self::InputRules,
            "forward-rules" => Self::ForwardRules,
            "settings" => Self::Settings,
            "preview" => Self::Preview,
            "packet-tester" => Self::PacketTester,
            "live-log" => Self::LiveLog,
            "connections" => Self::Connections,
            _ => Self::Zones,
        }
    }
}

#[cfg(test)]
mod route_tests {
    use super::*;

    #[test]
    fn selects_each_section_from_its_url() {
        assert!(matches!(
            FirewallTab::from_path("/firewall/zones"),
            FirewallTab::Zones
        ));
        assert!(matches!(
            FirewallTab::from_path("/firewall/groups"),
            FirewallTab::Groups
        ));
        assert!(matches!(
            FirewallTab::from_path("/firewall/zone-forwards"),
            FirewallTab::ZoneForwards
        ));
        assert!(matches!(
            FirewallTab::from_path("/firewall/port-forwards"),
            FirewallTab::PortForwards
        ));
        assert!(matches!(
            FirewallTab::from_path("/firewall/input-rules"),
            FirewallTab::InputRules
        ));
        assert!(matches!(
            FirewallTab::from_path("/firewall/forward-rules"),
            FirewallTab::ForwardRules
        ));
        assert!(matches!(
            FirewallTab::from_path("/firewall/settings"),
            FirewallTab::Settings
        ));
        assert!(matches!(
            FirewallTab::from_path("/firewall/preview"),
            FirewallTab::Preview
        ));
        assert!(matches!(
            FirewallTab::from_path("/firewall/packet-tester"),
            FirewallTab::PacketTester
        ));
        assert!(matches!(
            FirewallTab::from_path("/firewall/live-log"),
            FirewallTab::LiveLog
        ));
        assert!(matches!(
            FirewallTab::from_path("/firewall/connections"),
            FirewallTab::Connections
        ));
        assert!(matches!(
            FirewallTab::from_path("/firewall"),
            FirewallTab::Zones
        ));
    }
}

#[component]
pub fn FirewallPage(
    auth_token: ReadSignal<Option<String>>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    // Get the token as a derived signal that returns empty string if not set
    let token = Signal::derive(move || auth_token.get().unwrap_or_default());

    let location = use_location();

    // Trigger for reloading data
    let reload_trigger = RwSignal::new(0);

    // Every save or delete in the tabs bumps the reload trigger. Pages report
    // those changes to the pending-changes bar through this one effect.
    let config_changed = use_config_changed();
    Effect::new(move |previous: Option<i32>| {
        let current = reload_trigger.get();
        if previous.is_some() {
            config_changed.run(());
        }
        current
    });

    view! {
        <div class="space-y-6">
            <div>
                <h1 class="text-2xl font-semibold text-blue-300">"Firewall"</h1>
                <p class="text-gray-400">"Zone-based firewall configuration"</p>
            </div>

            // Tab content
            <div class="bg-gray-800 rounded-lg shadow-lg p-6">
                {move || match FirewallTab::from_path(&location.pathname.get()) {
                    FirewallTab::Zones => view! { <ZonesTab token=token reload_trigger=reload_trigger on_unauthorized=on_unauthorized /> }.into_any(),
                    FirewallTab::Groups => view! { <GroupsTab token=token reload_trigger=reload_trigger on_unauthorized=on_unauthorized /> }.into_any(),
                    FirewallTab::ZoneForwards => view! { <ZoneForwardsTab token=token reload_trigger=reload_trigger on_unauthorized=on_unauthorized /> }.into_any(),
                    FirewallTab::PortForwards => view! { <SimpleForwardsTab token=token reload_trigger=reload_trigger on_unauthorized=on_unauthorized /> }.into_any(),
                    FirewallTab::InputRules => view! { <InputRulesTab token=token reload_trigger=reload_trigger on_unauthorized=on_unauthorized /> }.into_any(),
                    FirewallTab::ForwardRules => view! { <ForwardRulesTab token=token reload_trigger=reload_trigger on_unauthorized=on_unauthorized /> }.into_any(),
                    FirewallTab::Settings => view! { <SettingsTab token=token on_unauthorized=on_unauthorized /> }.into_any(),
                    FirewallTab::Preview => view! { <PreviewTab token=token reload_trigger=reload_trigger on_unauthorized=on_unauthorized /> }.into_any(),
                    FirewallTab::PacketTester => view! { <PacketTesterTab token=token on_unauthorized=on_unauthorized /> }.into_any(),
                    FirewallTab::LiveLog => view! { <LiveLogTab token=token on_unauthorized=on_unauthorized /> }.into_any(),
                    FirewallTab::Connections => view! { <ConnectionsTab token=token on_unauthorized=on_unauthorized /> }.into_any(),
                }}
            </div>
        </div>
    }
}

// ============================================================================
// Zones Tab
// ============================================================================

/// The zones that match a search: name, description or an interface.
fn filter_zones(zones: &[FirewallZone], query: &str) -> Vec<FirewallZone> {
    zones
        .iter()
        .filter(|zone| {
            let mut fields = vec![
                zone.name.clone(),
                zone.description.clone().unwrap_or_default(),
            ];
            fields.extend(zone.interfaces.iter().cloned());
            matches_filter(query, &fields)
        })
        .cloned()
        .collect()
}

#[component]
fn ZonesTab(
    token: Signal<String>,
    reload_trigger: RwSignal<i32>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let zones = LocalResource::new(move || {
        let token = token.get();
        let _ = reload_trigger.get();
        async move { api::fetch_firewall_zones(&token).await }
    });

    let editing_zone = RwSignal::new(Option::<FirewallZone>::None);
    let error_message = RwSignal::new(String::new());
    let filter = RwSignal::new(String::new());

    view! {
        <div class="space-y-4">
            <div class="flex flex-wrap justify-between items-center gap-3">
                <h2 class="text-lg font-medium text-gray-200">"Firewall Zones"</h2>
                <div class="flex flex-wrap items-center gap-2">
                <FilterBox query=filter placeholder="Search zone, description, interface" />
                <button
                    class="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm"
                    on:click=move |_| {
                        editing_zone.set(Some(FirewallZone {
                            id: None,
                            name: String::new(),
                            description: None,
                            interfaces: Vec::new(),
                            is_wan: false,
                            masquerade_ipv4: false,
                            default_input_policy: FirewallPolicy::Drop,
                            default_forward_policy: FirewallPolicy::Drop,
                        }));
                    }
                >
                    "+ Add Zone"
                </button>
                </div>
            </div>

            // Error message
            {move || {
                let msg = error_message.get();
                if msg.is_empty() {
                    view! { <div></div> }.into_any()
                } else {
                    view! {
                        <div class="bg-red-900/50 border border-red-700 text-red-200 px-4 py-2 rounded text-sm">
                            {msg}
                        </div>
                    }.into_any()
                }
            }}

            // Zone editor modal
            {move || {
                if let Some(zone) = editing_zone.get() {
                    view! {
                        <ZoneEditor
                            zone=zone
                            token=token.get()
                            on_save=move |_| {
                                editing_zone.set(None);
                                reload_trigger.update(|v| *v += 1);
                            }
                            on_cancel=move || editing_zone.set(None)
                            error_message=error_message
                            on_unauthorized=on_unauthorized
                        />
                    }.into_any()
                } else {
                    view! { <div></div> }.into_any()
                }
            }}

            // Zones list
            <Suspense fallback=move || view! { <p class="text-gray-400">"Loading zones..."</p> }>
                {move || {
                    zones.get().map(|result| match result {
                        Ok(zone_list) => view! {
                            <div class="space-y-2">
                                <For
                                    each=move || filter_zones(&zone_list, &filter.get())
                                    key=|z| (z.id, z.name.clone())
                                    children=move |zone| {
                                        let zone_for_edit = zone.clone();
                                        let zone_for_delete = zone.clone();
                                        let token_for_delete = token.get();
                                        view! {
                                            <div class="flex items-center justify-between p-3 bg-gray-700/50 rounded">
                                                <div>
                                                    <span class="font-medium text-gray-200">{zone.name.clone()}</span>
                                                    {zone.description.clone().map(|d| view! {
                                                        <span class="text-gray-400 ml-2">" - "{d}</span>
                                                    })}
                                                    <div class="text-sm text-gray-400 mt-1">
                                                        "Interfaces: "
                                                        {if zone.interfaces.is_empty() {
                                                            "(none)".to_string()
                                                        } else {
                                                            zone.interfaces.join(", ")
                                                        }}
                                                        {if zone.is_wan { " | WAN" } else { "" }}
                                                        {if zone.masquerade_ipv4 { " | IPv4 NAT" } else { "" }}
                                                        " | Input: "
                                                        <span class=if zone.default_input_policy == FirewallPolicy::Accept { "text-green-400" } else { "text-red-400" }>
                                                            {format!("{:?}", zone.default_input_policy)}
                                                        </span>
                                                    </div>
                                                </div>
                                                <div class="flex gap-2">
                                                    <button
                                                        class="px-2 py-1 text-sm text-blue-400 hover:text-blue-300"
                                                        on:click=move |_| editing_zone.set(Some(zone_for_edit.clone()))
                                                    >
                                                        "Edit"
                                                    </button>
                                                    <button
                                                        class="px-2 py-1 text-sm text-red-400 hover:text-red-300"
                                                         on:click=move |_| {
                                                            if let Some(id) = zone_for_delete.id {
                                                                let token = token_for_delete.clone();
                                                                leptos::task::spawn_local(async move {
                                                                    match api::delete_firewall_zone(&token, id).await {
                                                                        Ok(_) => reload_trigger.update(|v| *v += 1),
                                                                        Err(e) => {
                                                                            if e.contains("Unauthorized") {
                                                                                on_unauthorized.run(());
                                                                            } else {
                                                                                error_message.set(e);
                                                                            }
                                                                        }
                                                                    }
                                                                });
                                                            }
                                                        }
                                                    >
                                                        "Delete"
                                                    </button>
                                                </div>
                                            </div>
                                        }
                                    }
                                />
                            </div>
                        }.into_any(),
                        Err(e) => {
                            if e.contains("Unauthorized") {
                                on_unauthorized.run(());
                            }
                            view! { <p class="text-red-400">"Error: "{e}</p> }.into_any()
                        }
                    })
                }}
            </Suspense>
        </div>
    }
}

#[component]
fn ZoneEditor(
    zone: FirewallZone,
    token: String,
    on_save: impl Fn(()) + 'static,
    on_cancel: impl Fn() + 'static,
    error_message: RwSignal<String>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let name = RwSignal::new(zone.name.clone());
    let description = RwSignal::new(zone.description.clone().unwrap_or_default());
    let selected_interfaces = RwSignal::new(zone.interfaces.clone());
    let is_wan = RwSignal::new(zone.is_wan);
    let masquerade_ipv4 = RwSignal::new(zone.masquerade_ipv4);
    let input_policy = RwSignal::new(zone.default_input_policy);
    // Not user-editable: forwarding is controlled by zone-to-zone policies.
    let forward_policy = zone.default_forward_policy;
    let saving = RwSignal::new(false);
    let zone_id = zone.id;

    // Fetch available interfaces
    let token_for_fetch = token.clone();
    let available_interfaces = LocalResource::new(move || {
        let token = token_for_fetch.clone();
        async move {
            api::fetch_managed_interfaces(&token)
                .await
                .map(|interfaces| interfaces.into_iter().map(|i| i.name).collect::<Vec<_>>())
        }
    });

    let on_save = std::rc::Rc::new(on_save);
    let on_save_clone = on_save.clone();

    let save_zone = move |_| {
        saving.set(true);
        error_message.set(String::new());

        let token = token.clone();
        let on_save = on_save_clone.clone();

        let new_zone = FirewallZone {
            id: zone_id,
            name: name.get(),
            description: if description.get().is_empty() {
                None
            } else {
                Some(description.get())
            },
            interfaces: selected_interfaces.get(),
            is_wan: is_wan.get(),
            masquerade_ipv4: masquerade_ipv4.get(),
            default_input_policy: input_policy.get(),
            default_forward_policy: forward_policy,
        };

        leptos::task::spawn_local(async move {
            match api::save_firewall_zone(&token, new_zone).await {
                Ok(_) => {
                    on_save(());
                }
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        error_message.set(e);
                    }
                }
            }
            saving.set(false);
        });
    };

    view! {
        <div class="bg-gray-700 p-4 rounded-lg space-y-4">
            <h3 class="text-lg font-medium text-gray-200">
                {if zone_id.is_some() { "Edit Zone" } else { "New Zone" }}
            </h3>

            <div class="grid grid-cols-2 gap-4">
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Name"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500 focus:border-blue-500 focus:outline-none"
                        prop:value=move || name.get()
                        on:input=move |ev| name.set(event_target_value(&ev))
                        placeholder="e.g., wan, lan, dmz"
                    />
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Description"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500 focus:border-blue-500 focus:outline-none"
                        prop:value=move || description.get()
                        on:input=move |ev| description.set(event_target_value(&ev))
                        placeholder="Optional description"
                    />
                </div>
            </div>

            // Interface selector
            <Suspense fallback=move || view! {
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Interfaces"</label>
                    <p class="text-gray-500 text-sm">"Loading interfaces..."</p>
                </div>
            }>
                {move || {
                    available_interfaces.get().map(|result| match result {
                        Ok(interfaces) => {
                            let interfaces_signal = Signal::derive(move || interfaces.clone());
                            view! {
                                <crate::components::form_utils::MultiSearchSelector
                                    available_items=interfaces_signal
                                    selected_items=selected_interfaces
                                    placeholder="Search and select interfaces..."
                                    label="Interfaces"
                                />
                            }.into_any()
                        },
                        Err(e) => {
                            view! {
                                <div>
                                    <label class="block text-sm text-gray-400 mb-1">"Interfaces"</label>
                                    <p class="text-red-400 text-sm">"Error loading interfaces: "{e}</p>
                                </div>
                            }.into_any()
                        }
                    })
                }}
            </Suspense>

            <div class="grid grid-cols-2 gap-4">
                <label class="flex items-center gap-2 cursor-pointer p-3 bg-gray-600/50 rounded">
                    <input
                        type="checkbox"
                        checked=move || is_wan.get()
                        on:change=move |ev| is_wan.set(event_target_checked(&ev))
                        class="w-4 h-4 rounded"
                    />
                    <span class="text-gray-200">"Internet-facing zone"</span>
                </label>
                <label class="flex items-center gap-2 cursor-pointer p-3 bg-gray-600/50 rounded">
                    <input
                        type="checkbox"
                        checked=move || masquerade_ipv4.get()
                        on:change=move |ev| masquerade_ipv4.set(event_target_checked(&ev))
                        class="w-4 h-4 rounded"
                    />
                    <span class="text-gray-200">"IPv4 masquerading"</span>
                </label>
            </div>

            <div class="grid grid-cols-2 gap-4">
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Default Input Policy"</label>
                    <select
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500 focus:border-blue-500 focus:outline-none"
                        on:change=move |ev| {
                            let value = event_target_value(&ev);
                            input_policy.set(if value == "accept" { FirewallPolicy::Accept } else { FirewallPolicy::Drop });
                        }
                    >
                        <option value="drop" selected=move || input_policy.get() == FirewallPolicy::Drop>"Drop"</option>
                        <option value="accept" selected=move || input_policy.get() == FirewallPolicy::Accept>"Accept"</option>
                    </select>
                </div>
                <p class="text-sm text-gray-400 self-end">
                    "To allow forwarding between zones, use the Zone Forwards tab."
                </p>
            </div>

            <div class="flex gap-2 pt-2">
                <button
                    class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded disabled:opacity-50"
                    on:click=save_zone
                    disabled=move || saving.get() || name.get().is_empty()
                >
                    {move || if saving.get() { "Saving..." } else { "Save" }}
                </button>
                <button
                    class="px-4 py-2 bg-gray-600 hover:bg-gray-500 text-white rounded"
                    on:click=move |_| on_cancel()
                >
                    "Cancel"
                </button>
            </div>
        </div>
    }
}

// ============================================================================
// Zone Forwards Tab (Zone-to-Zone Forwarding Policies)
// ============================================================================

#[component]
fn ZoneForwardsTab(
    token: Signal<String>,
    reload_trigger: RwSignal<i32>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let zone_forwards = LocalResource::new(move || {
        let token = token.get();
        let _ = reload_trigger.get();
        async move { api::fetch_zone_forwards(&token).await }
    });

    let editing = RwSignal::new(Option::<ZoneForwardPolicy>::None);
    let error_message = RwSignal::new(String::new());

    view! {
        <div class="space-y-4">
            <div class="flex justify-between items-center">
                <div>
                    <h2 class="text-lg font-medium text-gray-200">"Zone-to-Zone Forwarding Policies"</h2>
                    <p class="text-sm text-gray-400">"Define default forwarding behavior between zones"</p>
                </div>
                <button
                    class="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm"
                    on:click=move |_| {
                        editing.set(Some(ZoneForwardPolicy {
                            id: None,
                            source_zone: String::new(),
                            dest_zone: String::new(),
                            policy: FirewallAction::Drop,
                            enabled: true,
                        }));
                    }
                >
                    "+ Add Policy"
                </button>
            </div>

            {move || {
                let msg = error_message.get();
                if msg.is_empty() {
                    view! { <div></div> }.into_any()
                } else {
                    view! {
                        <div class="bg-red-900/50 border border-red-700 text-red-200 px-4 py-2 rounded text-sm">
                            {msg}
                        </div>
                    }.into_any()
                }
            }}

            // Editor
            {move || {
                if let Some(policy) = editing.get() {
                    view! {
                        <ZoneForwardEditor
                            policy=policy
                            token=token.get()
                            on_save=move |_| {
                                editing.set(None);
                                reload_trigger.update(|v| *v += 1);
                            }
                            on_cancel=move || editing.set(None)
                            error_message=error_message
                            on_unauthorized=on_unauthorized
                        />
                    }.into_any()
                } else {
                    view! { <div></div> }.into_any()
                }
            }}

            <Suspense fallback=move || view! { <p class="text-gray-400">"Loading..."</p> }>
                {move || {
                    zone_forwards.get().map(|result| match result {
                        Ok(policies) => {
                            let is_empty = policies.is_empty();
                            let policies_for_loop = policies.clone();
                            view! {
                                <div class="overflow-x-auto">
                                    <table class="w-full text-sm">
                                        <thead class="text-gray-400 border-b border-gray-600">
                                            <tr>
                                                <th class="text-left py-2 px-2">"Source Zone"</th>
                                                <th class="text-left py-2 px-2">"Dest Zone"</th>
                                                <th class="text-left py-2 px-2">"Policy"</th>
                                                <th class="text-left py-2 px-2">"Enabled"</th>
                                                <th class="text-right py-2 px-2">"Actions"</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <For
                                                each=move || policies_for_loop.clone()
                                                key=|p| (p.id, p.source_zone.clone(), p.dest_zone.clone())
                                                children=move |policy| {
                                                    let policy_for_edit = policy.clone();
                                                    let policy_for_delete = policy.clone();
                                                    let token_del = token.get();
                                                    view! {
                                                        <tr class="border-b border-gray-700 hover:bg-gray-700/30">
                                                            <td class="py-2 px-2 text-gray-200">{policy.source_zone.clone()}</td>
                                                            <td class="py-2 px-2 text-gray-200">{policy.dest_zone.clone()}</td>
                                                            <td class="py-2 px-2">
                                                                <span class=match policy.policy {
                                                                    FirewallAction::Accept => "text-green-400",
                                                                    FirewallAction::Drop => "text-red-400",
                                                                    FirewallAction::Reject => "text-yellow-400",
                                                                }>
                                                                    {format!("{:?}", policy.policy)}
                                                                </span>
                                                            </td>
                                                            <td class="py-2 px-2">
                                                                {if policy.enabled {
                                                                    view! { <span class="text-green-400">"Yes"</span> }.into_any()
                                                                } else {
                                                                    view! { <span class="text-gray-500">"No"</span> }.into_any()
                                                                }}
                                                            </td>
                                                            <td class="py-2 px-2 text-right whitespace-nowrap">
                                                                <button
                                                                    class="text-blue-400 hover:text-blue-300 mr-2"
                                                                    on:click=move |_| editing.set(Some(policy_for_edit.clone()))
                                                                >
                                                                    "Edit"
                                                                </button>
                                                                <button
                                                                    class="text-red-400 hover:text-red-300"
                                                                     on:click=move |_| {
                                                                        if let Some(id) = policy_for_delete.id {
                                                                            let token = token_del.clone();
                                                                            leptos::task::spawn_local(async move {
                                                                                match api::delete_zone_forward(&token, id).await {
                                                                                    Ok(_) => reload_trigger.update(|v| *v += 1),
                                                                                    Err(e) => {
                                                                                        if e.contains("Unauthorized") {
                                                                                            on_unauthorized.run(());
                                                                                        } else {
                                                                                            error_message.set(e);
                                                                                        }
                                                                                    }
                                                                                }
                                                                            });
                                                                        }
                                                                    }
                                                                >
                                                                    "Delete"
                                                                </button>
                                                            </td>
                                                        </tr>
                                                    }
                                                }
                                            />
                                        </tbody>
                                    </table>
                                    {if is_empty {
                                        view! { <p class="text-gray-500 text-center py-4">"No zone forwarding policies configured"</p> }.into_any()
                                    } else {
                                        view! { <div></div> }.into_any()
                                    }}
                                </div>
                            }.into_any()
                        },
                        Err(e) => {
                            if e.contains("Unauthorized") {
                                on_unauthorized.run(());
                            }
                            view! { <p class="text-red-400">"Error: "{e}</p> }.into_any()
                        }
                    })
                }}
            </Suspense>
        </div>
    }
}

#[component]
fn ZoneForwardEditor(
    policy: ZoneForwardPolicy,
    token: String,
    on_save: impl Fn(()) + 'static,
    on_cancel: impl Fn() + 'static,
    error_message: RwSignal<String>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let source_zone = RwSignal::new(policy.source_zone.clone());
    let dest_zone = RwSignal::new(policy.dest_zone.clone());
    let policy_action = RwSignal::new(policy.policy);
    let enabled = RwSignal::new(policy.enabled);
    let saving = RwSignal::new(false);
    let policy_id = policy.id;

    let on_save = std::rc::Rc::new(on_save);
    let on_save_clone = on_save.clone();

    let save = move |_| {
        saving.set(true);
        error_message.set(String::new());

        let token = token.clone();
        let on_save = on_save_clone.clone();

        let new_policy = ZoneForwardPolicy {
            id: policy_id,
            source_zone: source_zone.get(),
            dest_zone: dest_zone.get(),
            policy: policy_action.get(),
            enabled: enabled.get(),
        };

        leptos::task::spawn_local(async move {
            match api::save_zone_forward(&token, new_policy).await {
                Ok(_) => on_save(()),
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        error_message.set(e);
                    }
                }
            }
            saving.set(false);
        });
    };

    view! {
        <div class="bg-gray-700 p-4 rounded-lg space-y-4">
            <h3 class="text-lg font-medium text-gray-200">
                {if policy_id.is_some() { "Edit Zone Forward Policy" } else { "New Zone Forward Policy" }}
            </h3>

            <div class="grid grid-cols-3 gap-4">
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Source Zone"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || source_zone.get()
                        on:input=move |ev| source_zone.set(event_target_value(&ev))
                        placeholder="e.g., lan"
                    />
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Destination Zone"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || dest_zone.get()
                        on:input=move |ev| dest_zone.set(event_target_value(&ev))
                        placeholder="e.g., wan"
                    />
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Policy"</label>
                    <select
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        on:change=move |ev| {
                            let value = event_target_value(&ev);
                            policy_action.set(match value.as_str() {
                                "accept" => FirewallAction::Accept,
                                "reject" => FirewallAction::Reject,
                                _ => FirewallAction::Drop,
                            });
                        }
                    >
                        <option value="accept" selected=move || policy_action.get() == FirewallAction::Accept>"Accept"</option>
                        <option value="drop" selected=move || policy_action.get() == FirewallAction::Drop>"Drop"</option>
                        <option value="reject" selected=move || policy_action.get() == FirewallAction::Reject>"Reject"</option>
                    </select>
                </div>
            </div>

            <div class="flex items-center gap-2">
                <input
                    type="checkbox"
                    id="zf-enabled"
                    class="w-4 h-4"
                    prop:checked=move || enabled.get()
                    on:change=move |ev| enabled.set(event_target_checked(&ev))
                />
                <label for="zf-enabled" class="text-gray-300">"Enabled"</label>
            </div>

            <div class="flex gap-2 pt-2">
                <button
                    class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded disabled:opacity-50"
                    on:click=save
                    disabled=move || saving.get() || source_zone.get().is_empty() || dest_zone.get().is_empty()
                >
                    {move || if saving.get() { "Saving..." } else { "Save" }}
                </button>
                <button
                    class="px-4 py-2 bg-gray-600 hover:bg-gray-500 text-white rounded"
                    on:click=move |_| on_cancel()
                >
                    "Cancel"
                </button>
            </div>
        </div>
    }
}

// ============================================================================
// Settings Tab
// ============================================================================

#[component]
fn SettingsTab(token: Signal<String>, on_unauthorized: Callback<()>) -> impl IntoView {
    let config_changed = use_config_changed();
    let settings = LocalResource::new(move || {
        let token = token.get();
        async move { api::fetch_firewall_global_settings(&token).await }
    });

    // Local state for form
    let ping_wan_enabled = RwSignal::new(false);
    let ping_lan_enabled = RwSignal::new(true);
    let hairpin_nat_enabled = RwSignal::new(true);

    let status_message = RwSignal::new(String::new());
    let is_saving = RwSignal::new(false);
    let initialized = RwSignal::new(false);

    // Initialize form values when settings load
    Effect::new(move |_| {
        if let Some(Ok(s)) = settings.get()
            && !initialized.get()
        {
            ping_wan_enabled.set(s.ping_wan_enabled);
            ping_lan_enabled.set(s.ping_lan_enabled);
            hairpin_nat_enabled.set(s.hairpin_nat_enabled);
            initialized.set(true);
        }
    });

    let save_settings = move |_| {
        let token = token.get();
        let settings = FirewallGlobalSettings {
            ping_wan_enabled: ping_wan_enabled.get(),
            ping_lan_enabled: ping_lan_enabled.get(),
            hairpin_nat_enabled: hairpin_nat_enabled.get(),
        };

        is_saving.set(true);
        status_message.set(String::new());

        leptos::task::spawn_local(async move {
            match api::save_firewall_global_settings(&token, settings).await {
                Ok(response) => {
                    if response.success {
                        config_changed.run(());
                        status_message.set("Settings saved successfully".to_string());
                    } else {
                        status_message.set(format!("Error: {}", response.message));
                    }
                }
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        status_message.set(format!("Error: {}", e));
                    }
                }
            }
            is_saving.set(false);
        });
    };

    view! {
        <div class="space-y-6">
            <h2 class="text-lg font-medium text-gray-200">"Global Firewall Settings"</h2>

            <Suspense fallback=move || view! { <p class="text-gray-400">"Loading settings..."</p> }>
                {move || {
                    settings.get().map(|result| match result {
                        Ok(_) => view! {
                            <div class="space-y-6 max-w-xl">
                                // ICMP / Ping Settings
                                <div class="bg-gray-700/50 rounded-lg p-4 space-y-4">
                                    <h3 class="text-base font-medium text-gray-300">"ICMP Settings"</h3>
                                    <p class="text-sm text-gray-400">
                                        "Control whether the router responds to ping requests. "
                                        "Dangerous ICMP types (timestamp, redirect, address-mask) are always blocked."
                                    </p>

                                    <div class="space-y-3">
                                        <label class="flex items-center gap-3 cursor-pointer">
                                            <input
                                                type="checkbox"
                                                class="w-4 h-4 rounded bg-gray-600 border-gray-500 text-blue-500 focus:ring-blue-500"
                                                prop:checked=move || ping_lan_enabled.get()
                                                on:change=move |ev| ping_lan_enabled.set(event_target_checked(&ev))
                                            />
                                            <span class="text-gray-200">"Allow ping from LAN"</span>
                                        </label>

                                        <label class="flex items-center gap-3 cursor-pointer">
                                            <input
                                                type="checkbox"
                                                class="w-4 h-4 rounded bg-gray-600 border-gray-500 text-blue-500 focus:ring-blue-500"
                                                prop:checked=move || ping_wan_enabled.get()
                                                on:change=move |ev| ping_wan_enabled.set(event_target_checked(&ev))
                                            />
                                            <span class="text-gray-200">"Allow ping from WAN"</span>
                                            <span class="text-sm text-gray-500">"(less secure)"</span>
                                        </label>
                                    </div>
                                </div>

                                // Hairpin NAT Settings
                                <div class="bg-gray-700/50 rounded-lg p-4 space-y-4">
                                    <h3 class="text-base font-medium text-gray-300">"NAT Settings"</h3>
                                    <p class="text-sm text-gray-400">
                                        "Hairpin NAT (NAT reflection) allows LAN clients to access port-forwarded "
                                        "services using the router's external IP address."
                                    </p>

                                    <label class="flex items-center gap-3 cursor-pointer">
                                        <input
                                            type="checkbox"
                                            class="w-4 h-4 rounded bg-gray-600 border-gray-500 text-blue-500 focus:ring-blue-500"
                                            prop:checked=move || hairpin_nat_enabled.get()
                                            on:change=move |ev| hairpin_nat_enabled.set(event_target_checked(&ev))
                                        />
                                        <span class="text-gray-200">"Enable Hairpin NAT"</span>
                                    </label>
                                </div>

                                // Status message
                                {move || {
                                    let msg = status_message.get();
                                    if msg.is_empty() {
                                        view! { <div></div> }.into_any()
                                    } else if msg.starts_with("Error") {
                                        view! {
                                            <div class="bg-red-900/50 border border-red-700 text-red-200 px-4 py-2 rounded">
                                                {msg}
                                            </div>
                                        }.into_any()
                                    } else {
                                        view! {
                                            <div class="bg-green-900/50 border border-green-700 text-green-200 px-4 py-2 rounded">
                                                {msg}
                                            </div>
                                        }.into_any()
                                    }
                                }}

                                // Save button
                                <div class="pt-2">
                                    <button
                                        class="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-600/50 text-white rounded font-medium"
                                        on:click=save_settings
                                        disabled=move || is_saving.get()
                                    >
                                        {move || if is_saving.get() { "Saving..." } else { "Save Settings" }}
                                    </button>
                                    <p class="text-sm text-gray-500 mt-2">
                                        "Note: Changes take effect when you apply them with Apply all in the pending changes bar."
                                    </p>
                                </div>
                            </div>
                        }.into_any(),
                        Err(e) => {
                            if e.contains("Unauthorized") {
                                on_unauthorized.run(());
                            }
                            view! { <p class="text-red-400">"Error loading settings: "{e}</p> }.into_any()
                        }
                    })
                }}
            </Suspense>
        </div>
    }
}

// ============================================================================
// Preview Tab
// ============================================================================

#[component]
fn PreviewTab(
    token: Signal<String>,
    reload_trigger: RwSignal<i32>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let preview = LocalResource::new(move || {
        let token = token.get();
        let _ = reload_trigger.get();
        async move { api::fetch_firewall_preview(&token).await }
    });

    view! {
        <div class="space-y-4">
            <div class="flex justify-between items-center">
                <h2 class="text-lg font-medium text-gray-200">"Generated nftables Rules"</h2>
                <button
                    class="px-3 py-1.5 bg-gray-600 hover:bg-gray-500 text-white rounded text-sm"
                    on:click=move |_| reload_trigger.update(|v| *v += 1)
                >
                    "Refresh"
                </button>
            </div>

            <Suspense fallback=move || view! { <p class="text-gray-400">"Loading preview..."</p> }>
                {move || {
                    preview.get().map(|result| match result {
                        Ok(ruleset) => view! {
                            <pre class="bg-gray-900 p-4 rounded-lg text-sm text-gray-300 overflow-auto max-h-[600px] font-mono whitespace-pre-wrap">
                                {ruleset}
                            </pre>
                        }.into_any(),
                        Err(e) => {
                            if e.contains("Unauthorized") {
                                on_unauthorized.run(());
                            }
                            view! { <p class="text-red-400">"Error: "{e}</p> }.into_any()
                        }
                    })
                }}
            </Suspense>
        </div>
    }
}
