//! Input and forward rule tables and their editors.
//!
//! Both tables show live hit counters, a search box, and two ways to reorder
//! rules: drag a row by its handle, or use the move buttons. A reorder is shown
//! at once and put back if the daemon refuses it. Reordering is disabled while
//! a search filter is active, because the daemon orders the whole list.

use crate::api;
use crate::components::form_utils::{event_target_checked, event_target_value};
use crate::components::rule_table::{
    AddressField, AddressFieldInput, DragHandle, FilterBox, PortField, PortFieldInput,
    ReorderButtons, RuleHits, address_group_names, matches_filter, move_by, move_onto,
    port_group_names, use_rule_counters,
};
use keystone_core::{FirewallAction, ForwardRule, InputRule, LanDevice, RuleProtocol};
use leptos::prelude::*;
use leptos::task::spawn_local;
use web_sys::DragEvent;

/// Counter kinds that belong to an input rule and to a forward rule.
const INPUT_HIT_KINDS: &[&str] = &["input"];
const FORWARD_HIT_KINDS: &[&str] = &["forward"];

/// Human text for a rule's protocol, or `any`.
fn protocol_text(protocol: Option<&RuleProtocol>) -> String {
    protocol
        .map(|p| p.to_string())
        .unwrap_or_else(|| "any".to_string())
}

/// Human text for an address constraint: a literal, a group, or `any`.
fn address_text(literal: Option<&str>, group: Option<&str>) -> String {
    match (literal, group) {
        (Some(literal), _) => literal.to_string(),
        (None, Some(group)) => format!("group {group}"),
        (None, None) => "any".to_string(),
    }
}

/// Human text for a forward rule's destination. A suffix reads as `any prefix`
/// followed by the suffix, since it matches whatever prefix the ISP delegates.
fn forward_dest_text(rule: &ForwardRule) -> String {
    match rule.dest_ipv6_suffix.as_deref() {
        Some(suffix) => format!("*{suffix}"),
        None => address_text(rule.dest_ip.as_deref(), rule.dest_group.as_deref()),
    }
}

/// Human text for a port constraint: a group, a range, or `any`.
fn port_text(start: Option<u16>, end: Option<u16>, group: Option<&str>) -> String {
    if let Some(group) = group {
        return format!("group {group}");
    }
    match (start, end) {
        (Some(start), Some(end)) if end > start => format!("{start}-{end}"),
        (Some(start), _) => start.to_string(),
        (None, _) => "any".to_string(),
    }
}

/// Text a search matches against for an input rule.
fn input_rule_fields(rule: &InputRule) -> Vec<String> {
    vec![
        rule.name.clone(),
        rule.description.clone().unwrap_or_default(),
        rule.zone.clone().unwrap_or_default(),
        protocol_text(rule.protocol.as_ref()),
        port_text(
            rule.port_start,
            rule.port_end,
            rule.dest_port_group.as_deref(),
        ),
        address_text(rule.source_ip.as_deref(), rule.source_group.as_deref()),
        rule.action.to_string(),
    ]
}

/// Text a search matches against for a forward rule.
fn forward_rule_fields(rule: &ForwardRule) -> Vec<String> {
    vec![
        rule.name.clone(),
        rule.description.clone().unwrap_or_default(),
        rule.source_zone.clone().unwrap_or_default(),
        rule.dest_zone.clone().unwrap_or_default(),
        protocol_text(rule.protocol.as_ref()),
        port_text(
            rule.dest_port_start,
            rule.dest_port_end,
            rule.dest_port_group.as_deref(),
        ),
        address_text(rule.source_ip.as_deref(), rule.source_group.as_deref()),
        forward_dest_text(rule),
        rule.action.to_string(),
    ]
}

/// The rules in `ids` order, with positions renumbered to match.
fn reorder_by_ids<T: Clone>(
    list: &[T],
    ids: &[i64],
    id_of: impl Fn(&T) -> Option<i64>,
    set_position: impl Fn(&mut T, i32),
) -> Vec<T> {
    ids.iter()
        .filter_map(|id| list.iter().find(|item| id_of(item) == Some(*id)).cloned())
        .enumerate()
        .map(|(index, mut item)| {
            set_position(&mut item, index as i32);
            item
        })
        .collect()
}

fn action_class(action: FirewallAction) -> &'static str {
    match action {
        FirewallAction::Accept => "text-green-400",
        FirewallAction::Drop => "text-red-400",
        FirewallAction::Reject => "text-yellow-400",
    }
}

/// Shared state of a reorderable table: the optimistic order, the drag source,
/// and whether a save is in flight.
struct Reorder<T: Clone + Send + Sync + 'static> {
    order: RwSignal<Option<Vec<T>>>,
    busy: RwSignal<bool>,
    dragged: RwSignal<Option<i64>>,
}

// Manual impls: the signals are Copy whatever `T` is, so the derive would
// wrongly require `T: Copy`.
impl<T: Clone + Send + Sync + 'static> Clone for Reorder<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: Clone + Send + Sync + 'static> Copy for Reorder<T> {}

impl<T: Clone + Send + Sync + 'static> Reorder<T> {
    fn new() -> Self {
        Self {
            order: RwSignal::new(None),
            busy: RwSignal::new(false),
            dragged: RwSignal::new(None),
        }
    }
}

// ============================================================================
// Input Rules
// ============================================================================

#[component]
pub(super) fn InputRulesTab(
    token: Signal<String>,
    reload_trigger: RwSignal<i32>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let rules = LocalResource::new(move || {
        let token = token.get();
        let _ = reload_trigger.get();
        async move { api::fetch_input_rules(&token).await }
    });
    let counters = use_rule_counters(token, on_unauthorized);
    let address_groups = address_group_names(token, reload_trigger);
    let port_groups = port_group_names(token, reload_trigger);

    let editing = RwSignal::new(Option::<InputRule>::None);
    let error_message = RwSignal::new(String::new());
    let filter = RwSignal::new(String::new());
    let reorder = Reorder::<InputRule>::new();

    // The server's list is current again once it has been reloaded.
    Effect::new(move |_| {
        let _ = rules.get();
        reorder.order.set(None);
    });

    let locked = move || !filter.get().trim().is_empty() || reorder.busy.get();

    let current_list = move || -> Vec<InputRule> {
        reorder
            .order
            .get()
            .or_else(|| rules.get().and_then(|result| result.ok()))
            .unwrap_or_default()
    };

    let apply_order = move |list: Vec<InputRule>| {
        let ids: Vec<i64> = list.iter().filter_map(|rule| rule.id).collect();
        reorder.order.set(Some(list));
        reorder.busy.set(true);
        let token = token.get_untracked();
        spawn_local(async move {
            match api::reorder_input_rules(&token, ids).await {
                Ok(()) => {}
                Err(e) => {
                    reorder.order.set(None);
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        error_message.set(e);
                    }
                }
            }
            reorder.busy.set(false);
            reload_trigger.update(|v| *v += 1);
        });
    };

    let move_rule = move |id: i64, delta: isize| {
        let list = current_list();
        let ids: Vec<i64> = list.iter().filter_map(|rule| rule.id).collect();
        if let Some(new_ids) = move_by(&ids, id, delta) {
            apply_order(reorder_by_ids(
                &list,
                &new_ids,
                |r| r.id,
                |r, p| r.position = p,
            ));
        }
    };

    let drop_rule = move |from: i64, to: i64| {
        let list = current_list();
        let ids: Vec<i64> = list.iter().filter_map(|rule| rule.id).collect();
        if let Some(new_ids) = move_onto(&ids, from, to) {
            apply_order(reorder_by_ids(
                &list,
                &new_ids,
                |r| r.id,
                |r, p| r.position = p,
            ));
        }
    };

    let new_rule = move || InputRule {
        id: None,
        name: String::new(),
        description: None,
        enabled: true,
        position: 100,
        zone: None,
        protocol: Some(RuleProtocol::Tcp),
        port_start: None,
        port_end: None,
        source_ip: None,
        source_group: None,
        dest_port_group: None,
        action: FirewallAction::Accept,
        log_enabled: false,
        log_prefix: None,
        rate_limit: None,
    };

    let clone_rule = move |rule: &InputRule| -> InputRule {
        InputRule {
            id: None,
            name: format!("{} (copy)", rule.name),
            ..rule.clone()
        }
    };

    view! {
        <div class="space-y-4">
            <div class="flex flex-wrap justify-between items-center gap-3">
                <div>
                    <h2 class="text-lg font-medium text-gray-200">"Input Rules (Traffic to Router)"</h2>
                    <p class="text-sm text-gray-400">"Rules are evaluated in order; first match wins. Drag a row or use the arrows to reorder."</p>
                </div>
                <div class="flex flex-wrap items-center gap-2">
                    <FilterBox query=filter placeholder="Search name, zone, ports, addresses" />
                    <button
                        class="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm"
                        on:click=move |_| editing.set(Some(new_rule()))
                    >
                        "+ Add Rule"
                    </button>
                </div>
            </div>

            {move || {
                let msg = error_message.get();
                (!msg.is_empty()).then(|| view! {
                    <div class="bg-red-900/50 border border-red-700 text-red-200 px-4 py-2 rounded text-sm">{msg}</div>
                })
            }}

            {move || editing.get().map(|rule| view! {
                <InputRuleEditor
                    rule=rule
                    token=token.get()
                    on_save=move |_| {
                        editing.set(None);
                        reload_trigger.update(|v| *v += 1);
                    }
                    on_cancel=move || editing.set(None)
                    error_message=error_message
                    on_unauthorized=on_unauthorized
                    address_groups=address_groups
                    port_groups=port_groups
                />
            })}

            <Suspense fallback=move || view! { <p class="text-gray-400">"Loading..."</p> }>
                {move || {
                    rules.get().map(|result| match result {
                        Ok(_) => {
                            let list = current_list();
                            let query = filter.get();
                            let total = list.len();
                            let is_empty = total == 0;
                            let rows = list
                                .iter()
                                .enumerate()
                                .filter(|(_, rule)| matches_filter(&query, &input_rule_fields(rule)))
                                .map(|(index, rule)| {
                                    let id = rule.id;
                                    let rule_for_edit = rule.clone();
                                    let rule_for_clone = rule.clone();
                                    let rule_for_delete = rule.clone();
                                    let token_del = token.get_untracked();
                                    let source = address_text(rule.source_ip.as_deref(), rule.source_group.as_deref());
                                    let ports = port_text(rule.port_start, rule.port_end, rule.dest_port_group.as_deref());
                                    let action = rule.action;
                                    let can_up = index > 0;
                                    let can_down = index + 1 < total;
                                    let hit_ids: Vec<i64> = id.into_iter().collect();
                                    view! {
                                        <tr
                                            class="border-b border-gray-700 hover:bg-gray-700/30"
                                            draggable=move || if locked() { "false" } else { "true" }
                                            on:dragstart=move |ev: DragEvent| {
                                                if let Some(id) = id {
                                                    if let Some(transfer) = ev.data_transfer() {
                                                        let _ = transfer.set_data("text/plain", &id.to_string());
                                                        transfer.set_effect_allowed("move");
                                                    }
                                                    reorder.dragged.set(Some(id));
                                                }
                                            }
                                            on:dragover=move |ev: DragEvent| ev.prevent_default()
                                            on:drop=move |ev: DragEvent| {
                                                ev.prevent_default();
                                                if let (Some(from), Some(to)) = (reorder.dragged.get_untracked(), id)
                                                && !locked()
                                                {
                                                    drop_rule(from, to);
                                                }
                                                reorder.dragged.set(None);
                                            }
                                            on:dragend=move |_| reorder.dragged.set(None)
                                        >
                                            <td class="py-2 px-2 whitespace-nowrap">
                                                <DragHandle />
                                                <ReorderButtons
                                                    label=rule.name.clone()
                                                    can_up=can_up
                                                    can_down=can_down
                                                    disabled=Signal::derive(locked)
                                                    on_move=Callback::new(move |delta: isize| {
                                                        if let Some(id) = id {
                                                            move_rule(id, delta);
                                                        }
                                                    })
                                                />
                                            </td>
                                            <td class="py-2 px-2 text-gray-400">{rule.position}</td>
                                            <td class="py-2 px-2 text-gray-200">{rule.name.clone()}</td>
                                            <td class="py-2 px-2 text-gray-300">{rule.zone.clone().unwrap_or_else(|| "any".to_string())}</td>
                                            <td class="py-2 px-2 text-gray-300">{protocol_text(rule.protocol.as_ref())}</td>
                                            <td class="py-2 px-2 text-gray-300">{source}</td>
                                            <td class="py-2 px-2 text-gray-300">{ports}</td>
                                            <td class="py-2 px-2">
                                                <span class=action_class(action)>{format!("{:?}", action)}</span>
                                            </td>
                                            <td class="py-2 px-2 whitespace-nowrap">
                                                <RuleHits counters=counters kinds=INPUT_HIT_KINDS rule_ids=hit_ids />
                                            </td>
                                            <td class="py-2 px-2">
                                                {if rule.enabled {
                                                    view! { <span class="text-green-400">"Yes"</span> }.into_any()
                                                } else {
                                                    view! { <span class="text-gray-500">"No"</span> }.into_any()
                                                }}
                                            </td>
                                            <td class="py-2 px-2 text-right whitespace-nowrap">
                                                <button
                                                    class="text-blue-400 hover:text-blue-300 mr-2"
                                                    title="Edit"
                                                    on:click=move |_| editing.set(Some(rule_for_edit.clone()))
                                                >"Edit"</button>
                                                <button
                                                    class="text-purple-400 hover:text-purple-300 mr-2"
                                                    title="Clone"
                                                    on:click=move |_| editing.set(Some(clone_rule(&rule_for_clone)))
                                                >"Clone"</button>
                                                <button
                                                    class="text-red-400 hover:text-red-300"
                                                    title="Delete"
                                                    on:click=move |_| {
                                                        if let Some(id) = rule_for_delete.id {
                                                            let token = token_del.clone();
                                                            spawn_local(async move {
                                                                match api::delete_input_rule(&token, id).await {
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
                                                >"Delete"</button>
                                            </td>
                                        </tr>
                                    }
                                })
                                .collect::<Vec<_>>();
                            view! {
                                <div class="overflow-x-auto">
                                    <table class="w-full text-sm">
                                        <thead class="text-gray-400 border-b border-gray-600">
                                            <tr>
                                                <th class="text-left py-2 px-2">"Order"</th>
                                                <th class="text-left py-2 px-2">"#"</th>
                                                <th class="text-left py-2 px-2">"Name"</th>
                                                <th class="text-left py-2 px-2">"Zone"</th>
                                                <th class="text-left py-2 px-2">"Protocol"</th>
                                                <th class="text-left py-2 px-2">"Source"</th>
                                                <th class="text-left py-2 px-2">"Port"</th>
                                                <th class="text-left py-2 px-2">"Action"</th>
                                                <th class="text-left py-2 px-2">"Hits"</th>
                                                <th class="text-left py-2 px-2">"Enabled"</th>
                                                <th class="text-right py-2 px-2">"Actions"</th>
                                            </tr>
                                        </thead>
                                        <tbody>{rows}</tbody>
                                    </table>
                                    {if is_empty {
                                        view! { <p class="text-gray-500 text-center py-4">"No input rules configured"</p> }.into_any()
                                    } else if query.trim().is_empty() {
                                        view! { <div></div> }.into_any()
                                    } else {
                                        view! { <p class="text-gray-500 text-center py-4">"No rules match the search"</p> }.into_any()
                                    }}
                                </div>
                            }.into_any()
                        }
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
fn InputRuleEditor(
    rule: InputRule,
    token: String,
    on_save: impl Fn(()) + 'static,
    on_cancel: impl Fn() + 'static,
    error_message: RwSignal<String>,
    on_unauthorized: Callback<()>,
    address_groups: Signal<Vec<String>>,
    port_groups: Signal<Vec<String>>,
) -> impl IntoView {
    let name = RwSignal::new(rule.name.clone());
    let description = RwSignal::new(rule.description.clone().unwrap_or_default());
    let enabled = RwSignal::new(rule.enabled);
    let position = RwSignal::new(rule.position.to_string());
    let zone = RwSignal::new(rule.zone.clone().unwrap_or_default());
    let protocol = RwSignal::new(rule.protocol);
    let source = AddressField::new(rule.source_ip.clone(), rule.source_group.clone());
    let ports = PortField::new(rule.port_start, rule.port_end, rule.dest_port_group.clone());
    // Ports only apply to TCP, UDP and TCP+UDP.
    let ports_allowed = move || {
        matches!(
            protocol.get(),
            Some(RuleProtocol::Tcp | RuleProtocol::Udp | RuleProtocol::TcpUdp)
        )
    };
    let action = RwSignal::new(rule.action);
    let log_enabled = RwSignal::new(rule.log_enabled);
    let log_prefix = RwSignal::new(rule.log_prefix.clone().unwrap_or_default());
    let rate_limit = RwSignal::new(rule.rate_limit.clone().unwrap_or_default());
    let saving = RwSignal::new(false);
    let rule_id = rule.id;

    let on_save = std::rc::Rc::new(on_save);
    let on_save_clone = on_save.clone();

    let save = move |_| {
        saving.set(true);
        error_message.set(String::new());

        let token = token.clone();
        let on_save = on_save_clone.clone();

        let (source_ip, source_group) = source.values();
        let (port_start, port_end, dest_port_group) = if ports_allowed() {
            ports.values()
        } else {
            (None, None, None)
        };
        let new_rule = InputRule {
            id: rule_id,
            name: name.get(),
            description: Some(description.get()).filter(|text| !text.is_empty()),
            enabled: enabled.get(),
            position: position.get().parse().unwrap_or(100),
            zone: Some(zone.get()).filter(|text| !text.is_empty()),
            protocol: protocol.get(),
            port_start,
            port_end,
            source_ip,
            source_group,
            dest_port_group,
            action: action.get(),
            log_enabled: log_enabled.get(),
            log_prefix: Some(log_prefix.get()).filter(|text| !text.is_empty()),
            rate_limit: Some(rate_limit.get()).filter(|text| !text.is_empty()),
        };

        spawn_local(async move {
            match api::save_input_rule(&token, new_rule).await {
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

    let ports_allowed_signal = Signal::derive(ports_allowed);

    view! {
        <div class="bg-gray-700 p-4 rounded-lg space-y-4">
            <h3 class="text-lg font-medium text-gray-200">
                {if rule_id.is_some() { "Edit Input Rule" } else { "New Input Rule" }}
            </h3>

            <div class="grid grid-cols-2 gap-4">
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Name"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || name.get()
                        on:input=move |ev| name.set(event_target_value(&ev))
                        placeholder="e.g., Allow SSH"
                    />
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Position (lower = higher priority)"</label>
                    <input
                        type="number"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || position.get()
                        on:input=move |ev| position.set(event_target_value(&ev))
                    />
                </div>
            </div>

            <div>
                <label class="block text-sm text-gray-400 mb-1">"Description"</label>
                <input
                    type="text"
                    class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                    prop:value=move || description.get()
                    on:input=move |ev| description.set(event_target_value(&ev))
                    placeholder="Optional description"
                />
            </div>

            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Zone (blank = any)"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || zone.get()
                        on:input=move |ev| zone.set(event_target_value(&ev))
                        placeholder="e.g., wan"
                    />
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Protocol"</label>
                    <select
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        on:change=move |ev| {
                            let value = event_target_value(&ev);
                            protocol.set(match value.as_str() {
                                "tcp" => Some(RuleProtocol::Tcp),
                                "udp" => Some(RuleProtocol::Udp),
                                "tcp+udp" => Some(RuleProtocol::TcpUdp),
                                "icmp" => Some(RuleProtocol::Icmp),
                                "icmpv6" => Some(RuleProtocol::Icmpv6),
                                _ => None,
                            });
                        }
                    >
                        <option value="" selected=move || protocol.get().is_none()>"Any"</option>
                        <option value="tcp" selected=move || protocol.get() == Some(RuleProtocol::Tcp)>"TCP"</option>
                        <option value="udp" selected=move || protocol.get() == Some(RuleProtocol::Udp)>"UDP"</option>
                        <option value="tcp+udp" selected=move || protocol.get() == Some(RuleProtocol::TcpUdp)>"TCP+UDP"</option>
                        <option value="icmp" selected=move || protocol.get() == Some(RuleProtocol::Icmp)>"ICMP"</option>
                        <option value="icmpv6" selected=move || protocol.get() == Some(RuleProtocol::Icmpv6)>"ICMPv6"</option>
                    </select>
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Action"</label>
                    <select
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        on:change=move |ev| {
                            let value = event_target_value(&ev);
                            action.set(match value.as_str() {
                                "accept" => FirewallAction::Accept,
                                "reject" => FirewallAction::Reject,
                                _ => FirewallAction::Drop,
                            });
                        }
                    >
                        <option value="accept" selected=move || action.get() == FirewallAction::Accept>"Accept"</option>
                        <option value="drop" selected=move || action.get() == FirewallAction::Drop>"Drop"</option>
                        <option value="reject" selected=move || action.get() == FirewallAction::Reject>"Reject"</option>
                    </select>
                </div>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                <AddressFieldInput
                    field=source
                    label="Source"
                    placeholder="e.g., 192.168.1.0/24"
                    groups=address_groups
                />
                <PortFieldInput
                    field=ports
                    ports_allowed=ports_allowed_signal
                    groups=port_groups
                />
            </div>

            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Rate Limit"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || rate_limit.get()
                        on:input=move |ev| rate_limit.set(event_target_value(&ev))
                        placeholder="e.g., 10/minute"
                    />
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Log Prefix"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || log_prefix.get()
                        on:input=move |ev| log_prefix.set(event_target_value(&ev))
                        placeholder="e.g., INPUT_DROP"
                    />
                </div>
                <div class="flex items-end gap-4">
                    <div class="flex items-center gap-2">
                        <input
                            type="checkbox"
                            id="input-enabled"
                            class="w-4 h-4"
                            prop:checked=move || enabled.get()
                            on:change=move |ev| enabled.set(event_target_checked(&ev))
                        />
                        <label for="input-enabled" class="text-gray-300">"Enabled"</label>
                    </div>
                    <div class="flex items-center gap-2">
                        <input
                            type="checkbox"
                            id="input-log"
                            class="w-4 h-4"
                            prop:checked=move || log_enabled.get()
                            on:change=move |ev| log_enabled.set(event_target_checked(&ev))
                        />
                        <label for="input-log" class="text-gray-300">"Log"</label>
                    </div>
                </div>
            </div>

            <div class="flex gap-2 pt-2">
                <button
                    class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded disabled:opacity-50"
                    on:click=save
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
// Forward Rules
// ============================================================================

#[component]
pub(super) fn ForwardRulesTab(
    token: Signal<String>,
    reload_trigger: RwSignal<i32>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let rules = LocalResource::new(move || {
        let token = token.get();
        let _ = reload_trigger.get();
        async move { api::fetch_forward_rules(&token).await }
    });
    let counters = use_rule_counters(token, on_unauthorized);
    let address_groups = address_group_names(token, reload_trigger);
    let port_groups = port_group_names(token, reload_trigger);

    let editing = RwSignal::new(Option::<ForwardRule>::None);
    let error_message = RwSignal::new(String::new());
    let filter = RwSignal::new(String::new());
    let reorder = Reorder::<ForwardRule>::new();

    Effect::new(move |_| {
        let _ = rules.get();
        reorder.order.set(None);
    });

    let locked = move || !filter.get().trim().is_empty() || reorder.busy.get();

    let current_list = move || -> Vec<ForwardRule> {
        reorder
            .order
            .get()
            .or_else(|| rules.get().and_then(|result| result.ok()))
            .unwrap_or_default()
    };

    let apply_order = move |list: Vec<ForwardRule>| {
        let ids: Vec<i64> = list.iter().filter_map(|rule| rule.id).collect();
        reorder.order.set(Some(list));
        reorder.busy.set(true);
        let token = token.get_untracked();
        spawn_local(async move {
            match api::reorder_forward_rules(&token, ids).await {
                Ok(()) => {}
                Err(e) => {
                    reorder.order.set(None);
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        error_message.set(e);
                    }
                }
            }
            reorder.busy.set(false);
            reload_trigger.update(|v| *v += 1);
        });
    };

    let move_rule = move |id: i64, delta: isize| {
        let list = current_list();
        let ids: Vec<i64> = list.iter().filter_map(|rule| rule.id).collect();
        if let Some(new_ids) = move_by(&ids, id, delta) {
            apply_order(reorder_by_ids(
                &list,
                &new_ids,
                |r| r.id,
                |r, p| r.position = p,
            ));
        }
    };

    let drop_rule = move |from: i64, to: i64| {
        let list = current_list();
        let ids: Vec<i64> = list.iter().filter_map(|rule| rule.id).collect();
        if let Some(new_ids) = move_onto(&ids, from, to) {
            apply_order(reorder_by_ids(
                &list,
                &new_ids,
                |r| r.id,
                |r, p| r.position = p,
            ));
        }
    };

    let new_rule = move || ForwardRule {
        id: None,
        name: String::new(),
        description: None,
        enabled: true,
        position: 100,
        source_zone: None,
        dest_zone: None,
        protocol: Some(RuleProtocol::Tcp),
        dest_port_start: None,
        dest_port_end: None,
        source_ip: None,
        dest_ip: None,
        source_group: None,
        dest_group: None,
        dest_ipv6_suffix: None,
        dest_port_group: None,
        action: FirewallAction::Accept,
        log_enabled: false,
        log_prefix: None,
        rate_limit: None,
    };

    let clone_rule = move |rule: &ForwardRule| -> ForwardRule {
        ForwardRule {
            id: None,
            name: format!("{} (copy)", rule.name),
            ..rule.clone()
        }
    };

    view! {
        <div class="space-y-4">
            <div class="flex flex-wrap justify-between items-center gap-3">
                <div>
                    <h2 class="text-lg font-medium text-gray-200">"Forward Rules (Traffic Through Router)"</h2>
                    <p class="text-sm text-gray-400">"Rules are evaluated in order; first match wins. Drag a row or use the arrows to reorder."</p>
                </div>
                <div class="flex flex-wrap items-center gap-2">
                    <FilterBox query=filter placeholder="Search name, zones, ports, addresses" />
                    <button
                        class="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm"
                        on:click=move |_| editing.set(Some(new_rule()))
                    >
                        "+ Add Rule"
                    </button>
                </div>
            </div>

            {move || {
                let msg = error_message.get();
                (!msg.is_empty()).then(|| view! {
                    <div class="bg-red-900/50 border border-red-700 text-red-200 px-4 py-2 rounded text-sm">{msg}</div>
                })
            }}

            {move || editing.get().map(|rule| view! {
                <ForwardRuleEditor
                    rule=rule
                    token=token.get()
                    on_save=move |_| {
                        editing.set(None);
                        reload_trigger.update(|v| *v += 1);
                    }
                    on_cancel=move || editing.set(None)
                    error_message=error_message
                    on_unauthorized=on_unauthorized
                    address_groups=address_groups
                    port_groups=port_groups
                />
            })}

            <Suspense fallback=move || view! { <p class="text-gray-400">"Loading..."</p> }>
                {move || {
                    rules.get().map(|result| match result {
                        Ok(_) => {
                            let list = current_list();
                            let query = filter.get();
                            let total = list.len();
                            let is_empty = total == 0;
                            let rows = list
                                .iter()
                                .enumerate()
                                .filter(|(_, rule)| matches_filter(&query, &forward_rule_fields(rule)))
                                .map(|(index, rule)| {
                                    let id = rule.id;
                                    let rule_for_edit = rule.clone();
                                    let rule_for_clone = rule.clone();
                                    let rule_for_delete = rule.clone();
                                    let token_del = token.get_untracked();
                                    let source = address_text(rule.source_ip.as_deref(), rule.source_group.as_deref());
                                    let dest = forward_dest_text(rule);
                                    let ports = port_text(rule.dest_port_start, rule.dest_port_end, rule.dest_port_group.as_deref());
                                    let action = rule.action;
                                    let can_up = index > 0;
                                    let can_down = index + 1 < total;
                                    let hit_ids: Vec<i64> = id.into_iter().collect();
                                    view! {
                                        <tr
                                            class="border-b border-gray-700 hover:bg-gray-700/30"
                                            draggable=move || if locked() { "false" } else { "true" }
                                            on:dragstart=move |ev: DragEvent| {
                                                if let Some(id) = id {
                                                    if let Some(transfer) = ev.data_transfer() {
                                                        let _ = transfer.set_data("text/plain", &id.to_string());
                                                        transfer.set_effect_allowed("move");
                                                    }
                                                    reorder.dragged.set(Some(id));
                                                }
                                            }
                                            on:dragover=move |ev: DragEvent| ev.prevent_default()
                                            on:drop=move |ev: DragEvent| {
                                                ev.prevent_default();
                                                if let (Some(from), Some(to)) = (reorder.dragged.get_untracked(), id)
                                                && !locked()
                                                {
                                                    drop_rule(from, to);
                                                }
                                                reorder.dragged.set(None);
                                            }
                                            on:dragend=move |_| reorder.dragged.set(None)
                                        >
                                            <td class="py-2 px-2 whitespace-nowrap">
                                                <DragHandle />
                                                <ReorderButtons
                                                    label=rule.name.clone()
                                                    can_up=can_up
                                                    can_down=can_down
                                                    disabled=Signal::derive(locked)
                                                    on_move=Callback::new(move |delta: isize| {
                                                        if let Some(id) = id {
                                                            move_rule(id, delta);
                                                        }
                                                    })
                                                />
                                            </td>
                                            <td class="py-2 px-2 text-gray-400">{rule.position}</td>
                                            <td class="py-2 px-2 text-gray-200">{rule.name.clone()}</td>
                                            <td class="py-2 px-2 text-gray-300">{rule.source_zone.clone().unwrap_or_else(|| "any".to_string())}</td>
                                            <td class="py-2 px-2 text-gray-300">{rule.dest_zone.clone().unwrap_or_else(|| "any".to_string())}</td>
                                            <td class="py-2 px-2 text-gray-300">{protocol_text(rule.protocol.as_ref())}</td>
                                            <td class="py-2 px-2 text-gray-300">{source}</td>
                                            <td class="py-2 px-2 text-gray-300">{dest}</td>
                                            <td class="py-2 px-2 text-gray-300">{ports}</td>
                                            <td class="py-2 px-2">
                                                <span class=action_class(action)>{format!("{:?}", action)}</span>
                                            </td>
                                            <td class="py-2 px-2 whitespace-nowrap">
                                                <RuleHits counters=counters kinds=FORWARD_HIT_KINDS rule_ids=hit_ids />
                                            </td>
                                            <td class="py-2 px-2">
                                                {if rule.enabled {
                                                    view! { <span class="text-green-400">"Yes"</span> }.into_any()
                                                } else {
                                                    view! { <span class="text-gray-500">"No"</span> }.into_any()
                                                }}
                                            </td>
                                            <td class="py-2 px-2 text-right whitespace-nowrap">
                                                <button
                                                    class="text-blue-400 hover:text-blue-300 mr-2"
                                                    title="Edit"
                                                    on:click=move |_| editing.set(Some(rule_for_edit.clone()))
                                                >"Edit"</button>
                                                <button
                                                    class="text-purple-400 hover:text-purple-300 mr-2"
                                                    title="Clone"
                                                    on:click=move |_| editing.set(Some(clone_rule(&rule_for_clone)))
                                                >"Clone"</button>
                                                <button
                                                    class="text-red-400 hover:text-red-300"
                                                    title="Delete"
                                                    on:click=move |_| {
                                                        if let Some(id) = rule_for_delete.id {
                                                            let token = token_del.clone();
                                                            spawn_local(async move {
                                                                match api::delete_forward_rule(&token, id).await {
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
                                                >"Delete"</button>
                                            </td>
                                        </tr>
                                    }
                                })
                                .collect::<Vec<_>>();
                            view! {
                                <div class="overflow-x-auto">
                                    <table class="w-full text-sm">
                                        <thead class="text-gray-400 border-b border-gray-600">
                                            <tr>
                                                <th class="text-left py-2 px-2">"Order"</th>
                                                <th class="text-left py-2 px-2">"#"</th>
                                                <th class="text-left py-2 px-2">"Name"</th>
                                                <th class="text-left py-2 px-2">"Src Zone"</th>
                                                <th class="text-left py-2 px-2">"Dst Zone"</th>
                                                <th class="text-left py-2 px-2">"Protocol"</th>
                                                <th class="text-left py-2 px-2">"Source"</th>
                                                <th class="text-left py-2 px-2">"Destination"</th>
                                                <th class="text-left py-2 px-2">"Dst Port"</th>
                                                <th class="text-left py-2 px-2">"Action"</th>
                                                <th class="text-left py-2 px-2">"Hits"</th>
                                                <th class="text-left py-2 px-2">"Enabled"</th>
                                                <th class="text-right py-2 px-2">"Actions"</th>
                                            </tr>
                                        </thead>
                                        <tbody>{rows}</tbody>
                                    </table>
                                    {if is_empty {
                                        view! { <p class="text-gray-500 text-center py-4">"No forward rules configured"</p> }.into_any()
                                    } else if query.trim().is_empty() {
                                        view! { <div></div> }.into_any()
                                    } else {
                                        view! { <p class="text-gray-500 text-center py-4">"No rules match the search"</p> }.into_any()
                                    }}
                                </div>
                            }.into_any()
                        }
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
fn ForwardRuleEditor(
    rule: ForwardRule,
    token: String,
    on_save: impl Fn(()) + 'static,
    on_cancel: impl Fn() + 'static,
    error_message: RwSignal<String>,
    on_unauthorized: Callback<()>,
    address_groups: Signal<Vec<String>>,
    port_groups: Signal<Vec<String>>,
) -> impl IntoView {
    let name = RwSignal::new(rule.name.clone());
    let description = RwSignal::new(rule.description.clone().unwrap_or_default());
    let enabled = RwSignal::new(rule.enabled);
    let position = RwSignal::new(rule.position.to_string());
    let source_zone = RwSignal::new(rule.source_zone.clone().unwrap_or_default());
    let dest_zone = RwSignal::new(rule.dest_zone.clone().unwrap_or_default());
    let protocol = RwSignal::new(rule.protocol);
    let source = AddressField::new(rule.source_ip.clone(), rule.source_group.clone());
    let dest = AddressField::new(rule.dest_ip.clone(), rule.dest_group.clone());
    let dest_suffix = RwSignal::new(rule.dest_ipv6_suffix.clone().unwrap_or_default());
    // Discovered LAN devices, offered as a shortcut for filling in the suffix.
    let devices = RwSignal::new(Vec::<LanDevice>::new());
    {
        let token = token.clone();
        spawn_local(async move {
            if let Ok(found) = api::fetch_lan_devices(&token).await {
                devices.set(found);
            }
        });
    }
    let ports = PortField::new(
        rule.dest_port_start,
        rule.dest_port_end,
        rule.dest_port_group.clone(),
    );
    // Ports only apply to TCP, UDP and TCP+UDP.
    let ports_allowed = move || {
        matches!(
            protocol.get(),
            Some(RuleProtocol::Tcp | RuleProtocol::Udp | RuleProtocol::TcpUdp)
        )
    };
    let action = RwSignal::new(rule.action);
    let log_enabled = RwSignal::new(rule.log_enabled);
    let log_prefix = RwSignal::new(rule.log_prefix.clone().unwrap_or_default());
    let rate_limit = RwSignal::new(rule.rate_limit.clone().unwrap_or_default());
    let saving = RwSignal::new(false);
    let rule_id = rule.id;

    let on_save = std::rc::Rc::new(on_save);
    let on_save_clone = on_save.clone();

    let save = move |_| {
        saving.set(true);
        error_message.set(String::new());

        let token = token.clone();
        let on_save = on_save_clone.clone();

        let (source_ip, source_group) = source.values();
        // A suffix replaces the destination address or group.
        let dest_ipv6_suffix =
            Some(dest_suffix.get().trim().to_string()).filter(|text| !text.is_empty());
        let (dest_ip, dest_group) = if dest_ipv6_suffix.is_some() {
            (None, None)
        } else {
            dest.values()
        };
        let (dest_port_start, dest_port_end, dest_port_group) = if ports_allowed() {
            ports.values()
        } else {
            (None, None, None)
        };
        let new_rule = ForwardRule {
            id: rule_id,
            name: name.get(),
            description: Some(description.get()).filter(|text| !text.is_empty()),
            enabled: enabled.get(),
            position: position.get().parse().unwrap_or(100),
            source_zone: Some(source_zone.get()).filter(|text| !text.is_empty()),
            dest_zone: Some(dest_zone.get()).filter(|text| !text.is_empty()),
            protocol: protocol.get(),
            dest_port_start,
            dest_port_end,
            source_ip,
            dest_ip,
            source_group,
            dest_group,
            dest_ipv6_suffix,
            dest_port_group,
            action: action.get(),
            log_enabled: log_enabled.get(),
            log_prefix: Some(log_prefix.get()).filter(|text| !text.is_empty()),
            rate_limit: Some(rate_limit.get()).filter(|text| !text.is_empty()),
        };

        spawn_local(async move {
            match api::save_forward_rule(&token, new_rule).await {
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

    let ports_allowed_signal = Signal::derive(ports_allowed);

    view! {
        <div class="bg-gray-700 p-4 rounded-lg space-y-4">
            <h3 class="text-lg font-medium text-gray-200">
                {if rule_id.is_some() { "Edit Forward Rule" } else { "New Forward Rule" }}
            </h3>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Name"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || name.get()
                        on:input=move |ev| name.set(event_target_value(&ev))
                        placeholder="e.g., Allow LAN to WAN"
                    />
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Position (lower = higher priority)"</label>
                    <input
                        type="number"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || position.get()
                        on:input=move |ev| position.set(event_target_value(&ev))
                    />
                </div>
            </div>

            <div>
                <label class="block text-sm text-gray-400 mb-1">"Description"</label>
                <input
                    type="text"
                    class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                    prop:value=move || description.get()
                    on:input=move |ev| description.set(event_target_value(&ev))
                    placeholder="Optional description"
                />
            </div>

            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Source Zone"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || source_zone.get()
                        on:input=move |ev| source_zone.set(event_target_value(&ev))
                        placeholder="blank = any"
                    />
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Dest Zone"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || dest_zone.get()
                        on:input=move |ev| dest_zone.set(event_target_value(&ev))
                        placeholder="blank = any"
                    />
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Protocol"</label>
                    <select
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        on:change=move |ev| {
                            let value = event_target_value(&ev);
                            protocol.set(match value.as_str() {
                                "tcp" => Some(RuleProtocol::Tcp),
                                "udp" => Some(RuleProtocol::Udp),
                                "tcp+udp" => Some(RuleProtocol::TcpUdp),
                                "icmp" => Some(RuleProtocol::Icmp),
                                "icmpv6" => Some(RuleProtocol::Icmpv6),
                                _ => None,
                            });
                        }
                    >
                        <option value="" selected=move || protocol.get().is_none()>"Any"</option>
                        <option value="tcp" selected=move || protocol.get() == Some(RuleProtocol::Tcp)>"TCP"</option>
                        <option value="udp" selected=move || protocol.get() == Some(RuleProtocol::Udp)>"UDP"</option>
                        <option value="tcp+udp" selected=move || protocol.get() == Some(RuleProtocol::TcpUdp)>"TCP+UDP"</option>
                        <option value="icmp" selected=move || protocol.get() == Some(RuleProtocol::Icmp)>"ICMP"</option>
                        <option value="icmpv6" selected=move || protocol.get() == Some(RuleProtocol::Icmpv6)>"ICMPv6"</option>
                    </select>
                </div>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <AddressFieldInput
                    field=source
                    label="Source"
                    placeholder="e.g., 192.168.1.0/24"
                    groups=address_groups
                />
                <AddressFieldInput
                    field=dest
                    label="Destination"
                    placeholder="e.g., 192.168.2.0/24"
                    groups=address_groups
                />
            </div>

            <div>
                <label class="block text-sm text-gray-300 mb-1" for="dest-ipv6-suffix">
                    "Destination IPv6 suffix (optional)"
                </label>
                <select
                    class="w-full px-3 py-2 mb-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                    aria-label="Fill the suffix from a discovered device"
                    on:change=move |ev| {
                        let value = event_target_value(&ev);
                        if !value.is_empty() {
                            dest_suffix.set(value);
                        }
                    }
                >
                    <option value="">"Fill from a discovered LAN device"</option>
                    {move || {
                        devices
                            .get()
                            .into_iter()
                            .flat_map(|device| {
                                let name = device.hostname.clone().unwrap_or_else(|| device.mac.clone());
                                device
                                    .ipv6_suffixes()
                                    .into_iter()
                                    .map(move |suffix| {
                                        let label = format!("{name}  {suffix}");
                                        view! { <option value=suffix>{label}</option> }
                                    })
                                    .collect::<Vec<_>>()
                            })
                            .collect::<Vec<_>>()
                    }}
                </select>
                <input
                    id="dest-ipv6-suffix"
                    type="text"
                    class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                    placeholder="e.g., ::1234"
                    prop:value=move || dest_suffix.get()
                    on:input=move |ev| dest_suffix.set(event_target_value(&ev))
                />
                <p class="text-xs text-gray-400 mt-1">
                    "Matches the host whatever prefix your ISP delegates. Replaces the destination above."
                </p>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                <PortFieldInput
                    field=ports
                    ports_allowed=ports_allowed_signal
                    groups=port_groups
                />
                <div class="flex items-end">
                    <select
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        on:change=move |ev| {
                            let value = event_target_value(&ev);
                            action.set(match value.as_str() {
                                "accept" => FirewallAction::Accept,
                                "reject" => FirewallAction::Reject,
                                _ => FirewallAction::Drop,
                            });
                        }
                        aria-label="Action"
                    >
                        <option value="accept" selected=move || action.get() == FirewallAction::Accept>"Accept"</option>
                        <option value="drop" selected=move || action.get() == FirewallAction::Drop>"Drop"</option>
                        <option value="reject" selected=move || action.get() == FirewallAction::Reject>"Reject"</option>
                    </select>
                </div>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Rate Limit"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || rate_limit.get()
                        on:input=move |ev| rate_limit.set(event_target_value(&ev))
                        placeholder="e.g., 10/minute"
                    />
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Log Prefix"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || log_prefix.get()
                        on:input=move |ev| log_prefix.set(event_target_value(&ev))
                    />
                </div>
                <div class="flex items-end gap-4">
                    <div class="flex items-center gap-2">
                        <input
                            type="checkbox"
                            id="fwd-enabled"
                            class="w-4 h-4"
                            prop:checked=move || enabled.get()
                            on:change=move |ev| enabled.set(event_target_checked(&ev))
                        />
                        <label for="fwd-enabled" class="text-gray-300">"Enabled"</label>
                    </div>
                    <div class="flex items-center gap-2">
                        <input
                            type="checkbox"
                            id="fwd-log"
                            class="w-4 h-4"
                            prop:checked=move || log_enabled.get()
                            on:change=move |ev| log_enabled.set(event_target_checked(&ev))
                        />
                        <label for="fwd-log" class="text-gray-300">"Log"</label>
                    </div>
                </div>
            </div>

            <div class="flex gap-2 pt-2">
                <button
                    class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded disabled:opacity-50"
                    on:click=save
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reorder_renumbers_positions_in_the_new_order() {
        let list = vec![(1, 0), (2, 1), (3, 2)];
        let reordered =
            reorder_by_ids(&list, &[3, 1, 2], |item| Some(item.0), |item, p| item.1 = p);
        assert_eq!(reordered, vec![(3, 0), (1, 1), (2, 2)]);
    }

    #[test]
    fn port_text_prefers_a_group_then_a_range() {
        assert_eq!(port_text(Some(22), None, None), "22");
        assert_eq!(port_text(Some(8000), Some(8100), None), "8000-8100");
        assert_eq!(port_text(Some(22), None, Some("web")), "group web");
        assert_eq!(port_text(None, None, None), "any");
    }

    #[test]
    fn address_text_names_groups() {
        assert_eq!(address_text(Some("10.0.0.0/8"), None), "10.0.0.0/8");
        assert_eq!(address_text(None, Some("lan")), "group lan");
        assert_eq!(address_text(None, None), "any");
    }

    #[test]
    fn search_finds_group_names_and_ports() {
        let rule = InputRule {
            name: "SSH".into(),
            zone: Some("lan".into()),
            protocol: Some(RuleProtocol::Tcp),
            port_start: Some(22),
            source_group: Some("admins".into()),
            ..Default::default()
        };
        let fields = input_rule_fields(&rule);
        assert!(matches_filter("admins", &fields));
        assert!(matches_filter("ssh lan", &fields));
        assert!(matches_filter("22", &fields));
        assert!(!matches_filter("web", &fields));
    }
}
