//! Shared pieces of the firewall rule tables: filtering, ordering, hit
//! counters and the "literal or group" fields used by the rule editors.
//!
//! The pure functions here are unit-tested on the host; the components are
//! thin wrappers over them.

use super::form_utils::event_target_value;
use crate::api;
use gloo_timers::callback::Interval;
use keystone_core::{AddressGroup, FirewallRuleCounter, PortGroup};
use leptos::prelude::*;
use leptos::task::spawn_local;

/// How often the hit counters are refreshed while a rule table is open.
pub const COUNTER_REFRESH_MS: u32 = 5_000;

// ============================================================================
// Pure helpers
// ============================================================================

/// True when every whitespace-separated term of `query` appears, ignoring case,
/// in at least one of `fields`. An empty query matches everything.
pub fn matches_filter<S: AsRef<str>>(query: &str, fields: &[S]) -> bool {
    let haystacks: Vec<String> = fields
        .iter()
        .map(|field| field.as_ref().to_lowercase())
        .collect();
    query.split_whitespace().all(|term| {
        let term = term.to_lowercase();
        haystacks.iter().any(|haystack| haystack.contains(&term))
    })
}

/// The order after moving `id` one place up (`delta` -1) or down (`delta` +1).
/// `None` when `id` is absent or already at that edge.
pub fn move_by(ids: &[i64], id: i64, delta: isize) -> Option<Vec<i64>> {
    let index = ids.iter().position(|&value| value == id)?;
    let target = index.checked_add_signed(delta)?;
    if target >= ids.len() {
        return None;
    }
    let mut order = ids.to_vec();
    order.swap(index, target);
    Some(order)
}

/// The order after dragging `dragged` onto the position of `target`. Dragging
/// upwards places it before the target, dragging downwards places it after.
pub fn move_onto(ids: &[i64], dragged: i64, target: i64) -> Option<Vec<i64>> {
    if dragged == target {
        return None;
    }
    let from = ids.iter().position(|&value| value == dragged)?;
    let to = ids.iter().position(|&value| value == target)?;
    let mut order = ids.to_vec();
    let item = order.remove(from);
    order.insert(to, item);
    Some(order)
}

/// Format a count with a decimal suffix: `999`, `1.2k`, `12k`, `3.4M`.
pub fn format_count(value: u64) -> String {
    scaled(value, 1_000, &["", "k", "M", "G", "T"])
}

/// Format a byte count in binary units: `512 B`, `98.2 KiB`, `1.4 MiB`.
pub fn format_bytes(value: u64) -> String {
    if value < 1_024 {
        return format!("{value} B");
    }
    // Values of at least one KiB always select a unit from the list below.
    scaled(value, 1_024, &["", " KiB", " MiB", " GiB", " TiB"])
}

fn scaled(value: u64, base: u64, units: &[&str]) -> String {
    if value < base {
        return value.to_string();
    }
    let mut amount = value as f64;
    let mut unit = 0;
    while amount >= base as f64 && unit + 1 < units.len() {
        amount /= base as f64;
        unit += 1;
    }
    let text = if amount >= 10.0 {
        format!("{amount:.0}")
    } else {
        format!("{amount:.1}")
    };
    format!("{text}{}", units[unit])
}

/// Packets and bytes summed over every counter of `rule_id` whose kind is one
/// of `kinds`. A rule with no counter entry has seen no traffic.
pub fn hits_for(counters: &[FirewallRuleCounter], kinds: &[&str], rule_id: i64) -> (u64, u64) {
    counters
        .iter()
        .filter(|counter| counter.rule_id == rule_id && kinds.contains(&counter.kind.as_str()))
        .fold((0, 0), |(packets, bytes), counter| {
            (
                packets.saturating_add(counter.packets),
                bytes.saturating_add(counter.bytes),
            )
        })
}

// ============================================================================
// Signals
// ============================================================================

/// Hit counters, refreshed every [`COUNTER_REFRESH_MS`] while the calling
/// component is mounted. A failed refresh keeps the last values.
pub fn use_rule_counters(
    token: Signal<String>,
    on_unauthorized: Callback<()>,
) -> RwSignal<Vec<FirewallRuleCounter>> {
    let counters = RwSignal::new(Vec::<FirewallRuleCounter>::new());
    let poll = move || {
        let token = token.get_untracked();
        if token.is_empty() {
            return;
        }
        spawn_local(async move {
            match api::fetch_rule_counters(&token).await {
                Ok(list) => counters.set(list),
                Err(e) if e == "Unauthorized" => on_unauthorized.run(()),
                Err(_) => {}
            }
        });
    };
    // The Effect owns the Interval, which is dropped on unmount and stops polling.
    Effect::new(move |_prev: Option<Option<Interval>>| {
        poll();
        Some(Interval::new(COUNTER_REFRESH_MS, poll))
    });
    counters
}

/// Names of the address groups, refreshed when `reload` changes.
pub fn address_group_names(token: Signal<String>, reload: RwSignal<i32>) -> Signal<Vec<String>> {
    let groups = LocalResource::new(move || {
        let token = token.get();
        let _ = reload.get();
        async move { api::fetch_address_groups(&token).await }
    });
    Signal::derive(move || match groups.get() {
        Some(Ok(list)) => names_of(list.iter().map(|group: &AddressGroup| group.name.as_str())),
        _ => Vec::new(),
    })
}

/// Names of the port groups, refreshed when `reload` changes.
pub fn port_group_names(token: Signal<String>, reload: RwSignal<i32>) -> Signal<Vec<String>> {
    let groups = LocalResource::new(move || {
        let token = token.get();
        let _ = reload.get();
        async move { api::fetch_port_groups(&token).await }
    });
    Signal::derive(move || match groups.get() {
        Some(Ok(list)) => names_of(list.iter().map(|group: &PortGroup| group.name.as_str())),
        _ => Vec::new(),
    })
}

fn names_of<'a>(names: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut names: Vec<String> = names.map(str::to_owned).collect();
    names.sort();
    names
}

// ============================================================================
// Components
// ============================================================================

/// Case-insensitive search box for a table.
#[component]
pub fn FilterBox(query: RwSignal<String>, placeholder: &'static str) -> impl IntoView {
    view! {
        <input
            type="search"
            class="w-full md:w-72 px-3 py-1.5 bg-gray-700 text-gray-200 rounded border border-gray-600 text-sm"
            placeholder=placeholder
            aria-label=placeholder
            prop:value=move || query.get()
            on:input=move |ev| query.set(event_target_value(&ev))
        />
    }
}

/// Keyboard-accessible move buttons for one row. `label` names the row for
/// screen readers.
#[component]
pub fn ReorderButtons(
    label: String,
    can_up: bool,
    can_down: bool,
    disabled: Signal<bool>,
    on_move: Callback<isize>,
) -> impl IntoView {
    let up_label = format!("Move {label} up");
    let down_label = format!("Move {label} down");
    view! {
        <span class="inline-flex gap-1 mr-2">
            <button
                type="button"
                class="px-1.5 text-gray-300 hover:text-white disabled:opacity-30"
                aria-label=up_label.clone()
                title=up_label
                disabled=move || disabled.get() || !can_up
                on:click=move |_| on_move.run(-1)
            >"▲"</button>
            <button
                type="button"
                class="px-1.5 text-gray-300 hover:text-white disabled:opacity-30"
                aria-label=down_label.clone()
                title=down_label
                disabled=move || disabled.get() || !can_down
                on:click=move |_| on_move.run(1)
            >"▼"</button>
        </span>
    }
}

/// Visual grip for a draggable row. The whole row is the drag source; the
/// move buttons are the keyboard route to the same result.
#[component]
pub fn DragHandle() -> impl IntoView {
    view! {
        <span
            class="inline-block px-1 mr-1 text-gray-500 cursor-grab select-none"
            title="Drag to reorder"
            aria-hidden="true"
        >"⠿"</span>
    }
}

/// Hit counter cell for a rule, read from the shared counters so that a
/// refresh updates only this cell. `rule_ids` lists the rules whose hits add
/// up to the total (a simple forward has one rule per family) and `kinds` the
/// counter kinds that count.
#[component]
pub fn RuleHits(
    counters: RwSignal<Vec<FirewallRuleCounter>>,
    kinds: &'static [&'static str],
    rule_ids: Vec<i64>,
) -> impl IntoView {
    move || {
        let current = counters.get();
        let (packets, bytes) = rule_ids.iter().fold((0u64, 0u64), |(packets, bytes), id| {
            let (more_packets, more_bytes) = hits_for(&current, kinds, *id);
            (
                packets.saturating_add(more_packets),
                bytes.saturating_add(more_bytes),
            )
        });
        hits_view(packets, bytes)
    }
}

fn hits_view(packets: u64, bytes: u64) -> AnyView {
    if packets == 0 {
        view! {
            <span class="text-gray-500" title="No matching traffic since the last apply">"0 hits"</span>
        }
        .into_any()
    } else {
        view! {
            <span class="text-gray-200" title=format!("{packets} packets, {bytes} bytes")>
                {format!("{} hits · {}", format_count(packets), format_bytes(bytes))}
            </span>
        }
        .into_any()
    }
}

/// An address that is either typed in (`literal`) or taken from a named group.
#[derive(Clone, Copy)]
pub struct AddressField {
    pub literal: RwSignal<String>,
    pub group: RwSignal<String>,
    pub use_group: RwSignal<bool>,
}

impl AddressField {
    pub fn new(literal: Option<String>, group: Option<String>) -> Self {
        Self {
            use_group: RwSignal::new(group.is_some()),
            literal: RwSignal::new(literal.unwrap_or_default()),
            group: RwSignal::new(group.unwrap_or_default()),
        }
    }

    /// `(literal, group)` for the rule, following the selected mode.
    pub fn values(&self) -> (Option<String>, Option<String>) {
        let literal = self.literal.get_untracked().trim().to_owned();
        let group = self.group.get_untracked();
        if self.use_group.get_untracked() {
            (None, (!group.is_empty()).then_some(group))
        } else {
            ((!literal.is_empty()).then_some(literal), None)
        }
    }
}

/// Editor for an [`AddressField`]: a mode select plus either a text box or a
/// select of address groups.
#[component]
pub fn AddressFieldInput(
    field: AddressField,
    label: &'static str,
    placeholder: &'static str,
    groups: Signal<Vec<String>>,
) -> impl IntoView {
    view! {
        <div>
            <div class="flex items-center justify-between mb-1">
                <label class="block text-sm text-gray-400">{label}</label>
                <select
                    class="px-2 py-0.5 bg-gray-600 text-gray-200 rounded border border-gray-500 text-xs"
                    aria-label=format!("{label} type")
                    on:change=move |ev| field.use_group.set(event_target_value(&ev) == "group")
                >
                    <option value="address" selected=move || !field.use_group.get()>"Address"</option>
                    <option value="group" selected=move || field.use_group.get()>"Group"</option>
                </select>
            </div>
            {move || if field.use_group.get() {
                view! {
                    <select
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        aria-label=label
                        prop:value=move || field.group.get()
                        on:change=move |ev| field.group.set(event_target_value(&ev))
                    >
                        <option value="" selected=move || field.group.get().is_empty()>"Choose a group"</option>
                        {move || {
                            let mut names = groups.get();
                            let current = field.group.get();
                            // Keep a reference to a deleted or unloaded group visible.
                            if !current.is_empty() && !names.contains(&current) {
                                names.push(current);
                            }
                            names.into_iter().map(|name| {
                                let selected = name == field.group.get_untracked();
                                view! { <option value=name.clone() selected=selected>{name.clone()}</option> }
                            }).collect::<Vec<_>>()
                        }}
                    </select>
                    <p class="text-xs text-gray-500 mt-1">
                        "Manage groups on the Groups page."
                    </p>
                }
                .into_any()
            } else {
                view! {
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        aria-label=label
                        prop:value=move || field.literal.get()
                        on:input=move |ev| field.literal.set(event_target_value(&ev))
                        placeholder=placeholder
                    />
                }
                .into_any()
            }}
        </div>
    }
}

/// A destination port range that is either typed in or taken from a port group.
#[derive(Clone, Copy)]
pub struct PortField {
    pub start: RwSignal<String>,
    pub end: RwSignal<String>,
    pub group: RwSignal<String>,
    pub use_group: RwSignal<bool>,
}

impl PortField {
    pub fn new(start: Option<u16>, end: Option<u16>, group: Option<String>) -> Self {
        Self {
            use_group: RwSignal::new(group.is_some()),
            start: RwSignal::new(start.map(|p| p.to_string()).unwrap_or_default()),
            end: RwSignal::new(end.map(|p| p.to_string()).unwrap_or_default()),
            group: RwSignal::new(group.unwrap_or_default()),
        }
    }

    /// `(start, end, group)` for the rule, following the selected mode.
    pub fn values(&self) -> (Option<u16>, Option<u16>, Option<String>) {
        if self.use_group.get_untracked() {
            let group = self.group.get_untracked();
            return (None, None, (!group.is_empty()).then_some(group));
        }
        (
            self.start.get_untracked().trim().parse().ok(),
            self.end.get_untracked().trim().parse().ok(),
            None,
        )
    }
}

/// Editor for a [`PortField`]. The inputs are disabled unless the protocol
/// has ports (`ports_allowed`).
#[component]
pub fn PortFieldInput(
    field: PortField,
    #[prop(into)] ports_allowed: Signal<bool>,
    groups: Signal<Vec<String>>,
) -> impl IntoView {
    view! {
        <div class="md:col-span-2">
            <div class="flex items-center justify-between mb-1">
                <label class="block text-sm text-gray-400">"Destination ports"</label>
                <select
                    class="px-2 py-0.5 bg-gray-600 text-gray-200 rounded border border-gray-500 text-xs"
                    aria-label="Destination ports type"
                    prop:disabled=move || !ports_allowed.get()
                    on:change=move |ev| field.use_group.set(event_target_value(&ev) == "group")
                >
                    <option value="ports" selected=move || !field.use_group.get()>"Ports"</option>
                    <option value="group" selected=move || field.use_group.get()>"Port group"</option>
                </select>
            </div>
            {move || if field.use_group.get() {
                view! {
                    <select
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        aria-label="Port group"
                        prop:disabled=move || !ports_allowed.get()
                        prop:value=move || field.group.get()
                        on:change=move |ev| field.group.set(event_target_value(&ev))
                    >
                        <option value="" selected=move || field.group.get().is_empty()>"Choose a port group"</option>
                        {move || {
                            let mut names = groups.get();
                            let current = field.group.get();
                            if !current.is_empty() && !names.contains(&current) {
                                names.push(current);
                            }
                            names.into_iter().map(|name| {
                                let selected = name == field.group.get_untracked();
                                view! { <option value=name.clone() selected=selected>{name.clone()}</option> }
                            }).collect::<Vec<_>>()
                        }}
                    </select>
                }
                .into_any()
            } else {
                view! {
                    <div class="grid grid-cols-2 gap-3">
                        <input
                            type="number"
                            class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                            aria-label="Port start"
                            prop:disabled=move || !ports_allowed.get()
                            prop:value=move || field.start.get()
                            on:input=move |ev| field.start.set(event_target_value(&ev))
                            placeholder="e.g., 22"
                        />
                        <input
                            type="number"
                            class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                            aria-label="Port end"
                            prop:disabled=move || !ports_allowed.get()
                            prop:value=move || field.end.get()
                            on:input=move |ev| field.end.set(event_target_value(&ev))
                            placeholder="blank = single port"
                        />
                    </div>
                }
                .into_any()
            }}
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_matches_every_term_in_any_field() {
        let fields = ["Allow SSH", "lan", "22", "10.0.0.0/8"];
        assert!(matches_filter("", &fields));
        assert!(matches_filter("ssh", &fields));
        assert!(matches_filter("SSH 22", &fields));
        assert!(matches_filter("  lan   10.0 ", &fields));
        assert!(!matches_filter("ssh 443", &fields));
        assert!(!matches_filter("nothing", &fields));
    }

    #[test]
    fn filter_accepts_owned_fields() {
        let fields = vec!["web_ports".to_string(), "wan".to_string()];
        assert!(matches_filter("WEB", &fields));
        assert!(matches_filter("", &Vec::<String>::new()));
    }

    #[test]
    fn move_by_swaps_with_neighbour_and_stops_at_edges() {
        let ids = [10, 20, 30];
        assert_eq!(move_by(&ids, 20, -1), Some(vec![20, 10, 30]));
        assert_eq!(move_by(&ids, 20, 1), Some(vec![10, 30, 20]));
        assert_eq!(move_by(&ids, 10, -1), None);
        assert_eq!(move_by(&ids, 30, 1), None);
        assert_eq!(move_by(&ids, 99, 1), None);
    }

    #[test]
    fn move_onto_places_dragged_row_at_target() {
        let ids = [1, 2, 3, 4];
        // Dragging up lands before the target.
        assert_eq!(move_onto(&ids, 4, 2), Some(vec![1, 4, 2, 3]));
        // Dragging down lands after the target.
        assert_eq!(move_onto(&ids, 1, 3), Some(vec![2, 3, 1, 4]));
        assert_eq!(move_onto(&ids, 2, 2), None);
        assert_eq!(move_onto(&ids, 2, 9), None);
    }

    #[test]
    fn counts_are_scaled_for_humans() {
        assert_eq!(format_count(0), "0");
        assert_eq!(format_count(999), "999");
        assert_eq!(format_count(1_234), "1.2k");
        assert_eq!(format_count(12_345), "12k");
        assert_eq!(format_count(3_400_000), "3.4M");
    }

    #[test]
    fn byte_counts_carry_units() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1_024), "1.0 KiB");
        assert_eq!(format_bytes(100_000), "98 KiB");
        assert_eq!(format_bytes(1_572_864), "1.5 MiB");
    }

    fn counter(kind: &str, rule_id: i64, packets: u64, bytes: u64) -> FirewallRuleCounter {
        FirewallRuleCounter {
            kind: kind.into(),
            rule_id,
            packets,
            bytes,
        }
    }

    #[test]
    fn hits_sum_only_the_requested_kinds_of_one_rule() {
        let counters = vec![
            counter("portfwd", 2, 10, 1_000),
            counter("portfwd-hairpin", 2, 5, 500),
            counter("portfwd-accept", 2, 99, 9_999),
            counter("portfwd", 3, 1, 1),
        ];
        assert_eq!(
            hits_for(&counters, &["portfwd", "portfwd-hairpin"], 2),
            (15, 1_500)
        );
        assert_eq!(hits_for(&counters, &["portfwd"], 7), (0, 0));
    }

    #[test]
    fn port_field_values_follow_the_selected_mode() {
        let owner = Owner::new();
        owner.with(|| {
            let field = PortField::new(Some(443), None, None);
            assert_eq!(field.values(), (Some(443), None, None));
            field.use_group.set(true);
            field.group.set("web".into());
            assert_eq!(field.values(), (None, None, Some("web".into())));
        });
    }

    #[test]
    fn address_field_values_follow_the_selected_mode() {
        let owner = Owner::new();
        owner.with(|| {
            let field = AddressField::new(Some("10.0.0.0/8".into()), None);
            assert_eq!(field.values(), (Some("10.0.0.0/8".into()), None));
            field.use_group.set(true);
            field.group.set("lan".into());
            assert_eq!(field.values(), (None, Some("lan".into())));
            field.group.set(String::new());
            assert_eq!(field.values(), (None, None));
        });
    }
}
