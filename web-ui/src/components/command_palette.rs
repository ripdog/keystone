//! Command palette: one search box over pages, actions and LAN entities.
//!
//! Opened with Ctrl-K (Cmd-K on macOS), with "/" when focus is outside a text
//! field, or from the search button in the workspace toolbar. Pages and
//! actions are always available. Devices, firewall rules, DNS records and
//! interfaces are fetched the first time the palette opens and reused for
//! [`ENTITY_TTL_MS`]. A failed fetch keeps that group's last list and leaves
//! the other groups working.

use std::future::Future;

use crate::api;
use crate::components::{NAV_ITEMS, PendingActions, icon_path, pending_summary};
use keystone_core::{
    Client, DnsmasqHostRecord, DnsmasqStaticLease, ForwardRule, InputRule, Interface, PortForward,
    SimplePortForward,
};
use leptos::ev;
use leptos::html;
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::{NavigateOptions, hooks::use_navigate};
use wasm_bindgen::JsCast;

/// How long fetched entities are reused before the next open refetches them.
const ENTITY_TTL_MS: f64 = 30_000.0;

/// Results shown per group. A longer group is narrowed by typing.
const MAX_PER_GROUP: usize = 8;

const PREFIX_SCORE: u32 = 400;
const WORD_SCORE: u32 = 300;
const SUBSTRING_SCORE: u32 = 200;
const SUBSEQUENCE_SCORE: u32 = 100;

/// Result groups, in display order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Category {
    Pages,
    Actions,
    Clients,
    Firewall,
    DnsDhcp,
    Interfaces,
}

impl Category {
    const ALL: [Category; 6] = [
        Category::Pages,
        Category::Actions,
        Category::Clients,
        Category::Firewall,
        Category::DnsDhcp,
        Category::Interfaces,
    ];

    fn label(self) -> &'static str {
        match self {
            Category::Pages => "Pages",
            Category::Actions => "Actions",
            Category::Clients => "Clients",
            Category::Firewall => "Firewall",
            Category::DnsDhcp => "DNS & DHCP",
            Category::Interfaces => "Interfaces",
        }
    }

    /// Only pages and actions are listed before anything is typed.
    fn listed_when_empty(self) -> bool {
        matches!(self, Category::Pages | Category::Actions)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PaletteAction {
    ApplyAll,
    Review,
    Discard,
    Snapshot,
    Logout,
}

/// Where a result leads when it is chosen.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Target {
    /// A route, possibly with a query string.
    Href(String),
    Action(PaletteAction),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Candidate {
    category: Category,
    title: String,
    /// Muted line under the title, such as an address or the page's group.
    subtitle: String,
    /// Extra searchable text. It is never shown.
    keywords: String,
    icon: &'static str,
    target: Target,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ResultGroup {
    category: Category,
    items: Vec<Candidate>,
}

/// How well `query` matches `text`, or `None` for no match. Comparison ignores
/// case. Tiers, best first: prefix, start of a word, substring, letters in
/// order. Within a tier, a shorter text ranks higher.
fn match_score(query: &str, text: &str) -> Option<u32> {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return Some(0);
    }
    let text = text.to_lowercase();
    let closeness = 50u32.saturating_sub(text.chars().count() as u32);
    if text.starts_with(&query) {
        return Some(PREFIX_SCORE + closeness);
    }
    if text
        .split(|c: char| !c.is_alphanumeric())
        .any(|word| word.starts_with(&query))
    {
        return Some(WORD_SCORE + closeness);
    }
    if text.contains(&query) {
        return Some(SUBSTRING_SCORE + closeness);
    }
    is_subsequence(&query, &text).then_some(SUBSEQUENCE_SCORE)
}

/// Whether the non-space characters of `needle` appear in `haystack` in order.
fn is_subsequence(needle: &str, haystack: &str) -> bool {
    let mut chars = haystack.chars();
    needle
        .chars()
        .filter(|c| !c.is_whitespace())
        .all(|wanted| chars.any(|c| c == wanted))
}

/// Best score of one query word against the title and keywords. Keyword
/// matches count at half weight, so a title hit outranks a keyword hit.
fn field_score(query: &str, title: &str, keywords: &str) -> Option<u32> {
    let title_score = match_score(query, title);
    let keyword_score = match_score(query, keywords).map(|score| score / 2);
    title_score.max(keyword_score)
}

/// Score of a candidate for a whole query. A multi-word query matches when
/// every word matches on its own, and then scores as its weakest word.
fn score_candidate(query: &str, title: &str, keywords: &str) -> Option<u32> {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return Some(0);
    }
    if let Some(score) = field_score(&query, title, keywords) {
        return Some(score);
    }
    let words: Vec<&str> = query.split_whitespace().collect();
    if words.len() < 2 {
        return None;
    }
    words
        .iter()
        .map(|word| field_score(word, title, keywords))
        .collect::<Option<Vec<u32>>>()?
        .into_iter()
        .min()
}

/// Filter and rank candidates into display groups. Each group keeps its best
/// [`MAX_PER_GROUP`] matches. Equal scores keep the order they were given in.
/// With an empty query only pages and actions are listed, in their own order.
fn rank_groups(query: &str, candidates: &[Candidate]) -> Vec<ResultGroup> {
    let query = query.trim();
    let mut groups = Vec::new();
    for category in Category::ALL {
        if query.is_empty() && !category.listed_when_empty() {
            continue;
        }
        let mut scored: Vec<(u32, &Candidate)> = candidates
            .iter()
            .filter(|candidate| candidate.category == category)
            .filter_map(|candidate| {
                score_candidate(query, &candidate.title, &candidate.keywords)
                    .map(|score| (score, candidate))
            })
            .collect();
        // The sort is stable, so equal scores keep their original order.
        scored.sort_by_key(|(score, _)| std::cmp::Reverse(*score));
        let items: Vec<Candidate> = scored
            .into_iter()
            .take(MAX_PER_GROUP)
            .map(|(_, candidate)| candidate.clone())
            .collect();
        if !items.is_empty() {
            groups.push(ResultGroup { category, items });
        }
    }
    groups
}

/// The result at `index` when the groups are read as one list, top to bottom.
fn nth_candidate(groups: &[ResultGroup], index: usize) -> Option<&Candidate> {
    groups
        .iter()
        .flat_map(|group| group.items.iter())
        .nth(index)
}

fn result_count(groups: &[ResultGroup]) -> usize {
    groups.iter().map(|group| group.items.len()).sum()
}

/// `a · b`, skipping empty parts.
fn join(parts: &[&str]) -> String {
    parts
        .iter()
        .copied()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" \u{b7} ")
}

/// Space-separated keyword text.
fn keywords<I, S>(parts: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    parts
        .into_iter()
        .map(|part| part.as_ref().to_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// `name` when it is present and not empty, otherwise `fallback`.
fn named(name: Option<&str>, fallback: &str) -> String {
    name.filter(|name| !name.is_empty())
        .unwrap_or(fallback)
        .to_owned()
}

fn page_candidates() -> Vec<Candidate> {
    NAV_ITEMS
        .iter()
        .map(|item| Candidate {
            category: Category::Pages,
            title: item.title.to_owned(),
            subtitle: (if item.group.is_empty() {
                item.section
            } else {
                item.group
            })
            .to_owned(),
            keywords: item.keywords.to_owned(),
            icon: item.icon,
            target: Target::Href(item.href.to_owned()),
        })
        .collect()
}

fn action_candidates(summary: Option<&str>) -> Vec<Candidate> {
    let pending = summary.unwrap_or("Nothing pending");
    let action = |title: &str, subtitle: &str, keywords: &str, icon, action| Candidate {
        category: Category::Actions,
        title: title.to_owned(),
        subtitle: subtitle.to_owned(),
        keywords: keywords.to_owned(),
        icon,
        target: Target::Action(action),
    };
    vec![
        action(
            "Apply all pending changes",
            pending,
            "apply commit deploy activate publish save live",
            "check",
            PaletteAction::ApplyAll,
        ),
        action(
            "Review pending changes",
            pending,
            "review diff compare changes preview see",
            "eye",
            PaletteAction::Review,
        ),
        action(
            "Discard pending changes",
            pending,
            "discard revert undo reset cancel drop",
            "undo",
            PaletteAction::Discard,
        ),
        action(
            "Create configuration snapshot",
            "Save the current configuration to history",
            "snapshot backup checkpoint save history configuration",
            "camera",
            PaletteAction::Snapshot,
        ),
        action(
            "Log out",
            "End this session",
            "sign out signout logout quit session",
            "power",
            PaletteAction::Logout,
        ),
    ]
}

fn client_candidates(clients: &[Client]) -> Vec<Candidate> {
    clients
        .iter()
        .map(|client| {
            let address = client
                .ipv4
                .first()
                .or(client.ipv6.first())
                .map_or("No address", String::as_str);
            Candidate {
                category: Category::Clients,
                title: named(client.hostname.as_deref(), &client.mac),
                subtitle: join(&[address, client.mac.as_str()]),
                keywords: keywords(
                    client
                        .ipv4
                        .iter()
                        .chain(&client.ipv6)
                        .map(String::as_str)
                        .chain(client.vendor.as_deref())
                        .chain([client.mac.as_str()]),
                ),
                icon: "devices",
                target: Target::Href(format!("/clients?q={}", urlencoding::encode(&client.mac))),
            }
        })
        .collect()
}

fn firewall_candidates(
    inputs: &[InputRule],
    forwards: &[ForwardRule],
    simple: &[SimplePortForward],
    other: &[PortForward],
) -> Vec<Candidate> {
    let mut out = Vec::new();
    out.extend(inputs.iter().map(|rule| {
        Candidate {
            category: Category::Firewall,
            title: named(Some(rule.name.as_str()), "Unnamed input rule"),
            subtitle: join(&["Input rule", rule.zone.as_deref().unwrap_or("any zone")]),
            keywords: keywords(
                [
                    rule.description.as_deref(),
                    rule.zone.as_deref(),
                    rule.source_ip.as_deref(),
                ]
                .into_iter()
                .flatten(),
            ),
            icon: "shield",
            target: Target::Href("/firewall/input-rules".to_owned()),
        }
    }));
    out.extend(forwards.iter().map(|rule| {
        let route = format!(
            "{} to {}",
            rule.source_zone.as_deref().unwrap_or("any"),
            rule.dest_zone.as_deref().unwrap_or("any")
        );
        Candidate {
            category: Category::Firewall,
            title: named(Some(rule.name.as_str()), "Unnamed forward rule"),
            subtitle: join(&["Forward rule", route.as_str()]),
            keywords: keywords(
                [
                    rule.description.as_deref(),
                    rule.source_zone.as_deref(),
                    rule.dest_zone.as_deref(),
                    rule.source_ip.as_deref(),
                ]
                .into_iter()
                .flatten(),
            ),
            icon: "shield",
            target: Target::Href("/firewall/forward-rules".to_owned()),
        }
    }));
    out.extend(simple.iter().map(|forward| {
        let port = forward.external_port.to_string();
        let destination = forward
            .ipv4
            .as_deref()
            .or(forward.ipv6.as_deref())
            .unwrap_or("no destination");
        Candidate {
            category: Category::Firewall,
            title: named(Some(forward.name.as_str()), "Unnamed port forward"),
            subtitle: join(&["Port forward", destination]),
            keywords: keywords(
                [
                    forward.ipv4.as_deref(),
                    forward.ipv6.as_deref(),
                    forward.source_zone.as_deref(),
                    forward.source_ip.as_deref(),
                    forward.description.as_deref(),
                ]
                .into_iter()
                .flatten()
                .chain(std::iter::once(port.as_str())),
            ),
            icon: "shield",
            target: Target::Href("/firewall/port-forwards".to_owned()),
        }
    }));
    out.extend(other.iter().map(|forward| {
        Candidate {
            category: Category::Firewall,
            title: named(Some(forward.name.as_str()), "Unnamed port forward"),
            subtitle: join(&["Port forward", forward.dest_ip.as_str()]),
            keywords: keywords(
                [
                    Some(forward.dest_ip.as_str()),
                    forward.description.as_deref(),
                    forward.source_zone.as_deref(),
                    forward.source_ip.as_deref(),
                ]
                .into_iter()
                .flatten(),
            ),
            icon: "shield",
            target: Target::Href("/firewall/port-forwards".to_owned()),
        }
    }));
    out
}

fn dns_candidates(leases: &[DnsmasqStaticLease], records: &[DnsmasqHostRecord]) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = leases
        .iter()
        .map(|lease| Candidate {
            category: Category::DnsDhcp,
            title: named(lease.hostname.as_deref(), &lease.ip_address),
            subtitle: join(&[
                "Static lease",
                lease.ip_address.as_str(),
                lease.mac_address.as_str(),
            ]),
            keywords: keywords(
                [lease.mac_address.as_str(), lease.ip_address.as_str()]
                    .into_iter()
                    .chain(lease.hostname.as_deref())
                    .chain(lease.client_id.as_deref()),
            ),
            icon: "dns",
            target: Target::Href("/dnsmasq/static-leases".to_owned()),
        })
        .collect();
    out.extend(records.iter().map(|record| {
        let address = record
            .ipv4_address
            .as_deref()
            .or(record.ipv6_address.as_deref())
            .unwrap_or("");
        Candidate {
            category: Category::DnsDhcp,
            title: named(record.hostnames.first().map(String::as_str), "Host record"),
            subtitle: join(&["Host record", address]),
            keywords: keywords(
                record
                    .hostnames
                    .iter()
                    .map(String::as_str)
                    .chain(record.ipv4_address.as_deref())
                    .chain(record.ipv6_address.as_deref()),
            ),
            icon: "dns",
            target: Target::Href("/dnsmasq/host-records".to_owned()),
        }
    }));
    out
}

fn interface_candidates(interfaces: &[Interface]) -> Vec<Candidate> {
    interfaces
        .iter()
        .map(|iface| Candidate {
            category: Category::Interfaces,
            title: iface.name.clone(),
            subtitle: iface.address.as_deref().unwrap_or("No address").to_owned(),
            keywords: keywords(
                iface
                    .ipv4_addresses
                    .iter()
                    .map(String::as_str)
                    .chain([iface.name.as_str()]),
            ),
            icon: "network",
            target: Target::Href(format!("/interfaces/{}", urlencoding::encode(&iface.name))),
        })
        .collect()
}

/// Cached entity lists. Each type loads on its own, so one failing request
/// does not empty the others.
#[derive(Clone, Copy)]
struct Entities {
    clients: RwSignal<Vec<Client>>,
    input_rules: RwSignal<Vec<InputRule>>,
    forward_rules: RwSignal<Vec<ForwardRule>>,
    simple_forwards: RwSignal<Vec<SimplePortForward>>,
    port_forwards: RwSignal<Vec<PortForward>>,
    static_leases: RwSignal<Vec<DnsmasqStaticLease>>,
    host_records: RwSignal<Vec<DnsmasqHostRecord>>,
    interfaces: RwSignal<Vec<Interface>>,
    /// Time of the last request in milliseconds, or 0 before the first.
    requested_at: RwSignal<f64>,
}

impl Entities {
    fn new() -> Self {
        Self {
            clients: RwSignal::new(Vec::new()),
            input_rules: RwSignal::new(Vec::new()),
            forward_rules: RwSignal::new(Vec::new()),
            simple_forwards: RwSignal::new(Vec::new()),
            port_forwards: RwSignal::new(Vec::new()),
            static_leases: RwSignal::new(Vec::new()),
            host_records: RwSignal::new(Vec::new()),
            interfaces: RwSignal::new(Vec::new()),
            requested_at: RwSignal::new(0.0),
        }
    }

    /// Every entity as a candidate. Reads the signals, so it is tracked.
    fn candidates(self) -> Vec<Candidate> {
        let mut out = Vec::new();
        self.clients
            .with(|items| out.extend(client_candidates(items)));
        self.interfaces
            .with(|items| out.extend(interface_candidates(items)));
        self.static_leases.with(|leases| {
            self.host_records
                .with(|records| out.extend(dns_candidates(leases, records)))
        });
        self.input_rules.with(|inputs| {
            self.forward_rules.with(|forwards| {
                self.simple_forwards.with(|simple| {
                    self.port_forwards.with(|other| {
                        out.extend(firewall_candidates(inputs, forwards, simple, other))
                    })
                })
            })
        });
        out
    }
}

/// Stores the result of one request in `target`. A failed request keeps the
/// last good list.
fn load<T, Fut>(
    target: RwSignal<Vec<T>>,
    on_unauthorized: Callback<()>,
    token: String,
    request: impl FnOnce(String) -> Fut,
) where
    T: Send + Sync + 'static,
    Fut: Future<Output = Result<Vec<T>, String>> + 'static,
{
    let future = request(token);
    spawn_local(async move {
        match future.await {
            Ok(items) => target.set(items),
            Err(e) if e == "Unauthorized" => on_unauthorized.run(()),
            Err(_) => {}
        }
    });
}

/// Requests every entity type again if the cached copies are older than
/// [`ENTITY_TTL_MS`].
fn refresh_if_stale(
    entities: Entities,
    auth_token: ReadSignal<Option<String>>,
    on_unauthorized: Callback<()>,
) {
    let now = js_sys::Date::now();
    if now - entities.requested_at.get_untracked() < ENTITY_TTL_MS {
        return;
    }
    let Some(token) = auth_token.get_untracked() else {
        return;
    };
    entities.requested_at.set(now);

    load(
        entities.clients,
        on_unauthorized,
        token.clone(),
        |t| async move { api::fetch_clients(&t).await },
    );
    load(
        entities.interfaces,
        on_unauthorized,
        token.clone(),
        |t| async move {
            api::fetch_system_state(&t)
                .await
                .map(|state| state.interfaces)
        },
    );
    load(
        entities.input_rules,
        on_unauthorized,
        token.clone(),
        |t| async move { api::fetch_input_rules(&t).await },
    );
    load(
        entities.forward_rules,
        on_unauthorized,
        token.clone(),
        |t| async move { api::fetch_forward_rules(&t).await },
    );
    load(
        entities.simple_forwards,
        on_unauthorized,
        token.clone(),
        |t| async move { api::fetch_simple_forwards(&t).await },
    );
    load(
        entities.port_forwards,
        on_unauthorized,
        token.clone(),
        |t| async move { api::fetch_other_port_forwards(&t).await },
    );

    spawn_local(async move {
        match api::fetch_dnsmasq_state(&token).await {
            Ok(state) => {
                entities.static_leases.set(state.static_leases);
                entities.host_records.set(state.host_records);
            }
            Err(e) if e == "Unauthorized" => on_unauthorized.run(()),
            Err(_) => {}
        }
    });
}

fn create_snapshot(
    auth_token: ReadSignal<Option<String>>,
    on_unauthorized: Callback<()>,
    actions: PendingActions,
) {
    let Some(token) = auth_token.get_untracked() else {
        return;
    };
    spawn_local(async move {
        match api::create_snapshot(&token, None).await {
            Ok(response) => actions.notify(response.success, response.message),
            Err(e) if e == "Unauthorized" => on_unauthorized.run(()),
            Err(e) => actions.notify(false, format!("Could not create the snapshot: {e}")),
        }
    });
}

/// Carries out a chosen action. The palette has already closed.
fn run_action(
    action: PaletteAction,
    actions: PendingActions,
    auth_token: ReadSignal<Option<String>>,
    on_unauthorized: Callback<()>,
    on_logout: Callback<()>,
) {
    let nothing_pending = actions.pending.with_untracked(|pending| {
        pending
            .as_ref()
            .is_some_and(|pending| pending_summary(&pending.components).is_none())
    });
    match action {
        PaletteAction::ApplyAll if nothing_pending => {
            actions.notify(true, "Nothing is waiting to be applied.");
        }
        PaletteAction::ApplyAll => actions.apply_all.run(()),
        PaletteAction::Review => actions.reviewing.set(true),
        PaletteAction::Discard if nothing_pending => {
            actions.notify(true, "Nothing is waiting to be discarded.");
        }
        PaletteAction::Discard => actions.discard.run(None),
        PaletteAction::Snapshot => create_snapshot(auth_token, on_unauthorized, actions),
        PaletteAction::Logout => on_logout.run(()),
    }
}

/// Whether a key event comes from a field the user is typing in.
fn is_text_entry(event: &web_sys::KeyboardEvent) -> bool {
    let Some(element) = event
        .target()
        .and_then(|target| target.dyn_into::<web_sys::Element>().ok())
    else {
        return false;
    };
    matches!(element.tag_name().as_str(), "INPUT" | "TEXTAREA" | "SELECT")
        || element
            .dyn_ref::<web_sys::HtmlElement>()
            .is_some_and(|element| element.is_content_editable())
}

fn option_id(index: usize) -> String {
    format!("command-palette-option-{index}")
}

fn result_row(
    index: usize,
    item: Candidate,
    active: RwSignal<usize>,
    selected: Memo<usize>,
    run: Callback<Target>,
) -> impl IntoView {
    let Candidate {
        title,
        subtitle,
        icon,
        target,
        ..
    } = item;
    let is_selected = move || selected.get() == index;
    view! {
        <div
            id=option_id(index)
            role="option"
            aria-selected=move || if is_selected() { "true" } else { "false" }
            class=move || {
                if is_selected() {
                    "flex cursor-pointer items-center gap-3 rounded-lg bg-sky-400/10 px-3 py-2 text-sky-200 ring-1 ring-inset ring-sky-400/20"
                } else {
                    "flex cursor-pointer items-center gap-3 rounded-lg px-3 py-2 text-slate-300 hover:bg-white/5"
                }
            }
            on:mousemove=move |_| {
                if active.get_untracked() != index {
                    active.set(index);
                }
            }
            on:click=move |_| run.run(target.clone())
        >
            <svg class="h-4 w-4 shrink-0 text-slate-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d=icon_path(icon) />
            </svg>
            <div class="min-w-0 flex-1">
                <div class="truncate text-sm font-medium">{title}</div>
                {(!subtitle.is_empty()).then(|| view! {
                    <div class="truncate text-xs text-slate-500">{subtitle}</div>
                })}
            </div>
        </div>
    }
}

/// Global search over pages, actions and LAN entities. Mounted once in the
/// layout, so the keyboard shortcuts and the entity cache last the whole session.
#[component]
pub fn CommandPalette(
    open: RwSignal<bool>,
    auth_token: ReadSignal<Option<String>>,
    on_unauthorized: Callback<()>,
    on_logout: Callback<()>,
) -> impl IntoView {
    let actions = expect_context::<PendingActions>();
    let navigate = use_navigate();
    let entities = Entities::new();
    let query = RwSignal::new(String::new());
    let active = RwSignal::new(0_usize);
    let input_ref = NodeRef::<html::Input>::new();

    let groups = Memo::new(move |_| {
        let text = query.get();
        let summary = actions.pending.with(|pending| {
            pending
                .as_ref()
                .and_then(|p| pending_summary(&p.components))
        });
        let mut candidates = page_candidates();
        candidates.extend(action_candidates(summary.as_deref()));
        if !text.trim().is_empty() {
            candidates.extend(entities.candidates());
        }
        rank_groups(&text, &candidates)
    });
    let count = move || groups.with(|groups| result_count(groups));
    // The highlight never points past the end of a list that just shrank.
    let selected = Memo::new(move |_| active.get().min(count().saturating_sub(1)));

    let run = Callback::new(move |target: Target| {
        open.set(false);
        match target {
            Target::Href(href) => navigate(&href, NavigateOptions::default()),
            Target::Action(action) => {
                run_action(action, actions, auth_token, on_unauthorized, on_logout);
            }
        }
    });

    // Global shortcuts. The listener is removed when the palette unmounts.
    let shortcuts = window_event_listener(ev::keydown, move |event: web_sys::KeyboardEvent| {
        let key = event.key();
        let modified = event.ctrl_key() || event.meta_key();
        if modified && !event.alt_key() && key.eq_ignore_ascii_case("k") {
            event.prevent_default();
            open.update(|is_open| *is_open = !*is_open);
        } else if key == "/"
            && !modified
            && !event.alt_key()
            && !open.get_untracked()
            && !is_text_entry(&event)
        {
            event.prevent_default();
            open.set(true);
        }
    });
    on_cleanup(move || shortcuts.remove());

    // Each opening starts with an empty query and refreshes stale entities.
    Effect::new(move |_| {
        if open.get() {
            query.set(String::new());
            active.set(0);
            refresh_if_stale(entities, auth_token, on_unauthorized);
        }
    });

    // Focus the search field whenever the palette appears.
    Effect::new(move |_| {
        if open.get()
            && let Some(input) = input_ref.get()
        {
            let _ = input.focus();
        }
    });

    let on_keydown = move |event: web_sys::KeyboardEvent| {
        let total = count();
        match event.key().as_str() {
            "Escape" => {
                event.prevent_default();
                open.set(false);
            }
            "ArrowDown" if total > 0 => {
                event.prevent_default();
                active.set((selected.get_untracked() + 1) % total);
            }
            "ArrowUp" if total > 0 => {
                event.prevent_default();
                active.set((selected.get_untracked() + total - 1) % total);
            }
            "Enter" => {
                event.prevent_default();
                let target = groups.with_untracked(|groups| {
                    nth_candidate(groups, selected.get_untracked()).map(|item| item.target.clone())
                });
                if let Some(target) = target {
                    run.run(target);
                }
            }
            _ => {}
        }
    };

    view! {
        <Show when=move || open.get()>
            <div class="fixed inset-0 z-[60] flex items-start justify-center sm:px-4 sm:pt-[12vh]">
                <div
                    class="absolute inset-0 bg-slate-950/70 backdrop-blur-sm"
                    aria-hidden="true"
                    on:click=move |_| open.set(false)
                ></div>
                <div
                    class="relative flex h-full w-full flex-col overflow-hidden bg-[#0d1727] shadow-2xl sm:h-auto sm:max-h-[70vh] sm:max-w-xl sm:rounded-xl sm:border sm:border-slate-700"
                    role="dialog"
                    aria-modal="true"
                    aria-label="Search pages, actions and devices"
                    on:keydown=on_keydown
                >
                    <div class="flex shrink-0 items-center gap-3 border-b border-white/10 px-4 py-3">
                        <svg class="h-5 w-5 shrink-0 text-slate-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                            <path d=icon_path("search") />
                        </svg>
                        <input
                            node_ref=input_ref
                            type="text"
                            role="combobox"
                            aria-expanded="true"
                            aria-controls="command-palette-results"
                            aria-autocomplete="list"
                            aria-label="Search"
                            aria-activedescendant=move || (count() > 0).then(|| option_id(selected.get()))
                            autocomplete="off"
                            spellcheck="false"
                            placeholder="Search pages, actions and devices"
                            class="min-w-0 flex-1 bg-transparent text-base text-slate-100 placeholder:text-slate-500 focus:outline-none"
                            prop:value=move || query.get()
                            on:input=move |event| {
                                query.set(event_target_value(&event));
                                active.set(0);
                            }
                        />
                        <kbd class="hidden sm:inline-flex rounded-md border border-slate-700 px-1.5 py-0.5 text-[11px] text-slate-400">"Esc"</kbd>
                    </div>

                    <div
                        id="command-palette-results"
                        role="listbox"
                        aria-label="Results"
                        class="min-h-0 flex-1 overflow-y-auto p-2"
                    >
                        {move || {
                            let groups = groups.get();
                            if groups.is_empty() {
                                let text = query.with(|text| text.trim().to_owned());
                                let message = if text.is_empty() {
                                    "Nothing to show.".to_owned()
                                } else {
                                    format!("No matches for \u{201c}{text}\u{201d}.")
                                };
                                return view! {
                                    <p class="px-3 py-8 text-center text-sm text-slate-400" role="status">{message}</p>
                                }
                                .into_any();
                            }
                            let mut offset = 0;
                            groups
                                .into_iter()
                                .map(|group| {
                                    let start = offset;
                                    offset += group.items.len();
                                    view! {
                                        <div role="group" aria-label=group.category.label()>
                                            <p class="px-3 pb-1 pt-3 text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-500" aria-hidden="true">
                                                {group.category.label()}
                                            </p>
                                            {group
                                                .items
                                                .into_iter()
                                                .enumerate()
                                                .map(|(i, item)| result_row(start + i, item, active, selected, run))
                                                .collect_view()}
                                        </div>
                                    }
                                })
                                .collect_view()
                                .into_any()
                        }}
                    </div>

                    <div class="hidden shrink-0 items-center gap-4 border-t border-white/10 px-4 py-2 text-[11px] text-slate-500 sm:flex">
                        <span>"Up and down to move"</span>
                        <span>"Enter to open"</span>
                        <span>"Esc to close"</span>
                    </div>
                </div>
            </div>
        </Show>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keystone_core::InterfaceRole;

    fn candidate(category: Category, title: &str, keywords: &str) -> Candidate {
        Candidate {
            category,
            title: title.to_owned(),
            subtitle: String::new(),
            keywords: keywords.to_owned(),
            icon: "dashboard",
            target: Target::Href(format!("/{}", title.to_lowercase().replace(' ', "-"))),
        }
    }

    fn titles(groups: &[ResultGroup]) -> Vec<&str> {
        groups
            .iter()
            .flat_map(|group| group.items.iter().map(|item| item.title.as_str()))
            .collect()
    }

    fn client(mac: &str, hostname: Option<&str>, ip: &str) -> Client {
        Client {
            mac: mac.to_owned(),
            hostname: hostname.map(str::to_owned),
            vendor: Some("Intel Corporate".to_owned()),
            interface: None,
            zone: None,
            ipv4: vec![ip.to_owned()],
            ipv6: Vec::new(),
            online: true,
            neighbour_state: None,
            lease_expires_at: None,
            static_lease_id: None,
            static_ip: None,
            port_forward_count: 0,
        }
    }

    #[test]
    fn prefix_beats_word_start_beats_substring_beats_subsequence() {
        let prefix = match_score("cli", "Clients").unwrap();
        let word = match_score("dhcp", "DNS & DHCP").unwrap();
        let substring = match_score("ient", "Clients").unwrap();
        let subsequence = match_score("cnt", "Clients").unwrap();
        assert!(prefix > word, "prefix {prefix} vs word {word}");
        assert!(word > substring, "word {word} vs substring {substring}");
        assert!(
            substring > subsequence,
            "substring {substring} vs subsequence {subsequence}"
        );
    }

    #[test]
    fn shorter_text_ranks_higher_within_a_tier() {
        assert!(match_score("port", "Port") > match_score("port", "Port Forwards"));
    }

    #[test]
    fn matching_ignores_case() {
        assert!(match_score("SSH", "SSH Server").is_some());
        assert_eq!(
            match_score("SSH", "SSH Server"),
            match_score("ssh", "ssh server")
        );
    }

    #[test]
    fn unrelated_text_and_reversed_letters_do_not_match() {
        assert_eq!(match_score("zzq", "Clients"), None);
        assert_eq!(match_score("tc", "Clients"), None);
    }

    #[test]
    fn keywords_match_at_lower_weight_than_titles() {
        let keywords = "nat dnat open port forward";
        let title_hit = score_candidate("port", "Port Forwards", keywords).unwrap();
        let keyword_hit = score_candidate("nat", "Port Forwards", keywords).unwrap();
        assert!(title_hit > keyword_hit);
        assert!(
            score_candidate("bufferbloat", "Traffic Shaping", "sqm cake bufferbloat").is_some()
        );
    }

    #[test]
    fn multi_word_queries_need_every_word() {
        let keywords = "reservation dhcp fixed ip mac";
        assert!(score_candidate("static dhcp", "Static Leases", keywords).is_some());
        assert!(score_candidate("static printer", "Static Leases", keywords).is_none());
    }

    #[test]
    fn synonyms_find_their_pages_first() {
        let candidates = page_candidates();
        let top = |query: &str| rank_groups(query, &candidates)[0].items[0].title.clone();
        assert_eq!(top("nat"), "Port Forwards");
        assert_eq!(top("sqm"), "Traffic Shaping");
        assert_eq!(top("cake"), "Traffic Shaping");
        assert_eq!(top("reservation"), "Static Leases");
        assert_eq!(top("backup"), "Configuration history");
    }

    #[test]
    fn empty_query_lists_only_pages_and_actions_in_their_order() {
        let mut candidates = page_candidates();
        candidates.extend(action_candidates(None));
        candidates.push(candidate(Category::Clients, "Laptop", ""));

        let groups = rank_groups("   ", &candidates);
        let categories: Vec<Category> = groups.iter().map(|group| group.category).collect();
        assert_eq!(categories, vec![Category::Pages, Category::Actions]);
        assert_eq!(groups[0].items.len(), MAX_PER_GROUP);
        assert_eq!(groups[0].items[0].title, "Dashboard");
        assert_eq!(groups[1].items.len(), 5);
    }

    #[test]
    fn each_group_is_capped_and_equal_scores_keep_their_order() {
        let candidates: Vec<Candidate> = (1..=12)
            .map(|n| candidate(Category::Pages, &format!("Item {n}"), ""))
            .collect();
        let groups = rank_groups("item", &candidates);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].items.len(), MAX_PER_GROUP);
        let shown: Vec<&str> = titles(&groups);
        assert_eq!(shown[0], "Item 1");
        assert_eq!(shown[7], "Item 8");
    }

    #[test]
    fn groups_follow_category_order_and_empty_groups_are_dropped() {
        let candidates = vec![
            candidate(Category::Interfaces, "office0", ""),
            candidate(Category::Clients, "Printer", "office"),
            candidate(Category::Firewall, "Unrelated", ""),
        ];
        let groups = rank_groups("office", &candidates);
        let categories: Vec<Category> = groups.iter().map(|group| group.category).collect();
        assert_eq!(categories, vec![Category::Clients, Category::Interfaces]);
    }

    #[test]
    fn selection_walks_the_groups_top_to_bottom() {
        let candidates = vec![
            candidate(Category::Interfaces, "office0", ""),
            candidate(Category::Clients, "Printer", "office"),
        ];
        let groups = rank_groups("office", &candidates);
        assert_eq!(nth_candidate(&groups, 0).unwrap().title, "Printer");
        assert_eq!(nth_candidate(&groups, 1).unwrap().title, "office0");
        assert!(nth_candidate(&groups, 2).is_none());
        assert_eq!(result_count(&groups), 2);
    }

    #[test]
    fn a_client_links_to_the_clients_page_filtered_by_its_mac() {
        let clients = [client("aa:bb:cc:00:00:01", Some("Laptop"), "192.168.1.20")];
        let candidates = client_candidates(&clients);
        let groups = rank_groups("192.168.1.2", &candidates);
        let item = nth_candidate(&groups, 0).unwrap();
        assert_eq!(item.title, "Laptop");
        assert_eq!(item.subtitle, "192.168.1.20 \u{b7} aa:bb:cc:00:00:01");
        assert_eq!(
            item.target,
            Target::Href("/clients?q=aa%3Abb%3Acc%3A00%3A00%3A01".to_owned())
        );
    }

    #[test]
    fn unnamed_clients_are_titled_by_their_mac() {
        let clients = [client("aa:bb:cc:00:00:02", None, "192.168.1.30")];
        let candidates = client_candidates(&clients);
        assert_eq!(candidates[0].title, "aa:bb:cc:00:00:02");
        assert_eq!(
            candidates[0].subtitle,
            "192.168.1.30 \u{b7} aa:bb:cc:00:00:02"
        );
    }

    #[test]
    fn firewall_rules_and_static_leases_link_to_their_pages() {
        let forward = PortForward {
            id: Some(1),
            name: "web server".to_owned(),
            dest_ip: "192.168.1.50".to_owned(),
            ..Default::default()
        };
        let firewall = firewall_candidates(&[], &[], &[], std::slice::from_ref(&forward));
        assert_eq!(firewall[0].title, "web server");
        assert_eq!(
            firewall[0].target,
            Target::Href("/firewall/port-forwards".to_owned())
        );

        let lease = DnsmasqStaticLease {
            mac_address: "aa:bb:cc:00:00:03".to_owned(),
            ip_address: "192.168.1.60".to_owned(),
            hostname: Some("printer".to_owned()),
            ..Default::default()
        };
        let dns = dns_candidates(&[lease], &[]);
        assert_eq!(dns[0].title, "printer");
        assert!(dns[0].keywords.contains("192.168.1.60"));
        assert_eq!(
            dns[0].target,
            Target::Href("/dnsmasq/static-leases".to_owned())
        );
    }

    #[test]
    fn interfaces_link_to_their_edit_page() {
        let iface = Interface {
            name: "eth1".to_owned(),
            address: Some("10.0.0.1/24".to_owned()),
            ipv4_addresses: vec!["10.0.0.1".to_owned()],
            ipv6_addresses: Vec::new(),
            dhcp_enabled: false,
            role: InterfaceRole::LAN,
            enabled: true,
        };
        let candidates = interface_candidates(&[iface]);
        assert_eq!(candidates[0].subtitle, "10.0.0.1/24");
        assert_eq!(
            candidates[0].target,
            Target::Href("/interfaces/eth1".to_owned())
        );
    }

    #[test]
    fn actions_show_the_pending_summary_when_there_is_one() {
        let actions = action_candidates(Some("2 pending changes \u{b7} Firewall, Web Server"));
        assert_eq!(
            actions[0].subtitle,
            "2 pending changes \u{b7} Firewall, Web Server"
        );
        assert_eq!(action_candidates(None)[0].subtitle, "Nothing pending");
        assert_eq!(actions[4].target, Target::Action(PaletteAction::Logout));
    }
}
