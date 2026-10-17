//! Global pending-changes bar, review drawer and apply flow.
//!
//! Configuration edits are saved to the database at once, so the generated
//! system files can lag behind the database until the next apply. The bar at
//! the top of every page is the one status surface for this: it shows pending
//! changes, the progress of an action, an applied change awaiting confirmation,
//! or a failure. The drawer shows exactly what the apply would write.

use crate::api;
use crate::components::{Toasts, use_toasts};
use gloo_timers::callback::Interval;
use keystone_core::changes::{
    AwaitingConfirmation, Component, ComponentDiff, FileChangeStatus, FileDiff,
    PendingChangesResponse,
};
use keystone_core::{ApplyAllResponse, ApplyComponentResults, ComponentResult};
use leptos::html;
use leptos::prelude::*;
use leptos::task::spawn_local;

/// Milliseconds between background polls of the pending changes.
const POLL_MS: u32 = 5_000;

/// Counter bumped whenever a page changes configuration. The pending bar and
/// the confirmation banner refetch straight away when it changes, instead of
/// waiting for their next poll.
#[derive(Clone, Copy)]
pub struct ConfigRefresh(pub RwSignal<u32>);

impl ConfigRefresh {
    pub fn bump(self) {
        self.0.update(|count| *count = count.wrapping_add(1));
    }
}

/// Callback a page runs after a successful save, delete or import so the
/// pending bar refreshes at once. Safe to call from async tasks: the context is
/// looked up while the page is built, not when the callback runs.
pub fn use_config_changed() -> Callback<()> {
    let refresh = use_context::<ConfigRefresh>();
    Callback::new(move |()| {
        if let Some(refresh) = refresh {
            refresh.bump();
        }
    })
}

/// Name shown for a component in the bar, the drawer and the history page.
pub fn component_display_name(component: Component) -> &'static str {
    match component {
        Component::Networkd => "Network",
        Component::Firewall => "Firewall",
        Component::Dnsmasq => "DNS & DHCP",
        Component::Caddy => "Web Server",
        Component::Sqm => "Traffic Shaping",
        Component::Upnp => "UPnP / NAT-PMP",
        Component::Blocky => "DNS filtering",
        Component::Wireless => "Wi-Fi",
    }
}

/// Components that have pending changes, in apply order. A component whose
/// generation failed counts as changed, so it is listed too.
pub fn changed_components(components: &[ComponentDiff]) -> Vec<Component> {
    let mut changed: Vec<Component> = components
        .iter()
        .filter(|diff| diff.changed)
        .map(|diff| diff.component)
        .collect();
    changed.sort();
    changed.dedup();
    changed
}

/// `1 pending change` or `3 pending changes`.
pub fn pending_count_label(count: usize) -> String {
    match count {
        1 => "1 pending change".to_string(),
        n => format!("{n} pending changes"),
    }
}

/// One-line summary for the bar, or `None` when nothing is pending.
pub fn pending_summary(components: &[ComponentDiff]) -> Option<String> {
    let changed = changed_components(components);
    if changed.is_empty() {
        return None;
    }
    let names: Vec<&str> = changed.into_iter().map(component_display_name).collect();
    Some(format!(
        "{} \u{b7} {}",
        pending_count_label(names.len()),
        names.join(", ")
    ))
}

/// Kind of one line in a unified diff, used to pick its colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffLineKind {
    /// The `---`/`+++` pair naming the two sides. It is not a change.
    FileHeader,
    /// An `@@ -a,b +c,d @@` hunk marker.
    Hunk,
    Added,
    Removed,
    Context,
    /// `\ No newline at end of file` and similar notes.
    Note,
}

/// Classify every line of a unified diff.
///
/// The `---`/`+++` lines before the first hunk are file headers. After the
/// first `@@`, a line starting with `+++` or `---` is a real addition or
/// removal, because the header lines cannot appear inside a hunk.
pub fn classify_diff(diff: &str) -> Vec<(DiffLineKind, &str)> {
    let mut in_hunk = false;
    diff.lines()
        .map(|line| {
            if line.starts_with("@@") {
                in_hunk = true;
                return (DiffLineKind::Hunk, line);
            }
            if !in_hunk {
                return (DiffLineKind::FileHeader, line);
            }
            let kind = match line.as_bytes().first() {
                Some(b'+') => DiffLineKind::Added,
                Some(b'-') => DiffLineKind::Removed,
                Some(b'\\') => DiffLineKind::Note,
                _ => DiffLineKind::Context,
            };
            (kind, line)
        })
        .collect()
}

/// Tailwind classes for one diff line. Each line is a block so the `<pre>`
/// keeps its line breaks.
pub fn diff_line_class(kind: DiffLineKind) -> &'static str {
    match kind {
        DiffLineKind::FileHeader => "block text-slate-500",
        DiffLineKind::Hunk => "block bg-sky-400/5 text-sky-300/80",
        DiffLineKind::Added => "block bg-emerald-400/10 text-emerald-300",
        DiffLineKind::Removed => "block bg-rose-400/10 text-rose-300",
        DiffLineKind::Context => "block text-slate-400",
        DiffLineKind::Note => "block text-slate-500 italic",
    }
}

pub fn file_status_label(status: FileChangeStatus) -> &'static str {
    match status {
        FileChangeStatus::Added => "added",
        FileChangeStatus::Modified => "modified",
        FileChangeStatus::Removed => "removed",
    }
}

pub fn file_status_class(status: FileChangeStatus) -> &'static str {
    match status {
        FileChangeStatus::Added => {
            "inline-flex items-center rounded-md bg-emerald-400/10 px-2 py-0.5 text-xs font-medium text-emerald-200 ring-1 ring-inset ring-emerald-400/20"
        }
        FileChangeStatus::Modified => {
            "inline-flex items-center rounded-md bg-amber-400/10 px-2 py-0.5 text-xs font-medium text-amber-200 ring-1 ring-inset ring-amber-400/20"
        }
        FileChangeStatus::Removed => {
            "inline-flex items-center rounded-md bg-rose-400/10 px-2 py-0.5 text-xs font-medium text-rose-200 ring-1 ring-inset ring-rose-400/20"
        }
    }
}

/// Outcome word and detail for one component of an apply.
pub fn apply_outcome_label(result: &ComponentResult) -> &'static str {
    if result.skipped {
        "Skipped"
    } else if result.success {
        "Applied"
    } else {
        "Failed"
    }
}

/// The component results of an apply, in apply order.
pub fn apply_outcome_rows(results: &ApplyComponentResults) -> Vec<(Component, ComponentResult)> {
    vec![
        (Component::Networkd, results.networkd.clone()),
        (Component::Firewall, results.firewall.clone()),
        (Component::Sqm, results.sqm.clone()),
        (Component::Upnp, results.upnp.clone()),
        (Component::Blocky, results.blocky.clone()),
        (Component::Wireless, results.wireless.clone()),
        (Component::Dnsmasq, results.dnsmasq.clone()),
        (Component::Caddy, results.caddy.clone()),
    ]
}

/// Ask the user to confirm a discard. Returns `false` when the prompt is
/// unavailable, so nothing is discarded by accident.
fn confirm(question: &str) -> bool {
    web_sys::window()
        .and_then(|window| window.confirm_with_message(question).ok())
        .unwrap_or(false)
}

/// Message shown when an apply or a discard is tried while an applied change
/// still awaits confirmation.
pub const CONFIRM_FIRST: &str = "Confirm or roll back the previous change first.";

/// Pending-changes state and actions shared by the bar, its review drawer and
/// the command palette. Every apply, discard, confirm and rollback goes through
/// these callbacks, so the busy flag, the messages and the refresh stay in one
/// place.
#[derive(Clone, Copy)]
pub struct PendingActions {
    pub pending: RwSignal<Option<PendingChangesResponse>>,
    /// The applied change that awaits confirmation, if any.
    pub awaiting: Memo<Option<AwaitingConfirmation>>,
    /// A failed action. It stays until the next action starts or the user
    /// dismisses it.
    pub failure: RwSignal<Option<String>>,
    pub load_error: RwSignal<Option<String>>,
    pub busy: RwSignal<bool>,
    /// What the bar says while an action runs, such as "Applying changes".
    pub busy_label: RwSignal<&'static str>,
    /// True while an action runs or a confirmation is pending: configuration
    /// actions are not offered then.
    pub locked: Memo<bool>,
    pub reviewing: RwSignal<bool>,
    pub apply_result: RwSignal<Option<ApplyAllResponse>>,
    /// Apply every component that has pending changes.
    pub apply_all: Callback<()>,
    /// Discard one component's changes, or every change when `None`. Asks first.
    pub discard: Callback<Option<Component>>,
    /// Confirm the applied change that awaits confirmation.
    pub confirm: Callback<()>,
    /// Roll back the applied change that awaits confirmation.
    pub rollback: Callback<()>,
    toasts: Toasts,
}

impl PendingActions {
    /// Report a result: a success is a brief toast, a failure stays in the bar
    /// until dismissed.
    pub fn notify(&self, ok: bool, text: impl Into<String>) {
        let text = text.into();
        if ok {
            self.toasts.success(text);
        } else {
            self.failure.set(Some(text));
        }
    }
}

/// Start an action: the bar shows `label`, and the previous failure is cleared.
fn begin_action(
    busy: RwSignal<bool>,
    busy_label: RwSignal<&'static str>,
    failure: RwSignal<Option<String>>,
    label: &'static str,
) {
    failure.set(None);
    busy_label.set(label);
    busy.set(true);
}

/// Creates the pending-changes state and provides it to the page layout. The
/// palette signal is closed when a confirmation becomes pending, so the
/// confirmation is never hidden behind it. Call after [`ConfigRefresh`] and
/// [`provide_toasts`] are provided.
pub fn provide_pending_actions(
    auth_token: ReadSignal<Option<String>>,
    on_unauthorized: Callback<()>,
    palette_open: RwSignal<bool>,
) -> PendingActions {
    let refresh = expect_context::<ConfigRefresh>();
    let toasts = use_toasts();
    let pending = RwSignal::new(None::<PendingChangesResponse>);
    let awaiting = Memo::new(move |_| {
        pending.with(|response| {
            response
                .as_ref()
                .and_then(|response| response.awaiting_confirmation.clone())
        })
    });
    let failure = RwSignal::new(None::<String>);
    let load_error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let busy_label = RwSignal::new("Working");
    let locked = Memo::new(move |_| busy.get() || awaiting.with(|awaiting| awaiting.is_some()));
    let reviewing = RwSignal::new(false);
    let apply_result = RwSignal::new(None::<ApplyAllResponse>);

    // A confirmation that becomes pending closes the overlays above it. When it
    // is resolved, the apply that caused it and any message about the confirm
    // or rollback are no longer current, so they are cleared.
    Effect::new(move |previous: Option<bool>| {
        let active = awaiting.with(|awaiting| awaiting.is_some());
        if active {
            reviewing.set(false);
            palette_open.set(false);
        } else if previous == Some(true) {
            apply_result.set(None);
            failure.set(None);
        }
        active
    });

    let apply_all = Callback::new(move |()| {
        if busy.get_untracked() {
            return;
        }
        if awaiting.with_untracked(|awaiting| awaiting.is_some()) {
            failure.set(Some(CONFIRM_FIRST.to_string()));
            return;
        }
        let Some(token) = auth_token.get_untracked() else {
            return;
        };
        begin_action(busy, busy_label, failure, "Applying changes");
        apply_result.set(None);
        spawn_local(async move {
            match api::apply_all(&token).await {
                Ok(result) => {
                    if result.success {
                        reviewing.set(false);
                        if !result.firewall_pending_confirmation {
                            toasts.success(result.message.clone());
                        }
                    } else if !result.firewall_pending_confirmation {
                        // The full diagnostics are in the drawer; the bar gets a summary.
                        let parts = failed_part_lines(&result);
                        let text = if parts.is_empty() {
                            result.message.clone()
                        } else {
                            format!("Apply did not finish. {}", parts.join("; "))
                        };
                        failure.set(Some(text));
                    }
                    apply_result.set(Some(result));
                }
                Err(e) if e == "Unauthorized" => on_unauthorized.run(()),
                Err(e) => failure.set(Some(format!("Apply failed: {e}"))),
            }
            busy.set(false);
            refresh.bump();
        });
    });

    let discard = Callback::new(move |component: Option<Component>| {
        let question = match component {
            Some(component) => format!(
                "Discard the pending {} changes? The current configuration is kept as a snapshot in history.",
                component_display_name(component)
            ),
            None => "Discard all pending changes? The current configuration is kept as a snapshot in history.".to_string(),
        };
        if busy.get_untracked() || awaiting.with_untracked(|a| a.is_some()) {
            return;
        }
        if !confirm(&question) {
            return;
        }
        let Some(token) = auth_token.get_untracked() else {
            return;
        };
        begin_action(busy, busy_label, failure, "Discarding changes");
        spawn_local(async move {
            let selection = component.map(|component| vec![component]);
            match api::discard_changes(&token, selection).await {
                Ok(result) if result.success => toasts.success(format!(
                    "{} Pages that are already open may still show the replaced values until reloaded.",
                    result.message
                )),
                Ok(result) => failure.set(Some(result.message)),
                Err(e) if e == "Unauthorized" => on_unauthorized.run(()),
                Err(e) => failure.set(Some(format!("Discard failed: {e}"))),
            }
            busy.set(false);
            refresh.bump();
        });
    });

    let confirm_change = Callback::new(move |()| {
        if busy.get_untracked() {
            return;
        }
        let Some(awaiting_now) = awaiting.get_untracked() else {
            return;
        };
        let Some(token) = auth_token.get_untracked() else {
            return;
        };
        begin_action(busy, busy_label, failure, "Confirming");
        spawn_local(async move {
            match api::confirm_firewall(&token, &awaiting_now.session_id).await {
                Ok(result) if result.success => {
                    apply_result.set(None);
                    toasts.success(result.message);
                }
                Ok(result) => failure.set(Some(result.message)),
                Err(e) if e == "Unauthorized" => on_unauthorized.run(()),
                Err(e) => failure.set(Some(format!("Confirm failed: {e}"))),
            }
            busy.set(false);
            refresh.bump();
        });
    });

    let rollback_change = Callback::new(move |()| {
        if busy.get_untracked() {
            return;
        }
        let Some(token) = auth_token.get_untracked() else {
            return;
        };
        begin_action(busy, busy_label, failure, "Rolling back");
        spawn_local(async move {
            match api::rollback_firewall(&token).await {
                Ok(result) if result.success => {
                    apply_result.set(None);
                    toasts.success(result.message);
                }
                Ok(result) => failure.set(Some(result.message)),
                Err(e) if e == "Unauthorized" => on_unauthorized.run(()),
                Err(e) => failure.set(Some(format!("Rollback failed: {e}"))),
            }
            busy.set(false);
            refresh.bump();
        });
    });

    let actions = PendingActions {
        pending,
        awaiting,
        failure,
        load_error,
        busy,
        busy_label,
        locked,
        reviewing,
        apply_result,
        apply_all,
        discard,
        confirm: confirm_change,
        rollback: rollback_change,
        toasts,
    };
    provide_context(actions);
    actions
}

/// Seconds since the Unix epoch on this browser's clock.
fn browser_now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

/// How often the bar polls while a confirmation is pending, so a rollback shows
/// up at once.
const FAST_POLL_MS: u32 = 2_000;

/// What the bar shows. Exactly one state at a time, in priority order: busy,
/// awaiting confirmation, failed, pending changes.
#[derive(Clone, PartialEq)]
enum BarState {
    Hidden,
    Busy(&'static str),
    Awaiting(AwaitingConfirmation),
    Failed(String),
    Pending(String),
}

impl BarState {
    /// One colour per state.
    fn tone(&self) -> &'static str {
        match self {
            BarState::Hidden => "",
            BarState::Busy(_) => "border-slate-700 bg-slate-900/95 text-slate-200",
            BarState::Awaiting(_) => "border-sky-700/70 bg-sky-950/95 text-sky-100",
            BarState::Failed(_) => "border-red-700/70 bg-red-950/95 text-red-100",
            BarState::Pending(_) => "border-yellow-700/60 bg-yellow-950/95 text-yellow-100",
        }
    }
}

/// Lines describing the parts of an apply that failed, for an apply that also
/// left a change awaiting confirmation.
pub fn failed_part_lines(result: &ApplyAllResponse) -> Vec<String> {
    apply_outcome_rows(&result.components)
        .into_iter()
        .filter(|(_, outcome)| !outcome.success && !outcome.skipped && !outcome.message.is_empty())
        .map(|(component, outcome)| {
            format!("{}: {}", component_display_name(component), outcome.message)
        })
        .collect()
}

/// The single status surface at the top of every page, plus the review drawer
/// it opens. It is above the page and the drawer, so a confirmation can never
/// be hidden.
#[component]
pub fn PendingChangesBar(
    auth_token: ReadSignal<Option<String>>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let refresh = expect_context::<ConfigRefresh>();
    let PendingActions {
        pending,
        awaiting,
        failure,
        load_error,
        busy,
        busy_label,
        locked,
        reviewing,
        apply_result,
        apply_all,
        discard,
        confirm,
        rollback,
        ..
    } = expect_context::<PendingActions>();

    // Daemon clock minus browser clock, measured on each refresh. Countdowns
    // use it, so a skewed browser clock does not change when a change rolls back.
    let clock_skew = RwSignal::new(0_i64);
    let now = RwSignal::new(browser_now_secs());

    let fetch = move || {
        let Some(token) = auth_token.get_untracked() else {
            return;
        };
        spawn_local(async move {
            match api::fetch_pending_changes(&token).await {
                Ok(response) => {
                    clock_skew.set(response.server_time as i64 - browser_now_secs() as i64);
                    load_error.set(None);
                    pending.set(Some(response));
                }
                Err(e) if e == "Unauthorized" => on_unauthorized.run(()),
                // Keep the last known state through a transient daemon error.
                Err(e) => load_error.set(Some(e)),
            }
        });
    };

    // The Effect owns the Interval and restarts it after every bump, and when a
    // confirmation starts or ends, so polling follows the state.
    Effect::new(move |_prev: Option<Option<Interval>>| {
        let _ = refresh.0.get();
        let interval_ms = if awaiting.with(|awaiting| awaiting.is_some()) {
            FAST_POLL_MS
        } else {
            POLL_MS
        };
        if auth_token.get().is_some() {
            fetch();
            Some(Interval::new(interval_ms, fetch))
        } else {
            None
        }
    });

    // Ticks the countdown once a second.
    Effect::new(move |_prev: Option<Interval>| {
        Interval::new(1_000, move || {
            let _ = now.try_set(browser_now_secs());
        })
    });

    let summary = Memo::new(move |_| {
        pending.with(|response| {
            response
                .as_ref()
                .and_then(|response| pending_summary(&response.components))
        })
    });

    let state = Memo::new(move |_| {
        if busy.get() {
            return BarState::Busy(busy_label.get());
        }
        if let Some(awaiting) = awaiting.get() {
            return BarState::Awaiting(awaiting);
        }
        if let Some(message) = failure.get() {
            return BarState::Failed(message);
        }
        match summary.get() {
            Some(text) => BarState::Pending(text),
            None => BarState::Hidden,
        }
    });

    // The drawer opens below the bar, so the bar never covers its title or close
    // button. The bar's height depends on its state, so it is measured again
    // whenever the state or the drawer changes.
    let bar_ref = NodeRef::<html::Div>::new();
    let drawer_top = RwSignal::new(0.0_f64);
    Effect::new(move |_| {
        let _ = state.get();
        let _ = reviewing.get();
        drawer_top.set(
            bar_ref
                .get()
                .map(|bar| bar.get_bounding_client_rect().bottom())
                .unwrap_or(0.0),
        );
    });

    let seconds_left = move |deadline: u64| -> u64 {
        let server_now = now.get() as i64 + clock_skew.get();
        (deadline as i64 - server_now).max(0) as u64
    };

    let review_button = move || {
        summary.get().is_some().then(|| view! {
            <button
                type="button"
                class="px-3 py-1.5 rounded-lg bg-black/20 hover:bg-black/30 ring-1 ring-inset ring-current/30 font-medium"
                on:click=move |_| reviewing.set(true)
            >
                "Review"
            </button>
        })
    };

    view! {
        {move || {
            let current = state.get();
            if current == BarState::Hidden {
                return ().into_any();
            }
            let tone = current.tone();
            let class = format!(
                "sticky top-[57px] lg:top-0 z-[80] flex flex-wrap items-center justify-between gap-x-4 gap-y-2 border-b px-5 py-2.5 sm:px-7 xl:px-10 2xl:px-12 text-sm backdrop-blur {tone}"
            );
            match current {
                BarState::Hidden => ().into_any(),
                BarState::Busy(label) => view! {
                    <div class=class role="status" node_ref=bar_ref>
                        <div class="flex min-w-0 items-center gap-3">
                            <span class="inline-block h-4 w-4 shrink-0 animate-spin rounded-full border-2 border-slate-400 border-t-transparent" aria-hidden="true"></span>
                            <span class="font-medium">{format!("{label}\u{2026}")}</span>
                        </div>
                    </div>
                    }
                    .into_any(),
                BarState::Awaiting(awaiting_now) => {
                    let deadline = awaiting_now.deadline;
                    view! {
                        <div class=class role="status" aria-live="polite" node_ref=bar_ref>
                            <div class="min-w-0 flex-1 space-y-1 break-words">
                                <p class="font-semibold">
                                    "Applied. Confirm within "
                                    <span class="tabular-nums">{move || seconds_left(deadline).to_string()}</span>
                                    "s or it rolls back."
                                </p>
                                {move || {
                                    apply_result.get().and_then(|result| {
                                        let lines = failed_part_lines(&result);
                                        (!lines.is_empty()).then(|| view! {
                                            <p class="text-sky-200/90">
                                                "Some parts did not apply: "
                                                {lines.join("; ")}
                                            </p>
                                        })
                                    })
                                }}
                                {move || summary.get().map(|text| view! {
                                    <p class="text-sky-200/90">
                                        {format!("{text} wait for this confirmation. Apply them after you confirm or roll back.")}
                                    </p>
                                })}
                                {move || failure.get().map(|message| view! {
                                    <p class="font-medium">{message}</p>
                                })}
                            </div>
                            <div class="flex w-full flex-wrap gap-2 sm:w-auto">
                                {review_button}
                                <button
                                    type="button"
                                    class="flex-1 sm:flex-none px-3 py-1.5 rounded-lg bg-red-700 hover:bg-red-600 text-white font-medium disabled:opacity-50"
                                    disabled=move || busy.get()
                                    on:click=move |_| rollback.run(())
                                >
                                    "Roll back"
                                </button>
                                <button
                                    type="button"
                                    class="flex-1 sm:flex-none px-3 py-1.5 rounded-lg bg-green-600 hover:bg-green-700 text-white font-semibold disabled:opacity-50"
                                    disabled=move || busy.get()
                                    on:click=move |_| confirm.run(())
                                >
                                    "Confirm"
                                </button>
                            </div>
                        </div>
                    }
                    .into_any()
                }
                BarState::Failed(message) => view! {
                    <div class=class role="alert" node_ref=bar_ref>
                        <p class="min-w-0 flex-1 break-words font-medium">{message}</p>
                        <div class="flex w-full flex-wrap gap-2 sm:w-auto">
                            {review_button}
                            <button
                                type="button"
                                class="flex-1 sm:flex-none px-3 py-1.5 rounded-lg bg-black/20 hover:bg-black/30 ring-1 ring-inset ring-current/30"
                                on:click=move |_| failure.set(None)
                            >
                                "Dismiss"
                            </button>
                        </div>
                    </div>
                }
                .into_any(),
                BarState::Pending(text) => view! {
                    <div class=class role="status" node_ref=bar_ref>
                        <div class="min-w-0 flex-1 break-words">
                            <span class="font-semibold">{text}</span>
                            <span class="opacity-80">" not yet applied"</span>
                        </div>
                        <div class="flex w-full flex-wrap gap-2 sm:w-auto">
                            <button
                                type="button"
                                class="flex-1 sm:flex-none px-3 py-1.5 rounded-lg bg-yellow-900/70 hover:bg-yellow-800 ring-1 ring-inset ring-yellow-600/60 font-medium"
                                on:click=move |_| reviewing.set(true)
                            >
                                "Review"
                            </button>
                            <button
                                type="button"
                                class="flex-1 sm:flex-none px-3 py-1.5 rounded-lg bg-green-600 hover:bg-green-700 text-white font-medium disabled:opacity-50"
                                disabled=move || locked.get()
                                on:click=move |_| apply_all.run(())
                            >
                                "Apply all"
                            </button>
                            <button
                                type="button"
                                class="flex-1 sm:flex-none px-3 py-1.5 rounded-lg bg-gray-700 hover:bg-red-900/60 text-gray-200 disabled:opacity-50"
                                disabled=move || locked.get()
                                on:click=move |_| discard.run(None)
                            >
                                "Discard"
                            </button>
                        </div>
                    </div>
                }
                .into_any(),
            }
        }}

        <Show when=move || reviewing.get()>
            <div
                class="fixed inset-x-0 bottom-0 z-50 flex justify-end"
                style=move || format!("top: {}px", drawer_top.get())
            >
                <div
                    class="absolute inset-0 bg-black/60"
                    on:click=move |_| reviewing.set(false)
                ></div>
                <aside
                    class="relative flex h-full w-full sm:max-w-2xl flex-col border-l border-slate-700 bg-[#0d1727] shadow-2xl"
                    role="dialog"
                    aria-modal="true"
                    aria-label="Review pending changes"
                >
                    <div class="flex shrink-0 items-center justify-between gap-3 border-b border-white/10 px-5 py-4">
                        <div class="min-w-0">
                            <h2 class="text-lg font-semibold text-white">"Review pending changes"</h2>
                            <p class="text-xs text-slate-400">
                                "Generated files compared with the last applied configuration"
                            </p>
                        </div>
                        <button
                            type="button"
                            aria-label="Close"
                            class="shrink-0 rounded-lg p-2 text-slate-400 hover:bg-white/10 hover:text-white"
                            on:click=move |_| reviewing.set(false)
                        >
                            "\u{2715}"
                        </button>
                    </div>

                    <div class="min-h-0 min-w-0 flex-1 space-y-5 overflow-y-auto overflow-x-hidden p-5">
                        {move || apply_result.get().map(|result| view! { <ApplyResultPanel result=result /> })}

                        {move || load_error.get().map(|e| view! {
                            <div class="rounded-lg border border-red-700 bg-red-900/40 px-3 py-2 text-sm text-red-200 break-words">
                                {format!("Could not refresh pending changes: {e}")}
                            </div>
                        })}

                        <Show
                            when=move || summary.get().is_some()
                            fallback=|| view! {
                                <p class="text-sm text-slate-400">"Nothing is waiting to be applied."</p>
                            }
                        >
                            {move || {
                                let components = pending
                                    .get()
                                    .map(|p| changed_components(&p.components))
                                    .unwrap_or_default();
                                components
                                    .into_iter()
                                    .map(|component| view! {
                                        <ComponentSection
                                            component=component
                                            pending=pending
                                            discard=discard
                                            locked=locked
                                        />
                                    })
                                    .collect_view()
                            }}
                        </Show>
                    </div>

                    <div class="flex shrink-0 flex-wrap items-center justify-end gap-3 border-t border-white/10 px-5 py-4">
                        <p class="mr-auto text-xs text-sky-200/90">
                            {move || awaiting.get().map(|_| CONFIRM_FIRST)}
                        </p>
                        <button
                            type="button"
                            class="px-4 py-2 rounded-lg bg-gray-700 hover:bg-gray-600 text-gray-100"
                            on:click=move |_| reviewing.set(false)
                        >
                            "Close"
                        </button>
                        <button
                            type="button"
                            class="px-4 py-2 rounded-lg bg-green-600 hover:bg-green-700 text-white font-medium disabled:opacity-50"
                            disabled=move || locked.get() || summary.get().is_none()
                            on:click=move |_| apply_all.run(())
                        >
                            {move || if busy.get() { "Working..." } else { "Apply all" }}
                        </button>
                    </div>
                </aside>
            </div>
        </Show>
    }
}

/// Outcome of the last apply, per component. A component that did not run
/// (the apply was refused) is left out.
#[component]
fn ApplyResultPanel(result: ApplyAllResponse) -> impl IntoView {
    let tone = if result.success {
        "border-green-700 bg-green-900/30 text-green-100"
    } else {
        "border-red-700 bg-red-900/30 text-red-100"
    };
    let rows: Vec<(Component, ComponentResult)> = apply_outcome_rows(&result.components)
        .into_iter()
        .filter(|(_, outcome)| outcome.success || !outcome.message.is_empty())
        .collect();
    let confirmation = result.firewall_pending_confirmation;
    view! {
        <div class=format!("rounded-lg border px-4 py-3 text-sm space-y-2 {tone}")>
            <p class="font-medium break-words">{result.message}</p>
            <ul class="space-y-1">
                {rows
                    .into_iter()
                    .map(|(component, outcome)| {
                        let label = apply_outcome_label(&outcome);
                        let detail = outcome.message;
                        view! {
                            <li class="break-words">
                                <span class="font-medium">{component_display_name(component)}</span>
                                ": "
                                {label}
                                {(!detail.is_empty()).then(|| view! { <span class="text-slate-300">" \u{2014} " {detail}</span> })}
                            </li>
                        }
                    })
                    .collect_view()}
            </ul>
            {confirmation.then(|| view! {
                <p class="text-sky-200">
                    "The new configuration is live and waits for confirmation. Confirm it in the bar at the top of the page."
                </p>
            })}
        </div>
    }
}

/// One component in the drawer. The `<details>` element stays mounted across
/// polls, so a collapsed section stays collapsed while its diff refreshes.
#[component]
fn ComponentSection(
    component: Component,
    pending: RwSignal<Option<PendingChangesResponse>>,
    discard: Callback<Option<Component>>,
    locked: Memo<bool>,
) -> impl IntoView {
    // Memo only notifies when the component's diff actually changes.
    let diff = Memo::new(move |_| {
        pending.with(|response| {
            response.as_ref().and_then(|response| {
                response
                    .components
                    .iter()
                    .find(|diff| diff.component == component)
                    .cloned()
            })
        })
    });
    let name = component_display_name(component);

    view! {
        <details class="group rounded-xl border border-slate-700/70 bg-slate-900/40" open>
            <summary class="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-3">
                <span class="font-medium text-slate-100">{name}</span>
                <span class="text-xs text-slate-400">
                    {move || diff.get().map(|diff| {
                        if diff.error.is_some() {
                            "generation failed".to_string()
                        } else {
                            let count = diff.files.len();
                            format!("{count} {}", if count == 1 { "file" } else { "files" })
                        }
                    })}
                </span>
            </summary>
            <div class="space-y-4 border-t border-slate-700/70 p-4">
                <div class="flex justify-end">
                    <button
                        type="button"
                        class="px-3 py-1.5 rounded-lg bg-gray-700 hover:bg-red-900/60 text-gray-200 text-sm disabled:opacity-50"
                        disabled=move || locked.get()
                        on:click=move |_| discard.run(Some(component))
                    >
                        {format!("Discard {name} changes")}
                    </button>
                </div>
                {move || diff.get().map(|diff| {
                    let error = diff.error.clone();
                    view! {
                        {error.map(|message| view! {
                            <div class="rounded-lg border border-red-700 bg-red-900/40 px-3 py-2 text-sm text-red-200 break-words">
                                <span class="font-medium">"This component could not be generated. "</span>
                                {message}
                            </div>
                        })}
                        {diff.files.into_iter().map(|file| view! { <FileDiffView file=file /> }).collect_view()}
                    }
                })}
            </div>
        </details>
    }
}

/// One generated file with its unified diff.
#[component]
pub fn FileDiffView(file: FileDiff) -> impl IntoView {
    let lines: Vec<(DiffLineKind, String)> = classify_diff(&file.unified_diff)
        .into_iter()
        .map(|(kind, text)| (kind, text.to_string()))
        .collect();
    view! {
        <div class="min-w-0 overflow-hidden rounded-lg border border-slate-700/70">
            <div class="flex flex-wrap items-center justify-between gap-2 bg-slate-800/60 px-3 py-2">
                <span class="min-w-0 break-all font-mono text-xs text-slate-200">{file.path}</span>
                <span class=file_status_class(file.status)>{file_status_label(file.status)}</span>
            </div>
            <pre class="max-h-96 overflow-auto bg-slate-950/70 p-3 font-mono text-xs leading-5">
                {lines
                    .into_iter()
                    .map(|(kind, text)| view! { <span class=diff_line_class(kind)>{text}</span> })
                    .collect_view()}
            </pre>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn component(component: Component, changed: bool) -> ComponentDiff {
        ComponentDiff {
            component,
            changed,
            files: Vec::new(),
            error: None,
        }
    }

    #[test]
    fn component_names_match_the_bar_wording() {
        assert_eq!(component_display_name(Component::Networkd), "Network");
        assert_eq!(component_display_name(Component::Firewall), "Firewall");
        assert_eq!(component_display_name(Component::Dnsmasq), "DNS & DHCP");
        assert_eq!(component_display_name(Component::Caddy), "Web Server");
    }

    #[test]
    fn summary_lists_only_changed_components_in_apply_order() {
        let components = vec![
            component(Component::Caddy, true),
            component(Component::Networkd, false),
            component(Component::Dnsmasq, true),
            component(Component::Firewall, true),
        ];
        assert_eq!(
            changed_components(&components),
            vec![Component::Firewall, Component::Dnsmasq, Component::Caddy]
        );
        assert_eq!(
            pending_summary(&components).as_deref(),
            Some("3 pending changes \u{b7} Firewall, DNS & DHCP, Web Server")
        );
    }

    #[test]
    fn summary_is_absent_when_nothing_is_pending() {
        let components = vec![component(Component::Networkd, false)];
        assert!(changed_components(&components).is_empty());
        assert_eq!(pending_summary(&components), None);
        assert_eq!(pending_summary(&[]), None);
    }

    #[test]
    fn single_change_uses_singular_wording() {
        let components = vec![component(Component::Dnsmasq, true)];
        assert_eq!(
            pending_summary(&components).as_deref(),
            Some("1 pending change \u{b7} DNS & DHCP")
        );
    }

    #[test]
    fn a_component_that_failed_to_generate_counts_as_changed() {
        let failed = ComponentDiff {
            component: Component::Caddy,
            changed: true,
            files: Vec::new(),
            error: Some("bad template".into()),
        };
        assert_eq!(changed_components(&[failed]), vec![Component::Caddy]);
    }

    #[test]
    fn file_headers_are_not_classified_as_changes() {
        let diff = "--- applied/keystone.conf\n+++ live/keystone.conf\n@@ -1,2 +1,2 @@\n-old\n+new\n same\n";
        let kinds: Vec<DiffLineKind> = classify_diff(diff).into_iter().map(|(k, _)| k).collect();
        assert_eq!(
            kinds,
            vec![
                DiffLineKind::FileHeader,
                DiffLineKind::FileHeader,
                DiffLineKind::Hunk,
                DiffLineKind::Removed,
                DiffLineKind::Added,
                DiffLineKind::Context,
            ]
        );
    }

    #[test]
    fn plus_and_minus_lines_inside_a_hunk_are_changes_even_when_they_look_like_headers() {
        let diff = "--- a\n+++ b\n@@ -1 +1 @@\n--- removed sql comment\n+++ added\n";
        let kinds: Vec<DiffLineKind> = classify_diff(diff).into_iter().map(|(k, _)| k).collect();
        assert_eq!(kinds[3], DiffLineKind::Removed);
        assert_eq!(kinds[4], DiffLineKind::Added);
    }

    #[test]
    fn no_newline_notes_are_not_changes() {
        let diff = "@@ -1 +1 @@\n-a\n\\ No newline at end of file\n+a\n";
        let kinds: Vec<DiffLineKind> = classify_diff(diff).into_iter().map(|(k, _)| k).collect();
        assert_eq!(kinds[2], DiffLineKind::Note);
    }

    #[test]
    fn diff_lines_are_coloured_by_kind() {
        assert!(diff_line_class(DiffLineKind::Added).contains("text-emerald"));
        assert!(diff_line_class(DiffLineKind::Removed).contains("text-rose"));
        assert!(diff_line_class(DiffLineKind::Hunk).contains("text-sky"));
        assert!(!diff_line_class(DiffLineKind::FileHeader).contains("emerald"));
        assert!(!diff_line_class(DiffLineKind::FileHeader).contains("rose"));
    }

    #[test]
    fn apply_outcomes_report_skipped_failed_and_applied() {
        let applied = ComponentResult {
            success: true,
            message: String::new(),
            skipped: false,
        };
        let skipped = ComponentResult {
            success: true,
            message: String::new(),
            skipped: true,
        };
        let failed = ComponentResult {
            success: false,
            message: "nft rejected the ruleset".into(),
            skipped: false,
        };
        assert_eq!(apply_outcome_label(&applied), "Applied");
        assert_eq!(apply_outcome_label(&skipped), "Skipped");
        assert_eq!(apply_outcome_label(&failed), "Failed");

        let results = ApplyComponentResults {
            firewall: failed,
            ..Default::default()
        };
        let rows = apply_outcome_rows(&results);
        assert_eq!(rows[1].0, Component::Firewall);
        assert_eq!(rows[1].1.message, "nft rejected the ruleset");
    }

    #[test]
    fn only_parts_that_ran_and_failed_are_listed_after_a_partial_apply() {
        let failed = ComponentResult {
            success: false,
            message: "nft rejected the ruleset".into(),
            skipped: false,
        };
        // A component that was not run (refused apply) has no message.
        let not_run = ComponentResult {
            success: false,
            message: String::new(),
            skipped: false,
        };
        let skipped = ComponentResult {
            success: true,
            message: "Another apply is pending".into(),
            skipped: true,
        };
        let result = ApplyAllResponse {
            success: false,
            message: "Some components failed".into(),
            components: ApplyComponentResults {
                firewall: failed,
                dnsmasq: not_run,
                upnp: skipped.clone(),
                blocky: skipped,
                ..Default::default()
            },
            firewall_pending_confirmation: true,
            firewall_confirm_deadline: Some(1),
            firewall_session_id: Some("s1".into()),
            networkd_pending_confirmation: false,
        };
        assert_eq!(
            failed_part_lines(&result),
            vec!["Firewall: nft rejected the ruleset".to_string()]
        );
    }

    #[test]
    fn every_bar_state_has_one_colour_and_the_confirmation_is_distinct() {
        let awaiting = BarState::Awaiting(AwaitingConfirmation {
            session_id: "s1".into(),
            deadline: 1,
            components: Vec::new(),
        });
        let states = [
            BarState::Busy("Working"),
            awaiting.clone(),
            BarState::Failed("nope".into()),
            BarState::Pending("1 pending change".into()),
        ];
        let tones: Vec<&str> = states.iter().map(BarState::tone).collect();
        for (i, tone) in tones.iter().enumerate() {
            assert!(!tone.is_empty());
            for other in &tones[i + 1..] {
                assert_ne!(tone, other);
            }
        }
        assert_eq!(BarState::Hidden.tone(), "");
    }

    #[test]
    fn file_status_badges_have_distinct_labels() {
        assert_eq!(file_status_label(FileChangeStatus::Added), "added");
        assert_eq!(file_status_label(FileChangeStatus::Modified), "modified");
        assert_eq!(file_status_label(FileChangeStatus::Removed), "removed");
    }
}
