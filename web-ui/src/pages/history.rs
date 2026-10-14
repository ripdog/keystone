//! Configuration history: saved snapshots of the router database.
//!
//! Each row can be compared with the live configuration, restored, or
//! downloaded. A restore copies the snapshot into the live database. The result
//! is then pending like any other edit and takes effect only after Apply all.

use crate::api;
use crate::components::form_utils::{event_target_checked, event_target_value};
use crate::components::use_toasts;
use crate::components::{
    FileDiffView, changed_components, component_display_name, use_config_changed,
};
use gloo_timers::callback::Timeout;
use keystone_core::changes::{
    Component, PendingChangesResponse, SnapshotKind, SnapshotStatus, SnapshotSummary,
};
use leptos::prelude::*;
use leptos::task::spawn_local;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;

const INPUT: &str = "w-full px-3 py-2 bg-gray-700 text-gray-100 rounded border border-gray-600 focus:border-blue-500 focus:outline-none";
const BTN_PRIMARY: &str =
    "px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-medium disabled:opacity-50";
const BTN_GHOST: &str =
    "px-4 py-2 rounded-lg bg-gray-700 hover:bg-gray-600 text-gray-100 disabled:opacity-50";
const ACTION: &str = "text-blue-300 hover:text-blue-200 hover:underline underline-offset-2 disabled:opacity-50 whitespace-nowrap";

/// A snapshot the user has picked for a dialog.
#[derive(Clone)]
struct SnapshotRef {
    id: i64,
    label: String,
}

#[derive(Clone)]
struct Notice {
    text: String,
}

type DiffResult = Result<PendingChangesResponse, String>;

#[component]
pub fn HistoryPage(
    auth_token: ReadSignal<Option<String>>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let config_changed = use_config_changed();
    let snapshots = RwSignal::new(None::<Result<Vec<SnapshotSummary>, String>>);
    let notice = RwSignal::new(None::<Notice>);
    let toasts = use_toasts();
    // Successes are brief toasts; failures stay until dismissed.
    let report = move |ok: bool, text: String| {
        if ok {
            toasts.success(text);
        } else {
            notice.set(Some(Notice { text }));
        }
    };
    let busy = RwSignal::new(false);
    let note = RwSignal::new(String::new());

    let diff_target = RwSignal::new(None::<SnapshotRef>);
    let diff = RwSignal::new(None::<DiffResult>);

    let restore_target = RwSignal::new(None::<SnapshotRef>);
    let restore_diff = RwSignal::new(None::<DiffResult>);
    let restore_selection = RwSignal::new(Vec::<Component>::new());
    let restore_error = RwSignal::new(None::<String>);

    let reload = move || {
        let Some(token) = auth_token.get_untracked() else {
            return;
        };
        spawn_local(async move {
            match api::fetch_snapshots(&token).await {
                Ok(list) => snapshots.set(Some(Ok(list))),
                Err(e) if e == "Unauthorized" => on_unauthorized.run(()),
                Err(e) => snapshots.set(Some(Err(e))),
            }
        });
    };

    Effect::new(move |_| {
        if auth_token.get().is_some() {
            reload();
        }
    });

    let create_snapshot = move || {
        if busy.get_untracked() {
            return;
        }
        let Some(token) = auth_token.get_untracked() else {
            return;
        };
        let text = note.get_untracked().trim().to_owned();
        let text = (!text.is_empty()).then_some(text);
        busy.set(true);
        notice.set(None);
        spawn_local(async move {
            match api::create_snapshot(&token, text).await {
                Ok(response) => {
                    report(response.success, response.message);
                    note.set(String::new());
                    reload();
                }
                Err(e) if e == "Unauthorized" => on_unauthorized.run(()),
                Err(e) => report(false, format!("Could not create the snapshot: {e}")),
            }
            busy.set(false);
        });
    };

    let open_diff = move |target: SnapshotRef| {
        let Some(token) = auth_token.get_untracked() else {
            return;
        };
        let id = target.id;
        diff.set(None);
        diff_target.set(Some(target));
        spawn_local(async move {
            let result = api::fetch_snapshot_diff(&token, id).await;
            if matches!(&result, Err(e) if e == "Unauthorized") {
                on_unauthorized.run(());
                return;
            }
            diff.set(Some(result));
        });
    };

    let open_restore = move |target: SnapshotRef| {
        let Some(token) = auth_token.get_untracked() else {
            return;
        };
        let id = target.id;
        restore_diff.set(None);
        restore_selection.set(Vec::new());
        restore_error.set(None);
        restore_target.set(Some(target));
        spawn_local(async move {
            let result = api::fetch_snapshot_diff(&token, id).await;
            match &result {
                Err(e) if e == "Unauthorized" => {
                    on_unauthorized.run(());
                    return;
                }
                Ok(response) => restore_selection.set(default_restore_selection(response)),
                Err(_) => {}
            }
            restore_diff.set(Some(result));
        });
    };

    let confirm_restore = move || {
        if busy.get_untracked() {
            return;
        }
        let Some(target) = restore_target.get_untracked() else {
            return;
        };
        let selected = restore_selection.get_untracked();
        if selected.is_empty() {
            return;
        }
        let Some(token) = auth_token.get_untracked() else {
            return;
        };
        busy.set(true);
        restore_error.set(None);
        spawn_local(async move {
            match api::restore_snapshot(&token, target.id, Some(selected)).await {
                Ok(response) if response.success => {
                    restore_target.set(None);
                    report(true, response.message);
                    reload();
                    config_changed.run(());
                }
                Ok(response) => restore_error.set(Some(response.message)),
                Err(e) if e == "Unauthorized" => on_unauthorized.run(()),
                Err(e) => restore_error.set(Some(e)),
            }
            busy.set(false);
        });
    };

    let export = move |target: SnapshotRef| {
        let Some(token) = auth_token.get_untracked() else {
            return;
        };
        busy.set(true);
        notice.set(None);
        spawn_local(async move {
            match api::export_snapshot(&token, target.id).await {
                Ok(bytes) => {
                    let filename = format!("keystone-config-{}.db", target.id);
                    match download_bytes(&filename, &bytes, "application/vnd.sqlite3") {
                        Ok(()) => {
                            report(true, format!("Downloaded {} as {filename}.", target.label))
                        }
                        Err(e) => report(false, format!("Download failed: {e}")),
                    }
                }
                Err(e) if e == "Unauthorized" => on_unauthorized.run(()),
                Err(e) => report(false, format!("Export failed: {e}")),
            }
            busy.set(false);
        });
    };

    let on_import = move |ev: web_sys::Event| {
        let Some(input) = ev
            .target()
            .and_then(|target| target.dyn_into::<web_sys::HtmlInputElement>().ok())
        else {
            return;
        };
        let file = input.files().and_then(|files| files.get(0));
        // Clear the input so choosing the same file again still fires `change`.
        input.set_value("");
        let Some(file) = file else {
            return;
        };
        let Some(token) = auth_token.get_untracked() else {
            return;
        };
        busy.set(true);
        notice.set(None);
        spawn_local(async move {
            match api::import_snapshot(&token, file).await {
                Ok(response) => {
                    report(
                        response.success,
                        format!(
                            "{} Use Restore on it to bring it into the live configuration.",
                            response.message
                        ),
                    );
                    reload();
                }
                Err(e) if e == "Unauthorized" => on_unauthorized.run(()),
                Err(e) => report(false, format!("Import failed: {e}")),
            }
            busy.set(false);
        });
    };

    view! {
        <div class="space-y-6">
            <div>
                <h1 class="text-2xl font-semibold text-blue-300">"Configuration history"</h1>
                <p class="text-gray-400">
                    "Each apply records a snapshot. Restoring one makes it pending until you apply it."
                </p>
            </div>

            {move || notice.get().map(|item| {
                let class = "flex items-start justify-between gap-3 rounded-lg border border-red-600 bg-red-900/40 px-4 py-3 text-sm text-red-100";
                view! {
                    <div class=class role="status">
                        <span class="min-w-0 break-words">{item.text}</span>
                        <button
                            type="button"
                            aria-label="Dismiss"
                            class="shrink-0 opacity-70 hover:opacity-100"
                            on:click=move |_| notice.set(None)
                        >
                            "\u{2715}"
                        </button>
                    </div>
                }
            })}

            <div class="bg-gray-800 rounded-xl shadow-lg p-5 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
                <div class="min-w-0 flex-1 space-y-2">
                    <label class="block text-sm text-gray-300" for="snapshot-note">"Note for a new snapshot"</label>
                    <input
                        id="snapshot-note"
                        type="text"
                        maxlength="500"
                        class=INPUT
                        placeholder="Optional, for example: before the VLAN change"
                        prop:value=move || note.get()
                        on:input=move |ev| note.set(event_target_value(&ev))
                    />
                </div>
                <div class="flex flex-wrap gap-2">
                    <button
                        type="button"
                        class=BTN_PRIMARY
                        disabled=move || busy.get()
                        on:click=move |_| create_snapshot()
                    >
                        "Create snapshot"
                    </button>
                    <label class="inline-flex cursor-pointer items-center rounded-lg bg-gray-700 px-4 py-2 font-medium text-gray-100 hover:bg-gray-600">
                        "Import\u{2026}"
                        <input
                            type="file"
                            class="hidden"
                            accept=".db,application/vnd.sqlite3,application/octet-stream"
                            disabled=move || busy.get()
                            on:change=on_import
                        />
                    </label>
                </div>
            </div>

            <div class="bg-gray-800 rounded-xl shadow-lg overflow-hidden">
                <div class="overflow-x-auto">
                    <table class="min-w-full text-sm">
                        <thead class="bg-gray-900/60 text-left text-xs uppercase tracking-wide text-gray-400">
                            <tr>
                                <th class="px-4 py-3 font-medium">"Created"</th>
                                <th class="px-4 py-3 font-medium">"Kind"</th>
                                <th class="px-4 py-3 font-medium">"Status"</th>
                                <th class="px-4 py-3 font-medium">"Actor"</th>
                                <th class="px-4 py-3 font-medium">"Components"</th>
                                <th class="px-4 py-3 font-medium">"Note"</th>
                                <th class="px-4 py-3 font-medium">"Size"</th>
                                <th class="px-4 py-3 font-medium">"Actions"</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-700">
                            {move || match snapshots.get() {
                                None => view! {
                                    <tr><td colspan="8" class="px-4 py-6 text-center text-gray-400">"Loading history..."</td></tr>
                                }.into_any(),
                                Some(Err(e)) => view! {
                                    <tr><td colspan="8" class="px-4 py-6 text-center text-red-300">{format!("Could not load the history: {e}")}</td></tr>
                                }.into_any(),
                                Some(Ok(list)) if list.is_empty() => view! {
                                    <tr><td colspan="8" class="px-4 py-6 text-center text-gray-400">"No snapshots yet. Applying the configuration creates one."</td></tr>
                                }.into_any(),
                                Some(Ok(list)) => list
                                    .into_iter()
                                    .map(|snapshot| view! {
                                        <SnapshotRow
                                            snapshot=snapshot
                                            busy=busy
                                            on_diff=Callback::new(open_diff)
                                            on_restore=Callback::new(open_restore)
                                            on_export=Callback::new(export)
                                        />
                                    })
                                    .collect_view()
                                    .into_any(),
                            }}
                        </tbody>
                    </table>
                </div>
            </div>

            {move || diff_target.get().map(|target| view! {
                <DiffDialog
                    target=target
                    diff=diff
                    on_close=Callback::new(move |()| diff_target.set(None))
                />
            })}

            {move || restore_target.get().map(|target| view! {
                <RestoreDialog
                    target=target
                    diff=restore_diff
                    selection=restore_selection
                    error=restore_error
                    busy=busy
                    on_confirm=Callback::new(move |()| confirm_restore())
                    on_close=Callback::new(move |()| restore_target.set(None))
                />
            })}
        </div>
    }
}

#[component]
fn SnapshotRow(
    snapshot: SnapshotSummary,
    busy: RwSignal<bool>,
    on_diff: Callback<SnapshotRef>,
    on_restore: Callback<SnapshotRef>,
    on_export: Callback<SnapshotRef>,
) -> impl IntoView {
    let created = format_local_time(snapshot.created_at);
    let target = SnapshotRef {
        id: snapshot.id,
        label: format!("snapshot #{} from {created}", snapshot.id),
    };
    let diff_target = target.clone();
    let restore_target = target.clone();
    let export_target = target;
    let components = format_components(&snapshot.components);
    let note = snapshot.note.clone().unwrap_or_default();
    let note_title = note.clone();
    let actor = snapshot.actor.clone().unwrap_or_else(|| "\u{2014}".into());

    view! {
        <tr class="align-top hover:bg-gray-700/30">
            <td class="px-4 py-3 whitespace-nowrap text-gray-200">{created}</td>
            <td class="px-4 py-3"><span class=kind_class(snapshot.kind)>{kind_label(snapshot.kind)}</span></td>
            <td class="px-4 py-3"><span class=status_class(snapshot.status)>{status_label(snapshot.status)}</span></td>
            <td class="px-4 py-3 text-gray-300">{actor}</td>
            <td class="px-4 py-3 text-gray-300">{components}</td>
            <td class="px-4 py-3 max-w-xs text-gray-300 break-words" title=note_title>{note}</td>
            <td class="px-4 py-3 whitespace-nowrap text-gray-400">{format_bytes(snapshot.size_bytes)}</td>
            <td class="px-4 py-3">
                <div class="flex flex-wrap gap-x-4 gap-y-2">
                    <button type="button" class=ACTION disabled=move || busy.get()
                        on:click=move |_| on_diff.run(diff_target.clone())>
                        "Diff vs current"
                    </button>
                    <button type="button" class=ACTION disabled=move || busy.get()
                        on:click=move |_| on_restore.run(restore_target.clone())>
                        "Restore\u{2026}"
                    </button>
                    <button type="button" class=ACTION disabled=move || busy.get()
                        on:click=move |_| on_export.run(export_target.clone())>
                        "Export"
                    </button>
                </div>
            </td>
        </tr>
    }
}

/// Comparison of a snapshot with the live configuration. The live side is the
/// old side and the snapshot the new side, so the lines show what a restore
/// would write.
#[component]
fn DiffDialog(
    target: SnapshotRef,
    diff: RwSignal<Option<DiffResult>>,
    on_close: Callback<()>,
) -> impl IntoView {
    view! {
        <Dialog title="Changes if restored".to_string() subtitle=format!(
            "Live configuration against {}. Restoring would change the lines below: red lines are removed, green lines are added.",
            target.label
        ) on_close=on_close>
            {move || match diff.get() {
                None => view! { <p class="text-gray-400">"Comparing with the live configuration..."</p> }.into_any(),
                Some(Err(e)) => view! {
                    <p class="rounded-lg border border-red-700 bg-red-900/40 px-3 py-2 text-sm text-red-200 break-words">{e}</p>
                }.into_any(),
                Some(Ok(response)) => {
                    let changed = response.components.into_iter().filter(|d| d.changed).collect::<Vec<_>>();
                    if changed.is_empty() {
                        view! { <p class="text-gray-300">"Restoring this snapshot would change nothing. It matches the live configuration."</p> }.into_any()
                    } else {
                        changed.into_iter().map(|component| view! {
                            <section class="space-y-3">
                                <h3 class="font-medium text-slate-100">{component_display_name(component.component)}</h3>
                                {component.error.map(|message| view! {
                                    <p class="rounded-lg border border-red-700 bg-red-900/40 px-3 py-2 text-sm text-red-200 break-words">{message}</p>
                                })}
                                {component.files.into_iter().map(|file| view! { <FileDiffView file=file /> }).collect_view()}
                            </section>
                        }).collect_view().into_any()
                    }
                }
            }}
        </Dialog>
    }
}

/// Choose which components to restore. Each row says whether the snapshot
/// differs from the live configuration for that component.
#[component]
fn RestoreDialog(
    target: SnapshotRef,
    diff: RwSignal<Option<DiffResult>>,
    selection: RwSignal<Vec<Component>>,
    error: RwSignal<Option<String>>,
    busy: RwSignal<bool>,
    on_confirm: Callback<()>,
    on_close: Callback<()>,
) -> impl IntoView {
    let can_restore =
        move || !busy.get() && !selection.get().is_empty() && matches!(diff.get(), Some(Ok(_)));

    let footer = view! {
        <button type="button" class=BTN_GHOST disabled=move || busy.get()
            on:click=move |_| on_close.run(())>
            "Cancel"
        </button>
        <button type="button" class=BTN_PRIMARY disabled=move || !can_restore()
            on:click=move |_| on_confirm.run(())>
            {move || if busy.get() { "Restoring..." } else { "Restore selected" }}
        </button>
    }
    .into_any();

    view! {
        <Dialog title=format!("Restore {}", target.label) subtitle="The configuration this replaces is saved as a new snapshot first.".to_string() on_close=on_close footer=footer>
            <p class="text-sm text-gray-300">
                "The restored configuration becomes pending. Nothing changes on the system until you apply it with Apply all."
            </p>

            {move || error.get().map(|e| view! {
                <p class="rounded-lg border border-red-700 bg-red-900/40 px-3 py-2 text-sm text-red-200 break-words">{e}</p>
            })}

            {move || match diff.get() {
                None => view! { <p class="text-gray-400">"Comparing with the live configuration..."</p> }.into_any(),
                Some(Err(e)) => view! {
                    <p class="rounded-lg border border-red-700 bg-red-900/40 px-3 py-2 text-sm text-red-200 break-words">{format!("Could not compare: {e}")}</p>
                }.into_any(),
                Some(Ok(response)) => Component::ALL
                    .into_iter()
                    .map(|component| {
                        let entry = response
                            .components
                            .iter()
                            .find(|d| d.component == component)
                            .cloned();
                        let changed = entry.as_ref().is_some_and(|d| d.changed);
                        let files = entry.map(|d| d.files).unwrap_or_default();
                        view! {
                            <div class="rounded-lg border border-gray-700 p-4 space-y-3">
                                <label class="flex items-center gap-3 cursor-pointer">
                                    <input
                                        type="checkbox"
                                        class="h-4 w-4 rounded border-gray-500 bg-gray-700"
                                        prop:checked=move || selection.get().contains(&component)
                                        disabled=move || busy.get()
                                        on:change=move |ev| {
                                            let checked = event_target_checked(&ev);
                                            selection.update(|list| {
                                                list.retain(|c| *c != component);
                                                if checked {
                                                    list.push(component);
                                                    list.sort();
                                                }
                                            });
                                        }
                                    />
                                    <span class="font-medium text-slate-100">{component_display_name(component)}</span>
                                    <span class=if changed { "text-xs text-amber-300" } else { "text-xs text-gray-500" }>
                                        {if changed { "differs from the live configuration" } else { "same as the live configuration" }}
                                    </span>
                                </label>
                                {(!files.is_empty()).then(|| view! {
                                    <ul class="space-y-1 pl-7 text-xs text-gray-300">
                                        {files.into_iter().map(|file| view! {
                                            <li class="break-all font-mono">{file.path}</li>
                                        }).collect_view()}
                                    </ul>
                                })}
                            </div>
                        }
                    })
                    .collect_view()
                    .into_any(),
            }}
        </Dialog>
    }
}

/// Shared modal frame: a backdrop that closes the dialog, and a panel with a
/// scrolling body. On phones the panel fills the screen width.
#[component]
fn Dialog(
    #[prop(into)] title: String,
    #[prop(into)] subtitle: String,
    on_close: Callback<()>,
    children: Children,
    #[prop(optional)] footer: Option<AnyView>,
) -> impl IntoView {
    let aria_label = title.clone();
    view! {
        <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" on:click=move |_| on_close.run(())>
            <div
                class="flex max-h-[90vh] w-full max-w-3xl min-w-0 flex-col rounded-xl border border-slate-700 bg-[#0d1727] shadow-2xl"
                role="dialog"
                aria-modal="true"
                aria-label=aria_label
                on:click=|ev| ev.stop_propagation()
            >
                <div class="flex shrink-0 items-start justify-between gap-3 border-b border-white/10 px-5 py-4">
                    <div class="min-w-0">
                        <h2 class="text-lg font-semibold text-white break-words">{title}</h2>
                        <p class="text-xs text-slate-400 break-words">{subtitle}</p>
                    </div>
                    <button
                        type="button"
                        aria-label="Close"
                        class="shrink-0 rounded-lg p-2 text-slate-400 hover:bg-white/10 hover:text-white"
                        on:click=move |_| on_close.run(())
                    >
                        "\u{2715}"
                    </button>
                </div>
                <div class="min-h-0 min-w-0 flex-1 space-y-4 overflow-y-auto overflow-x-hidden p-5">
                    {children()}
                </div>
                {footer.map(|footer| view! {
                    <div class="flex shrink-0 flex-wrap justify-end gap-3 border-t border-white/10 px-5 py-4">
                        {footer}
                    </div>
                })}
            </div>
        </div>
    }
}

/// Components a restore starts with: the ones that differ from the live
/// configuration.
pub fn default_restore_selection(response: &PendingChangesResponse) -> Vec<Component> {
    changed_components(&response.components)
}

pub fn kind_label(kind: SnapshotKind) -> &'static str {
    match kind {
        SnapshotKind::Applied => "Applied",
        SnapshotKind::PreRestore => "Before restore",
        SnapshotKind::Imported => "Imported",
        SnapshotKind::Manual => "Manual",
    }
}

pub fn kind_class(kind: SnapshotKind) -> &'static str {
    match kind {
        SnapshotKind::Applied => {
            "inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset bg-sky-400/10 text-sky-200 ring-sky-400/20"
        }
        SnapshotKind::PreRestore => {
            "inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset bg-violet-400/10 text-violet-200 ring-violet-400/20"
        }
        SnapshotKind::Imported => {
            "inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset bg-indigo-400/10 text-indigo-200 ring-indigo-400/20"
        }
        SnapshotKind::Manual => {
            "inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset bg-slate-400/10 text-slate-200 ring-slate-400/20"
        }
    }
}

pub fn status_label(status: SnapshotStatus) -> &'static str {
    match status {
        SnapshotStatus::Active => "Active",
        SnapshotStatus::PendingConfirmation => "Awaiting confirmation",
        SnapshotStatus::RolledBack => "Rolled back",
    }
}

pub fn status_class(status: SnapshotStatus) -> &'static str {
    match status {
        SnapshotStatus::Active => {
            "inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset bg-emerald-400/10 text-emerald-200 ring-emerald-400/20"
        }
        SnapshotStatus::PendingConfirmation => {
            "inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset bg-amber-400/10 text-amber-200 ring-amber-400/20"
        }
        SnapshotStatus::RolledBack => {
            "inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset bg-rose-400/10 text-rose-200 ring-rose-400/20"
        }
    }
}

/// Component names, or a dash when the snapshot is not an applied baseline.
pub fn format_components(components: &[Component]) -> String {
    if components.is_empty() {
        return "\u{2014}".to_string();
    }
    components
        .iter()
        .map(|component| component_display_name(*component))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `512 B`, `12.3 KB` or `1.4 MB`.
pub fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    let value = bytes as f64;
    if value < KIB {
        format!("{bytes} B")
    } else if value < MIB {
        format!("{:.1} KB", value / KIB)
    } else {
        format!("{:.1} MB", value / MIB)
    }
}

/// `YYYY-MM-DD HH:MM` in the browser's local time zone.
fn format_local_time(unix_secs: i64) -> String {
    let date = js_sys::Date::new(&JsValue::from_f64(unix_secs as f64 * 1000.0));
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        date.get_full_year(),
        date.get_month() + 1,
        date.get_date(),
        date.get_hours(),
        date.get_minutes()
    )
}

/// Save bytes as a file through a temporary object URL.
fn download_bytes(filename: &str, bytes: &[u8], mime: &str) -> Result<(), String> {
    let js_error = |e: JsValue| e.as_string().unwrap_or_else(|| "browser error".to_string());

    let parts = js_sys::Array::new();
    parts.push(&js_sys::Uint8Array::from(bytes));
    let options = web_sys::BlobPropertyBag::new();
    options.set_type(mime);
    let blob = web_sys::Blob::new_with_u8_array_sequence_and_options(&parts, &options)
        .map_err(js_error)?;
    let url = web_sys::Url::create_object_url_with_blob(&blob).map_err(js_error)?;

    let document = web_sys::window()
        .and_then(|window| window.document())
        .ok_or_else(|| "no document".to_string())?;
    let body = document.body().ok_or_else(|| "no page body".to_string())?;
    let anchor = document
        .create_element("a")
        .map_err(js_error)?
        .dyn_into::<web_sys::HtmlAnchorElement>()
        .map_err(|_| "could not create a download link".to_string())?;
    anchor.set_href(&url);
    anchor.set_download(filename);
    body.append_child(&anchor).map_err(js_error)?;
    anchor.click();
    let _ = body.remove_child(&anchor);

    // Revoke after the browser has started the download.
    Timeout::new(1_000, move || {
        let _ = web_sys::Url::revoke_object_url(&url);
    })
    .forget();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use keystone_core::changes::{ComponentBaselines, ComponentDiff};

    fn diff(component: Component, changed: bool) -> ComponentDiff {
        ComponentDiff {
            component,
            changed,
            files: Vec::new(),
            error: None,
        }
    }

    #[test]
    fn restore_starts_with_the_components_that_differ() {
        let response = PendingChangesResponse {
            components: vec![
                diff(Component::Networkd, false),
                diff(Component::Firewall, true),
                diff(Component::Dnsmasq, false),
                diff(Component::Caddy, true),
            ],
            baseline_ids: ComponentBaselines::default(),
            awaiting_confirmation: None,
            server_time: 0,
        };
        assert_eq!(
            default_restore_selection(&response),
            vec![Component::Firewall, Component::Caddy]
        );
    }

    #[test]
    fn restore_selection_is_empty_when_nothing_differs() {
        let response = PendingChangesResponse {
            components: Component::ALL.iter().map(|c| diff(*c, false)).collect(),
            baseline_ids: ComponentBaselines::default(),
            awaiting_confirmation: None,
            server_time: 0,
        };
        assert!(default_restore_selection(&response).is_empty());
    }

    #[test]
    fn snapshot_kinds_and_statuses_have_readable_labels() {
        assert_eq!(kind_label(SnapshotKind::Applied), "Applied");
        assert_eq!(kind_label(SnapshotKind::PreRestore), "Before restore");
        assert_eq!(kind_label(SnapshotKind::Imported), "Imported");
        assert_eq!(kind_label(SnapshotKind::Manual), "Manual");
        assert_eq!(status_label(SnapshotStatus::Active), "Active");
        assert_eq!(
            status_label(SnapshotStatus::PendingConfirmation),
            "Awaiting confirmation"
        );
        assert_eq!(status_label(SnapshotStatus::RolledBack), "Rolled back");
    }

    #[test]
    fn components_column_names_components_or_shows_a_dash() {
        assert_eq!(format_components(&[]), "\u{2014}");
        assert_eq!(
            format_components(&[Component::Dnsmasq, Component::Caddy]),
            "DNS & DHCP, Web Server"
        );
    }

    #[test]
    fn sizes_use_bytes_kilobytes_or_megabytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(12_595), "12.3 KB");
        assert_eq!(format_bytes(1_572_864), "1.5 MB");
    }
}
