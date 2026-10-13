//! Named address and port groups: the list and the editor. Rules refer to a
//! group by name, so the daemon refuses to delete a group that a rule uses.

use crate::api;
use crate::components::form_utils::event_target_value;
use keystone_core::validation::{address_group_entry, group_name, port_group_entry};
use keystone_core::{AddressGroup, PortGroup};
use leptos::prelude::*;

/// Which kind of group the editor is working on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GroupKind {
    Address,
    Port,
}

impl GroupKind {
    fn title(self) -> &'static str {
        match self {
            GroupKind::Address => "Address group",
            GroupKind::Port => "Port group",
        }
    }

    fn hint(self) -> &'static str {
        match self {
            GroupKind::Address => {
                "One IPv4 or IPv6 address or CIDR network per line, e.g. 10.0.0.0/8 or fd00::1"
            }
            GroupKind::Port => "One port or inclusive range per line, e.g. 443 or 8000-8100",
        }
    }
}

/// Entries of `text`: one per non-blank line, trimmed.
pub fn entries_of(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Problems with the entries in `text`, as `(line number, message)`. Line
/// numbers count every line of the text, including blank ones, so they match
/// what the user sees in the textarea.
pub fn entry_problems(kind: GroupKind, text: &str) -> Vec<(usize, String)> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .filter_map(|(index, line)| {
            let problem = match kind {
                GroupKind::Address => address_group_entry(line).err(),
                GroupKind::Port => port_group_entry(line).err(),
            }?;
            Some((index + 1, problem))
        })
        .collect()
}

/// Problem with a group name, if any.
pub fn name_problem(name: &str) -> Option<String> {
    group_name(name).err()
}

/// Which group is open in the editor.
#[derive(Clone, PartialEq)]
struct Editing {
    kind: GroupKind,
    id: Option<i64>,
    name: String,
    description: String,
    entries: String,
}

#[component]
pub fn GroupsTab(
    token: Signal<String>,
    reload_trigger: RwSignal<i32>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let address_groups = LocalResource::new(move || {
        let token = token.get();
        let _ = reload_trigger.get();
        async move { api::fetch_address_groups(&token).await }
    });
    let port_groups = LocalResource::new(move || {
        let token = token.get();
        let _ = reload_trigger.get();
        async move { api::fetch_port_groups(&token).await }
    });

    let editing = RwSignal::new(Option::<Editing>::None);
    let error_message = RwSignal::new(String::new());

    let open_new = move |kind: GroupKind| {
        error_message.set(String::new());
        editing.set(Some(Editing {
            kind,
            id: None,
            name: String::new(),
            description: String::new(),
            entries: String::new(),
        }));
    };

    let delete_group = move |kind: GroupKind, id: i64| {
        error_message.set(String::new());
        let token = token.get_untracked();
        leptos::task::spawn_local(async move {
            let outcome = match kind {
                GroupKind::Address => api::delete_address_group(&token, id).await,
                GroupKind::Port => api::delete_port_group(&token, id).await,
            };
            match outcome {
                Ok(response) if response.success => {
                    if editing
                        .get_untracked()
                        .is_some_and(|open| open.id == Some(id) && open.kind == kind)
                    {
                        editing.set(None);
                    }
                    reload_trigger.update(|v| *v += 1);
                }
                Ok(response) => error_message.set(response.message),
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        error_message.set(e);
                    }
                }
            }
        });
    };

    view! {
        <div class="space-y-6">
            <div class="flex justify-between items-center">
                <div>
                    <h2 class="text-lg font-medium text-gray-200">"Groups"</h2>
                    <p class="text-sm text-gray-400">"Named addresses and ports that rules can use as a source, destination or port list"</p>
                </div>
                <div class="flex gap-2">
                    <button
                        class="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm"
                        on:click=move |_| open_new(GroupKind::Address)
                    >"+ Address Group"</button>
                    <button
                        class="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm"
                        on:click=move |_| open_new(GroupKind::Port)
                    >"+ Port Group"</button>
                </div>
            </div>

            {move || {
                let msg = error_message.get();
                (!msg.is_empty()).then(|| view! {
                    <div class="bg-red-900/50 border border-red-700 text-red-200 px-4 py-2 rounded text-sm">{msg}</div>
                })
            }}

            {move || editing.get().map(|open| view! {
                <GroupEditor
                    open=open
                    token=token
                    error_message=error_message
                    on_unauthorized=on_unauthorized
                    on_saved=move || {
                        editing.set(None);
                        reload_trigger.update(|v| *v += 1);
                    }
                    on_cancel=move || editing.set(None)
                />
            })}

            <Suspense fallback=move || view! { <p class="text-gray-400">"Loading groups..."</p> }>
                {move || {
                    let addresses = address_groups.get();
                    let ports = port_groups.get();
                    match (addresses, ports) {
                        (Some(Ok(addresses)), Some(Ok(ports))) => view! {
                            <GroupList
                                kind=GroupKind::Address
                                rows=addresses.into_iter().map(|g| GroupRow {
                                    id: g.id, name: g.name, description: g.description, entries: g.entries,
                                }).collect()
                                editing=editing
                                on_edit=move |row: GroupRow| editing.set(Some(Editing {
                                    kind: GroupKind::Address, id: row.id, name: row.name,
                                    description: row.description.unwrap_or_default(),
                                    entries: row.entries.join("\n"),
                                }))
                                on_delete=move |id| delete_group(GroupKind::Address, id)
                            />
                            <GroupList
                                kind=GroupKind::Port
                                rows=ports.into_iter().map(|g| GroupRow {
                                    id: g.id, name: g.name, description: g.description, entries: g.entries,
                                }).collect()
                                editing=editing
                                on_edit=move |row: GroupRow| editing.set(Some(Editing {
                                    kind: GroupKind::Port, id: row.id, name: row.name,
                                    description: row.description.unwrap_or_default(),
                                    entries: row.entries.join("\n"),
                                }))
                                on_delete=move |id| delete_group(GroupKind::Port, id)
                            />
                        }.into_any(),
                        (Some(Err(e)), _) | (_, Some(Err(e))) => {
                            if e.contains("Unauthorized") {
                                on_unauthorized.run(());
                            }
                            view! { <p class="text-red-400">"Error: "{e}</p> }.into_any()
                        }
                        _ => view! { <p class="text-gray-400">"Loading groups..."</p> }.into_any(),
                    }
                }}
            </Suspense>
        </div>
    }
}

/// One row of a group table, independent of the kind of group.
#[derive(Clone, PartialEq)]
struct GroupRow {
    id: Option<i64>,
    name: String,
    description: Option<String>,
    entries: Vec<String>,
}

#[component]
fn GroupList(
    kind: GroupKind,
    rows: Vec<GroupRow>,
    editing: RwSignal<Option<Editing>>,
    on_edit: impl Fn(GroupRow) + Clone + Send + Sync + 'static,
    on_delete: impl Fn(i64) + Clone + Send + Sync + 'static,
) -> impl IntoView {
    let empty = rows.is_empty();
    let entry_header = match kind {
        GroupKind::Address => "Addresses",
        GroupKind::Port => "Ports",
    };
    view! {
        <div class="space-y-2">
            <h3 class="text-base font-medium text-gray-200">{format!("{}s", kind.title())}</h3>
            <div class="overflow-x-auto">
                <table class="w-full text-sm">
                    <thead class="text-gray-400 border-b border-gray-600">
                        <tr>
                            <th class="text-left py-2 px-2">"Name"</th>
                            <th class="text-left py-2 px-2">"Description"</th>
                            <th class="text-left py-2 px-2">{entry_header}</th>
                            <th class="text-right py-2 px-2">"Actions"</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows.into_iter().map(|row| {
                            let summary = row.entries.join(", ");
                            let count = row.entries.len();
                            let description = row.description.clone().unwrap_or_default();
                            let edit_row = row.clone();
                            let delete_id = row.id;
                            let on_edit = on_edit.clone();
                            let on_delete = on_delete.clone();
                            let row_id = row.id;
                            let is_open = move || editing.get().is_some_and(|open| open.kind == kind && row_id.is_some() && open.id == row_id);
                            view! {
                                <tr class=move || if is_open() { "border-b border-gray-700 bg-gray-700/40" } else { "border-b border-gray-700 hover:bg-gray-700/30" }>
                                    <td class="py-2 px-2 text-gray-200 font-mono">{row.name.clone()}</td>
                                    <td class="py-2 px-2 text-gray-400">{description}</td>
                                    <td class="py-2 px-2 text-gray-300" title=summary.clone()>
                                        {format!("{count} {}", if count == 1 { "entry" } else { "entries" })}
                                    </td>
                                    <td class="py-2 px-2 text-right whitespace-nowrap">
                                        <button class="text-blue-400 hover:text-blue-300 mr-2"
                                            on:click=move |_| on_edit(edit_row.clone())>"Edit"</button>
                                        <button class="text-red-400 hover:text-red-300"
                                            on:click=move |_| if let Some(id) = delete_id { on_delete(id) }>"Delete"</button>
                                    </td>
                                </tr>
                            }
                        }).collect::<Vec<_>>()}
                    </tbody>
                </table>
                {empty.then(|| view! { <p class="text-gray-500 text-center py-3">"None yet"</p> })}
            </div>
        </div>
    }
}

#[component]
fn GroupEditor(
    open: Editing,
    token: Signal<String>,
    error_message: RwSignal<String>,
    on_unauthorized: Callback<()>,
    on_saved: impl Fn() + Clone + Send + Sync + 'static,
    on_cancel: impl Fn() + Clone + Send + Sync + 'static,
) -> impl IntoView {
    let kind = open.kind;
    let id = open.id;
    let name = RwSignal::new(open.name.clone());
    let description = RwSignal::new(open.description.clone());
    let entries = RwSignal::new(open.entries.clone());
    let saving = RwSignal::new(false);

    let problems = move || entry_problems(kind, &entries.get());
    let count = move || entries_of(&entries.get()).len();
    let name_error = move || {
        let current = name.get();
        if current.is_empty() {
            Some("A name is required".to_string())
        } else {
            name_problem(&current)
        }
    };
    let can_save =
        move || !saving.get() && name_error().is_none() && problems().is_empty() && count() > 0;

    let on_saved = on_saved.clone();
    let save = move |_| {
        if !can_save() {
            return;
        }
        saving.set(true);
        error_message.set(String::new());
        let token = token.get_untracked();
        let description_text = description.get_untracked().trim().to_owned();
        let description = (!description_text.is_empty()).then_some(description_text);
        let entries = entries_of(&entries.get_untracked());
        let name = name.get_untracked().trim().to_owned();
        let on_saved = on_saved.clone();
        leptos::task::spawn_local(async move {
            let outcome = match kind {
                GroupKind::Address => api::save_address_group(
                    &token,
                    AddressGroup {
                        id,
                        name,
                        description,
                        entries,
                    },
                )
                .await
                .map(|_| ()),
                GroupKind::Port => api::save_port_group(
                    &token,
                    PortGroup {
                        id,
                        name,
                        description,
                        entries,
                    },
                )
                .await
                .map(|_| ()),
            };
            match outcome {
                Ok(()) => on_saved(),
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

    let on_cancel = on_cancel.clone();
    view! {
        <div class="bg-gray-700 p-4 rounded-lg space-y-4">
            <h3 class="text-lg font-medium text-gray-200">
                {if id.is_some() { format!("Edit {}", kind.title().to_lowercase()) } else { format!("New {}", kind.title().to_lowercase()) }}
            </h3>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Name"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500 font-mono"
                        prop:value=move || name.get()
                        on:input=move |ev| name.set(event_target_value(&ev))
                        placeholder="e.g., lan_hosts"
                    />
                    {move || name_error().filter(|_| !name.get().is_empty()).map(|msg| view! {
                        <p class="text-xs text-red-300 mt-1">{msg}</p>
                    })}
                    <p class="text-xs text-gray-500 mt-1">"Lowercase letters, digits and underscores; starts with a letter; up to 31 characters. Unique across address and port groups."</p>
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Description"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || description.get()
                        on:input=move |ev| description.set(event_target_value(&ev))
                        placeholder="Optional"
                    />
                </div>
            </div>
            <div>
                <div class="flex justify-between items-baseline mb-1">
                    <label class="block text-sm text-gray-400">{if kind == GroupKind::Address { "Addresses and networks" } else { "Ports and ranges" }}</label>
                    <span class="text-xs text-gray-400">{move || format!("{} {}", count(), if count() == 1 { "entry" } else { "entries" })}</span>
                </div>
                <textarea
                    rows="8"
                    class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500 font-mono text-sm"
                    prop:value=move || entries.get()
                    on:input=move |ev| entries.set(event_target_value(&ev))
                    placeholder=kind.hint()
                    aria-describedby="group-entry-hint"
                ></textarea>
                <p id="group-entry-hint" class="text-xs text-gray-500 mt-1">{kind.hint()}</p>
                {move || {
                    let found = problems();
                    (!found.is_empty()).then(|| view! {
                        <ul class="mt-2 text-xs text-red-300 space-y-0.5" role="alert">
                            {found.into_iter().map(|(line, message)| view! {
                                <li>{format!("Line {line}: {message}")}</li>
                            }).collect::<Vec<_>>()}
                        </ul>
                    })
                }}
            </div>
            <div class="flex gap-2 pt-2">
                <button
                    class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded disabled:opacity-50"
                    on:click=save
                    disabled=move || !can_save()
                >
                    {move || if saving.get() { "Saving..." } else { "Save" }}
                </button>
                <button
                    class="px-4 py-2 bg-gray-600 hover:bg-gray-500 text-white rounded"
                    on:click=move |_| on_cancel()
                >"Cancel"</button>
            </div>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_ignore_blank_lines_and_surrounding_space() {
        assert_eq!(
            entries_of("  10.0.0.0/8 \n\n fd00::1\n"),
            vec!["10.0.0.0/8", "fd00::1"]
        );
        assert!(entries_of("  \n").is_empty());
    }

    #[test]
    fn problems_report_the_physical_line_number() {
        let text = "10.0.0.0/8\n\nnot-an-address\n10.1.2.3/8";
        let problems = entry_problems(GroupKind::Address, text);
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert_eq!(problems[0].0, 3);
        assert_eq!(problems[1].0, 4);
        assert!(problems[1].1.contains("host bits"), "{problems:?}");
    }

    #[test]
    fn port_problems_reject_bad_ranges() {
        let problems = entry_problems(GroupKind::Port, "443\n8100-8000\n0\n80-90");
        let lines: Vec<usize> = problems.iter().map(|(line, _)| *line).collect();
        assert_eq!(lines, vec![2, 3]);
    }

    #[test]
    fn valid_text_has_no_problems() {
        assert!(entry_problems(GroupKind::Address, "192.0.2.0/24\n2001:db8::/32").is_empty());
        assert!(entry_problems(GroupKind::Port, "22\n8000-8100").is_empty());
    }

    #[test]
    fn group_names_follow_the_daemon_rule() {
        assert!(name_problem("lan_hosts").is_none());
        assert!(name_problem("Lan").is_some());
        assert!(name_problem("1lan").is_some());
        assert!(name_problem(&"a".repeat(32)).is_some());
    }
}
