//! Diagnostics: one journal viewer for any of the managed services.

use crate::api;
use crate::components::LogViewer;
use keystone_core::SystemdUnit;
use leptos::prelude::*;
use leptos::task::spawn_local;

/// Services shown first: without them the router has no network or DNS/DHCP.
const DEFAULT_UNITS: [&str; 2] = ["systemd-networkd.service", "dnsmasq.service"];

fn default_units() -> Vec<String> {
    DEFAULT_UNITS.map(str::to_string).to_vec()
}

/// Add `unit` to the selection, or remove it when present. The selection keeps
/// the order of `all`, so the button label and the request do not depend on the
/// order the boxes were ticked in.
fn toggled(selected: &[String], all: &[SystemdUnit], unit: &str) -> Vec<String> {
    all.iter()
        .map(|candidate| candidate.name.as_str())
        .filter(|name| {
            let was_selected = selected.iter().any(|current| current == name);
            if *name == unit {
                !was_selected
            } else {
                was_selected
            }
        })
        .map(str::to_string)
        .collect()
}

/// Text of the selector button.
fn selection_label(selected: &[String]) -> String {
    let short = |unit: &String| unit.strip_suffix(".service").unwrap_or(unit).to_string();
    match selected {
        [] => "No services".to_string(),
        [one] => short(one),
        [first, second] => format!("{}, {}", short(first), short(second)),
        many => format!("{} services", many.len()),
    }
}

#[component]
pub fn DiagnosticsLogsPage(
    auth_token: ReadSignal<Option<String>>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let token = Signal::derive(move || auth_token.get().unwrap_or_default());
    let selected = RwSignal::new(default_units());
    let available = RwSignal::new(Vec::<SystemdUnit>::new());
    let open = RwSignal::new(false);

    Effect::new(move |_| {
        let token_value = token.get();
        if token_value.is_empty() {
            return;
        }
        spawn_local(async move {
            match api::fetch_units(&token_value, true).await {
                Ok(units) => available.set(units),
                Err(message) if message.contains("Unauthorized") => on_unauthorized.run(()),
                // The selector keeps working with the defaults.
                Err(_) => {}
            }
        });
    });

    view! {
        <div class="space-y-4">
            <div class="flex flex-wrap items-end justify-between gap-3">
                <div>
                    <h1 class="text-2xl font-semibold text-blue-300">"Logs"</h1>
                    <p class="text-gray-400 text-sm">"Journal entries of the selected services, newest first."</p>
                </div>
                <div class="relative">
                    <button
                        type="button"
                        class="flex items-center gap-2 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-gray-100 rounded border border-gray-600 text-sm"
                        aria-haspopup="listbox"
                        aria-expanded=move || open.get()
                        on:click=move |_| open.update(|value| *value = !*value)
                    >
                        <span class="text-gray-400">"Services:"</span>
                        {move || selection_label(&selected.get())}
                        <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" aria-hidden="true">
                            <path d="m6 9 6 6 6-6" />
                        </svg>
                    </button>
                    <Show when=move || open.get()>
                        <div class="fixed inset-0 z-10" on:click=move |_| open.set(false)></div>
                        <div class="absolute right-0 z-20 mt-1 w-72 max-w-[calc(100vw-2rem)] bg-gray-800 border border-gray-600 rounded shadow-lg p-1" role="listbox" aria-multiselectable="true">
                            <For
                                each=move || available.get()
                                key=|unit| unit.name.clone()
                                children=move |unit| {
                                    let name = unit.name.clone();
                                    let checked_name = name.clone();
                                    view! {
                                        <label class="flex items-center gap-2 px-2 py-1.5 rounded hover:bg-gray-700 text-sm text-gray-200 cursor-pointer">
                                            <input
                                                type="checkbox"
                                                prop:checked=move || selected.with(|list| list.contains(&checked_name))
                                                on:change=move |_| {
                                                    let next = toggled(&selected.get_untracked(), &available.get_untracked(), &name);
                                                    selected.set(next);
                                                }
                                            />
                                            <span class="flex-1">{unit.name.clone()}</span>
                                            <span class=if unit.active_state == keystone_core::SystemdActiveState::Active {
                                                "w-2 h-2 rounded-full bg-emerald-400"
                                            } else {
                                                "w-2 h-2 rounded-full bg-slate-500"
                                            }></span>
                                        </label>
                                    }
                                }
                            />
                        </div>
                    </Show>
                </div>
            </div>

            <LogViewer
                token=token
                on_unauthorized=on_unauthorized
                units=Signal::derive(move || selected.get())
            />
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(name: &str) -> SystemdUnit {
        SystemdUnit {
            name: name.to_string(),
            ..SystemdUnit::default()
        }
    }

    #[test]
    fn toggling_adds_and_removes_in_listed_order() {
        let all = [unit("a.service"), unit("b.service"), unit("c.service")];
        let selected = vec!["c.service".to_string()];
        let added = toggled(&selected, &all, "a.service");
        assert_eq!(added, ["a.service", "c.service"]);
        assert_eq!(toggled(&added, &all, "c.service"), ["a.service"]);
    }

    #[test]
    fn the_default_selection_is_what_connectivity_needs() {
        let defaults = default_units();
        assert!(defaults.contains(&"systemd-networkd.service".to_string()));
        assert!(defaults.contains(&"dnsmasq.service".to_string()));
    }

    #[test]
    fn the_selector_label_names_few_services_and_counts_many() {
        assert_eq!(selection_label(&[]), "No services");
        assert_eq!(
            selection_label(&default_units()),
            "systemd-networkd, dnsmasq"
        );
        let many: Vec<String> = (0..4).map(|n| format!("u{n}.service")).collect();
        assert!(selection_label(&many).contains("services"));
    }
}
