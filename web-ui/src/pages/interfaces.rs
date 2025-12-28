//! Interfaces management page

use keystone_core::{InterfaceRole, ManagedInterface, SystemState};
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::components::A;
use std::collections::HashMap;

use crate::api;

#[component]
pub fn InterfacesPage(
    auth_token: ReadSignal<Option<String>>,
    state: ReadSignal<SystemState>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    // Managed interfaces from the database
    let (managed_interfaces, set_managed_interfaces) = signal::<Vec<ManagedInterface>>(vec![]);
    // Local edits (interface name -> Option<role>, None means not managed)
    let (pending_changes, set_pending_changes) =
        signal::<HashMap<String, Option<InterfaceRole>>>(HashMap::new());
    let (loading, set_loading) = signal(true);
    let (saving, set_saving) = signal(false);
    let (applying, set_applying) = signal(false);
    let (error, set_error) = signal::<Option<String>>(None);
    let (success, set_success) = signal::<Option<String>>(None);

    // Load managed interfaces on mount
    {
        spawn_local(async move {
            if let Some(token) = auth_token.get() {
                match api::fetch_managed_interfaces(&token).await {
                    Ok(interfaces) => {
                        set_managed_interfaces.set(interfaces);
                    }
                    Err(e) => {
                        if e == "Unauthorized" {
                            on_unauthorized.run(());
                        } else {
                            set_error.set(Some(e));
                        }
                    }
                }
            }
            set_loading.set(false);
        });
    }

    // Get current managed state for an interface (checking pending changes first)
    let get_interface_role = move |name: &str| -> Option<InterfaceRole> {
        let changes = pending_changes.get();
        if let Some(role) = changes.get(name) {
            return *role;
        }
        // Check saved managed interfaces
        managed_interfaces
            .get()
            .iter()
            .find(|m| m.name == name)
            .map(|m| m.role)
    };

    // Check if there are unsaved changes
    let has_changes = move || !pending_changes.get().is_empty();

    // Handle toggling interface management
    let toggle_interface = move |name: String, current_role: Option<InterfaceRole>| {
        set_pending_changes.update(|changes| {
            let new_role = match current_role {
                None => Some(InterfaceRole::LAN), // Default to LAN when enabling
                Some(_) => None,                  // Disable management
            };
            changes.insert(name, new_role);
        });
        set_success.set(None);
    };

    // Handle changing role
    let change_role = move |name: String, role: InterfaceRole| {
        set_pending_changes.update(|changes| {
            changes.insert(name, Some(role));
        });
        set_success.set(None);
    };

    // Save changes
    let save_changes = move |_| {
        spawn_local(async move {
            set_saving.set(true);
            set_error.set(None);

            if let Some(token) = auth_token.get() {
                // Build new managed interfaces list
                let mut new_managed: HashMap<String, ManagedInterface> = managed_interfaces
                    .get()
                    .iter()
                    .map(|m| (m.name.clone(), m.clone()))
                    .collect();

                // Apply pending changes
                for (name, role) in pending_changes.get().iter() {
                    match role {
                        Some(r) => {
                            new_managed.insert(
                                name.clone(),
                                ManagedInterface {
                                    name: name.clone(),
                                    role: *r,
                                    static_ip: None,
                                    enabled: true,
                                },
                            );
                        }
                        None => {
                            new_managed.remove(name);
                        }
                    }
                }

                let interfaces: Vec<ManagedInterface> = new_managed.into_values().collect();

                match api::save_managed_interfaces(&token, interfaces.clone()).await {
                    Ok(response) => {
                        if response.success {
                            set_managed_interfaces.set(interfaces);
                            set_pending_changes.set(HashMap::new());
                            set_success.set(Some(response.message));
                        } else {
                            set_error.set(Some(response.message));
                        }
                    }
                    Err(e) => {
                        if e == "Unauthorized" {
                            on_unauthorized.run(());
                        } else {
                            set_error.set(Some(e));
                        }
                    }
                }
            }
            set_saving.set(false);
        });
    };

    // Discard changes
    let discard_changes = move |_| {
        set_pending_changes.set(HashMap::new());
        set_error.set(None);
        set_success.set(None);
    };

    // Apply configuration to system (write networkd files and reload)
    let apply_to_system = move |_| {
        spawn_local(async move {
            set_applying.set(true);
            set_error.set(None);
            set_success.set(None);

            if let Some(token) = auth_token.get() {
                match api::apply_networkd(&token).await {
                    Ok(response) => {
                        if response.success {
                            set_success.set(Some(response.message));
                        } else {
                            let errors_msg = if response.errors.is_empty() {
                                response.message
                            } else {
                                format!("{}: {}", response.message, response.errors.join(", "))
                            };
                            set_error.set(Some(errors_msg));
                        }
                    }
                    Err(e) => {
                        if e == "Unauthorized" {
                            on_unauthorized.run(());
                        } else {
                            set_error.set(Some(e));
                        }
                    }
                }
            }
            set_applying.set(false);
        });
    };

    view! {
        <div class="space-y-6">
            <div>
                <h1 class="text-2xl font-semibold text-blue-300">"Interface Management"</h1>
                <p class="text-gray-400">"Select which interfaces Keystone should manage and assign them a role."</p>
            </div>

            // Unsaved changes indicator
            <Show when=move || has_changes()>
                <div class="bg-yellow-900/30 border border-yellow-600 text-yellow-200 px-4 py-2 rounded">
                    "You have unsaved changes"
                </div>
            </Show>

            // Error/Success messages
            <Show when=move || error.get().is_some()>
                <div class="bg-red-900/50 border border-red-500 text-red-200 px-4 py-2 rounded">
                    {move || error.get().unwrap_or_default()}
                </div>
            </Show>
            <Show when=move || success.get().is_some()>
                <div class="bg-green-900/50 border border-green-500 text-green-200 px-4 py-2 rounded">
                    {move || success.get().unwrap_or_default()}
                </div>
            </Show>

            <Show
                when=move || !loading.get()
                fallback=|| view! {
                    <div class="text-gray-400">"Loading interfaces..."</div>
                }
            >
                <div class="bg-gray-800 rounded-lg shadow-lg overflow-hidden">
                    <div class="space-y-1 p-4">
                        <For
                            each=move || state.get().interfaces.clone()
                            key=|iface| iface.name.clone()
                            children=move |iface| {
                                let name = iface.name.clone();
                                let name2 = iface.name.clone();
                                let name3 = iface.name.clone();
                                let name4 = iface.name.clone();
                                let name5 = iface.name.clone();
                                let name6 = iface.name.clone();
                                let name7 = iface.name.clone();
                                let name8 = iface.name.clone();
                                let address = iface.address.clone().unwrap_or_else(|| "No IP".to_string());

                                let is_managed = move || get_interface_role(&name3).is_some();
                                let role_section_class = move || {
                                    if is_managed() {
                                        "flex items-center gap-3"
                                    } else {
                                        "hidden"
                                    }
                                };

                                view! {
                                    <div class="bg-gray-700 rounded p-4 flex items-center justify-between">
                                        <div class="flex items-center gap-4">
                                            // Checkbox to toggle management
                                            <input
                                                type="checkbox"
                                                checked=move || get_interface_role(&name).is_some()
                                                class="w-5 h-5 rounded border-gray-500 bg-gray-600 text-blue-500 focus:ring-blue-500"
                                                on:change=move |_| {
                                                    let n = name2.clone();
                                                    toggle_interface(n.clone(), get_interface_role(&n))
                                                }
                                            />
                                            <div>
                                                <div class="font-medium text-white">{name4.clone()}</div>
                                                <div class="text-sm text-gray-400">{address}</div>
                                            </div>
                                        </div>

                                        // Role selector and edit button (hidden when not managed)
                                        <div class=role_section_class>
                                            <select
                                                class="bg-gray-600 text-white rounded px-3 py-1.5 border border-gray-500 focus:border-blue-500 focus:outline-none"
                                                on:change=move |ev| {
                                                    let value = event_target_value(&ev);
                                                    let role = match value.as_str() {
                                                        "WAN" => InterfaceRole::WAN,
                                                        _ => InterfaceRole::LAN,
                                                    };
                                                    change_role(name5.clone(), role);
                                                }
                                            >
                                                <option
                                                    value="LAN"
                                                    selected=move || get_interface_role(&name6) == Some(InterfaceRole::LAN)
                                                >
                                                    "LAN"
                                                </option>
                                                <option
                                                    value="WAN"
                                                    selected=move || get_interface_role(&name7) == Some(InterfaceRole::WAN)
                                                >
                                                    "WAN"
                                                </option>
                                            </select>

                                            <A
                                                href=move || format!("/interfaces/{}", name8)
                                                attr:class="bg-blue-600 hover:bg-blue-700 text-white px-3 py-1.5 rounded text-sm"
                                            >
                                                "Edit"
                                            </A>
                                        </div>
                                    </div>
                                }
                            }
                        />
                    </div>
                </div>

                // Save/Discard buttons
                <Show when=move || has_changes()>
                    <div class="flex gap-3">
                        <button
                            class="bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 disabled:cursor-not-allowed text-white px-4 py-2 rounded font-medium"
                            disabled=move || saving.get()
                            on:click=save_changes
                        >
                            {move || if saving.get() { "Saving..." } else { "Save Changes" }}
                        </button>
                        <button
                            class="bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded"
                            disabled=move || saving.get()
                            on:click=discard_changes
                        >
                            "Discard"
                        </button>
                    </div>
                </Show>

                // Apply to System button (always visible when not loading)
                <div class="pt-4 border-t border-gray-700">
                    <div class="flex items-center justify-between">
                        <div>
                            <h3 class="text-lg font-medium text-gray-200">"Apply Configuration"</h3>
                            <p class="text-sm text-gray-400">"Write interface configs to systemd-networkd and reload the network"</p>
                        </div>
                        <button
                            class="bg-green-600 hover:bg-green-700 disabled:bg-green-800 disabled:cursor-not-allowed text-white px-6 py-2.5 rounded font-medium"
                            disabled=move || applying.get() || has_changes()
                            on:click=apply_to_system
                        >
                            {move || if applying.get() { "Applying..." } else { "Apply to System" }}
                        </button>
                    </div>
                    <Show when=move || has_changes()>
                        <p class="text-yellow-400 text-sm mt-2">"Save your changes before applying to the system."</p>
                    </Show>
                </div>
            </Show>
        </div>
    }
}
