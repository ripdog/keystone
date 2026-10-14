//! Interfaces management page

use crate::components::{PendingActions, use_toasts};
use keystone_core::{Interface, InterfaceRole, ManagedInterface, SystemState};
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::components::A;
use std::collections::HashMap;

use crate::api;
use crate::components::use_config_changed;

#[component]
pub fn InterfacesPage(
    auth_token: ReadSignal<Option<String>>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let toasts = use_toasts();
    // Runtime interface discovery is owned by this page, not the Dashboard.
    // Direct navigation to /interfaces must not depend on visiting / first.
    let (state, set_state) = signal(SystemState::default());
    // Managed interfaces from the database
    let (managed_interfaces, set_managed_interfaces) = signal::<Vec<ManagedInterface>>(vec![]);
    // Local edits (interface name -> Option<role>, None means not managed)
    let (pending_changes, set_pending_changes) =
        signal::<HashMap<String, Option<InterfaceRole>>>(HashMap::new());
    let (loading, set_loading) = signal(true);
    let (saving, set_saving) = signal(false);
    let (renewing, set_renewing) = signal::<Option<String>>(None);
    let (rename_busy, set_rename_busy) = signal(false);
    // Bumped to reload the interface list after a rename.
    let (reload, set_reload) = signal(0u32);
    let locked = expect_context::<PendingActions>().locked;
    let config_changed = use_config_changed();
    let (error, set_error) = signal::<Option<String>>(None);

    // Load both discovered hardware and persisted management configuration.
    // The separate /state endpoint supplies physical interfaces that are not
    // yet managed; /managed-interfaces contains only configured interfaces.
    Effect::new(move || {
        reload.track();
        let Some(token) = auth_token.get() else {
            set_loading.set(false);
            return;
        };
        set_loading.set(true);
        spawn_local(async move {
            let discovered = api::fetch_system_state(&token).await;
            let managed = api::fetch_managed_interfaces(&token).await;
            match (discovered, managed) {
                (Ok(discovered), Ok(managed)) => {
                    set_state.set(SystemState {
                        interfaces: merge_interfaces(discovered.interfaces, &managed),
                    });
                    set_managed_interfaces.set(managed);
                    set_error.set(None);
                }
                (Err(e), _) | (_, Err(e)) => {
                    if e == "Unauthorized" {
                        on_unauthorized.run(());
                    } else {
                        set_error.set(Some(format!("Failed to load interfaces: {e}")));
                    }
                }
            }
            set_loading.set(false);
        });
    });

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
    };

    // Handle changing role
    let change_role = move |name: String, role: InterfaceRole| {
        set_pending_changes.update(|changes| {
            changes.insert(name, Some(role));
        });
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
                            config_changed.run(());
                            toasts.success(response.message);
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
    };

    let renew_link = move |name: String| {
        let Some(token) = auth_token.get_untracked() else {
            return;
        };
        set_renewing.set(Some(name.clone()));
        set_error.set(None);
        spawn_local(async move {
            match api::renew_interface(&token, &name).await {
                Ok(result) if result.success => toasts.success(result.message),
                Ok(result) => set_error.set(Some(result.message)),
                Err(e) if e == "Unauthorized" => on_unauthorized.run(()),
                Err(e) => set_error.set(Some(format!("Failed to renew {name}: {e}"))),
            }
            set_renewing.set(None);
        });
    };

    let rename_link = Callback::new(move |(name, new_name, allow): (String, String, bool)| {
        if has_changes() {
            set_error.set(Some(
                "Save or discard your changes to the interface list before renaming an interface"
                    .to_string(),
            ));
            return;
        }
        let Some(token) = auth_token.get_untracked() else {
            return;
        };
        set_rename_busy.set(true);
        set_error.set(None);
        spawn_local(async move {
            match api::rename_interface(&token, &name, &new_name, allow).await {
                Ok(response) => {
                    let renamed = response.apply.is_some();
                    if response.success {
                        toasts.success(response.message);
                    } else {
                        set_error.set(Some(response.message));
                    }
                    if renamed {
                        // The interface now has its new name; show it, and let
                        // the pending-changes bar pick up a confirmation.
                        set_reload.update(|count| *count = count.wrapping_add(1));
                        config_changed.run(());
                    }
                }
                Err(e) if e == "Unauthorized" => on_unauthorized.run(()),
                Err(e) => set_error.set(Some(format!("Failed to rename {name}: {e}"))),
            }
            set_rename_busy.set(false);
        });
    });

    view! {
        <div class="space-y-6">
            <div>
                <h1 class="text-2xl font-semibold text-blue-300">"Interface Management"</h1>
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
                                let name9 = iface.name.clone();
                                let name10 = iface.name.clone();
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
                                                <RenameControl
                                                    name=iface.name.clone()
                                                    dhcp=iface.dhcp_enabled
                                                    disabled=Signal::derive(move || locked.get() || rename_busy.get())
                                                    busy=rename_busy
                                                    on_rename=rename_link
                                                />
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

                                            <button
                                                class="bg-gray-600 hover:bg-gray-500 disabled:opacity-50 text-white px-3 py-1.5 rounded text-sm"
                                                disabled=move || renewing.get().is_some()
                                                on:click=move |_| renew_link(name9.clone())
                                                title="Ask systemd-networkd to renew DHCP and other dynamic configuration"
                                            >
                                                {move || if renewing.get().as_deref() == Some(name10.as_str()) {
                                                    "Renewing..."
                                                } else { "Renew" }}
                                            </button>
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
                        <Show when=move || state.get().interfaces.is_empty()>
                            <p class="text-yellow-300 text-sm p-2">
                                "No interfaces were returned by the system. Check the system status and interface discovery service."
                            </p>
                        </Show>
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
            </Show>
        </div>
    }
}

/// A "Rename" link that opens an inline editor for the interface's new name.
#[component]
fn RenameControl(
    name: String,
    /// The interface gets its address by DHCP, so renaming restarts the client.
    dhcp: bool,
    disabled: Signal<bool>,
    busy: ReadSignal<bool>,
    on_rename: Callback<(String, String, bool)>,
) -> impl IntoView {
    let (editing, set_editing) = signal(false);
    let (accepted, set_accepted) = signal(false);
    let (input, set_input) = signal(name.clone());
    let open_name = name.clone();

    move || {
        if !editing.get() {
            let open_name = open_name.clone();
            return view! {
                <button
                    class="text-xs text-blue-300 hover:text-blue-200 disabled:opacity-50 underline"
                    disabled=move || disabled.get()
                    title="Give this network card a persistent name such as wan0 or lan0"
                    on:click=move |_| {
                        set_input.set(open_name.clone());
                        set_editing.set(true);
                    }
                >
                    "Rename"
                </button>
            }
            .into_any();
        }
        let submit_name = name.clone();
        view! {
            <div class="mt-1 space-y-1">
                <div class="flex items-center gap-2">
                    <input
                        type="text"
                        maxlength="15"
                        class="bg-gray-600 text-white rounded px-2 py-1 text-sm border border-gray-500 focus:border-blue-500 focus:outline-none w-32"
                        prop:value=move || input.get()
                        on:input=move |ev| set_input.set(event_target_value(&ev))
                    />
                    <button
                        class="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white px-2 py-1 rounded text-sm"
                        disabled=move || disabled.get() || (dhcp && !accepted.get())
                        on:click=move |_| {
                            on_rename.run((
                                submit_name.clone(),
                                input.get_untracked().trim().to_string(),
                                accepted.get_untracked(),
                            ))
                        }
                    >
                        {move || if busy.get() { "Renaming..." } else { "Rename" }}
                    </button>
                    <button
                        class="bg-gray-600 hover:bg-gray-500 text-white px-2 py-1 rounded text-sm"
                        disabled=move || busy.get()
                        on:click=move |_| set_editing.set(false)
                    >
                        "Cancel"
                    </button>
                </div>
                {dhcp.then(|| view! {
                    <label class="flex items-start gap-2 text-xs text-red-200">
                        <input
                            type="checkbox"
                            prop:checked=move || accepted.get()
                            on:change=move |ev| set_accepted.set(event_target_checked(&ev))
                        />
                        "This interface gets its address by DHCP. Renaming restarts the DHCP client, and some ISPs then stop routing your traffic until the old lease expires (about 25 minutes). I accept this."
                    </label>
                })}
                <p class="text-xs text-yellow-200">
                    "The interface briefly goes down and its configuration is re-applied; confirm the change afterwards. Letters, digits, '-' and '_' only, up to 15 characters; not eth0, wlan0, enp3s0 style names."
                </p>
            </div>
        }
        .into_any()
    }
}

/// Include configured interfaces even when runtime discovery omits them (for
/// example, an interface without carrier or an unavailable kernel query).
/// The live address list and link state win when an interface is discovered.
fn merge_interfaces(
    mut discovered: Vec<Interface>,
    managed: &[ManagedInterface],
) -> Vec<Interface> {
    for managed_iface in managed.iter().filter(|iface| iface.enabled) {
        if let Some(existing) = discovered
            .iter_mut()
            .find(|iface| iface.name == managed_iface.name)
        {
            existing.role = managed_iface.role;
        } else {
            let address = managed_iface.static_ip.clone();
            let ipv4_addresses = address
                .iter()
                .filter(|addr| !addr.contains(':'))
                .cloned()
                .collect();
            let ipv6_addresses = address
                .iter()
                .filter(|addr| addr.contains(':'))
                .cloned()
                .collect();
            discovered.push(Interface {
                name: managed_iface.name.clone(),
                address,
                ipv4_addresses,
                ipv6_addresses,
                dhcp_enabled: managed_iface.static_ip.is_none(),
                role: managed_iface.role,
                enabled: false,
            });
        }
    }
    discovered.sort_by(|left, right| left.name.cmp(&right.name));
    discovered
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_interfaces_are_shown_even_without_dashboard_or_runtime_state() {
        let managed = [
            ManagedInterface {
                name: "enp2s0".into(),
                role: InterfaceRole::LAN,
                static_ip: Some("192.168.1.1/24".into()),
                enabled: true,
            },
            ManagedInterface {
                name: "enp3s0".into(),
                role: InterfaceRole::WAN,
                static_ip: None,
                enabled: true,
            },
        ];
        let found = merge_interfaces(vec![], &managed);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].address.as_deref(), Some("192.168.1.1/24"));
        assert_eq!(found[1].role, InterfaceRole::WAN);
        assert!(found[1].dhcp_enabled);
    }

    #[test]
    fn discovered_live_addresses_are_preserved_and_managed_role_wins() {
        let discovered = vec![Interface {
            name: "enp3s0".into(),
            address: Some("103.187.6.32/32".into()),
            ipv4_addresses: vec!["103.187.6.32/32".into()],
            ipv6_addresses: vec!["fe80::1/64".into()],
            dhcp_enabled: true,
            role: InterfaceRole::LAN,
            enabled: true,
        }];
        let managed = [ManagedInterface {
            name: "enp3s0".into(),
            role: InterfaceRole::WAN,
            static_ip: None,
            enabled: true,
        }];
        let merged = merge_interfaces(discovered, &managed);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].role, InterfaceRole::WAN);
        assert_eq!(merged[0].ipv6_addresses, vec!["fe80::1/64"]);
        assert_eq!(merged[0].address.as_deref(), Some("103.187.6.32/32"));
    }
}
