//! VLAN configuration page

use keystone_core::{ManagedInterface, VlanConfig, VlanProtocol};
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::api;

#[component]
pub fn VlansPage(
    auth_token: ReadSignal<Option<String>>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let (vlans, set_vlans) = signal(Vec::<VlanConfig>::new());
    let (managed_interfaces, set_managed_interfaces) = signal(Vec::<ManagedInterface>::new());
    let (loading, set_loading) = signal(true);
    let (error_msg, set_error_msg) = signal(Option::<String>::None);
    let (success_msg, set_success_msg) = signal(Option::<String>::None);

    // Modal state
    let (show_modal, set_show_modal) = signal(false);
    let (editing_vlan, set_editing_vlan) = signal(Option::<VlanConfig>::None);
    let (modal_name, set_modal_name) = signal(String::new());
    let (modal_parent, set_modal_parent) = signal(String::new());
    let (modal_vlan_id, set_modal_vlan_id) = signal(String::new());
    let (modal_protocol, set_modal_protocol) = signal(VlanProtocol::Dot1Q);
    let (modal_description, set_modal_description) = signal(String::new());
    let (modal_error, set_modal_error) = signal(Option::<String>::None);

    // Load VLANs and managed interfaces on mount
    Effect::new(move || {
        if let Some(token) = auth_token.get() {
            let token_clone = token.clone();
            spawn_local(async move {
                match api::fetch_vlans(&token).await {
                    Ok(vlan_list) => {
                        set_vlans.set(vlan_list);
                        set_loading.set(false);
                    }
                    Err(e) => {
                        if e.contains("Unauthorized") {
                            on_unauthorized.run(());
                        } else {
                            set_error_msg.set(Some(e));
                            set_loading.set(false);
                        }
                    }
                }
            });

            spawn_local(async move {
                match api::fetch_managed_interfaces(&token_clone).await {
                    Ok(interfaces) => {
                        set_managed_interfaces.set(interfaces);
                    }
                    Err(e) => {
                        if e.contains("Unauthorized") {
                            on_unauthorized.run(());
                        }
                    }
                }
            });
        }
    });

    let open_new_vlan_modal = move |_| {
        set_editing_vlan.set(None);
        set_modal_name.set(String::new());
        set_modal_parent.set(String::new());
        set_modal_vlan_id.set(String::new());
        set_modal_protocol.set(VlanProtocol::Dot1Q);
        set_modal_description.set(String::new());
        set_modal_error.set(None);
        set_show_modal.set(true);
    };

    let open_edit_vlan_modal = move |vlan: VlanConfig| {
        set_editing_vlan.set(Some(vlan.clone()));
        set_modal_name.set(vlan.name.clone());
        set_modal_parent.set(vlan.parent_interface.clone());
        set_modal_vlan_id.set(vlan.vlan_id.to_string());
        set_modal_protocol.set(vlan.protocol);
        set_modal_description.set(vlan.description.clone().unwrap_or_default());
        set_modal_error.set(None);
        set_show_modal.set(true);
    };

    let close_modal = move |_| {
        set_show_modal.set(false);
        set_modal_error.set(None);
    };

    let save_vlan = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();

        let token = match auth_token.get() {
            Some(t) => t,
            None => return,
        };

        let name = modal_name.get();
        let parent = modal_parent.get();
        let vlan_id_str = modal_vlan_id.get();
        let protocol = modal_protocol.get();
        let description = modal_description.get();
        let existing_id = editing_vlan.get().and_then(|v| v.id);

        // Validation
        if name.is_empty() {
            set_modal_error.set(Some("VLAN name is required".to_string()));
            return;
        }

        if parent.is_empty() {
            set_modal_error.set(Some("Parent interface is required".to_string()));
            return;
        }

        let vlan_id: u16 = match vlan_id_str.parse() {
            Ok(id) if (1..=4094).contains(&id) => id,
            _ => {
                set_modal_error.set(Some("VLAN ID must be between 1 and 4094".to_string()));
                return;
            }
        };

        let config = VlanConfig {
            id: existing_id,
            name,
            parent_interface: parent,
            vlan_id,
            protocol,
            description: if description.is_empty() {
                None
            } else {
                Some(description)
            },
            interface_config_id: None,
        };

        spawn_local(async move {
            match api::save_vlan(&token, config).await {
                Ok(response) => {
                    if response.success {
                        set_show_modal.set(false);
                        set_success_msg.set(Some(response.message.clone()));
                        // Reload VLANs
                        if let Ok(vlan_list) = api::fetch_vlans(&token).await {
                            set_vlans.set(vlan_list);
                        }
                    } else {
                        set_modal_error.set(Some(response.message));
                    }
                }
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        set_modal_error.set(Some(format!("Error: {}", e)));
                    }
                }
            }
        });
    };

    let delete_vlan = move |vlan_id: i64| {
        let token = match auth_token.get() {
            Some(t) => t,
            None => return,
        };

        if !web_sys::window()
            .and_then(|w| {
                w.confirm_with_message("Are you sure you want to delete this VLAN?")
                    .ok()
            })
            .unwrap_or(false)
        {
            return;
        }

        spawn_local(async move {
            match api::delete_vlan(&token, vlan_id).await {
                Ok(response) => {
                    if response.success {
                        set_success_msg.set(Some(response.message.clone()));
                        // Reload VLANs
                        if let Ok(vlan_list) = api::fetch_vlans(&token).await {
                            set_vlans.set(vlan_list);
                        }
                    } else {
                        set_error_msg.set(Some(response.message));
                    }
                }
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        set_error_msg.set(Some(format!("Error: {}", e)));
                    }
                }
            }
        });
    };

    view! {
        <div class="space-y-6">
            <div class="flex items-center justify-between">
                <div>
                    <h1 class="text-2xl font-semibold text-blue-300">"VLANs"</h1>
                    <p class="text-gray-400">"Configure 802.1Q VLAN interfaces"</p>
                </div>
                <button
                    on:click=open_new_vlan_modal
                    class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
                >
                    "+ Add VLAN"
                </button>
            </div>

            <Show when=move || success_msg.get().is_some()>
                <div class="bg-green-900/50 border border-green-500 rounded p-4 text-green-200">
                    {move || success_msg.get().unwrap_or_default()}
                </div>
            </Show>

            <Show when=move || error_msg.get().is_some()>
                <div class="bg-red-900/50 border border-red-500 rounded p-4 text-red-200">
                    {move || error_msg.get().unwrap_or_default()}
                </div>
            </Show>

            <Show when=move || loading.get()>
                <div class="text-center py-8 text-gray-400">"Loading VLANs..."</div>
            </Show>

            <Show when=move || !loading.get() && vlans.get().is_empty()>
                <div class="bg-gray-800 rounded-lg p-8 text-center">
                    <p class="text-gray-400 mb-4">"No VLANs configured yet."</p>
                    <button
                        on:click=open_new_vlan_modal
                        class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
                    >
                        "Create your first VLAN"
                    </button>
                </div>
            </Show>

            <Show when=move || !loading.get() && !vlans.get().is_empty()>
                <div class="bg-gray-800 rounded-lg shadow-lg overflow-hidden">
                    <table class="w-full">
                        <thead class="bg-gray-700">
                            <tr>
                                <th class="px-4 py-3 text-left text-gray-300 font-medium">"Name"</th>
                                <th class="px-4 py-3 text-left text-gray-300 font-medium">"VLAN ID"</th>
                                <th class="px-4 py-3 text-left text-gray-300 font-medium">"Parent"</th>
                                <th class="px-4 py-3 text-left text-gray-300 font-medium">"Protocol"</th>
                                <th class="px-4 py-3 text-left text-gray-300 font-medium">"Description"</th>
                                <th class="px-4 py-3 text-right text-gray-300 font-medium">"Actions"</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-700">
                            <For
                                each=move || vlans.get()
                                key=|vlan| (vlan.id, vlan.name.clone(), vlan.vlan_id)
                                children=move |vlan: VlanConfig| {
                                    let vlan_for_edit = vlan.clone();
                                    let vlan_id_for_delete = vlan.id.unwrap_or(0);
                                    let name = vlan.name.clone();
                                    let vlan_id = vlan.vlan_id;
                                    let parent = vlan.parent_interface.clone();
                                    let protocol = format!("{}", vlan.protocol);
                                    let description = vlan.description.clone().unwrap_or_else(|| "-".to_string());
                                    view! {
                                        <tr class="hover:bg-gray-750">
                                            <td class="px-4 py-3 text-white font-medium">{name}</td>
                                            <td class="px-4 py-3 text-gray-300">{vlan_id}</td>
                                            <td class="px-4 py-3 text-gray-300">{parent}</td>
                                            <td class="px-4 py-3 text-gray-300">{protocol}</td>
                                            <td class="px-4 py-3 text-gray-400">{description}</td>
                                            <td class="px-4 py-3 text-right">
                                                <div class="flex gap-2 justify-end">
                                                    <button
                                                        on:click=move |_| open_edit_vlan_modal(vlan_for_edit.clone())
                                                        class="bg-yellow-600 hover:bg-yellow-700 text-white px-3 py-1 rounded text-sm"
                                                    >
                                                        "Edit"
                                                    </button>
                                                    <button
                                                        on:click=move |_| delete_vlan(vlan_id_for_delete)
                                                        class="bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded text-sm"
                                                    >
                                                        "Delete"
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                    }
                                }
                            />
                        </tbody>
                    </table>
                </div>
            </Show>

            // VLAN Modal
            <Show when=move || show_modal.get()>
                <div class="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
                    <div class="bg-gray-800 rounded-lg p-6 max-w-lg w-full">
                        <h2 class="text-xl font-semibold text-white mb-4">
                            {move || if editing_vlan.get().is_some() { "Edit VLAN" } else { "Add VLAN" }}
                        </h2>

                        <form on:submit=save_vlan>
                            <div class="space-y-4">
                                <div>
                                    <label class="block text-gray-300 mb-2">"VLAN Name"</label>
                                    <input
                                        type="text"
                                        prop:value=move || modal_name.get()
                                        on:input=move |ev| set_modal_name.set(event_target_value(&ev))
                                        placeholder="e.g., vlan10, guest_vlan"
                                        class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white"
                                        required
                                    />
                                    <p class="text-sm text-gray-500 mt-1">"This will be the interface name"</p>
                                </div>

                                <div class="grid grid-cols-2 gap-4">
                                    <div>
                                        <label class="block text-gray-300 mb-2">"Parent Interface"</label>
                                        <select
                                            prop:value=move || modal_parent.get()
                                            on:change=move |ev| set_modal_parent.set(event_target_value(&ev))
                                            class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white"
                                            required
                                        >
                                            <option value="" disabled=true selected=move || modal_parent.get().is_empty()>
                                                "Select interface..."
                                            </option>
                                            <For
                                                each=move || managed_interfaces.get()
                                                key=|iface| iface.name.clone()
                                                children=move |iface: ManagedInterface| {
                                                    let name = iface.name.clone();
                                                    let label = format!("{} ({})", iface.name, iface.role);
                                                    view! {
                                                        <option value=name.clone()>{label}</option>
                                                    }
                                                }
                                            />
                                        </select>
                                    </div>

                                    <div>
                                        <label class="block text-gray-300 mb-2">"VLAN ID"</label>
                                        <input
                                            type="number"
                                            min="1"
                                            max="4094"
                                            prop:value=move || modal_vlan_id.get()
                                            on:input=move |ev| set_modal_vlan_id.set(event_target_value(&ev))
                                            placeholder="1-4094"
                                            class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white"
                                            required
                                        />
                                    </div>
                                </div>

                                <div>
                                    <label class="block text-gray-300 mb-2">"Protocol"</label>
                                    <select
                                        prop:value=move || modal_protocol.get().to_string()
                                        on:change=move |ev| {
                                            let value = event_target_value(&ev);
                                            set_modal_protocol.set(
                                                value.parse().unwrap_or(VlanProtocol::Dot1Q)
                                            );
                                        }
                                        class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white"
                                    >
                                        <option value="802.1q">"802.1Q (Standard VLAN)"</option>
                                        <option value="802.1ad">"802.1ad (QinQ / Provider Bridging)"</option>
                                    </select>
                                </div>

                                <div>
                                    <label class="block text-gray-300 mb-2">"Description (optional)"</label>
                                    <input
                                        type="text"
                                        prop:value=move || modal_description.get()
                                        on:input=move |ev| set_modal_description.set(event_target_value(&ev))
                                        placeholder="e.g., Guest network VLAN"
                                        class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white"
                                    />
                                </div>

                                <Show when=move || modal_error.get().is_some()>
                                    <div class="bg-red-900/50 border border-red-500 rounded p-3 text-red-200 text-sm">
                                        {move || modal_error.get().unwrap_or_default()}
                                    </div>
                                </Show>

                                <div class="flex gap-2 pt-2">
                                    <button
                                        type="submit"
                                        class="flex-1 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
                                    >
                                        "Save"
                                    </button>
                                    <button
                                        type="button"
                                        on:click=close_modal
                                        class="flex-1 bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded"
                                    >
                                        "Cancel"
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </Show>
        </div>
    }
}
