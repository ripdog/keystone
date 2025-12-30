//! Bridge configuration page

use keystone_core::{BridgeConfig, ManagedInterface};
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::api;

#[component]
pub fn BridgesPage(
    auth_token: ReadSignal<Option<String>>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let (bridges, set_bridges) = signal(Vec::<BridgeConfig>::new());
    let (managed_interfaces, set_managed_interfaces) = signal(Vec::<ManagedInterface>::new());
    let (loading, set_loading) = signal(true);
    let (error_msg, set_error_msg) = signal(Option::<String>::None);
    let (success_msg, set_success_msg) = signal(Option::<String>::None);

    // Modal state
    let (show_modal, set_show_modal) = signal(false);
    let (editing_bridge, set_editing_bridge) = signal(Option::<BridgeConfig>::None);
    let (modal_name, set_modal_name) = signal(String::new());
    let (modal_members, set_modal_members) = signal(Vec::<String>::new());
    let (modal_stp, set_modal_stp) = signal(false);
    let (modal_stp_forward_delay, set_modal_stp_forward_delay) = signal(String::from("15"));
    let (modal_description, set_modal_description) = signal(String::new());
    let (modal_error, set_modal_error) = signal(Option::<String>::None);

    // Load bridges and managed interfaces on mount
    Effect::new(move || {
        if let Some(token) = auth_token.get() {
            let token_clone = token.clone();
            spawn_local(async move {
                match api::fetch_bridges(&token).await {
                    Ok(bridge_list) => {
                        set_bridges.set(bridge_list);
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

    let open_new_bridge_modal = move |_| {
        set_editing_bridge.set(None);
        set_modal_name.set(String::new());
        set_modal_members.set(Vec::new());
        set_modal_stp.set(false);
        set_modal_stp_forward_delay.set(String::from("15"));
        set_modal_description.set(String::new());
        set_modal_error.set(None);
        set_show_modal.set(true);
    };

    let open_edit_bridge_modal = move |bridge: BridgeConfig| {
        set_editing_bridge.set(Some(bridge.clone()));
        set_modal_name.set(bridge.name.clone());
        set_modal_members.set(bridge.members.clone());
        set_modal_stp.set(bridge.stp);
        set_modal_stp_forward_delay.set(bridge.stp_forward_delay.to_string());
        set_modal_description.set(bridge.description.clone().unwrap_or_default());
        set_modal_error.set(None);
        set_show_modal.set(true);
    };

    let close_modal = move |_| {
        set_show_modal.set(false);
        set_modal_error.set(None);
    };

    let toggle_member = move |interface_name: String| {
        set_modal_members.update(|members| {
            if members.contains(&interface_name) {
                members.retain(|m| m != &interface_name);
            } else {
                members.push(interface_name);
            }
        });
    };

    let save_bridge = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();

        let token = match auth_token.get() {
            Some(t) => t,
            None => return,
        };

        let name = modal_name.get();
        let members = modal_members.get();
        let stp = modal_stp.get();
        let stp_forward_delay_str = modal_stp_forward_delay.get();
        let description = modal_description.get();
        let existing_id = editing_bridge.get().and_then(|b| b.id);

        // Validation
        if name.is_empty() {
            set_modal_error.set(Some("Bridge name is required".to_string()));
            return;
        }

        let stp_forward_delay: u32 = match stp_forward_delay_str.parse() {
            Ok(delay) if (2..=30).contains(&delay) => delay,
            _ => {
                set_modal_error.set(Some(
                    "STP forward delay must be between 2 and 30 seconds".to_string(),
                ));
                return;
            }
        };

        let config = BridgeConfig {
            id: existing_id,
            name,
            members,
            stp,
            stp_forward_delay,
            description: if description.is_empty() {
                None
            } else {
                Some(description)
            },
            interface_config_id: None,
        };

        spawn_local(async move {
            match api::save_bridge(&token, config).await {
                Ok(response) => {
                    if response.success {
                        set_show_modal.set(false);
                        set_success_msg.set(Some(response.message.clone()));
                        // Reload bridges
                        if let Ok(bridge_list) = api::fetch_bridges(&token).await {
                            set_bridges.set(bridge_list);
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

    let delete_bridge = move |bridge_id: i64| {
        let token = match auth_token.get() {
            Some(t) => t,
            None => return,
        };

        if !web_sys::window()
            .and_then(|w| {
                w.confirm_with_message("Are you sure you want to delete this bridge?")
                    .ok()
            })
            .unwrap_or(false)
        {
            return;
        }

        spawn_local(async move {
            match api::delete_bridge(&token, bridge_id).await {
                Ok(response) => {
                    if response.success {
                        set_success_msg.set(Some(response.message.clone()));
                        // Reload bridges
                        if let Ok(bridge_list) = api::fetch_bridges(&token).await {
                            set_bridges.set(bridge_list);
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
                    <h1 class="text-2xl font-semibold text-blue-300">"Bridges"</h1>
                    <p class="text-gray-400">"Configure network bridges to combine interfaces"</p>
                </div>
                <button
                    on:click=open_new_bridge_modal
                    class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
                >
                    "+ Add Bridge"
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
                <div class="text-center py-8 text-gray-400">"Loading bridges..."</div>
            </Show>

            <Show when=move || !loading.get() && bridges.get().is_empty()>
                <div class="bg-gray-800 rounded-lg p-8 text-center">
                    <p class="text-gray-400 mb-4">"No bridges configured yet."</p>
                    <button
                        on:click=open_new_bridge_modal
                        class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
                    >
                        "Create your first bridge"
                    </button>
                </div>
            </Show>

            <Show when=move || !loading.get() && !bridges.get().is_empty()>
                <div class="bg-gray-800 rounded-lg shadow-lg overflow-hidden">
                    <table class="w-full">
                        <thead class="bg-gray-700">
                            <tr>
                                <th class="px-4 py-3 text-left text-gray-300 font-medium">"Name"</th>
                                <th class="px-4 py-3 text-left text-gray-300 font-medium">"Members"</th>
                                <th class="px-4 py-3 text-left text-gray-300 font-medium">"STP"</th>
                                <th class="px-4 py-3 text-left text-gray-300 font-medium">"Description"</th>
                                <th class="px-4 py-3 text-right text-gray-300 font-medium">"Actions"</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-700">
                            <For
                                each=move || bridges.get()
                                key=|bridge| (bridge.id, bridge.name.clone(), bridge.members.len())
                                children=move |bridge: BridgeConfig| {
                                    let bridge_for_edit = bridge.clone();
                                    let bridge_id_for_delete = bridge.id.unwrap_or(0);
                                    let name = bridge.name.clone();
                                    let members = if bridge.members.is_empty() {
                                        "-".to_string()
                                    } else {
                                        bridge.members.join(", ")
                                    };
                                    let stp_status = if bridge.stp {
                                        format!("Enabled ({}s)", bridge.stp_forward_delay)
                                    } else {
                                        "Disabled".to_string()
                                    };
                                    let description = bridge.description.clone().unwrap_or_else(|| "-".to_string());
                                    view! {
                                        <tr class="hover:bg-gray-750">
                                            <td class="px-4 py-3 text-white font-medium">{name}</td>
                                            <td class="px-4 py-3 text-gray-300">{members}</td>
                                            <td class="px-4 py-3 text-gray-300">{stp_status}</td>
                                            <td class="px-4 py-3 text-gray-400">{description}</td>
                                            <td class="px-4 py-3 text-right">
                                                <div class="flex gap-2 justify-end">
                                                    <button
                                                        on:click=move |_| open_edit_bridge_modal(bridge_for_edit.clone())
                                                        class="bg-yellow-600 hover:bg-yellow-700 text-white px-3 py-1 rounded text-sm"
                                                    >
                                                        "Edit"
                                                    </button>
                                                    <button
                                                        on:click=move |_| delete_bridge(bridge_id_for_delete)
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

            // Bridge Modal
            <Show when=move || show_modal.get()>
                <div class="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
                    <div class="bg-gray-800 rounded-lg p-6 max-w-lg w-full max-h-[90vh] overflow-y-auto">
                        <h2 class="text-xl font-semibold text-white mb-4">
                            {move || if editing_bridge.get().is_some() { "Edit Bridge" } else { "Add Bridge" }}
                        </h2>

                        <form on:submit=save_bridge>
                            <div class="space-y-4">
                                <div>
                                    <label class="block text-gray-300 mb-2">"Bridge Name"</label>
                                    <input
                                        type="text"
                                        prop:value=move || modal_name.get()
                                        on:input=move |ev| set_modal_name.set(event_target_value(&ev))
                                        placeholder="e.g., br0, bridge-lan"
                                        class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white"
                                        required
                                    />
                                    <p class="text-sm text-gray-500 mt-1">"This will be the interface name"</p>
                                </div>

                                <div>
                                    <label class="block text-gray-300 mb-2">"Member Interfaces"</label>
                                    <div class="bg-gray-700 border border-gray-600 rounded p-3 space-y-2 max-h-48 overflow-y-auto">
                                        <Show when=move || managed_interfaces.get().is_empty()>
                                            <p class="text-gray-500 text-sm">"No managed interfaces available"</p>
                                        </Show>
                                        <For
                                            each=move || managed_interfaces.get()
                                            key=|iface| iface.name.clone()
                                            children=move |iface: ManagedInterface| {
                                                let iface_name_for_check = iface.name.clone();
                                                let iface_name_for_toggle = iface.name.clone();
                                                let label = format!("{} ({})", iface.name, iface.role);
                                                view! {
                                                    <label class="flex items-center gap-2 cursor-pointer hover:bg-gray-600 p-2 rounded">
                                                        <input
                                                            type="checkbox"
                                                            prop:checked=move || modal_members.get().contains(&iface_name_for_check)
                                                            on:change=move |_| toggle_member(iface_name_for_toggle.clone())
                                                            class="w-4 h-4 text-blue-600 bg-gray-700 border-gray-600 rounded"
                                                        />
                                                        <span class="text-white">{label}</span>
                                                    </label>
                                                }
                                            }
                                        />
                                    </div>
                                    <p class="text-sm text-gray-500 mt-1">"Select interfaces to add to this bridge"</p>
                                </div>

                                <div class="flex items-center gap-4">
                                    <label class="flex items-center gap-2 cursor-pointer">
                                        <input
                                            type="checkbox"
                                            prop:checked=move || modal_stp.get()
                                            on:change=move |ev| set_modal_stp.set(event_target_checked(&ev))
                                            class="w-4 h-4 text-blue-600 bg-gray-700 border-gray-600 rounded"
                                        />
                                        <span class="text-gray-300">"Enable STP (Spanning Tree Protocol)"</span>
                                    </label>
                                </div>

                                <Show when=move || modal_stp.get()>
                                    <div>
                                        <label class="block text-gray-300 mb-2">"STP Forward Delay (seconds)"</label>
                                        <input
                                            type="number"
                                            min="2"
                                            max="30"
                                            prop:value=move || modal_stp_forward_delay.get()
                                            on:input=move |ev| set_modal_stp_forward_delay.set(event_target_value(&ev))
                                            class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white"
                                        />
                                        <p class="text-sm text-gray-500 mt-1">"Time to wait before forwarding (2-30s, default 15)"</p>
                                    </div>
                                </Show>

                                <div>
                                    <label class="block text-gray-300 mb-2">"Description (optional)"</label>
                                    <input
                                        type="text"
                                        prop:value=move || modal_description.get()
                                        on:input=move |ev| set_modal_description.set(event_target_value(&ev))
                                        placeholder="e.g., LAN bridge for home network"
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
