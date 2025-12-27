//! Interface edit page for configuring individual interface settings

use keystone_core::{InterfaceRole, ManagedInterface};
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::hooks::use_params_map;

use crate::api;

#[component]
pub fn InterfaceEditPage(
    auth_token: ReadSignal<Option<String>>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let params = use_params_map();
    
    let (interface_name, set_interface_name) = signal(String::new());
    let (managed_interface, set_managed_interface) = signal::<Option<ManagedInterface>>(None);
    let (loading, set_loading) = signal(true);
    let (saving, set_saving) = signal(false);
    let (error, set_error) = signal::<Option<String>>(None);
    let (success, set_success) = signal::<Option<String>>(None);

    let (use_dhcp, set_use_dhcp) = signal(true);
    let (static_ip, set_static_ip) = signal(String::new());
    let (role, set_role) = signal(InterfaceRole::LAN);

    Effect::new(move |_| {
        let name = params.read().get("name").unwrap_or_default();
        set_interface_name.set(name.clone());
        
        if let Some(token) = auth_token.get() {
            let name = name.clone();
            spawn_local(async move {
                match api::fetch_managed_interfaces(&token).await {
                    Ok(interfaces) => {
                        if let Some(iface) = interfaces.into_iter().find(|i| i.name == name) {
                            set_use_dhcp.set(iface.static_ip.is_none());
                            if let Some(ref ip) = iface.static_ip {
                                set_static_ip.set(ip.clone());
                            }
                            set_role.set(iface.role);
                            set_managed_interface.set(Some(iface));
                        } else {
                            set_error.set(Some(format!("Interface '{}' is not managed", name)));
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
                set_loading.set(false);
            });
        }
    });

    let save_changes = move |_| {
        spawn_local(async move {
            set_saving.set(true);
            set_error.set(None);
            set_success.set(None);

            if let Some(token) = auth_token.get() {
                match api::fetch_managed_interfaces(&token).await {
                    Ok(mut interfaces) => {
                        if let Some(current) = managed_interface.get() {
                            let new_static_ip = if use_dhcp.get() {
                                None
                            } else {
                                let ip = static_ip.get();
                                if ip.is_empty() { None } else { Some(ip) }
                            };

                            let updated = ManagedInterface {
                                name: current.name.clone(),
                                role: role.get(),
                                static_ip: new_static_ip,
                                enabled: current.enabled,
                            };

                            if let Some(pos) = interfaces.iter().position(|i| i.name == current.name) {
                                interfaces[pos] = updated.clone();
                            }

                            match api::save_managed_interfaces(&token, interfaces).await {
                                Ok(response) => {
                                    if response.success {
                                        set_managed_interface.set(Some(updated));
                                        set_success.set(Some("Configuration saved".to_string()));
                                    } else {
                                        set_error.set(Some(response.message));
                                    }
                                }
                                Err(e) => set_error.set(Some(e)),
                            }
                        }
                    }
                    Err(e) => set_error.set(Some(e)),
                }
            }
            set_saving.set(false);
        });
    };

    let go_back = move |_| {
        if let Some(window) = web_sys::window() {
            let _ = window.location().set_href("/interfaces");
        }
    };

    let loading_class = move || if loading.get() { "" } else { "hidden" };
    let form_class = move || if !loading.get() && managed_interface.get().is_some() { "" } else { "hidden" };
    let not_found_class = move || if !loading.get() && managed_interface.get().is_none() { "" } else { "hidden" };
    let static_ip_class = move || if use_dhcp.get() { "hidden" } else { "" };

    view! {
        <div class="space-y-6">
            <div class="flex items-center gap-4">
                <button class="text-gray-400 hover:text-white" on:click=go_back>
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/>
                    </svg>
                </button>
                <div>
                    <h1 class="text-2xl font-semibold text-blue-300">
                        "Configure " {move || interface_name.get()}
                    </h1>
                    <p class="text-gray-400">"Edit interface settings"</p>
                </div>
            </div>

            <Show when=move || error.get().is_some()>
                <div class="bg-red-900/50 border border-red-500 text-red-200 px-4 py-3 rounded">
                    {move || error.get().unwrap_or_default()}
                </div>
            </Show>
            <Show when=move || success.get().is_some()>
                <div class="bg-green-900/50 border border-green-500 text-green-200 px-4 py-3 rounded">
                    {move || success.get().unwrap_or_default()}
                </div>
            </Show>

            <div class=loading_class>"Loading..."</div>

            <div class=form_class>
                <div class="bg-gray-800 rounded-lg p-6 shadow-lg space-y-6">
                    <div>
                        <label class="block text-gray-300 mb-2 font-medium">"Role"</label>
                        <select
                            class="w-full bg-gray-700 text-white rounded px-4 py-2.5 border border-gray-600"
                            on:change=move |ev| {
                                set_role.set(match event_target_value(&ev).as_str() {
                                    "WAN" => InterfaceRole::WAN,
                                    _ => InterfaceRole::LAN,
                                });
                            }
                        >
                            <option value="LAN" selected=move || role.get() == InterfaceRole::LAN>"LAN"</option>
                            <option value="WAN" selected=move || role.get() == InterfaceRole::WAN>"WAN"</option>
                        </select>
                    </div>

                    <div>
                        <label class="block text-gray-300 mb-2 font-medium">"IP Configuration"</label>
                        <div class="space-y-3">
                            <label class="flex items-center gap-3 cursor-pointer">
                                <input type="radio" name="ip_mode" checked=move || use_dhcp.get() on:change=move |_| set_use_dhcp.set(true) class="w-4 h-4"/>
                                <span class="text-gray-200">"DHCP"</span>
                            </label>
                            <label class="flex items-center gap-3 cursor-pointer">
                                <input type="radio" name="ip_mode" checked=move || !use_dhcp.get() on:change=move |_| set_use_dhcp.set(false) class="w-4 h-4"/>
                                <span class="text-gray-200">"Static IP"</span>
                            </label>
                        </div>
                    </div>

                    <div class=static_ip_class>
                        <label class="block text-gray-300 mb-2 font-medium">"Static IP Address"</label>
                        <input
                            type="text"
                            placeholder="192.168.1.1/24"
                            prop:value=move || static_ip.get()
                            on:input=move |ev| set_static_ip.set(event_target_value(&ev))
                            class="w-full bg-gray-700 text-white rounded px-4 py-2.5 border border-gray-600"
                        />
                    </div>

                    <div class="flex gap-3 pt-4 border-t border-gray-700">
                        <button
                            class="bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 text-white px-6 py-2.5 rounded font-medium"
                            disabled=move || saving.get()
                            on:click=save_changes
                        >
                            {move || if saving.get() { "Saving..." } else { "Save" }}
                        </button>
                        <button class="bg-gray-600 hover:bg-gray-700 text-white px-6 py-2.5 rounded" on:click=go_back>
                            "Cancel"
                        </button>
                    </div>
                </div>
            </div>

            <div class=not_found_class>
                <div class="bg-gray-800 rounded-lg p-6">
                    <p class="text-gray-400">"Interface not found or not managed."</p>
                    <button class="text-blue-400 hover:text-blue-300 mt-4" on:click=go_back>"Back"</button>
                </div>
            </div>
        </div>
    }
}
