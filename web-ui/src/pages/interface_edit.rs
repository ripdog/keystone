//! Interface edit page for configuring individual interface settings

use keystone_core::{
    DhcpMode, InterfaceConfig, InterfaceRole, IpForwardMode, IpMasqueradeMode, StaticAddress,
    StaticRoute,
};
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

    // Page state
    let (interface_name, set_interface_name) = signal(String::new());
    let (config, set_config) = signal::<Option<InterfaceConfig>>(None);
    let (loading, set_loading) = signal(true);
    let (saving, set_saving) = signal(false);
    let (error, set_error) = signal::<Option<String>>(None);
    let (success, set_success) = signal::<Option<String>>(None);
    let (is_new, set_is_new) = signal(false);

    // Form fields
    let (role, set_role) = signal(InterfaceRole::LAN);
    let (dhcp_mode, set_dhcp_mode) = signal(DhcpMode::No);
    let (addresses, set_addresses) = signal::<Vec<StaticAddress>>(vec![]);
    let (new_address, set_new_address) = signal(String::new());
    let (gateway, set_gateway) = signal(String::new());
    let (dns_servers, set_dns_servers) = signal::<Vec<String>>(vec![]);
    let (new_dns, set_new_dns) = signal(String::new());
    let (routes, set_routes) = signal::<Vec<StaticRoute>>(vec![]);
    let (new_route_dest, set_new_route_dest) = signal(String::new());
    let (new_route_gw, set_new_route_gw) = signal(String::new());
    let (new_route_metric, set_new_route_metric) = signal(String::new());
    let (ipv6_accept_ra, set_ipv6_accept_ra) = signal(true);
    let (ip_forward, set_ip_forward) = signal(IpForwardMode::No);
    let (ip_masquerade, set_ip_masquerade) = signal(IpMasqueradeMode::No);

    // Load interface configuration
    Effect::new(move |_| {
        let name = params.read().get("name").unwrap_or_default();
        set_interface_name.set(name.clone());

        if let Some(token) = auth_token.get() {
            let name = name.clone();
            spawn_local(async move {
                match api::fetch_interface_config(&token, &name).await {
                    Ok(Some(cfg)) => {
                        // Populate form fields from config
                        set_role.set(cfg.role);
                        set_dhcp_mode.set(cfg.dhcp_mode);
                        set_addresses.set(cfg.addresses.clone());
                        set_gateway.set(cfg.gateway.clone().unwrap_or_default());
                        set_dns_servers.set(cfg.dns_servers.clone());
                        set_routes.set(cfg.routes.clone());
                        set_ipv6_accept_ra.set(cfg.ipv6_accept_ra);
                        set_ip_forward.set(cfg.ip_forward);
                        set_ip_masquerade.set(cfg.ip_masquerade);
                        set_config.set(Some(cfg));
                        set_is_new.set(false);
                    }
                    Ok(None) => {
                        // New interface - create default config
                        let new_cfg = InterfaceConfig {
                            id: None,
                            name: name.clone(),
                            role: InterfaceRole::LAN,
                            enabled: true,
                            dhcp_mode: DhcpMode::Ipv4,
                            addresses: vec![],
                            routes: vec![],
                            dns_servers: vec![],
                            gateway: None,
                            ipv6_accept_ra: true,
                            ip_forward: IpForwardMode::No,
                            ip_masquerade: IpMasqueradeMode::No,
                        };
                        set_dhcp_mode.set(DhcpMode::Ipv4);
                        set_config.set(Some(new_cfg));
                        set_is_new.set(true);
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

    // Add static address (inner logic)
    let do_add_address = move || {
        let addr = new_address.get();
        if !addr.is_empty() {
            set_addresses.update(|list| {
                list.push(StaticAddress {
                    address: addr,
                    label: None,
                });
            });
            set_new_address.set(String::new());
        }
    };

    // Remove static address
    let remove_address = move |index: usize| {
        set_addresses.update(|list| {
            if index < list.len() {
                list.remove(index);
            }
        });
    };

    // Add DNS server (inner logic)
    let do_add_dns = move || {
        let dns = new_dns.get();
        if !dns.is_empty() {
            set_dns_servers.update(|list| {
                list.push(dns);
            });
            set_new_dns.set(String::new());
        }
    };

    // Remove DNS server
    let remove_dns = move |index: usize| {
        set_dns_servers.update(|list| {
            if index < list.len() {
                list.remove(index);
            }
        });
    };

    // Add static route (inner logic)
    let do_add_route = move || {
        let gw = new_route_gw.get();
        if !gw.is_empty() {
            let dest = new_route_dest.get();
            let metric_str = new_route_metric.get();
            let metric = metric_str.parse::<u32>().ok();

            set_routes.update(|list| {
                list.push(StaticRoute {
                    destination: if dest.is_empty() { None } else { Some(dest) },
                    gateway: gw,
                    metric,
                });
            });
            set_new_route_dest.set(String::new());
            set_new_route_gw.set(String::new());
            set_new_route_metric.set(String::new());
        }
    };

    // Remove static route
    let remove_route = move |index: usize| {
        set_routes.update(|list| {
            if index < list.len() {
                list.remove(index);
            }
        });
    };

    // Save configuration
    let save_changes = move |_| {
        spawn_local(async move {
            set_saving.set(true);
            set_error.set(None);
            set_success.set(None);

            if let Some(token) = auth_token.get()
                && let Some(current) = config.get()
            {
                let gw = gateway.get();
                let updated = InterfaceConfig {
                    id: current.id,
                    name: current.name.clone(),
                    role: role.get(),
                    enabled: true,
                    dhcp_mode: dhcp_mode.get(),
                    addresses: addresses.get(),
                    routes: routes.get(),
                    dns_servers: dns_servers.get(),
                    gateway: if gw.is_empty() { None } else { Some(gw) },
                    ipv6_accept_ra: ipv6_accept_ra.get(),
                    ip_forward: ip_forward.get(),
                    ip_masquerade: ip_masquerade.get(),
                };

                match api::save_interface_config(&token, updated.clone()).await {
                    Ok(response) => {
                        if response.success {
                            set_config.set(Some(InterfaceConfig {
                                id: response.config_id,
                                ..updated
                            }));
                            set_is_new.set(false);
                            set_success.set(Some("Configuration saved".to_string()));
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

    let go_back = move |_| {
        if let Some(window) = web_sys::window() {
            let _ = window.location().set_href("/interfaces");
        }
    };

    // Derived signals for For components to avoid complex expressions in view
    let addresses_indexed = move || {
        addresses.get().into_iter().enumerate().collect::<Vec<_>>()
    };
    let dns_indexed = move || {
        dns_servers.get().into_iter().enumerate().collect::<Vec<_>>()
    };
    let routes_indexed = move || {
        routes.get().into_iter().enumerate().collect::<Vec<_>>()
    };

    view! {
        <div class="space-y-6">
            // Header
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
                    <p class="text-gray-400">
                        {move || if is_new.get() { "New interface configuration" } else { "Edit interface settings" }}
                    </p>
                </div>
            </div>

            // Messages
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

            // Loading state
            <Show when=move || loading.get()>
                <div class="text-gray-400">"Loading..."</div>
            </Show>

            // Main form
            <Show when=move || !loading.get() && config.get().is_some()>
                <div class="bg-gray-800 rounded-lg p-6 shadow-lg space-y-6">
                    // Role
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

                    // DHCP Mode
                    <div>
                        <label class="block text-gray-300 mb-2 font-medium">"DHCP Mode"</label>
                        <select
                            class="w-full bg-gray-700 text-white rounded px-4 py-2.5 border border-gray-600"
                            on:change=move |ev| {
                                set_dhcp_mode.set(match event_target_value(&ev).as_str() {
                                    "yes" => DhcpMode::Yes,
                                    "ipv4" => DhcpMode::Ipv4,
                                    "ipv6" => DhcpMode::Ipv6,
                                    _ => DhcpMode::No,
                                });
                            }
                        >
                            <option value="no" selected=move || dhcp_mode.get() == DhcpMode::No>"Disabled"</option>
                            <option value="ipv4" selected=move || dhcp_mode.get() == DhcpMode::Ipv4>"IPv4 Only"</option>
                            <option value="ipv6" selected=move || dhcp_mode.get() == DhcpMode::Ipv6>"IPv6 Only"</option>
                            <option value="yes" selected=move || dhcp_mode.get() == DhcpMode::Yes>"IPv4 + IPv6"</option>
                        </select>
                    </div>

                    // Static Addresses
                    <div>
                        <label class="block text-gray-300 mb-2 font-medium">"Static IP Addresses"</label>
                        <div class="space-y-2">
                            <For
                                each=addresses_indexed
                                key=|(i, addr)| (*i, addr.address.clone())
                                children=move |(i, addr)| {
                                    view! {
                                        <div class="flex items-center gap-2">
                                            <span class="flex-1 bg-gray-700 text-white rounded px-3 py-2">{addr.address}</span>
                                            <button
                                                class="text-red-400 hover:text-red-300 px-2"
                                                on:click=move |_| remove_address(i)
                                            >
                                                "✕"
                                            </button>
                                        </div>
                                    }
                                }
                            />
                            <div class="flex gap-2">
                                <input
                                    type="text"
                                    placeholder="192.168.1.1/24"
                                    prop:value=move || new_address.get()
                                    on:input=move |ev| set_new_address.set(event_target_value(&ev))
                                    on:keydown=move |ev| {
                                        if ev.key() == "Enter" {
                                            ev.prevent_default();
                                            do_add_address();
                                        }
                                    }
                                    class="flex-1 bg-gray-700 text-white rounded px-4 py-2 border border-gray-600"
                                />
                                <button
                                    class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
                                    on:click=move |_| do_add_address()
                                >
                                    "Add"
                                </button>
                            </div>
                        </div>
                    </div>

                    // Gateway
                    <div>
                        <label class="block text-gray-300 mb-2 font-medium">"Default Gateway"</label>
                        <input
                            type="text"
                            placeholder="192.168.1.254"
                            prop:value=move || gateway.get()
                            on:input=move |ev| set_gateway.set(event_target_value(&ev))
                            class="w-full bg-gray-700 text-white rounded px-4 py-2.5 border border-gray-600"
                        />
                    </div>

                    // DNS Servers
                    <div>
                        <label class="block text-gray-300 mb-2 font-medium">"DNS Servers"</label>
                        <div class="space-y-2">
                            <For
                                each=dns_indexed
                                key=|(i, dns)| (*i, dns.clone())
                                children=move |(i, dns)| {
                                    view! {
                                        <div class="flex items-center gap-2">
                                            <span class="flex-1 bg-gray-700 text-white rounded px-3 py-2">{dns}</span>
                                            <button
                                                class="text-red-400 hover:text-red-300 px-2"
                                                on:click=move |_| remove_dns(i)
                                            >
                                                "✕"
                                            </button>
                                        </div>
                                    }
                                }
                            />
                            <div class="flex gap-2">
                                <input
                                    type="text"
                                    placeholder="8.8.8.8"
                                    prop:value=move || new_dns.get()
                                    on:input=move |ev| set_new_dns.set(event_target_value(&ev))
                                    on:keydown=move |ev| {
                                        if ev.key() == "Enter" {
                                            ev.prevent_default();
                                            do_add_dns();
                                        }
                                    }
                                    class="flex-1 bg-gray-700 text-white rounded px-4 py-2 border border-gray-600"
                                />
                                <button
                                    class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
                                    on:click=move |_| do_add_dns()
                                >
                                    "Add"
                                </button>
                            </div>
                        </div>
                    </div>

                    // Static Routes
                    <div>
                        <label class="block text-gray-300 mb-2 font-medium">"Static Routes"</label>
                        <div class="space-y-2">
                            <For
                                each=routes_indexed
                                key=|(i, r)| (*i, r.gateway.clone(), r.destination.clone())
                                children=move |(i, route)| {
                                    let dest = route.destination.clone().unwrap_or_else(|| "default".to_string());
                                    let metric_str = route.metric.map(|m| format!(" (metric {})", m)).unwrap_or_default();
                                    view! {
                                        <div class="flex items-center gap-2">
                                            <span class="flex-1 bg-gray-700 text-white rounded px-3 py-2">
                                                {dest} " via " {route.gateway} {metric_str}
                                            </span>
                                            <button
                                                class="text-red-400 hover:text-red-300 px-2"
                                                on:click=move |_| remove_route(i)
                                            >
                                                "✕"
                                            </button>
                                        </div>
                                    }
                                }
                            />
                            <div class="flex gap-2 flex-wrap">
                                <input
                                    type="text"
                                    placeholder="Destination (e.g., 10.0.0.0/8)"
                                    prop:value=move || new_route_dest.get()
                                    on:input=move |ev| set_new_route_dest.set(event_target_value(&ev))
                                    class="flex-1 min-w-32 bg-gray-700 text-white rounded px-3 py-2 border border-gray-600"
                                />
                                <input
                                    type="text"
                                    placeholder="Gateway"
                                    prop:value=move || new_route_gw.get()
                                    on:input=move |ev| set_new_route_gw.set(event_target_value(&ev))
                                    class="flex-1 min-w-32 bg-gray-700 text-white rounded px-3 py-2 border border-gray-600"
                                />
                                <input
                                    type="text"
                                    placeholder="Metric"
                                    prop:value=move || new_route_metric.get()
                                    on:input=move |ev| set_new_route_metric.set(event_target_value(&ev))
                                    class="w-24 bg-gray-700 text-white rounded px-3 py-2 border border-gray-600"
                                />
                                <button
                                    class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
                                    on:click=move |_| do_add_route()
                                >
                                    "Add"
                                </button>
                            </div>
                        </div>
                    </div>

                    // IPv6 Accept RA
                    <div>
                        <label class="flex items-center gap-3 cursor-pointer">
                            <input
                                type="checkbox"
                                checked=move || ipv6_accept_ra.get()
                                on:change=move |ev| set_ipv6_accept_ra.set(event_target_checked(&ev))
                                class="w-5 h-5 rounded"
                            />
                            <span class="text-gray-200">"Accept IPv6 Router Advertisements"</span>
                        </label>
                    </div>

                    // IP Forwarding
                    <div>
                        <label class="block text-gray-300 mb-2 font-medium">"IP Forwarding"</label>
                        <select
                            class="w-full bg-gray-700 text-white rounded px-4 py-2.5 border border-gray-600"
                            on:change=move |ev| {
                                set_ip_forward.set(match event_target_value(&ev).as_str() {
                                    "yes" => IpForwardMode::Yes,
                                    "ipv4" => IpForwardMode::Ipv4,
                                    "ipv6" => IpForwardMode::Ipv6,
                                    _ => IpForwardMode::No,
                                });
                            }
                        >
                            <option value="no" selected=move || ip_forward.get() == IpForwardMode::No>"Disabled"</option>
                            <option value="ipv4" selected=move || ip_forward.get() == IpForwardMode::Ipv4>"IPv4 Only"</option>
                            <option value="ipv6" selected=move || ip_forward.get() == IpForwardMode::Ipv6>"IPv6 Only"</option>
                            <option value="yes" selected=move || ip_forward.get() == IpForwardMode::Yes>"IPv4 + IPv6"</option>
                        </select>
                    </div>

                    // IP Masquerade (NAT)
                    <div>
                        <label class="block text-gray-300 mb-2 font-medium">"IP Masquerade (NAT)"</label>
                        <select
                            class="w-full bg-gray-700 text-white rounded px-4 py-2.5 border border-gray-600"
                            on:change=move |ev| {
                                set_ip_masquerade.set(match event_target_value(&ev).as_str() {
                                    "both" => IpMasqueradeMode::Both,
                                    "ipv4" => IpMasqueradeMode::Ipv4,
                                    "ipv6" => IpMasqueradeMode::Ipv6,
                                    _ => IpMasqueradeMode::No,
                                });
                            }
                        >
                            <option value="no" selected=move || ip_masquerade.get() == IpMasqueradeMode::No>"Disabled"</option>
                            <option value="ipv4" selected=move || ip_masquerade.get() == IpMasqueradeMode::Ipv4>"IPv4 Only"</option>
                            <option value="ipv6" selected=move || ip_masquerade.get() == IpMasqueradeMode::Ipv6>"IPv6 Only"</option>
                            <option value="both" selected=move || ip_masquerade.get() == IpMasqueradeMode::Both>"IPv4 + IPv6"</option>
                        </select>
                    </div>

                    // Save/Cancel buttons
                    <div class="flex gap-3 pt-4 border-t border-gray-700">
                        <button
                            class="bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 text-white px-6 py-2.5 rounded font-medium"
                            disabled=move || saving.get()
                            on:click=save_changes
                        >
                            {move || if saving.get() { "Saving..." } else { "Save" }}
                        </button>
                        <button
                            class="bg-gray-600 hover:bg-gray-700 text-white px-6 py-2.5 rounded"
                            on:click=go_back
                        >
                            "Cancel"
                        </button>
                    </div>
                </div>
            </Show>
        </div>
    }
}

fn event_target_checked(ev: &web_sys::Event) -> bool {
    use wasm_bindgen::JsCast;
    ev.target()
        .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
        .map(|e| e.checked())
        .unwrap_or(false)
}
