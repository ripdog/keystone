//! Static IP configuration component
//!
//! Handles static IP addresses, gateway, DNS servers, search domains, routes, and MTU.

use keystone_core::{StaticAddress, StaticRoute};
use leptos::prelude::*;

use crate::components::form_utils::event_target_value;

/// Component for static IP, gateway, DNS, search domains, routes, and MTU settings
#[component]
pub fn StaticIpSettings(
    addresses_indexed: impl Fn() -> Vec<(usize, StaticAddress)> + Copy + Send + 'static,
    new_address: ReadSignal<String>,
    set_new_address: WriteSignal<String>,
    add_address: impl Fn() + Copy + Send + 'static,
    remove_address: impl Fn(usize) + Copy + Send + 'static,
    gateway: ReadSignal<String>,
    set_gateway: WriteSignal<String>,
    dns_indexed: impl Fn() -> Vec<(usize, String)> + Copy + Send + 'static,
    new_dns: ReadSignal<String>,
    set_new_dns: WriteSignal<String>,
    add_dns: impl Fn() + Copy + Send + 'static,
    remove_dns: impl Fn(usize) + Copy + Send + 'static,
    domains_indexed: impl Fn() -> Vec<(usize, String)> + Copy + Send + 'static,
    new_domain: ReadSignal<String>,
    set_new_domain: WriteSignal<String>,
    add_domain: impl Fn() + Copy + Send + 'static,
    remove_domain: impl Fn(usize) + Copy + Send + 'static,
    routes_indexed: impl Fn() -> Vec<(usize, StaticRoute)> + Copy + Send + 'static,
    new_route_dest: ReadSignal<String>,
    set_new_route_dest: WriteSignal<String>,
    new_route_gw: ReadSignal<String>,
    set_new_route_gw: WriteSignal<String>,
    new_route_metric: ReadSignal<String>,
    set_new_route_metric: WriteSignal<String>,
    add_route: impl Fn() + Copy + Send + 'static,
    remove_route: impl Fn(usize) + Copy + Send + 'static,
    #[prop(default = false)] show_dhcp_warnings: bool,
    dhcp_use_dns: ReadSignal<bool>,
    dhcp_use_gateway: ReadSignal<bool>,
    link_mtu: ReadSignal<String>,
    set_link_mtu: WriteSignal<String>,
) -> impl IntoView {
    view! {
        <>
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
                                    add_address();
                                }
                            }
                            class="flex-1 bg-gray-700 text-white rounded px-4 py-2 border border-gray-600"
                        />
                        <button
                            class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
                            on:click=move |_| add_address()
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
                <Show when=move || show_dhcp_warnings && dhcp_use_gateway.get()>
                    <p class="text-yellow-400 text-sm mt-1">
                        "⚠ DHCP gateway is enabled. This static gateway will be used if DHCP doesn't provide one."
                    </p>
                </Show>
            </div>

            // MTU
            <div>
                <label class="block text-gray-300 mb-2 font-medium">"MTU (bytes)"</label>
                <input
                    type="text"
                    placeholder="1500 (default)"
                    prop:value=move || link_mtu.get()
                    on:input=move |ev| set_link_mtu.set(event_target_value(&ev))
                    class="w-full bg-gray-700 text-white rounded px-4 py-2.5 border border-gray-600"
                />
                <p class="text-gray-400 text-sm mt-1">
                    "Common values: 1500 (default), 1492 (PPPoE), 9000 (jumbo). Leave empty for default."
                </p>
            </div>

            // DNS Servers
            <div>
                <label class="block text-gray-300 mb-2 font-medium">"DNS Servers"</label>

                <Show when=move || show_dhcp_warnings && dhcp_use_dns.get()>
                    <div class="bg-blue-900/30 border border-blue-600 text-blue-200 px-3 py-2 rounded mb-2 text-sm">
                        "DHCP DNS is enabled. Static DNS servers will be used in addition to DHCP-provided servers."
                    </div>
                </Show>

                <div class="space-y-2">
                    <For
                        each=dns_indexed
                        key=|(i, dns)| (*i, dns.clone())
                        children=move |(i, _dns)| {
                            let dns_list = dns_indexed();
                            let dns_value = dns_list.iter().find(|(idx, _)| *idx == i).map(|(_, d)| d.clone()).unwrap_or_default();
                            view! {
                                <div class="flex items-center gap-2">
                                    <span class="flex-1 bg-gray-700 text-white rounded px-3 py-2">{dns_value}</span>
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
                                    add_dns();
                                }
                            }
                            class="flex-1 bg-gray-700 text-white rounded px-4 py-2 border border-gray-600"
                        />
                        <button
                            class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
                            on:click=move |_| add_dns()
                        >
                            "Add"
                        </button>
                    </div>
                </div>
            </div>

            // Search Domains
            <div>
                <label class="block text-gray-300 mb-2 font-medium">"Search Domains"</label>
                <div class="space-y-2">
                    <For
                        each=domains_indexed
                        key=|(i, domain)| (*i, domain.clone())
                        children=move |(i, _domain)| {
                            let domain_list = domains_indexed();
                            let domain_value = domain_list.iter().find(|(idx, _)| *idx == i).map(|(_, d)| d.clone()).unwrap_or_default();
                            view! {
                                <div class="flex items-center gap-2">
                                    <span class="flex-1 bg-gray-700 text-white rounded px-3 py-2">{domain_value}</span>
                                    <button
                                        class="text-red-400 hover:text-red-300 px-2"
                                        on:click=move |_| remove_domain(i)
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
                            placeholder="example.com"
                            prop:value=move || new_domain.get()
                            on:input=move |ev| set_new_domain.set(event_target_value(&ev))
                            on:keydown=move |ev| {
                                if ev.key() == "Enter" {
                                    ev.prevent_default();
                                    add_domain();
                                }
                            }
                            class="flex-1 bg-gray-700 text-white rounded px-4 py-2 border border-gray-600"
                        />
                        <button
                            class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
                            on:click=move |_| add_domain()
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
                        key=|(i, route)| (*i, route.destination.clone(), route.gateway.clone())
                        children=move |(i, route)| {
                            view! {
                                <div class="flex items-center gap-2 bg-gray-700 rounded px-3 py-2">
                                    <span class="flex-1 text-white">
                                        {route.destination.clone().unwrap_or_else(|| "default".to_string())}
                                        " via "
                                        {route.gateway.clone()}
                                        {route.metric.map(|m| format!(" (metric {})", m)).unwrap_or_default()}
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
                            placeholder="Destination (CIDR)"
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
                            on:click=move |_| add_route()
                        >
                            "Add"
                        </button>
                    </div>
                </div>
            </div>
        </>
    }
}
