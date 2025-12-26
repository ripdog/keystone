//! Keystone Web UI - Leptos Frontend (WASM)
//! 
//! This module contains the Leptos components that compile to WASM
//! and run in the browser as a Single Page Application.

use leptos::prelude::*;
use keystone_core::{Interface, InterfaceRole, FirewallRule, SystemState};

#[component]
pub fn App() -> impl IntoView {
    let (state, _set_state) = signal(SystemState::default());

    view! {
        <div class="min-h-screen bg-gray-900 text-gray-100 p-8">
            <div class="max-w-7xl mx-auto">
                <header class="mb-8">
                    <h1 class="text-4xl font-bold text-blue-400 mb-2">
                        "🔐 Keystone Router Manager"
                    </h1>
                    <p class="text-gray-400">
                        "Secure router configuration for Arch Linux"
                    </p>
                </header>

                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <InterfacesPanel state=state/>
                    <FirewallPanel state=state/>
                </div>

                <SystemSettingsPanel state=state/>
            </div>
        </div>
    }
}

#[component]
fn InterfacesPanel(state: ReadSignal<SystemState>) -> impl IntoView {
    view! {
        <div class="bg-gray-800 rounded-lg p-6 shadow-lg">
            <h2 class="text-2xl font-semibold text-blue-300 mb-4">
                "Network Interfaces"
            </h2>

            <div class="space-y-4">
                <Show
                    when=move || !state.get().interfaces.is_empty()
                    fallback=|| view! {
                        <p class="text-gray-500 italic">"No interfaces configured"</p>
                    }
                >
                    <For
                        each=move || state.get().interfaces.clone()
                        key=|iface| iface.name.clone()
                        children=|iface| view! { <InterfaceCard interface=iface/> }
                    />
                </Show>
            </div>

            <button class="mt-4 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded">
                "+ Add Interface"
            </button>
        </div>
    }
}

#[component]
fn InterfaceCard(interface: Interface) -> impl IntoView {
    let role_color = match interface.role {
        InterfaceRole::WAN => "text-red-400",
        InterfaceRole::LAN => "text-green-400",
    };

    let name = interface.name.clone();
    let role_str = format!("{:?}", interface.role);
    let address = interface.address.clone().unwrap_or_else(|| "Not configured".to_string());
    let dhcp_status = if interface.dhcp_enabled { "Enabled" } else { "Disabled" };
    let enabled_status = if interface.enabled { "Enabled" } else { "Disabled" };
    let status_class = if interface.enabled {
        "bg-green-600 text-white px-2 py-1 rounded text-xs"
    } else {
        "bg-gray-600 text-white px-2 py-1 rounded text-xs"
    };
    let toggle_text = if interface.enabled { "Disable" } else { "Enable" };

    view! {
        <div class="bg-gray-700 rounded p-4 border-l-4 border-blue-500">
            <div class="flex justify-between items-start mb-2">
                <div>
                    <h3 class="text-lg font-medium">{name}</h3>
                    <span class={format!("text-sm {}", role_color)}>
                        {role_str}
                    </span>
                </div>
                <span class={status_class}>
                    {enabled_status}
                </span>
            </div>

            <div class="text-sm text-gray-300 space-y-1">
                <div>
                    <span class="text-gray-400">"IP: "</span>
                    {address}
                </div>
                <div>
                    <span class="text-gray-400">"DHCP: "</span>
                    {dhcp_status}
                </div>
            </div>

            <div class="mt-3 flex gap-2">
                <button class="text-xs bg-blue-600 hover:bg-blue-700 px-3 py-1 rounded">
                    "Edit"
                </button>
                <button class="text-xs bg-gray-600 hover:bg-gray-700 px-3 py-1 rounded">
                    {toggle_text}
                </button>
            </div>
        </div>
    }
}

#[component]
fn FirewallPanel(state: ReadSignal<SystemState>) -> impl IntoView {
    view! {
        <div class="bg-gray-800 rounded-lg p-6 shadow-lg">
            <h2 class="text-2xl font-semibold text-blue-300 mb-4">
                "Firewall Rules"
            </h2>

            <div class="space-y-3">
                <Show
                    when=move || !state.get().firewall_rules.is_empty()
                    fallback=|| view! {
                        <p class="text-gray-500 italic">"No firewall rules configured"</p>
                    }
                >
                    <For
                        each=move || state.get().firewall_rules.clone()
                        key=|rule| rule.id.clone()
                        children=|rule| view! { <FirewallRuleCard rule=rule/> }
                    />
                </Show>
            </div>

            <button class="mt-4 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded">
                "+ Add Rule"
            </button>
        </div>
    }
}

#[component]
fn FirewallRuleCard(rule: FirewallRule) -> impl IntoView {
    let action_color = match rule.action {
        keystone_core::FirewallAction::Accept => "text-green-400",
        keystone_core::FirewallAction::Drop => "text-red-400",
        keystone_core::FirewallAction::Reject => "text-yellow-400",
    };

    let description = rule.description.clone();
    let action_str = format!("{:?}", rule.action);
    let port = rule.port;
    let protocol_str = format!("{:?}", rule.protocol);
    let enabled_status = if rule.enabled { "On" } else { "Off" };
    let status_class = if rule.enabled {
        "bg-green-600 text-white px-2 py-1 rounded text-xs"
    } else {
        "bg-gray-600 text-white px-2 py-1 rounded text-xs"
    };

    view! {
        <div class="bg-gray-700 rounded p-3 text-sm">
            <div class="flex justify-between items-start mb-2">
                <div>
                    <span class="font-medium">{description}</span>
                    <span class={format!("ml-2 {}", action_color)}>
                        {action_str}
                    </span>
                </div>
                <span class={status_class}>
                    {enabled_status}
                </span>
            </div>

            <div class="text-gray-300 space-y-1">
                <div>
                    <span class="text-gray-400">"Port: "</span>
                    {port}
                    " | "
                    <span class="text-gray-400">"Protocol: "</span>
                    {protocol_str}
                </div>
            </div>
        </div>
    }
}

#[component]
fn SystemSettingsPanel(state: ReadSignal<SystemState>) -> impl IntoView {
    view! {
        <div class="bg-gray-800 rounded-lg p-6 shadow-lg mt-6">
            <h2 class="text-2xl font-semibold text-blue-300 mb-4">
                "System Settings"
            </h2>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div class="bg-gray-700 rounded p-4">
                    <h3 class="font-medium mb-2">"IP Forwarding"</h3>
                    <label class="flex items-center cursor-pointer">
                        <input
                            type="checkbox"
                            prop:checked=move || state.get().ip_forwarding_enabled
                            class="form-checkbox h-5 w-5 text-blue-600"
                        />
                        <span class="ml-2 text-gray-300">
                            {move || if state.get().ip_forwarding_enabled {
                                "Enabled"
                            } else {
                                "Disabled"
                            }}
                        </span>
                    </label>
                </div>

                <div class="bg-gray-700 rounded p-4">
                    <h3 class="font-medium mb-2">"NAT / Masquerading"</h3>
                    <label class="flex items-center cursor-pointer">
                        <input
                            type="checkbox"
                            prop:checked=move || state.get().nat_enabled
                            class="form-checkbox h-5 w-5 text-blue-600"
                        />
                        <span class="ml-2 text-gray-300">
                            {move || if state.get().nat_enabled {
                                "Enabled"
                            } else {
                                "Disabled"
                            }}
                        </span>
                    </label>
                </div>
            </div>

            <button class="mt-6 bg-green-600 hover:bg-green-700 text-white px-6 py-2 rounded font-medium">
                "💾 Apply Configuration"
            </button>
        </div>
    }
}
