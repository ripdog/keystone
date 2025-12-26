/// Keystone Web UI - Leptos Frontend (WASM)
/// 
/// This module contains the Leptos components that compile to WASM
/// and run in the browser as a Single Page Application.

use leptos::*;
use leptos_meta::*;
use leptos_router::*;
use keystone_core::{Interface, InterfaceRole, FirewallRule, SystemState};

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();

    view! {
        <Router>
            <Routes>
                <Route path="/" view=Dashboard/>
            </Routes>
        </Router>
    }
}

#[component]
fn Dashboard() -> impl IntoView {
    let (state, _set_state) = create_signal(SystemState::default());
    let (_loading, set_loading) = create_signal(false);

    // Fetch initial state
    create_effect(move |_| {
        spawn_local(async move {
            set_loading.set(true);
            // TODO: Implement actual API call
            // let response = fetch("/api/state").await;
            set_loading.set(false);
        });
    });

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

    view! {
        <div class="bg-gray-700 rounded p-4 border-l-4 border-blue-500">
            <div class="flex justify-between items-start mb-2">
                <div>
                    <h3 class="text-lg font-medium">{interface.name}</h3>
                    <span class={format!("text-sm {}", role_color)}>
                        {format!("{:?}", interface.role)}
                    </span>
                </div>
                <span class={if interface.enabled {
                    "bg-green-600 text-white px-2 py-1 rounded text-xs"
                } else {
                    "bg-gray-600 text-white px-2 py-1 rounded text-xs"
                }}>
                    {if interface.enabled { "Enabled" } else { "Disabled" }}
                </span>
            </div>

            <div class="text-sm text-gray-300 space-y-1">
                <div>
                    <span class="text-gray-400">"IP: "</span>
                    {interface.address.unwrap_or_else(|| "Not configured".to_string())}
                </div>
                <div>
                    <span class="text-gray-400">"DHCP: "</span>
                    {if interface.dhcp_enabled { "Enabled" } else { "Disabled" }}
                </div>
            </div>

            <div class="mt-3 flex gap-2">
                <button class="text-xs bg-blue-600 hover:bg-blue-700 px-3 py-1 rounded">
                    "Edit"
                </button>
                <button class="text-xs bg-gray-600 hover:bg-gray-700 px-3 py-1 rounded">
                    {if interface.enabled { "Disable" } else { "Enable" }}
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

    view! {
        <div class="bg-gray-700 rounded p-3 text-sm">
            <div class="flex justify-between items-start mb-2">
                <div>
                    <span class="font-medium">{rule.description}</span>
                    <span class={format!("ml-2 {}", action_color)}>
                        {format!("{:?}", rule.action)}
                    </span>
                </div>
                <span class={if rule.enabled {
                    "bg-green-600 text-white px-2 py-1 rounded text-xs"
                } else {
                    "bg-gray-600 text-white px-2 py-1 rounded text-xs"
                }}>
                    {if rule.enabled { "On" } else { "Off" }}
                </span>
            </div>

            <div class="text-gray-300 space-y-1">
                <div>
                    <span class="text-gray-400">"Port: "</span>
                    {rule.port}
                    " | "
                    <span class="text-gray-400">"Protocol: "</span>
                    {format!("{:?}", rule.protocol)}
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
