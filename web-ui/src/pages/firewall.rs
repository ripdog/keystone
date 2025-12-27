//! Firewall configuration page

use keystone_core::{FirewallAction, FirewallRule, SystemState};
use leptos::prelude::*;

#[component]
pub fn FirewallPage(state: ReadSignal<SystemState>) -> impl IntoView {
    view! {
        <div class="space-y-6">
            <div>
                <h1 class="text-2xl font-semibold text-blue-300">"Firewall Rules"</h1>
                <p class="text-gray-400">"Configure firewall rules for your network"</p>
            </div>

            <div class="bg-gray-800 rounded-lg shadow-lg overflow-hidden">
                <div class="p-4 space-y-3">
                    <Show
                        when=move || !state.get().firewall_rules.is_empty()
                        fallback=|| view! {
                            <p class="text-gray-500 italic py-4">"No firewall rules configured"</p>
                        }
                    >
                        <For
                            each=move || state.get().firewall_rules.clone()
                            key=|rule| rule.id.clone()
                            children=|rule| view! { <FirewallRuleCard rule=rule/> }
                        />
                    </Show>
                </div>
            </div>

            <button class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded">
                "+ Add Rule"
            </button>
        </div>
    }
}

#[component]
fn FirewallRuleCard(rule: FirewallRule) -> impl IntoView {
    let action_color = match rule.action {
        FirewallAction::Accept => "text-green-400",
        FirewallAction::Drop => "text-red-400",
        FirewallAction::Reject => "text-yellow-400",
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
        <div class="bg-gray-700 rounded p-4">
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

            <div class="text-sm text-gray-300">
                <span class="text-gray-400">"Port: "</span>
                {port}
                " | "
                <span class="text-gray-400">"Protocol: "</span>
                {protocol_str}
            </div>

            <div class="mt-3 flex gap-2">
                <button class="text-xs bg-blue-600 hover:bg-blue-700 px-3 py-1 rounded">
                    "Edit"
                </button>
                <button class="text-xs bg-red-600 hover:bg-red-700 px-3 py-1 rounded">
                    "Delete"
                </button>
            </div>
        </div>
    }
}
