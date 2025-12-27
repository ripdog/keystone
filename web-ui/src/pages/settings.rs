//! System settings page

use keystone_core::SystemState;
use leptos::prelude::*;

#[component]
pub fn SettingsPage(state: ReadSignal<SystemState>) -> impl IntoView {
    view! {
        <div class="space-y-6">
            <div>
                <h1 class="text-2xl font-semibold text-blue-300">"System Settings"</h1>
                <p class="text-gray-400">"Configure system-wide router settings"</p>
            </div>

            <div class="bg-gray-800 rounded-lg p-6 shadow-lg">
                <h2 class="text-lg font-medium text-white mb-4">"Network Settings"</h2>

                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div class="bg-gray-700 rounded p-4">
                        <h3 class="font-medium mb-2">"IP Forwarding"</h3>
                        <label class="flex items-center cursor-pointer">
                            <input
                                type="checkbox"
                                prop:checked=move || state.get().ip_forwarding_enabled
                                class="w-5 h-5 rounded border-gray-500 bg-gray-600 text-blue-500"
                            />
                            <span class="ml-3 text-gray-300">
                                {move || if state.get().ip_forwarding_enabled {
                                    "Enabled"
                                } else {
                                    "Disabled"
                                }}
                            </span>
                        </label>
                        <p class="text-sm text-gray-500 mt-2">
                            "Allow traffic to be routed between interfaces"
                        </p>
                    </div>

                    <div class="bg-gray-700 rounded p-4">
                        <h3 class="font-medium mb-2">"NAT / Masquerading"</h3>
                        <label class="flex items-center cursor-pointer">
                            <input
                                type="checkbox"
                                prop:checked=move || state.get().nat_enabled
                                class="w-5 h-5 rounded border-gray-500 bg-gray-600 text-blue-500"
                            />
                            <span class="ml-3 text-gray-300">
                                {move || if state.get().nat_enabled {
                                    "Enabled"
                                } else {
                                    "Disabled"
                                }}
                            </span>
                        </label>
                        <p class="text-sm text-gray-500 mt-2">
                            "Translate private IP addresses to public IP for internet access"
                        </p>
                    </div>
                </div>
            </div>

            <div class="bg-gray-800 rounded-lg p-6 shadow-lg">
                <h2 class="text-lg font-medium text-white mb-4">"Danger Zone"</h2>

                <div class="space-y-4">
                    <div class="flex items-center justify-between p-4 bg-gray-700 rounded border border-gray-600">
                        <div>
                            <h3 class="font-medium">"Restart Network Services"</h3>
                            <p class="text-sm text-gray-400">"Restart systemd-networkd and apply all configuration"</p>
                        </div>
                        <button class="bg-yellow-600 hover:bg-yellow-700 text-white px-4 py-2 rounded">
                            "Restart"
                        </button>
                    </div>

                    <div class="flex items-center justify-between p-4 bg-gray-700 rounded border border-red-900">
                        <div>
                            <h3 class="font-medium text-red-400">"Reset Configuration"</h3>
                            <p class="text-sm text-gray-400">"Remove all Keystone configuration and start fresh"</p>
                        </div>
                        <button class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded">
                            "Reset"
                        </button>
                    </div>
                </div>
            </div>

            <button class="bg-green-600 hover:bg-green-700 text-white px-6 py-2.5 rounded font-medium">
                "💾 Apply Configuration"
            </button>
        </div>
    }
}
