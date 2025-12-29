//! Firewall configuration page
//!
//! This is a placeholder that will be replaced in Phase 5 with a full
//! zone-based firewall UI including tabs for Zones, Port Forwards, and Rules.

use leptos::prelude::*;

#[component]
pub fn FirewallPage() -> impl IntoView {
    view! {
        <div class="space-y-6">
            <div>
                <h1 class="text-2xl font-semibold text-blue-300">"Firewall"</h1>
                <p class="text-gray-400">"Zone-based firewall configuration"</p>
            </div>

            <div class="bg-gray-800 rounded-lg shadow-lg p-6">
                <div class="text-center py-8">
                    <div class="text-6xl mb-4">"🛡️"</div>
                    <h2 class="text-xl font-medium text-gray-300 mb-2">"Firewall Management Coming Soon"</h2>
                    <p class="text-gray-500 max-w-md mx-auto">
                        "The zone-based firewall UI is under development. "
                        "It will include:"
                    </p>
                    <ul class="text-gray-400 mt-4 space-y-2">
                        <li>"• Zone configuration (WAN, LAN, custom zones)"</li>
                        <li>"• Inter-zone forwarding policies"</li>
                        <li>"• Port forwarding / DNAT rules"</li>
                        <li>"• Input and forward rules with priorities"</li>
                        <li>"• Safe apply with automatic rollback"</li>
                    </ul>
                </div>
            </div>
        </div>
    }
}
