//! Main application layout with navigation

use leptos::prelude::*;
use leptos_router::components::A;

/// Main layout wrapper with sidebar navigation
#[component]
pub fn AppLayout(on_logout: Callback<()>, children: Children) -> impl IntoView {
    let (sidebar_open, set_sidebar_open) = signal(false);

    let logout_click = move |_| on_logout.run(());

    view! {
        <div class="min-h-screen bg-gray-900 text-white w-full mx-auto" style="max-width: 1000px;">
            // Mobile header
            <header class="lg:hidden bg-gray-800 p-4 flex justify-between items-center">
                <div class="text-xl font-semibold text-blue-400">"Keystone"</div>
                <button
                    class="text-gray-300 hover:text-white"
                    on:click=move |_| set_sidebar_open.update(|v| *v = !*v)
                >
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/>
                    </svg>
                </button>
            </header>

            <div class="flex">
                // Desktop sidebar
                <aside class="hidden lg:block w-64 bg-gray-800 min-h-screen p-4 fixed">
                    <div class="h-full flex flex-col">
                        <div class="mb-6">
                            <div class="text-xl font-semibold text-blue-400">"Keystone"</div>
                            <div class="text-sm text-gray-400">"Router Manager"</div>
                        </div>

                        <nav class="space-y-1">
                            <A href="/" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200">"Dashboard"</A>
                            <A href="/interfaces" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200">"Interfaces"</A>
                            <A href="/vlans" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200">"VLANs"</A>
                            <A href="/bridges" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200">"Bridges"</A>
                            <A href="/networkd-preview" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200">"Networkd Preview"</A>
                            <A href="/firewall" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200">"Firewall"</A>
                            <A href="/settings" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200">"Settings"</A>
                        </nav>

                        <div class="mt-auto pt-4 border-t border-gray-700">
                            <button
                                class="w-full text-left px-3 py-2 rounded hover:bg-red-900 text-red-400"
                                on:click=logout_click
                            >
                                "Logout"
                            </button>
                        </div>
                    </div>
                </aside>

                // Mobile sidebar overlay
                <Show when=move || sidebar_open.get()>
                    <div
                        class="fixed inset-0 bg-black/50 z-40 lg:hidden"
                        on:click=move |_| set_sidebar_open.set(false)
                    />
                    <aside class="fixed left-0 top-0 w-64 h-full bg-gray-800 p-4 z-50 lg:hidden">
                        <div class="h-full flex flex-col">
                            <div class="mb-6">
                                <div class="text-xl font-semibold text-blue-400">"Keystone"</div>
                                <div class="text-sm text-gray-400">"Router Manager"</div>
                            </div>

                            <nav class="space-y-1">
                                <A href="/" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200" on:click=move |_| set_sidebar_open.set(false)>"Dashboard"</A>
                                <A href="/interfaces" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200" on:click=move |_| set_sidebar_open.set(false)>"Interfaces"</A>
                                <A href="/vlans" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200" on:click=move |_| set_sidebar_open.set(false)>"VLANs"</A>
                                <A href="/bridges" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200" on:click=move |_| set_sidebar_open.set(false)>"Bridges"</A>
                                <A href="/networkd-preview" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200" on:click=move |_| set_sidebar_open.set(false)>"Networkd Preview"</A>
                                <A href="/firewall" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200" on:click=move |_| set_sidebar_open.set(false)>"Firewall"</A>
                                <A href="/settings" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200" on:click=move |_| set_sidebar_open.set(false)>"Settings"</A>
                            </nav>

                            <div class="mt-auto pt-4 border-t border-gray-700">
                                <button
                                    class="w-full text-left px-3 py-2 rounded hover:bg-red-900 text-red-400"
                                    on:click=logout_click
                                >
                                    "Logout"
                                </button>
                            </div>
                        </div>
                    </aside>
                </Show>

                // Main content area
                <main class="flex-1 lg:ml-64 p-4 lg:p-8">
                    {children()}
                </main>
            </div>
        </div>
    }
}
