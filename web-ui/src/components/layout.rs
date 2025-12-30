//! Main application layout with navigation

use crate::api;
use gloo_timers::callback::Interval;
use leptos::prelude::*;
use leptos_router::components::A;
use std::cell::RefCell;
use std::rc::Rc;
use wasm_bindgen::prelude::*;

// JS binding to get current time
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = Date)]
    fn now() -> f64;
}

/// Main layout wrapper with sidebar navigation
#[component]
pub fn AppLayout(
    auth_token: ReadSignal<Option<String>>,
    on_logout: Callback<()>,
    on_unauthorized: Callback<()>,
    children: Children,
) -> impl IntoView {
    let (sidebar_open, set_sidebar_open) = signal(false);

    // Unified apply state
    let applying = RwSignal::new(false);
    let apply_message = RwSignal::new(String::new());
    let apply_error = RwSignal::new(false);
    let pending_session = RwSignal::new(Option::<String>::None);
    let seconds_remaining = RwSignal::new(0u32);

    // Store the interval handle so it can be cancelled
    let interval_handle: Rc<RefCell<Option<Interval>>> = Rc::new(RefCell::new(None));
    let interval_handle_for_effect = interval_handle.clone();

    // Countdown timer effect - runs when pending_session changes
    Effect::new(move |_| {
        let has_pending = pending_session.get().is_some();

        if has_pending {
            // Start countdown interval
            let handle = Interval::new(1000, move || {
                seconds_remaining.update(|s| {
                    if *s > 0 {
                        *s -= 1;
                    } else {
                        // Timer expired - clear pending session
                        pending_session.set(None);
                        apply_message.set(
                            "Firewall changes timed out and were rolled back.".to_string(),
                        );
                        apply_error.set(true);
                    }
                });
            });
            *interval_handle_for_effect.borrow_mut() = Some(handle);
        } else {
            // Clear the interval when no longer pending
            *interval_handle_for_effect.borrow_mut() = None;
        }
    });

    let logout_click = move |_| on_logout.run(());

    // Get token as string
    let token = Signal::derive(move || auth_token.get().unwrap_or_default());

    // Apply all configuration
    let on_apply_all = move |_| {
        applying.set(true);
        apply_message.set(String::new());
        apply_error.set(false);

        let token = token.get();
        leptos::task::spawn_local(async move {
            match api::apply_all_config(&token).await {
                Ok(response) => {
                    apply_error.set(!response.success);
                    apply_message.set(response.message);

                    if response.firewall_pending_confirmation {
                        pending_session.set(response.firewall_session_id);
                        if let Some(deadline) = response.firewall_confirm_deadline {
                            let now_ms = now() as u64 / 1000;
                            let remaining = deadline.saturating_sub(now_ms) as u32;
                            seconds_remaining.set(remaining);
                        }
                    }
                }
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        apply_error.set(true);
                        apply_message.set(format!("Error: {}", e));
                    }
                }
            }
            applying.set(false);
        });
    };

    // Confirm firewall changes
    let on_confirm = move |_| {
        if let Some(session_id) = pending_session.get() {
            let token = token.get();
            leptos::task::spawn_local(async move {
                match api::confirm_firewall(&token, &session_id).await {
                    Ok(response) => {
                        if response.success {
                            apply_message.set(response.message);
                            apply_error.set(false);
                            pending_session.set(None);
                        } else {
                            apply_error.set(true);
                            apply_message.set(format!("Confirm failed: {}", response.message));
                        }
                    }
                    Err(e) => {
                        if e.contains("Unauthorized") {
                            on_unauthorized.run(());
                        } else {
                            apply_error.set(true);
                            apply_message.set(format!("Error: {}", e));
                        }
                    }
                }
            });
        }
    };

    // Rollback firewall changes
    let on_rollback = move |_| {
        let token = token.get();
        leptos::task::spawn_local(async move {
            match api::rollback_firewall(&token).await {
                Ok(response) => {
                    if response.success {
                        apply_message.set(response.message);
                        apply_error.set(false);
                        pending_session.set(None);
                    } else {
                        apply_error.set(true);
                        apply_message.set(format!("Rollback failed: {}", response.message));
                    }
                }
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        apply_error.set(true);
                        apply_message.set(format!("Error: {}", e));
                    }
                }
            }
        });
    };

    // Desktop sidebar content (extracted to avoid duplication)
    let nav_links = move || {
        view! {
            <A href="/" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200">"Dashboard"</A>
            <A href="/interfaces" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200">"Interfaces"</A>
            <A href="/vlans" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200">"VLANs"</A>
            <A href="/bridges" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200">"Bridges"</A>
            <A href="/dnsmasq" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200">"DNS & DHCP"</A>
            <A href="/caddy" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200">"Web Server"</A>
            <A href="/networkd-preview" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200">"Networkd Preview"</A>
            <A href="/firewall" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200">"Firewall"</A>
            <A href="/services" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200">"Services"</A>
            <A href="/settings" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200">"Settings"</A>
        }
    };

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

                        // Apply All button
                        <div class="mb-4">
                            <button
                                class="w-full px-3 py-2 bg-green-600 hover:bg-green-700 text-white rounded font-medium disabled:opacity-50 disabled:cursor-not-allowed"
                                on:click=on_apply_all
                                disabled=move || applying.get() || pending_session.get().is_some()
                            >
                                {move || if applying.get() { "Applying..." } else { "Apply All Changes" }}
                            </button>
                        </div>

                        <nav class="space-y-1">
                            {nav_links()}
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

                            // Apply All button (mobile)
                            <div class="mb-4">
                                <button
                                    class="w-full px-3 py-2 bg-green-600 hover:bg-green-700 text-white rounded font-medium disabled:opacity-50 disabled:cursor-not-allowed"
                                    on:click=on_apply_all
                                    disabled=move || applying.get() || pending_session.get().is_some()
                                >
                                    {move || if applying.get() { "Applying..." } else { "Apply All Changes" }}
                                </button>
                            </div>

                            <nav class="space-y-1">
                                <A href="/" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200" on:click=move |_| set_sidebar_open.set(false)>"Dashboard"</A>
                                <A href="/interfaces" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200" on:click=move |_| set_sidebar_open.set(false)>"Interfaces"</A>
                                <A href="/vlans" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200" on:click=move |_| set_sidebar_open.set(false)>"VLANs"</A>
                                <A href="/bridges" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200" on:click=move |_| set_sidebar_open.set(false)>"Bridges"</A>
                                <A href="/dnsmasq" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200" on:click=move |_| set_sidebar_open.set(false)>"DNS & DHCP"</A>
                                <A href="/caddy" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200" on:click=move |_| set_sidebar_open.set(false)>"Web Server"</A>
                                <A href="/networkd-preview" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200" on:click=move |_| set_sidebar_open.set(false)>"Networkd Preview"</A>
                                <A href="/firewall" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200" on:click=move |_| set_sidebar_open.set(false)>"Firewall"</A>
                                <A href="/services" attr:class="block w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-gray-200" on:click=move |_| set_sidebar_open.set(false)>"Services"</A>
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
                    // Global status messages and confirmation banner
                    <div class="space-y-4 mb-4">
                        // Apply result message
                        {move || {
                            let msg = apply_message.get();
                            if msg.is_empty() {
                                view! { <div></div> }.into_any()
                            } else {
                                let class = if apply_error.get() {
                                    "bg-red-900/50 border border-red-700 text-red-200 px-4 py-3 rounded"
                                } else {
                                    "bg-green-900/50 border border-green-700 text-green-200 px-4 py-3 rounded"
                                };
                                view! {
                                    <div class=class>
                                        {msg}
                                        <button
                                            class="float-right text-gray-400 hover:text-white"
                                            on:click=move |_| apply_message.set(String::new())
                                        >
                                            "×"
                                        </button>
                                    </div>
                                }.into_any()
                            }
                        }}

                        // Firewall confirmation banner
                        {move || {
                            if let Some(_session_id) = pending_session.get() {
                                let remaining = seconds_remaining.get();
                                view! {
                                    <div class="bg-yellow-900/50 border border-yellow-600 text-yellow-200 px-4 py-3 rounded">
                                        <div class="flex items-center justify-between flex-wrap gap-2">
                                            <div>
                                                <span class="font-medium">"Firewall changes pending!"</span>
                                                " Confirm within "
                                                <span class="font-bold">{remaining}</span>
                                                " seconds or changes will roll back."
                                            </div>
                                            <div class="flex gap-2">
                                                <button
                                                    class="px-3 py-1 bg-green-600 hover:bg-green-700 text-white rounded text-sm font-medium"
                                                    on:click=on_confirm
                                                >
                                                    "Confirm"
                                                </button>
                                                <button
                                                    class="px-3 py-1 bg-red-600 hover:bg-red-700 text-white rounded text-sm font-medium"
                                                    on:click=on_rollback
                                                >
                                                    "Rollback"
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                }.into_any()
                            } else {
                                view! { <div></div> }.into_any()
                            }
                        }}
                    </div>

                    {children()}
                </main>
            </div>
        </div>
    }
}
