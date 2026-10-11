//! Main application layout with navigation

use crate::api;
use crate::components::SidebarNavigation;
use gloo_timers::callback::Interval;
use leptos::prelude::*;
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
                        apply_message
                            .set("Firewall changes timed out and were rolled back.".to_string());
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

    let location = leptos_router::hooks::use_location();
    let on_navigate = Callback::new(move |()| set_sidebar_open.set(false));

    view! {
        <div class="min-h-screen w-full bg-slate-950 text-slate-100">
            // Permanent desktop navigation
            <aside class="hidden lg:flex fixed inset-y-0 left-0 z-30 w-72 flex-col border-r border-slate-800/80 bg-[#0d1727]">
                <div class="h-[88px] px-6 flex items-center gap-3 shrink-0 border-b border-white/5">
                    <div class="h-10 w-10 rounded-xl bg-gradient-to-br from-sky-400 to-blue-700 flex items-center justify-center shadow-lg shadow-sky-900/30">
                        <svg class="h-6 w-6 text-white" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                            <path d="M12 2 3 7v5c0 5 3.5 8 9 10 5.5-2 9-5 9-10V7l-9-5Z"/>
                            <path d="m8 12 3 3 5-6"/>
                        </svg>
                    </div>
                    <div>
                        <div class="text-lg font-bold tracking-tight text-white">"Keystone"</div>
                        <div class="text-[11px] tracking-widest uppercase text-slate-500">"Router management"</div>
                    </div>
                </div>
                <div class="flex-1 min-h-0 overflow-y-auto px-4 py-6">
                    <SidebarNavigation on_navigate=on_navigate />
                </div>
                <div class="p-4 border-t border-white/5 shrink-0">
                    <div class="mb-3 flex items-center gap-2 px-3 text-xs text-slate-500">
                        <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
                        "Local administration"
                    </div>
                    <button type="button"
                        class="w-full text-left px-3 py-2.5 rounded-xl text-sm text-slate-400 hover:text-rose-300 hover:bg-rose-400/10 transition-colors"
                        on:click=logout_click
                    >
                        "Sign out"
                    </button>
                </div>
            </aside>

            // Mobile title bar and navigation drawer
            <header class="lg:hidden sticky top-0 z-30 bg-[#0d1727] border-b border-slate-800 px-4 py-3 flex items-center justify-between">
                <div class="flex items-center gap-2.5">
                    <span class="h-8 w-8 rounded-lg bg-gradient-to-br from-sky-400 to-blue-700 flex items-center justify-center font-bold">"K"</span>
                    <span class="font-semibold tracking-tight">"Keystone"</span>
                </div>
                <button type="button" aria-label="Open navigation"
                    class="p-2 rounded-lg text-slate-300 hover:bg-white/10"
                    on:click=move |_| set_sidebar_open.set(true)
                >
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" viewBox="0 0 24 24" aria-hidden="true">
                        <path d="M4 6h16M4 12h16M4 18h16"/>
                    </svg>
                </button>
            </header>
            <Show when=move || sidebar_open.get()>
                <div class="fixed inset-0 z-40 bg-black/70 lg:hidden" on:click=move |_| set_sidebar_open.set(false)></div>
                <aside class="fixed inset-y-0 left-0 z-50 w-72 max-w-[88vw] lg:hidden flex flex-col bg-[#0d1727] border-r border-slate-700 shadow-2xl">
                    <div class="h-[72px] flex justify-between items-center px-5 border-b border-white/5">
                        <div class="font-bold text-lg">"Keystone"</div>
                        <button type="button" aria-label="Close navigation"
                            class="p-2 rounded-lg text-slate-400 hover:bg-white/10"
                            on:click=move |_| set_sidebar_open.set(false)
                        >"✕"</button>
                    </div>
                    <div class="flex-1 min-h-0 overflow-y-auto px-4 py-5">
                        <SidebarNavigation on_navigate=on_navigate />
                    </div>
                    <div class="shrink-0 p-4 border-t border-white/5">
                        <button type="button" class="w-full text-left px-3 py-2 rounded-lg text-rose-300 hover:bg-rose-400/10" on:click=logout_click>"Sign out"</button>
                    </div>
                </aside>
            </Show>

            <div class="lg:pl-72 min-w-0 w-full">
                <div class="min-h-screen flex flex-col">
                    // Shared workspace bar
                    <div class="border-b border-slate-800/80 bg-[#101b2b]/80">
                        <div class="px-5 sm:px-7 xl:px-10 2xl:px-12 py-5 flex flex-wrap items-center justify-between gap-4">
                            <div class="min-w-0">
                                <div class="text-[10px] uppercase tracking-[0.24em] text-slate-500 font-semibold mb-1">"Network control"</div>
                                <div class="text-sm font-medium text-slate-200">{move || crate::components::breadcrumb(&location.pathname.get())}</div>
                            </div>
                            <button type="button"
                                class="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-semibold shadow-lg shadow-emerald-950/30 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                                on:click=on_apply_all
                                disabled=move || applying.get() || pending_session.get().is_some()
                            >
                                <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                                    <path d="M5 12l5 5L20 7"/>
                                </svg>
                                {move || if applying.get() { "Applying..." } else { "Apply All Changes" }}
                            </button>
                        </div>
                    </div>
                    <main class="flex-1 min-w-0 w-full p-5 sm:p-7 xl:p-10 2xl:p-12">
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
        </div>
    }
}
