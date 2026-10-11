//! Main application layout with navigation

use crate::components::SidebarNavigation;
use leptos::prelude::*;
/// Main layout wrapper with sidebar navigation
#[component]
pub fn AppLayout(on_logout: Callback<()>, children: Children) -> impl IntoView {
    let (sidebar_open, set_sidebar_open) = signal(false);

    let logout_click = move |_| on_logout.run(());

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
                        </div>
                    </div>
                    <main class="flex-1 min-w-0 w-full p-5 sm:p-7 xl:p-10 2xl:p-12">
                        {children()}
                    </main>
                </div>
            </div>
        </div>
    }
}
