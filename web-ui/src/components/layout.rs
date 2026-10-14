//! Main application layout with navigation

use crate::components::{
    CommandPalette, ConfigRefresh, PendingChangesBar, SidebarNavigation, ToastHost, icon_path,
    provide_pending_actions, provide_toasts,
};
use leptos::prelude::*;

/// Main layout wrapper with sidebar navigation
#[component]
pub fn AppLayout(
    auth_token: ReadSignal<Option<String>>,
    on_unauthorized: Callback<()>,
    on_logout: Callback<()>,
    children: Children,
) -> impl IntoView {
    let (sidebar_open, set_sidebar_open) = signal(false);
    // Pages bump this after saving so the pending-changes bar refetches at once.
    provide_context(ConfigRefresh(RwSignal::new(0)));
    let palette_open = RwSignal::new(false);
    // Brief confirmations for saves; shared by every page.
    provide_toasts();
    // Shared by the pending bar, its review drawer and the command palette. The
    // palette closes when a confirmation becomes pending.
    provide_pending_actions(auth_token, on_unauthorized, palette_open);

    let logout_click = move |_| on_logout.run(());

    let location = leptos_router::hooks::use_location();

    // Keep the browser tab title in step with the current page.
    Effect::new(move || set_document_title(&document_title(&location.pathname.get())));
    on_cleanup(|| set_document_title(DEFAULT_TITLE));
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
                                class="inline-flex shrink-0 items-center gap-2 rounded-xl border border-slate-700 bg-slate-900/60 px-3 py-2 text-sm text-slate-400 hover:bg-white/5 hover:text-white transition-colors"
                                aria-label="Search pages, actions and devices"
                                aria-haspopup="dialog"
                                on:click=move |_| palette_open.set(true)
                            >
                                <svg class="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                                    <path d=icon_path("search") />
                                </svg>
                                <span class="hidden sm:inline">"Search"</span>
                                <kbd class="hidden sm:inline-flex rounded-md border border-slate-700 bg-slate-800 px-1.5 py-0.5 text-[11px] text-slate-400">"Ctrl K"</kbd>
                            </button>
                        </div>
                    </div>
                    <PendingChangesBar auth_token=auth_token on_unauthorized=on_unauthorized />
                    <CommandPalette
                        open=palette_open
                        auth_token=auth_token
                        on_unauthorized=on_unauthorized
                        on_logout=on_logout
                    />
                    <main class="flex-1 min-w-0 w-full p-5 sm:p-7 xl:p-10 2xl:p-12">
                        {children()}
                    </main>
                </div>
            </div>
            <ToastHost />
        </div>
    }
}

const DEFAULT_TITLE: &str = "Keystone Router Manager";

/// Tab title for a path, e.g. `Firewall / Rules - Keystone`.
fn document_title(path: &str) -> String {
    match crate::components::breadcrumb(path).as_str() {
        "Keystone" => DEFAULT_TITLE.to_string(),
        crumb => format!("{crumb} - Keystone"),
    }
}

pub fn set_document_title(title: &str) {
    if let Some(document) = web_sys::window().and_then(|w| w.document()) {
        document.set_title(title);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn titles_follow_the_breadcrumb() {
        assert_eq!(document_title("/unknown"), DEFAULT_TITLE);
        assert_eq!(
            document_title("/interfaces/eth0"),
            "Interfaces / Edit - Keystone"
        );
        assert!(document_title("/").ends_with(" - Keystone"));
    }
}
