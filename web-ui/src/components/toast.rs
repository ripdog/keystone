//! Brief confirmations for successful saves and actions.
//!
//! A success is shown for a few seconds and then removed, so it never stays on
//! the page after the moment has passed. Failures and validation errors are not
//! toasts: they stay on screen until the user fixes or dismisses them.

use gloo_timers::callback::Timeout;
use leptos::prelude::*;

/// How long a toast stays visible.
const TOAST_MS: u32 = 4_000;

/// The toasts on screen, oldest first.
#[derive(Clone, Copy)]
pub struct Toasts {
    items: RwSignal<Vec<(u64, String)>>,
    next_id: RwSignal<u64>,
}

impl Toasts {
    /// Show `text` as a success for a few seconds.
    pub fn success(&self, text: impl Into<String>) {
        let text = text.into();
        if text.trim().is_empty() {
            return;
        }
        let id = self.next_id.get_untracked();
        self.next_id.set(id.wrapping_add(1));
        self.items.update(|items| items.push((id, text)));
        self.remove_later(id);
    }

    /// Remove one toast now. Harmless when it has already gone.
    pub fn dismiss(&self, id: u64) {
        self.items
            .update(|items| items.retain(|(item, _)| *item != id));
    }

    fn remove_later(&self, id: u64) {
        let items = self.items;
        // The signal may be gone after logout; `try_update` then does nothing.
        Timeout::new(TOAST_MS, move || {
            let _ = items.try_update(|items| items.retain(|(item, _)| *item != id));
        })
        .forget();
    }
}

/// Create the toast list and provide it to the page layout.
pub fn provide_toasts() -> Toasts {
    let toasts = Toasts {
        items: RwSignal::new(Vec::new()),
        next_id: RwSignal::new(0),
    };
    provide_context(toasts);
    toasts
}

/// The toast list provided by the page layout.
pub fn use_toasts() -> Toasts {
    expect_context::<Toasts>()
}

/// Renders the toasts, bottom right, above every other surface except the
/// confirmation bar's own stacking layer.
#[component]
pub fn ToastHost() -> impl IntoView {
    let toasts = use_toasts();
    view! {
        <div
            class="pointer-events-none fixed bottom-4 right-4 left-4 sm:left-auto z-[90] flex flex-col items-stretch sm:items-end gap-2"
            role="status"
            aria-live="polite"
        >
            <For
                each=move || toasts.items.get()
                key=|(id, _)| *id
                children=move |(id, text)| view! {
                    <div class="pointer-events-auto flex items-start gap-3 rounded-lg border border-emerald-600/60 bg-slate-900 px-4 py-3 text-sm text-emerald-100 shadow-xl sm:max-w-sm">
                        <span class="min-w-0 flex-1 break-words">{text}</span>
                        <button
                            type="button"
                            aria-label="Dismiss"
                            class="shrink-0 text-emerald-200/70 hover:text-white"
                            on:click=move |_| toasts.dismiss(id)
                        >
                            "\u{2715}"
                        </button>
                    </div>
                }
            />
        </div>
    }
}
