//! Keystone brand mark: an arch held by its keystone, with traffic passing through.

use leptos::prelude::*;

/// The Keystone logo mark, without a background tile. Size it with `class`.
/// Keep the geometry in step with `web-ui/favicon.svg`.
#[component]
pub fn KeystoneLogo(#[prop(into, optional)] class: String) -> impl IntoView {
    view! {
        <svg class=class viewBox="15 16 70 70" aria-hidden="true">
            <path d="M17 83V57A33 33 0 0 1 41.36 25.15L44.05 38.96A19 19 0 0 0 31 57V83Z" fill="#3b5f99"/>
            <path d="M83 83V57A33 33 0 0 0 58.64 25.15L55.95 38.96A19 19 0 0 1 69 57V83Z" fill="#3b5f99"/>
            <path d="M46.37 38.35L42.42 18H57.58L53.63 38.35Z" fill="#38bdf8"/>
            <path d="M45.43 58L56.31 68.88L45.43 79.75" fill="none" stroke="#e2e8f0" stroke-width="6.5" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}
