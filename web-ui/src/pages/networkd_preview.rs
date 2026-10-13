//! Networkd Preview Page
//!
//! Displays a preview of systemd-networkd configuration files
//! without writing them to disk.

use crate::api;
use keystone_core::NetworkdPreviewResponse;
use leptos::prelude::*;
use leptos::task::spawn_local;

#[component]
pub fn NetworkdPreviewPage(
    auth_token: ReadSignal<Option<String>>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let (preview_data, set_preview_data) = signal::<Option<NetworkdPreviewResponse>>(None);
    let (error, set_error) = signal::<Option<String>>(None);
    let (loading, set_loading) = signal(true);

    // Load preview on mount
    Effect::new(move |_| {
        let token = auth_token.get();
        if token.is_none() {
            return;
        }

        let token = token.unwrap();

        set_loading.set(true);
        set_error.set(None);

        spawn_local(async move {
            match api::get_networkd_preview(&token).await {
                Ok(data) => {
                    set_preview_data.set(Some(data));
                    set_loading.set(false);
                }
                Err(e) => {
                    if e.contains("401") || e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        set_error.set(Some(format!("Failed to load preview: {}", e)));
                        set_loading.set(false);
                    }
                }
            }
        });
    });

    let refresh = move |_| {
        let token = match auth_token.get() {
            Some(t) => t,
            None => return,
        };

        set_loading.set(true);
        set_error.set(None);

        spawn_local(async move {
            match api::get_networkd_preview(&token).await {
                Ok(data) => {
                    set_preview_data.set(Some(data));
                    set_loading.set(false);
                }
                Err(e) => {
                    if e.contains("401") || e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        set_error.set(Some(format!("Failed to load preview: {}", e)));
                        set_loading.set(false);
                    }
                }
            }
        });
    };

    view! {
        <div class="space-y-6">
            <div class="flex justify-between items-start">
                <div>
                    <h1 class="text-2xl font-semibold text-blue-300">"Networkd Configuration Preview"</h1>
                    <p class="text-gray-400">"Preview of generated .network files without writing to disk"</p>
                </div>
                <button
                    class="bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 text-white px-4 py-2 rounded"
                    on:click=refresh
                    disabled=move || loading.get()
                >
                    {move || if loading.get() { "Loading..." } else { "Refresh" }}
                </button>
            </div>

            // Error message
            <Show when=move || error.get().is_some()>
                <div class="bg-red-900/50 border border-red-500 text-red-200 px-4 py-2 rounded">
                    {move || error.get().unwrap_or_default()}
                </div>
            </Show>

            <Show
                when=move || !loading.get()
                fallback=|| view! {
                    <div class="text-gray-400">"Loading preview..."</div>
                }
            >
                {move || preview_data.get().map(|data| {
                    if data.files.is_empty() {
                        view! {
                            <div class="bg-blue-900/50 border border-blue-500 text-blue-200 px-4 py-2 rounded">
                                "No enabled interfaces configured. Go to Interfaces page to add configurations."
                            </div>
                        }.into_any()
                    } else {
                        view! {
                            <div class="space-y-4">
                                <div class="text-sm text-slate-400">
                                    {format!("Showing {} configuration file(s)", data.files.len())}
                                </div>
                                <For
                                    each=move || data.files.clone()
                                    key=|file| file.filename.clone()
                                    children=move |file| {
                                        view! {
                                            <div class="bg-gray-800 rounded-lg shadow-lg overflow-hidden">
                                                <div class="px-4 py-3 bg-gray-700 border-b border-gray-600">
                                                    <h3 class="text-lg font-mono text-blue-300">
                                                        {file.filename.clone()}
                                                    </h3>
                                                </div>
                                                <div class="p-4">
                                                    <pre class="bg-gray-900 p-4 rounded overflow-x-auto text-sm font-mono text-gray-300 whitespace-pre">
                                                        {file.content.clone()}
                                                    </pre>
                                                </div>
                                            </div>
                                        }
                                    }
                                />
                            </div>
                        }.into_any()
                    }
                })}
            </Show>
        </div>
    }
}
