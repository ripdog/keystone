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
    let (loading, set_loading) = signal(false);

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
        <div class="p-4">
            <div class="mb-4 flex justify-between items-center">
                <div>
                    <h2 class="text-2xl font-bold text-white">"systemd-networkd Configuration Preview"</h2>
                    <p class="text-gray-400">
                        "Preview of generated .network files without writing to disk"
                    </p>
                </div>
                <button
                    class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded disabled:opacity-50"
                    on:click=refresh
                    disabled=move || loading.get()
                >
                    {move || if loading.get() { "Loading..." } else { "Refresh" }}
                </button>
            </div>

            {move || error.get().map(|err| view! {
                <div class="mb-4 p-4 bg-red-900/20 border border-red-700 rounded text-red-300">
                    {err}
                </div>
            })}

            <Show
                when=move || preview_data.get().is_some()
                fallback=move || view! {
                    <div class="text-center py-12">
                        <Show
                            when=move || loading.get()
                            fallback=move || view! { <p class="text-gray-400">"No configuration to preview"</p> }
                        >
                            <div class="inline-block w-8 h-8 border-4 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
                        </Show>
                    </div>
                }
            >
                {move || preview_data.get().map(|data| {
                    if data.files.is_empty() {
                        view! {
                            <div class="p-4 bg-blue-900/20 border border-blue-700 rounded text-blue-300">
                                "No enabled interfaces configured. Go to Interfaces page to add configurations."
                            </div>
                        }.into_any()
                    } else {
                        view! {
                            <div>
                                <div class="mb-4 p-4 bg-blue-900/20 border border-blue-700 rounded text-blue-300">
                                    {format!("Showing {} configuration file(s)", data.files.len())}
                                </div>
                                <For
                                    each=move || data.files.clone()
                                    key=|file| file.filename.clone()
                                    children=move |file| {
                                        view! {
                                            <div class="mb-4 bg-gray-800 rounded-lg overflow-hidden">
                                                <div class="flex justify-between items-center p-4 bg-gray-700">
                                                    <h5 class="text-lg font-mono text-white">
                                                        {file.filename.clone()}
                                                    </h5>
                                                </div>
                                                <div class="p-4">
                                                    <pre class="bg-gray-900 p-4 rounded overflow-x-auto">
                                                        <code class="text-gray-300 text-sm">{file.content.clone()}</code>
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
