//! Login page component

use leptos::prelude::*;
use leptos::task::spawn_local;

use super::set_stored_token;
use crate::api;

/// Login page with password authentication
#[component]
pub fn LoginPage(on_login: WriteSignal<Option<String>>) -> impl IntoView {
    crate::components::set_document_title("Sign in - Keystone");
    let (username, set_username) = signal(String::from("admin"));
    let (password, set_password) = signal(String::new());
    let (error_msg, set_error_msg) = signal(Option::<String>::None);
    let (loading, set_loading) = signal(false);

    let handle_submit = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();

        let username_value = username.get();
        let password_value = password.get();
        set_loading.set(true);
        set_error_msg.set(None);

        spawn_local(async move {
            match api::login(&username_value, &password_value).await {
                Ok(response) => {
                    if response.success {
                        if let Some(token) = &response.token {
                            set_stored_token(token);
                            on_login.set(Some(token.to_string()));
                        }
                    } else {
                        set_error_msg.set(Some(response.message));
                        set_loading.set(false);
                    }
                }
                Err(e) => {
                    set_error_msg.set(Some(format!("Login failed: {}", e)));
                    set_loading.set(false);
                }
            }
        });
    };

    view! {
        <div class="min-h-screen bg-gray-900 flex items-center justify-center p-4">
            <div class="bg-gray-800 rounded-lg p-8 shadow-2xl max-w-md w-full">
                <div class="text-center mb-8">
                    <h1 class="text-3xl font-bold text-blue-400 mb-2">
                        "🔐 Keystone"
                    </h1>
                    <p class="text-gray-400">"Router Manager"</p>
                </div>

                <form on:submit=handle_submit>
                    <div class="mb-4">
                        <label class="block text-gray-300 mb-2 font-medium">
                            "Username"
                        </label>
                        <input
                            type="text"
                            prop:value=move || username.get()
                            on:input=move |ev| set_username.set(event_target_value(&ev))
                            placeholder="admin"
                            class="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded focus:outline-none focus:border-blue-500 text-white"
                            disabled=move || loading.get()
                        />
                    </div>

                    <div class="mb-6">
                        <label class="block text-gray-300 mb-2 font-medium">
                            "Password"
                        </label>
                        <input
                            type="password"
                            prop:value=move || password.get()
                            on:input=move |ev| set_password.set(event_target_value(&ev))
                            placeholder="Enter admin password"
                            class="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded focus:outline-none focus:border-blue-500 text-white"
                            disabled=move || loading.get()
                        />
                    </div>

                    <Show when=move || error_msg.get().is_some()>
                        <div class="mb-4 p-3 bg-red-900/50 border border-red-500 rounded text-red-200 text-sm">
                            {move || error_msg.get().unwrap_or_default()}
                        </div>
                    </Show>

                    <button
                        type="submit"
                        class="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 text-white font-medium py-3 rounded transition-colors"
                        disabled=move || loading.get()
                    >
                        {move || if loading.get() { "Logging in..." } else { "Login" }}
                    </button>
                </form>

                <div class="mt-6 text-center text-sm text-gray-400">
                    <p>"First installation? On the router console run:"</p>
                    <code class="block mt-2 bg-gray-700 px-2 py-2 rounded">"sudo keystonectl bootstrap-admin"</code>
                </div>
            </div>
        </div>
    }
}
