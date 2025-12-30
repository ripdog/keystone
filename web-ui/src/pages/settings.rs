//! System settings page

use keystone_core::{GlobalSettings, SaveUserRequest, UserInfo};
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::api;

#[component]
pub fn SettingsPage(
    auth_token: ReadSignal<Option<String>>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let (users, set_users) = signal(Vec::<UserInfo>::new());
    let (show_user_modal, set_show_user_modal) = signal(false);
    let (editing_user, set_editing_user) = signal(Option::<UserInfo>::None);
    let (modal_username, set_modal_username) = signal(String::new());
    let (modal_email, set_modal_email) = signal(String::new());
    let (modal_password, set_modal_password) = signal(String::new());
    let (error_msg, set_error_msg) = signal(Option::<String>::None);
    let (success_msg, set_success_msg) = signal(Option::<String>::None);
    let (global_settings, set_global_settings) = signal(GlobalSettings::default());
    let (settings_loading, set_settings_loading) = signal(true);

    // Load users and global settings on mount
    Effect::new(move || {
        if let Some(token) = auth_token.get() {
            let token_clone = token.clone();
            spawn_local(async move {
                match api::fetch_users(&token).await {
                    Ok(users_list) => set_users.set(users_list),
                    Err(e) => {
                        if e.contains("Unauthorized") {
                            on_unauthorized.run(());
                        }
                    }
                }
            });
            spawn_local(async move {
                set_settings_loading.set(true);
                match api::fetch_global_settings(&token_clone).await {
                    Ok(settings) => set_global_settings.set(settings),
                    Err(e) => {
                        if e.contains("Unauthorized") {
                            on_unauthorized.run(());
                        }
                    }
                }
                set_settings_loading.set(false);
            });
        }
    });

    let open_new_user_modal = move |_| {
        set_editing_user.set(None);
        set_modal_username.set(String::new());
        set_modal_email.set(String::new());
        set_modal_password.set(String::new());
        set_error_msg.set(None);
        set_show_user_modal.set(true);
    };

    let open_edit_user_modal = move |user: UserInfo| {
        set_editing_user.set(Some(user.clone()));
        set_modal_username.set(user.username.clone());
        set_modal_email.set(user.email.clone().unwrap_or_default());
        set_modal_password.set(String::new());
        set_error_msg.set(None);
        set_show_user_modal.set(true);
    };

    let close_modal = move |_| {
        set_show_user_modal.set(false);
        set_error_msg.set(None);
    };

    let save_user = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();

        let token = match auth_token.get() {
            Some(t) => t,
            None => return,
        };

        let username = modal_username.get();
        let email = modal_email.get();
        let password = modal_password.get();
        let user_id = editing_user.get().map(|u| u.id);

        if username.is_empty() {
            set_error_msg.set(Some("Username is required".to_string()));
            return;
        }

        if user_id.is_none() && password.is_empty() {
            set_error_msg.set(Some("Password is required for new users".to_string()));
            return;
        }

        let request = SaveUserRequest {
            id: user_id,
            username: username.clone(),
            email: if email.is_empty() { None } else { Some(email) },
            password: if password.is_empty() {
                None
            } else {
                Some(password)
            },
        };

        spawn_local(async move {
            match api::save_user(&token, request).await {
                Ok(response) => {
                    if response.success {
                        set_show_user_modal.set(false);
                        set_success_msg.set(Some(response.message.clone()));
                        // Reload users
                        if let Ok(users_list) = api::fetch_users(&token).await {
                            leptos::logging::log!("Reloaded {} users after save", users_list.len());
                            set_users.set(users_list);
                        } else {
                            leptos::logging::warn!("Failed to reload users after save");
                        }
                    } else {
                        set_error_msg.set(Some(response.message));
                    }
                }
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        set_error_msg.set(Some(format!("Error: {}", e)));
                    }
                }
            }
        });
    };

    let delete_user = move |user_id: i64| {
        let token = match auth_token.get() {
            Some(t) => t,
            None => return,
        };

        if !web_sys::window()
            .and_then(|w| {
                w.confirm_with_message("Are you sure you want to delete this user?")
                    .ok()
            })
            .unwrap_or(false)
        {
            return;
        }

        spawn_local(async move {
            match api::delete_user(&token, user_id).await {
                Ok(response) => {
                    if response.success {
                        set_success_msg.set(Some(response.message.clone()));
                        // Reload users
                        if let Ok(users_list) = api::fetch_users(&token).await {
                            leptos::logging::log!(
                                "Reloaded {} users after delete",
                                users_list.len()
                            );
                            set_users.set(users_list);
                        } else {
                            leptos::logging::warn!("Failed to reload users after delete");
                        }
                    } else {
                        set_error_msg.set(Some(response.message));
                    }
                }
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        set_error_msg.set(Some(format!("Error: {}", e)));
                    }
                }
            }
        });
    };

    view! {
        <div class="space-y-6">
            <div>
                <h1 class="text-2xl font-semibold text-blue-300">"System Settings"</h1>
                <p class="text-gray-400">"Configure system-wide router settings"</p>
            </div>

            <Show when=move || success_msg.get().is_some()>
                <div class="bg-green-900/50 border border-green-500 rounded p-4 text-green-200">
                    {move || success_msg.get().unwrap_or_default()}
                </div>
            </Show>

            <div class="bg-gray-800 rounded-lg p-6 shadow-lg">
                <div class="flex items-center justify-between mb-4">
                    <h2 class="text-lg font-medium text-white">"User Management"</h2>
                    <button
                        on:click=open_new_user_modal
                        class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
                    >
                        "+ Add User"
                    </button>
                </div>

                <div class="space-y-2">
                    <For
                        each=move || users.get()
                        key=|user| (user.id, user.username.clone(), user.email.clone())
                        children=move |user: UserInfo| {
                            let user_for_edit = user.clone();
                            let user_id_for_delete = user.id;
                            let username = user.username.clone();
                            let email = user.email.clone();
                            view! {
                                <div class="flex items-center justify-between p-4 bg-gray-700 rounded">
                                    <div>
                                        <h3 class="font-medium text-white">{username}</h3>
                                        <p class="text-sm text-gray-400">
                                            {email.unwrap_or_else(|| "No email".to_string())}
                                        </p>
                                    </div>
                                    <div class="flex gap-2">
                                        <button
                                            on:click=move |_| open_edit_user_modal(user_for_edit.clone())
                                            class="bg-yellow-600 hover:bg-yellow-700 text-white px-3 py-1 rounded text-sm"
                                        >
                                            "Edit"
                                        </button>
                                        <button
                                            on:click=move |_| delete_user(user_id_for_delete)
                                            class="bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded text-sm"
                                        >
                                            "Delete"
                                        </button>
                                    </div>
                                </div>
                            }
                        }
                    />
                </div>
            </div>

            <div class="bg-gray-800 rounded-lg p-6 shadow-lg">
                <h2 class="text-lg font-medium text-white mb-4">"Configuration Lock"</h2>

                <Show when=move || settings_loading.get()>
                    <p class="text-gray-400">"Loading settings..."</p>
                </Show>

                <Show when=move || !settings_loading.get()>
                    <div class="bg-gray-700 rounded p-4">
                        <label class="flex items-center cursor-pointer">
                            <input
                                type="checkbox"
                                prop:checked=move || global_settings.get().config_changes_disabled
                                on:change=move |ev| {
                                    let checked = event_target_checked(&ev);
                                    let token = match auth_token.get() {
                                        Some(t) => t,
                                        None => return,
                                    };
                                    let mut settings = global_settings.get();
                                    settings.config_changes_disabled = checked;
                                    set_global_settings.set(settings.clone());
                                    spawn_local(async move {
                                        match api::save_global_settings(&token, settings).await {
                                            Ok(response) => {
                                                if response.success {
                                                    set_success_msg.set(Some(response.message));
                                                } else {
                                                    set_error_msg.set(Some(response.message));
                                                }
                                            }
                                            Err(e) => {
                                                set_error_msg.set(Some(format!("Error: {}", e)));
                                            }
                                        }
                                    });
                                }
                                class="w-5 h-5 rounded border-gray-500 bg-gray-600 text-blue-500"
                            />
                            <span class="ml-3 text-gray-300">
                                {move || if global_settings.get().config_changes_disabled {
                                    "Configuration changes are DISABLED"
                                } else {
                                    "Configuration changes are enabled"
                                }}
                            </span>
                        </label>
                        <p class="text-sm text-gray-500 mt-2">
                            "When enabled, prevents applying any configuration changes to the router. "
                            "Useful for preventing accidental changes in production."
                        </p>
                    </div>
                </Show>
            </div>

            // User Modal
            <Show when=move || show_user_modal.get()>
                <div class="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
                    <div class="bg-gray-800 rounded-lg p-6 max-w-md w-full">
                        <h2 class="text-xl font-semibold text-white mb-4">
                            {move || if editing_user.get().is_some() { "Edit User" } else { "Add User" }}
                        </h2>

                        <form on:submit=save_user>
                            <div class="space-y-4">
                                <div>
                                    <label class="block text-gray-300 mb-2">"Username"</label>
                                    <input
                                        type="text"
                                        prop:value=move || modal_username.get()
                                        on:input=move |ev| set_modal_username.set(event_target_value(&ev))
                                        class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white"
                                        required
                                    />
                                </div>

                                <div>
                                    <label class="block text-gray-300 mb-2">"Email (optional)"</label>
                                    <input
                                        type="email"
                                        prop:value=move || modal_email.get()
                                        on:input=move |ev| set_modal_email.set(event_target_value(&ev))
                                        class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white"
                                    />
                                </div>

                                <div>
                                    <label class="block text-gray-300 mb-2">
                                        {move || if editing_user.get().is_some() {
                                            "Password (leave empty to keep current)"
                                        } else {
                                            "Password"
                                        }}
                                    </label>
                                    <input
                                        type="password"
                                        prop:value=move || modal_password.get()
                                        on:input=move |ev| set_modal_password.set(event_target_value(&ev))
                                        class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white"
                                        required=move || editing_user.get().is_none()
                                    />
                                </div>

                                <Show when=move || error_msg.get().is_some()>
                                    <div class="bg-red-900/50 border border-red-500 rounded p-3 text-red-200 text-sm">
                                        {move || error_msg.get().unwrap_or_default()}
                                    </div>
                                </Show>

                                <div class="flex gap-2">
                                    <button
                                        type="submit"
                                        class="flex-1 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
                                    >
                                        "Save"
                                    </button>
                                    <button
                                        type="button"
                                        on:click=close_modal
                                        class="flex-1 bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded"
                                    >
                                        "Cancel"
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </Show>
        </div>
    }
}
