//! Setup Wizard Page
//!
//! Multi-step wizard for initial Keystone configuration.
//! Steps:
//! 0. Welcome - Introduction and login
//! 1. Password Change - Force change of default password
//! 2. System Checks - Verify packages and services
//! 3. Interface Assignment - Assign WAN/LAN roles
//! 4. Complete - Summary and apply

// Leptos empty fragments (view! { <></> }) return unit which is intentional
#![allow(clippy::unit_arg)]

use keystone_core::{
    CheckCategory, CheckSeverity, InterfaceRole, SaveUserRequest, SystemCheck,
    SystemStatusResponse, WizardInterfaceAssignment, WizardSaveInterfacesRequest, WizardState,
    WizardStep,
};
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::api;
use crate::components::set_stored_token;

/// Setup wizard page component
#[component]
pub fn WizardPage(
    auth_token: ReadSignal<Option<String>>,
    set_auth_token: WriteSignal<Option<String>>,
    on_wizard_complete: Callback<()>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    // Wizard state from server
    let (wizard_state, set_wizard_state) = signal(Option::<WizardState>::None);
    let (loading, set_loading) = signal(true);
    let (error, set_error) = signal(Option::<String>::None);

    // Fetch wizard state
    let fetch_state = move || {
        let token = auth_token.get();
        spawn_local(async move {
            set_loading.set(true);
            set_error.set(None);

            if let Some(token) = token {
                match api::fetch_wizard_state(&token).await {
                    Ok(state) => {
                        if state.is_complete {
                            on_wizard_complete.run(());
                        } else {
                            set_wizard_state.set(Some(state));
                        }
                    }
                    Err(e) => {
                        if e.contains("Unauthorized") {
                            on_unauthorized.run(());
                        } else {
                            set_error.set(Some(e));
                        }
                    }
                }
            } else {
                // Not logged in - show welcome with login
                set_wizard_state.set(Some(WizardState::default()));
            }
            set_loading.set(false);
        });
    };

    // Fetch on mount and when token changes
    Effect::new(move || {
        let _ = auth_token.get(); // Track token changes
        fetch_state();
    });

    view! {
        <div class="min-h-screen bg-gray-900">
            // Loading state
            <Show when=move || loading.get()>
                <div class="flex items-center justify-center min-h-screen">
                    <div class="text-center">
                        <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
                        <p class="text-gray-400">"Loading wizard..."</p>
                    </div>
                </div>
            </Show>

            // Error state
            <Show when=move || error.get().is_some() && !loading.get()>
                <div class="flex items-center justify-center min-h-screen">
                    <div class="bg-red-900/50 border border-red-500 rounded-lg p-6 max-w-md">
                        <h2 class="text-xl font-semibold text-red-300 mb-2">"Error"</h2>
                        <p class="text-red-200">{move || error.get().unwrap_or_default()}</p>
                        <button
                            class="mt-4 bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded"
                            on:click=move |_| fetch_state()
                        >
                            "Retry"
                        </button>
                    </div>
                </div>
            </Show>

            // Wizard content
            <Show when=move || wizard_state.get().is_some() && !loading.get() && error.get().is_none()>
                {move || {
                    let state = wizard_state.get().unwrap();
                    let current_step = state.current_step;

                    view! {
                        <div class="max-w-4xl mx-auto p-8">
                            // Progress indicator
                            <WizardProgress current_step=current_step />

                            // Step content
                            {match current_step {
                                WizardStep::NotStarted => view! {
                                    <WelcomeStep
                                        auth_token=auth_token
                                        set_auth_token=set_auth_token
                                        on_advance=Callback::new(move |_| fetch_state())
                                        on_skip=Callback::new(move |_| on_wizard_complete.run(()))
                                        on_unauthorized=on_unauthorized
                                    />
                                }.into_any(),
                                WizardStep::PasswordChanged => view! {
                                    <PasswordStep
                                        auth_token=auth_token
                                        on_advance=Callback::new(move |_| fetch_state())
                                        on_unauthorized=on_unauthorized
                                    />
                                }.into_any(),
                                WizardStep::SystemChecksCompleted => view! {
                                    <SystemChecksStep
                                        auth_token=auth_token
                                        system_status=state.system_status.clone()
                                        on_advance=Callback::new(move |_| fetch_state())
                                        on_unauthorized=on_unauthorized
                                    />
                                }.into_any(),
                                WizardStep::InterfacesAssigned => view! {
                                    <InterfacesStep
                                        auth_token=auth_token
                                        on_advance=Callback::new(move |_| fetch_state())
                                        on_unauthorized=on_unauthorized
                                    />
                                }.into_any(),
                                WizardStep::Complete => view! {
                                    <CompleteStep
                                        on_finish=Callback::new(move |_| on_wizard_complete.run(()))
                                    />
                                }.into_any(),
                            }}
                        </div>
                    }
                }}
            </Show>
        </div>
    }
}

/// Progress indicator showing current step
#[component]
fn WizardProgress(current_step: WizardStep) -> impl IntoView {
    let steps = [
        (WizardStep::NotStarted, "Welcome"),
        (WizardStep::PasswordChanged, "Password"),
        (WizardStep::SystemChecksCompleted, "System Checks"),
        (WizardStep::InterfacesAssigned, "Interfaces"),
        (WizardStep::Complete, "Complete"),
    ];

    view! {
        <div class="mb-8">
            <div class="flex items-center justify-between">
                {steps.iter().enumerate().map(|(i, (step, name))| {
                    let is_current = *step == current_step;
                    let is_complete = (*step as u8) < (current_step as u8);
                    let is_last = i == steps.len() - 1;

                    view! {
                        <>
                            <div class="flex flex-col items-center">
                                <div class=move || format!(
                                    "w-10 h-10 rounded-full flex items-center justify-center text-sm font-medium {}",
                                    if is_complete {
                                        "bg-green-600 text-white"
                                    } else if is_current {
                                        "bg-blue-600 text-white"
                                    } else {
                                        "bg-gray-700 text-gray-400"
                                    }
                                )>
                                    {if is_complete {
                                        view! { <span>"✓"</span> }.into_any()
                                    } else {
                                        view! { <span>{i + 1}</span> }.into_any()
                                    }}
                                </div>
                                <span class=move || format!(
                                    "mt-2 text-xs {}",
                                    if is_current { "text-blue-400 font-medium" } else { "text-gray-500" }
                                )>
                                    {*name}
                                </span>
                            </div>
                            {if !is_last {
                                view! {
                                    <div class=move || format!(
                                        "flex-1 h-0.5 mx-2 {}",
                                        if is_complete { "bg-green-600" } else { "bg-gray-700" }
                                    )></div>
                                }.into_any()
                            } else {
                                view! { <></> }.into_any()
                            }}
                        </>
                    }
                }).collect_view()}
            </div>
        </div>
    }
}

/// Step 0: Welcome screen with login
#[component]
fn WelcomeStep(
    auth_token: ReadSignal<Option<String>>,
    set_auth_token: WriteSignal<Option<String>>,
    on_advance: Callback<()>,
    on_skip: Callback<()>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let (advancing, set_advancing) = signal(false);
    let (error, set_error) = signal(Option::<String>::None);
    let (show_skip_confirm, set_show_skip_confirm) = signal(false);

    // Handle advancing to next step
    let advance = move |_| {
        let token = match auth_token.get() {
            Some(t) => t,
            None => return,
        };

        set_advancing.set(true);
        set_error.set(None);

        spawn_local(async move {
            match api::advance_wizard(&token, WizardStep::NotStarted).await {
                Ok(response) => {
                    if response.success {
                        on_advance.run(());
                    } else {
                        set_error.set(Some(response.message));
                    }
                }
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        set_error.set(Some(e));
                    }
                }
            }
            set_advancing.set(false);
        });
    };

    // Handle skip
    let skip = move |_| {
        let token = match auth_token.get() {
            Some(t) => t,
            None => return,
        };

        spawn_local(async move {
            match api::skip_wizard(&token, true).await {
                Ok(response) => {
                    if response.success {
                        on_skip.run(());
                    } else {
                        set_error.set(Some(response.message));
                    }
                }
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        set_error.set(Some(e));
                    }
                }
            }
            set_show_skip_confirm.set(false);
        });
    };

    view! {
        <div class="bg-gray-800 rounded-lg p-8 shadow-xl">
            <div class="text-center mb-8">
                <h1 class="text-3xl font-bold text-blue-400 mb-4">"Welcome to Keystone"</h1>
                <p class="text-gray-300 text-lg">
                    "Keystone is a router and firewall manager for Arch Linux."
                </p>
                <p class="text-gray-400 mt-2">
                    "This wizard will help you configure your system for the first time."
                </p>
            </div>

            // Show login form if not authenticated
            <Show when=move || auth_token.get().is_none()>
                <div class="border-t border-gray-700 pt-6 mt-6">
                    <h2 class="text-xl font-semibold text-gray-200 mb-4 text-center">"Login to Continue"</h2>
                    <LoginForm set_auth_token=set_auth_token />
                </div>
            </Show>

            // Show continue button if authenticated
            <Show when=move || auth_token.get().is_some()>
                <div class="border-t border-gray-700 pt-6 mt-6">
                    <Show when=move || error.get().is_some()>
                        <div class="bg-red-900/50 border border-red-500 rounded p-4 mb-4 text-red-200">
                            {move || error.get().unwrap_or_default()}
                        </div>
                    </Show>

                    <div class="flex justify-between items-center">
                        <button
                            class="text-gray-400 hover:text-gray-300 text-sm underline"
                            on:click=move |_| set_show_skip_confirm.set(true)
                        >
                            "Skip wizard (advanced users)"
                        </button>
                        <button
                            class="bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 text-white px-8 py-3 rounded-lg font-medium text-lg"
                            disabled=move || advancing.get()
                            on:click=advance
                        >
                            {move || if advancing.get() { "Starting..." } else { "Start Setup" }}
                        </button>
                    </div>

                    // Skip confirmation dialog
                    <Show when=move || show_skip_confirm.get()>
                        <div class="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
                            <div class="bg-gray-800 rounded-lg p-6 max-w-md shadow-xl">
                                <h3 class="text-xl font-semibold text-yellow-400 mb-4">"Skip Wizard?"</h3>
                                <p class="text-gray-300 mb-6">
                                    "Skipping the wizard means you will need to configure interfaces, "
                                    "firewall zones, and other settings manually. This is only recommended "
                                    "for advanced users."
                                </p>
                                <div class="flex justify-end gap-4">
                                    <button
                                        class="bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded"
                                        on:click=move |_| set_show_skip_confirm.set(false)
                                    >
                                        "Cancel"
                                    </button>
                                    <button
                                        class="bg-yellow-600 hover:bg-yellow-700 text-white px-4 py-2 rounded"
                                        on:click=skip
                                    >
                                        "Skip Wizard"
                                    </button>
                                </div>
                            </div>
                        </div>
                    </Show>
                </div>
            </Show>

            // What the wizard will configure
            <div class="mt-8 grid grid-cols-1 md:grid-cols-2 gap-4">
                <div class="bg-gray-700/50 rounded-lg p-4">
                    <h3 class="text-blue-300 font-medium mb-2">"1. Secure Your Account"</h3>
                    <p class="text-gray-400 text-sm">"Change the default admin password"</p>
                </div>
                <div class="bg-gray-700/50 rounded-lg p-4">
                    <h3 class="text-blue-300 font-medium mb-2">"2. System Checks"</h3>
                    <p class="text-gray-400 text-sm">"Verify required packages and services"</p>
                </div>
                <div class="bg-gray-700/50 rounded-lg p-4">
                    <h3 class="text-blue-300 font-medium mb-2">"3. Configure Interfaces"</h3>
                    <p class="text-gray-400 text-sm">"Assign WAN and LAN roles to interfaces"</p>
                </div>
                <div class="bg-gray-700/50 rounded-lg p-4">
                    <h3 class="text-blue-300 font-medium mb-2">"4. Firewall Zones"</h3>
                    <p class="text-gray-400 text-sm">"Create basic firewall zones and policies"</p>
                </div>
            </div>
        </div>
    }
}

/// Inline login form for welcome step
#[component]
fn LoginForm(set_auth_token: WriteSignal<Option<String>>) -> impl IntoView {
    let (username, set_username) = signal(String::from("admin"));
    let (password, set_password) = signal(String::new());
    let (error, set_error) = signal(Option::<String>::None);
    let (loading, set_loading) = signal(false);

    let handle_submit = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();

        let username_val = username.get();
        let password_val = password.get();
        set_loading.set(true);
        set_error.set(None);

        spawn_local(async move {
            match api::login(&username_val, &password_val).await {
                Ok(response) => {
                    if response.success {
                        if let Some(token) = &response.token {
                            set_stored_token(token);
                            set_auth_token.set(Some(token.clone()));
                        }
                    } else {
                        set_error.set(Some(response.message));
                    }
                }
                Err(e) => {
                    set_error.set(Some(format!("Login failed: {}", e)));
                }
            }
            set_loading.set(false);
        });
    };

    view! {
        <form on:submit=handle_submit class="max-w-sm mx-auto">
            <div class="mb-4">
                <label class="block text-gray-300 mb-2 text-sm">"Username"</label>
                <input
                    type="text"
                    prop:value=move || username.get()
                    on:input=move |ev| set_username.set(event_target_value(&ev))
                    class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded focus:outline-none focus:border-blue-500 text-white"
                    disabled=move || loading.get()
                />
            </div>
            <div class="mb-4">
                <label class="block text-gray-300 mb-2 text-sm">"Password"</label>
                <input
                    type="password"
                    prop:value=move || password.get()
                    on:input=move |ev| set_password.set(event_target_value(&ev))
                    class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded focus:outline-none focus:border-blue-500 text-white"
                    disabled=move || loading.get()
                />
            </div>
            <Show when=move || error.get().is_some()>
                <div class="mb-4 p-3 bg-red-900/50 border border-red-500 rounded text-red-200 text-sm">
                    {move || error.get().unwrap_or_default()}
                </div>
            </Show>
            <button
                type="submit"
                class="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 text-white py-2 rounded"
                disabled=move || loading.get()
            >
                {move || if loading.get() { "Logging in..." } else { "Login" }}
            </button>
            <p class="text-center text-gray-500 text-xs mt-2">
                "Default: admin / admin"
            </p>
        </form>
    }
}

/// Step 1: Password change
#[component]
fn PasswordStep(
    auth_token: ReadSignal<Option<String>>,
    on_advance: Callback<()>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let (new_password, set_new_password) = signal(String::new());
    let (confirm_password, set_confirm_password) = signal(String::new());
    let (saving, set_saving) = signal(false);
    let (error, set_error) = signal(Option::<String>::None);

    let passwords_match = move || {
        let pw = new_password.get();
        let confirm = confirm_password.get();
        !pw.is_empty() && pw == confirm
    };

    let password_valid = move || {
        let pw = new_password.get();
        pw.len() >= 8
    };

    let can_submit = move || passwords_match() && password_valid();

    let handle_submit = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();

        if !can_submit() {
            return;
        }

        let token = match auth_token.get() {
            Some(t) => t,
            None => {
                on_unauthorized.run(());
                return;
            }
        };

        let password = new_password.get();
        set_saving.set(true);
        set_error.set(None);

        spawn_local(async move {
            // First, save the new password for the admin user
            let request = SaveUserRequest {
                id: Some(1), // Admin user is always ID 1
                username: "admin".to_string(),
                email: None,
                password: Some(password),
            };

            match api::save_user(&token, request).await {
                Ok(response) => {
                    if response.success {
                        // Now advance the wizard
                        match api::advance_wizard(&token, WizardStep::NotStarted).await {
                            Ok(advance_response) => {
                                if advance_response.success {
                                    on_advance.run(());
                                } else {
                                    set_error.set(Some(advance_response.message));
                                }
                            }
                            Err(e) => {
                                if e.contains("Unauthorized") {
                                    on_unauthorized.run(());
                                } else {
                                    set_error.set(Some(e));
                                }
                            }
                        }
                    } else {
                        set_error.set(Some(response.message));
                    }
                }
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        set_error.set(Some(e));
                    }
                }
            }
            set_saving.set(false);
        });
    };

    view! {
        <div class="bg-gray-800 rounded-lg p-8 shadow-xl">
            <h2 class="text-2xl font-bold text-blue-400 mb-2">"Change Default Password"</h2>
            <p class="text-gray-400 mb-6">
                "For security, you must change the default admin password before continuing."
            </p>

            <form on:submit=handle_submit class="max-w-md">
                <div class="mb-4">
                    <label class="block text-gray-300 mb-2">"New Password"</label>
                    <input
                        type="password"
                        prop:value=move || new_password.get()
                        on:input=move |ev| set_new_password.set(event_target_value(&ev))
                        class="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded focus:outline-none focus:border-blue-500 text-white"
                        placeholder="At least 8 characters"
                        disabled=move || saving.get()
                    />
                    <Show when=move || !new_password.get().is_empty() && !password_valid()>
                        <p class="text-red-400 text-sm mt-1">"Password must be at least 8 characters"</p>
                    </Show>
                </div>

                <div class="mb-6">
                    <label class="block text-gray-300 mb-2">"Confirm Password"</label>
                    <input
                        type="password"
                        prop:value=move || confirm_password.get()
                        on:input=move |ev| set_confirm_password.set(event_target_value(&ev))
                        class="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded focus:outline-none focus:border-blue-500 text-white"
                        placeholder="Re-enter your password"
                        disabled=move || saving.get()
                    />
                    <Show when=move || !confirm_password.get().is_empty() && !passwords_match()>
                        <p class="text-red-400 text-sm mt-1">"Passwords do not match"</p>
                    </Show>
                </div>

                <Show when=move || error.get().is_some()>
                    <div class="mb-4 p-3 bg-red-900/50 border border-red-500 rounded text-red-200">
                        {move || error.get().unwrap_or_default()}
                    </div>
                </Show>

                <button
                    type="submit"
                    class="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white px-6 py-3 rounded font-medium w-full"
                    disabled=move || !can_submit() || saving.get()
                >
                    {move || if saving.get() { "Saving..." } else { "Save Password & Continue" }}
                </button>
            </form>
        </div>
    }
}

/// Step 2: System checks
#[component]
fn SystemChecksStep(
    auth_token: ReadSignal<Option<String>>,
    system_status: Option<SystemStatusResponse>,
    on_advance: Callback<()>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let (status, set_status) = signal(system_status);
    let (loading, set_loading) = signal(false);
    let (advancing, set_advancing) = signal(false);
    let (error, set_error) = signal(Option::<String>::None);

    let all_pass = move || status.get().map(|s| s.all_checks_pass).unwrap_or(false);

    // Refresh checks
    let refresh = move |_| {
        spawn_local(async move {
            set_loading.set(true);
            match api::fetch_system_status().await {
                Ok(s) => set_status.set(Some(s)),
                Err(e) => set_error.set(Some(e)),
            }
            set_loading.set(false);
        });
    };

    // Advance to next step
    let advance = move |_| {
        let token = match auth_token.get() {
            Some(t) => t,
            None => {
                on_unauthorized.run(());
                return;
            }
        };

        set_advancing.set(true);
        set_error.set(None);

        spawn_local(async move {
            match api::advance_wizard(&token, WizardStep::PasswordChanged).await {
                Ok(response) => {
                    if response.success {
                        on_advance.run(());
                    } else {
                        set_error.set(Some(response.message));
                    }
                }
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        set_error.set(Some(e));
                    }
                }
            }
            set_advancing.set(false);
        });
    };

    view! {
        <div class="bg-gray-800 rounded-lg p-8 shadow-xl">
            <div class="flex items-center justify-between mb-6">
                <div>
                    <h2 class="text-2xl font-bold text-blue-400">"System Requirements"</h2>
                    <p class="text-gray-400">
                        "Verifying that all required packages and services are available."
                    </p>
                </div>
                <button
                    class="bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded"
                    disabled=move || loading.get()
                    on:click=refresh
                >
                    {move || if loading.get() { "Checking..." } else { "Refresh" }}
                </button>
            </div>

            // Summary
            <Show when=move || status.get().is_some()>
                {move || {
                    let s = status.get().unwrap();
                    let summary_class = if s.all_checks_pass {
                        "bg-green-900/30 border-green-500"
                    } else {
                        "bg-red-900/30 border-red-500"
                    };

                    view! {
                        <div class=format!("rounded-lg p-4 mb-6 border {}", summary_class)>
                            <div class="flex items-center gap-3">
                                {if s.all_checks_pass {
                                    view! { <span class="text-green-500 text-2xl">"✓"</span> }.into_any()
                                } else {
                                    view! { <span class="text-red-500 text-2xl">"✗"</span> }.into_any()
                                }}
                                <div>
                                    <h3 class="text-lg font-semibold text-white">
                                        {if s.all_checks_pass { "All Checks Passed" } else { "Issues Found" }}
                                    </h3>
                                    <p class="text-gray-400">
                                        {format!("{} errors, {} warnings", s.error_count, s.warning_count)}
                                    </p>
                                </div>
                            </div>
                        </div>
                    }
                }}
            </Show>

            // Check categories
            <Show when=move || status.get().is_some()>
                {move || {
                    let s = status.get().unwrap();
                    let package_checks: Vec<_> = s.checks.iter()
                        .filter(|c| c.category == CheckCategory::Package)
                        .cloned()
                        .collect();
                    let service_checks: Vec<_> = s.checks.iter()
                        .filter(|c| c.category == CheckCategory::Service)
                        .cloned()
                        .collect();

                    view! {
                        <div class="space-y-4 max-h-96 overflow-y-auto">
                            <CheckCategorySection title="Required Packages" checks=package_checks />
                            <CheckCategorySection title="System Services" checks=service_checks />
                        </div>
                    }
                }}
            </Show>

            // Error
            <Show when=move || error.get().is_some()>
                <div class="mt-4 p-3 bg-red-900/50 border border-red-500 rounded text-red-200">
                    {move || error.get().unwrap_or_default()}
                </div>
            </Show>

            // Continue button
            <div class="mt-6 flex justify-end">
                <button
                    class="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white px-6 py-3 rounded font-medium"
                    disabled=move || !all_pass() || advancing.get()
                    on:click=advance
                >
                    {move || if advancing.get() { "Continuing..." } else { "Continue" }}
                </button>
            </div>

            <Show when=move || !all_pass()>
                <p class="text-yellow-400 text-sm mt-2 text-right">
                    "Please resolve all errors before continuing"
                </p>
            </Show>
        </div>
    }
}

/// Reusable check category section
#[component]
fn CheckCategorySection(title: &'static str, checks: Vec<SystemCheck>) -> impl IntoView {
    if checks.is_empty() {
        return view! { <></> }.into_any();
    }

    view! {
        <div class="bg-gray-700/50 rounded-lg p-4">
            <h3 class="text-lg font-medium text-gray-200 mb-3">{title}</h3>
            <div class="space-y-2">
                <For
                    each=move || checks.clone()
                    key=|check| check.id.clone()
                    children=move |check| {
                        let icon = match check.severity {
                            CheckSeverity::Pass => ("✓", "text-green-500"),
                            CheckSeverity::Warning => ("⚠", "text-yellow-500"),
                            CheckSeverity::Error => ("✗", "text-red-500"),
                        };
                        let fix_advice = check.fix_advice.clone();

                        view! {
                            <div class="flex items-start gap-3 py-2">
                                <span class=format!("text-lg {}", icon.1)>{icon.0}</span>
                                <div class="flex-1">
                                    <div class="text-gray-200">{check.name.clone()}</div>
                                    <div class="text-gray-400 text-sm">{check.message.clone()}</div>
                                    {fix_advice.map(|advice| view! {
                                        <code class="text-blue-300 text-xs mt-1 block">{advice}</code>
                                    })}
                                </div>
                            </div>
                        }
                    }
                />
            </div>
        </div>
    }.into_any()
}

/// Step 3: Interface assignment
#[component]
fn InterfacesStep(
    auth_token: ReadSignal<Option<String>>,
    on_advance: Callback<()>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    // Interface assignments: name -> (role, use_dhcp, static_ip)
    let (assignments, set_assignments) =
        signal::<Vec<(String, Option<InterfaceRole>, bool, String)>>(vec![]);
    let (interfaces, set_interfaces) = signal::<Vec<keystone_core::Interface>>(vec![]);
    let (loading, set_loading) = signal(true);
    let (saving, set_saving) = signal(false);
    let (error, set_error) = signal(Option::<String>::None);

    // Load interfaces
    Effect::new(move || {
        spawn_local(async move {
            match api::fetch_dashboard(&auth_token.get().unwrap_or_default()).await {
                Ok(dashboard) => {
                    let ifaces = dashboard.state.interfaces.clone();
                    // Initialize assignments with default values
                    let initial: Vec<_> = ifaces
                        .iter()
                        .map(|i| (i.name.clone(), None, true, String::new()))
                        .collect();
                    set_interfaces.set(ifaces);
                    set_assignments.set(initial);
                }
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        set_error.set(Some(e));
                    }
                }
            }
            set_loading.set(false);
        });
    });

    // Count WAN and LAN assignments
    let wan_count = move || {
        assignments
            .get()
            .iter()
            .filter(|(_, role, _, _)| *role == Some(InterfaceRole::WAN))
            .count()
    };
    let lan_count = move || {
        assignments
            .get()
            .iter()
            .filter(|(_, role, _, _)| *role == Some(InterfaceRole::LAN))
            .count()
    };

    let can_continue = move || wan_count() >= 1 && lan_count() >= 1;

    // Update assignment
    let update_role = move |name: String, role: Option<InterfaceRole>| {
        set_assignments.update(|a| {
            if let Some(entry) = a.iter_mut().find(|(n, _, _, _)| n == &name) {
                entry.1 = role;
            }
        });
    };

    let update_dhcp = move |name: String, use_dhcp: bool| {
        set_assignments.update(|a| {
            if let Some(entry) = a.iter_mut().find(|(n, _, _, _)| n == &name) {
                entry.2 = use_dhcp;
            }
        });
    };

    let update_ip = move |name: String, ip: String| {
        set_assignments.update(|a| {
            if let Some(entry) = a.iter_mut().find(|(n, _, _, _)| n == &name) {
                entry.3 = ip;
            }
        });
    };

    // Save and advance
    let save_and_continue = move |_| {
        let token = match auth_token.get() {
            Some(t) => t,
            None => {
                on_unauthorized.run(());
                return;
            }
        };

        let current_assignments = assignments.get();
        let wizard_assignments: Vec<WizardInterfaceAssignment> = current_assignments
            .iter()
            .filter_map(|(name, role, use_dhcp, static_ip)| {
                role.map(|r| WizardInterfaceAssignment {
                    name: name.clone(),
                    role: r,
                    use_dhcp: *use_dhcp,
                    static_ip: if static_ip.is_empty() {
                        None
                    } else {
                        Some(static_ip.clone())
                    },
                })
            })
            .collect();

        set_saving.set(true);
        set_error.set(None);

        spawn_local(async move {
            // First save interface assignments
            let request = WizardSaveInterfacesRequest {
                assignments: wizard_assignments,
            };

            match api::save_wizard_interfaces(&token, request).await {
                Ok(response) => {
                    if response.success {
                        // Now advance the wizard
                        match api::advance_wizard(&token, WizardStep::SystemChecksCompleted).await {
                            Ok(advance_response) => {
                                if advance_response.success {
                                    on_advance.run(());
                                } else {
                                    set_error.set(Some(advance_response.message));
                                }
                            }
                            Err(e) => {
                                if e.contains("Unauthorized") {
                                    on_unauthorized.run(());
                                } else {
                                    set_error.set(Some(e));
                                }
                            }
                        }
                    } else {
                        set_error.set(Some(response.message));
                    }
                }
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        set_error.set(Some(e));
                    }
                }
            }
            set_saving.set(false);
        });
    };

    view! {
        <div class="bg-gray-800 rounded-lg p-8 shadow-xl">
            <h2 class="text-2xl font-bold text-blue-400 mb-2">"Configure Network Interfaces"</h2>
            <p class="text-gray-400 mb-6">
                "Assign each interface a role. WAN interfaces connect to the internet, "
                "LAN interfaces connect to your local network."
            </p>

            // Requirements
            <div class="flex gap-4 mb-6">
                <div class=move || format!(
                    "px-4 py-2 rounded {}",
                    if wan_count() >= 1 { "bg-green-900/30 border border-green-600" } else { "bg-gray-700" }
                )>
                    <span class="text-gray-300">"WAN: "</span>
                    <span class={move || if wan_count() >= 1 { "text-green-400" } else { "text-gray-400" }}>
                        {move || wan_count()}
                    </span>
                    <span class="text-gray-500">" (need 1+)"</span>
                </div>
                <div class=move || format!(
                    "px-4 py-2 rounded {}",
                    if lan_count() >= 1 { "bg-green-900/30 border border-green-600" } else { "bg-gray-700" }
                )>
                    <span class="text-gray-300">"LAN: "</span>
                    <span class={move || if lan_count() >= 1 { "text-green-400" } else { "text-gray-400" }}>
                        {move || lan_count()}
                    </span>
                    <span class="text-gray-500">" (need 1+)"</span>
                </div>
            </div>

            <Show
                when=move || !loading.get()
                fallback=|| view! { <div class="text-gray-400">"Loading interfaces..."</div> }
            >
                <div class="space-y-4 max-h-96 overflow-y-auto">
                    <For
                        each=move || {
                            let ifaces = interfaces.get();
                            let assigns = assignments.get();
                            ifaces.into_iter().zip(assigns.into_iter()).collect::<Vec<_>>()
                        }
                        key=|(iface, _)| iface.name.clone()
                        children=move |(iface, (name, role, use_dhcp, static_ip))| {
                            let name1 = name.clone();
                            let name2 = name.clone();
                            let name3 = name.clone();
                            let name4 = name.clone();
                            let name5 = name.clone();
                            let name6 = name.clone();
                            let address = iface.address.clone().unwrap_or_else(|| "No IP".to_string());
                            let current_role = role;
                            let current_dhcp = use_dhcp;
                            let current_ip = static_ip.clone();

                            view! {
                                <div class="bg-gray-700 rounded-lg p-4">
                                    <div class="flex items-center justify-between mb-3">
                                        <div>
                                            <div class="font-medium text-white">{name.clone()}</div>
                                            <div class="text-sm text-gray-400">{address}</div>
                                        </div>
                                        <select
                                            class="bg-gray-600 text-white rounded px-3 py-2 border border-gray-500"
                                            on:change=move |ev| {
                                                let value = event_target_value(&ev);
                                                let role = match value.as_str() {
                                                    "wan" => Some(InterfaceRole::WAN),
                                                    "lan" => Some(InterfaceRole::LAN),
                                                    _ => None,
                                                };
                                                update_role(name1.clone(), role);
                                            }
                                        >
                                            <option value="" selected=move || current_role.is_none()>
                                                "Not managed"
                                            </option>
                                            <option value="wan" selected=move || current_role == Some(InterfaceRole::WAN)>
                                                "WAN (Internet)"
                                            </option>
                                            <option value="lan" selected=move || current_role == Some(InterfaceRole::LAN)>
                                                "LAN (Local)"
                                            </option>
                                        </select>
                                    </div>

                                    // Show IP configuration if WAN
                                    <Show when=move || current_role == Some(InterfaceRole::WAN)>
                                        {
                                            let name3_inner = name3.clone();
                                            let name5_inner = name5.clone();
                                            view! {
                                                <div class="border-t border-gray-600 pt-3 mt-3">
                                                    <div class="flex items-center gap-4">
                                                        <label class="flex items-center gap-2 text-gray-300">
                                                            <input
                                                                type="radio"
                                                                name=format!("{}-ip-mode", name2)
                                                                checked=move || current_dhcp
                                                                on:change=move |_| update_dhcp(name3_inner.clone(), true)
                                                                class="text-blue-500"
                                                            />
                                                            "DHCP"
                                                        </label>
                                                        <label class="flex items-center gap-2 text-gray-300">
                                                            <input
                                                                type="radio"
                                                                name=format!("{}-ip-mode", name4)
                                                                checked=move || !current_dhcp
                                                                on:change=move |_| update_dhcp(name5_inner.clone(), false)
                                                                class="text-blue-500"
                                                            />
                                                            "Static IP"
                                                        </label>
                                                    </div>
                                                </div>
                                            }
                                        }
                                    </Show>

                                    // Show static IP input for LAN
                                    <Show when=move || current_role == Some(InterfaceRole::LAN)>
                                        {
                                            let name6_inner = name6.clone();
                                            let current_ip_inner = current_ip.clone();
                                            view! {
                                                <div class="border-t border-gray-600 pt-3 mt-3">
                                                    <label class="block text-gray-300 text-sm mb-1">"Static IP (CIDR)"</label>
                                                    <input
                                                        type="text"
                                                        placeholder="e.g., 192.168.1.1/24"
                                                        prop:value=current_ip_inner
                                                        on:input=move |ev| update_ip(name6_inner.clone(), event_target_value(&ev))
                                                        class="w-full px-3 py-2 bg-gray-600 border border-gray-500 rounded text-white"
                                                    />
                                                </div>
                                            }
                                        }
                                    </Show>
                                </div>
                            }
                        }
                    />
                </div>
            </Show>

            // Error
            <Show when=move || error.get().is_some()>
                <div class="mt-4 p-3 bg-red-900/50 border border-red-500 rounded text-red-200">
                    {move || error.get().unwrap_or_default()}
                </div>
            </Show>

            // Continue button
            <div class="mt-6 flex justify-end">
                <button
                    class="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white px-6 py-3 rounded font-medium"
                    disabled=move || !can_continue() || saving.get()
                    on:click=save_and_continue
                >
                    {move || if saving.get() { "Saving..." } else { "Save & Continue" }}
                </button>
            </div>

            <Show when=move || !can_continue()>
                <p class="text-yellow-400 text-sm mt-2 text-right">
                    "Select at least one WAN and one LAN interface"
                </p>
            </Show>
        </div>
    }
}

/// Step 4: Complete
#[component]
fn CompleteStep(on_finish: Callback<()>) -> impl IntoView {
    view! {
        <div class="bg-gray-800 rounded-lg p-8 shadow-xl text-center">
            <div class="text-6xl mb-6">"🎉"</div>
            <h2 class="text-3xl font-bold text-green-400 mb-4">"Setup Complete!"</h2>
            <p class="text-gray-300 text-lg mb-6">
                "Your Keystone router is now configured and ready to use."
            </p>

            <div class="bg-gray-700/50 rounded-lg p-6 mb-8 text-left max-w-md mx-auto">
                <h3 class="text-lg font-medium text-gray-200 mb-3">"What's been configured:"</h3>
                <ul class="space-y-2 text-gray-400">
                    <li class="flex items-center gap-2">
                        <span class="text-green-500">"✓"</span>
                        "Admin password changed"
                    </li>
                    <li class="flex items-center gap-2">
                        <span class="text-green-500">"✓"</span>
                        "System requirements verified"
                    </li>
                    <li class="flex items-center gap-2">
                        <span class="text-green-500">"✓"</span>
                        "WAN and LAN interfaces configured"
                    </li>
                    <li class="flex items-center gap-2">
                        <span class="text-green-500">"✓"</span>
                        "Firewall zones created (wan, lan)"
                    </li>
                    <li class="flex items-center gap-2">
                        <span class="text-green-500">"✓"</span>
                        "LAN to WAN forwarding enabled"
                    </li>
                </ul>
            </div>

            <div class="space-y-4">
                <button
                    class="bg-green-600 hover:bg-green-700 text-white px-8 py-3 rounded-lg font-medium text-lg"
                    on:click=move |_| on_finish.run(())
                >
                    "Go to Dashboard"
                </button>
                <p class="text-gray-500 text-sm">
                    "You can adjust settings anytime from the Settings page."
                </p>
            </div>
        </div>
    }
}
