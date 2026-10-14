//! System status check page
//!
//! Displayed on first launch to ensure all required packages and services are available.
//! Redirects all routes to this page until setup is complete.

use keystone_core::{CheckCategory, CheckSeverity, SystemCheck, SystemStatusResponse};
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::api;

#[component]
pub fn StatusPage(
    auth_token: ReadSignal<Option<String>>,
    on_setup_complete: Callback<()>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let (status, set_status) = signal(Option::<SystemStatusResponse>::None);
    let (loading, set_loading) = signal(true);
    let (error_msg, set_error_msg) = signal(Option::<String>::None);
    let (completing, set_completing) = signal(false);

    // Load status on mount
    let fetch_status = move || {
        spawn_local(async move {
            set_loading.set(true);
            set_error_msg.set(None);
            match api::fetch_system_status().await {
                Ok(s) => {
                    set_status.set(Some(s));
                }
                Err(e) => {
                    set_error_msg.set(Some(format!("Failed to fetch status: {}", e)));
                }
            }
            set_loading.set(false);
        });
    };

    // Initial fetch
    Effect::new(move || {
        fetch_status();
    });

    let complete_setup = move |_| {
        let token = match auth_token.get() {
            Some(t) => t,
            None => {
                set_error_msg.set(Some("Please login first".to_string()));
                return;
            }
        };

        set_completing.set(true);
        spawn_local(async move {
            match api::complete_setup(&token).await {
                Ok(response) => {
                    if response.success {
                        on_setup_complete.run(());
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
            set_completing.set(false);
        });
    };

    let refresh_status = move |_| {
        fetch_status();
    };

    view! {
        <div class="min-h-screen bg-gray-900 p-8">
            <div class="max-w-4xl mx-auto">
                <div class="text-center mb-8">
                    <h1 class="text-3xl font-bold text-blue-300 mb-2">"Keystone System Status"</h1>
                </div>

                <Show when=move || loading.get()>
                    <div class="bg-gray-800 rounded-lg p-8 text-center">
                        <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
                        <p class="text-gray-400">"Running system checks..."</p>
                    </div>
                </Show>

                <Show when=move || error_msg.get().is_some()>
                    <div class="bg-red-900/50 border border-red-500 rounded-lg p-4 text-red-200 mb-6">
                        {move || error_msg.get().unwrap_or_default()}
                    </div>
                </Show>

                <Show when=move || !loading.get() && status.get().is_some()>
                    {move || {
                        let s = status.get().unwrap();
                        view! {
                            <div>
                                // Summary card
                                <div class=move || format!(
                                    "rounded-lg p-6 mb-6 {}",
                                    if s.all_checks_pass && s.warning_count > 0 {
                                        "bg-yellow-900/30 border border-yellow-500"
                                    } else if s.all_checks_pass {
                                        "bg-green-900/30 border border-green-500"
                                    } else {
                                        "bg-red-900/30 border border-red-500"
                                    }
                                )>
                                    <div class="flex items-center justify-between">
                                        <div>
                                            <h2 class="text-xl font-semibold text-white mb-1">
                                                {if s.all_checks_pass && s.warning_count > 0 {
                                                    "Passed with Warnings"
                                                } else if s.all_checks_pass {
                                                    "All Checks Passed"
                                                } else {
                                                    "Issues Found"
                                                }}
                                            </h2>
                                            <p class="text-gray-400">
                                                {format!(
                                                    "{} errors, {} warnings",
                                                    s.error_count,
                                                    s.warning_count
                                                )}
                                            </p>
                                        </div>
                                        <div class="flex gap-4">
                                            <button
                                                on:click=refresh_status
                                                class="bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded"
                                            >
                                                "Refresh"
                                            </button>
                                            <Show when=move || s.all_checks_pass && auth_token.get().is_some()>
                                                <button
                                                    on:click=complete_setup
                                                    disabled=move || completing.get()
                                                    class="bg-green-600 hover:bg-green-700 disabled:bg-green-800 disabled:cursor-not-allowed text-white px-6 py-2 rounded font-semibold"
                                                >
                                                    {move || if completing.get() { "Completing..." } else { "Continue Setup" }}
                                                </button>
                                            </Show>
                                        </div>
                                    </div>
                                </div>

                                // Login reminder if not authenticated
                                <Show when=move || auth_token.get().is_none()>
                                    <div class="bg-yellow-900/30 border border-yellow-500 rounded-lg p-4 mb-6">
                                        <p class="text-yellow-200">
                                            "Please "
                                            <a href="/" class="underline hover:text-yellow-100">"login"</a>
                                            " to continue setup after all checks pass."
                                        </p>
                                    </div>
                                </Show>

                                // Group checks by category
                                {
                                    let package_checks: Vec<_> = s.checks.iter()
                                        .filter(|c| c.category == CheckCategory::Package)
                                        .cloned()
                                        .collect();
                                    let service_checks: Vec<_> = s.checks.iter()
                                        .filter(|c| c.category == CheckCategory::Service)
                                        .cloned()
                                        .collect();
                                    let permission_checks: Vec<_> = s.checks.iter()
                                        .filter(|c| c.category == CheckCategory::Permission)
                                        .cloned()
                                        .collect();
                                    let network_checks: Vec<_> = s.checks.iter()
                                        .filter(|c| c.category == CheckCategory::Network)
                                        .cloned()
                                        .collect();
                                    let config_checks: Vec<_> = s.checks.iter()
                                        .filter(|c| c.category == CheckCategory::Configuration)
                                        .cloned()
                                        .collect();

                                    view! {
                                        <>
                                            <CheckCategorySection
                                                title="Required Packages"
                                                checks=package_checks
                                            />

                                            <CheckCategorySection
                                                title="System Services"
                                                checks=service_checks
                                            />

                                            <CheckCategorySection
                                                title="File Permissions"
                                                checks=permission_checks
                                            />

                                            <CheckCategorySection
                                                title="Network Configuration"
                                                checks=network_checks
                                            />

                                            <CheckCategorySection
                                                title="System Configuration"
                                                checks=config_checks
                                            />
                                        </>
                                    }
                                }
                            </div>
                        }
                    }}
                </Show>
            </div>
        </div>
    }
}

#[component]
fn CheckCategorySection(title: &'static str, checks: Vec<SystemCheck>) -> impl IntoView {
    if checks.is_empty() {
        return view! { <div></div> }.into_any();
    }

    view! {
        <div class="bg-gray-800 rounded-lg p-6 mb-6">
            <h3 class="text-lg font-semibold text-white mb-4">{title}</h3>
            <div class="space-y-3">
                <For
                    each=move || checks.clone()
                    key=|check| check.id.clone()
                    children=move |check| {
                        view! { <CheckItem check=check /> }
                    }
                />
            </div>
        </div>
    }
    .into_any()
}

#[component]
fn CheckItem(check: SystemCheck) -> impl IntoView {
    let severity_icon = match check.severity {
        CheckSeverity::Pass => view! {
            <span class="text-green-500 text-xl" title="Pass">"✓"</span>
        }
        .into_any(),
        CheckSeverity::Warning => view! {
            <span class="text-yellow-500 text-xl" title="Warning">"⚠"</span>
        }
        .into_any(),
        CheckSeverity::Error => view! {
            <span class="text-red-500 text-xl" title="Error">"✗"</span>
        }
        .into_any(),
    };

    let bg_class = match check.severity {
        CheckSeverity::Pass => "bg-gray-700/50",
        CheckSeverity::Warning => "bg-yellow-900/20 border border-yellow-700",
        CheckSeverity::Error => "bg-red-900/20 border border-red-700",
    };

    // Clone fix_advice for use in closures
    let fix_advice = check.fix_advice.clone();
    let has_fix_advice = fix_advice.is_some();
    let fix_advice_text = fix_advice.unwrap_or_default();

    view! {
        <div class=format!("rounded p-4 {}", bg_class)>
            <div class="flex items-start gap-3">
                <div class="flex-shrink-0 mt-0.5">
                    {severity_icon}
                </div>
                <div class="flex-1">
                    <div class="flex items-center gap-2">
                        <h4 class="font-medium text-white">{check.name.clone()}</h4>
                    </div>
                    <p class="text-sm text-gray-400 mt-1">{check.message.clone()}</p>
                    <Show when=move || has_fix_advice>
                        <div class="mt-2 p-2 bg-gray-800 rounded text-sm">
                            <span class="text-gray-500">"Fix: "</span>
                            <span class="text-blue-300 break-words">{fix_advice_text.clone()}</span>
                        </div>
                    </Show>
                </div>
            </div>
        </div>
    }
}
