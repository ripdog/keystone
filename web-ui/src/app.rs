//! Keystone Web UI - Leptos Frontend (WASM)
//!
//! This module contains the Leptos components that compile to WASM
//! and run in the browser as a Single Page Application.

use crate::api;
use crate::components::{AppLayout, LoginPage, clear_stored_token, get_stored_token};
use crate::pages::{
    BridgesPage, CaddyPage, DashboardPage, DnsmasqPage, FirewallPage, InterfaceEditPage,
    InterfacesPage, NetworkdPreviewPage, ServiceDetailPage, ServicesPage, SettingsPage, StatusPage,
    VlansPage,
};
use keystone_core::SystemState;
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::{
    components::{Route, Router, Routes},
    path,
};

/// Represents the current setup state of the application
#[derive(Clone, Copy, PartialEq)]
enum SetupState {
    /// Still checking if setup is complete
    Loading,
    /// Setup is not complete, show status page
    NeedsSetup,
    /// Setup is complete, show normal UI
    Complete,
}

#[component]
pub fn App() -> impl IntoView {
    let (auth_token, set_auth_token) = signal(get_stored_token());
    let (state, set_state) = signal(SystemState::default());
    let (setup_state, set_setup_state) = signal(SetupState::Loading);

    let logout = Callback::new(move |()| {
        clear_stored_token();
        set_auth_token.set(None);
    });

    let on_unauthorized = Callback::new(move |()| {
        clear_stored_token();
        set_auth_token.set(None);
    });

    // Check setup status on mount
    Effect::new(move || {
        spawn_local(async move {
            match api::fetch_system_status().await {
                Ok(status) => {
                    if status.setup_complete {
                        set_setup_state.set(SetupState::Complete);
                    } else {
                        set_setup_state.set(SetupState::NeedsSetup);
                    }
                }
                Err(_) => {
                    // If we can't reach the daemon, show status page to display errors
                    set_setup_state.set(SetupState::NeedsSetup);
                }
            }
        });
    });

    // Callback when setup is marked complete
    let on_setup_complete = Callback::new(move |()| {
        set_setup_state.set(SetupState::Complete);
    });

    view! {
        <Router>
            // Show loading state while checking setup status
            <Show when=move || setup_state.get() == SetupState::Loading>
                <div class="min-h-screen bg-gray-900 flex items-center justify-center">
                    <div class="text-center">
                        <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
                        <p class="text-gray-400">"Checking system status..."</p>
                    </div>
                </div>
            </Show>

            // Show status page when setup is not complete
            <Show when=move || setup_state.get() == SetupState::NeedsSetup>
                <Show
                    when=move || auth_token.get().is_some()
                    fallback=move || view! {
                        // Show login or status page for unauthenticated users
                        <StatusPage
                            auth_token=auth_token
                            on_setup_complete=on_setup_complete
                            on_unauthorized=on_unauthorized
                        />
                    }
                >
                    <StatusPage
                        auth_token=auth_token
                        on_setup_complete=on_setup_complete
                        on_unauthorized=on_unauthorized
                    />
                </Show>
            </Show>

            // Show normal app when setup is complete
            <Show when=move || setup_state.get() == SetupState::Complete>
                <Show
                    when=move || auth_token.get().is_some()
                    fallback=move || view! { <LoginPage on_login=set_auth_token/> }
                >
                    <AppLayout auth_token=auth_token on_logout=logout on_unauthorized=on_unauthorized>
                        <Routes fallback=|| "Page not found">
                            <Route
                                path=path!("/")
                                view=move || view! {
                                    <DashboardPage
                                        auth_token=auth_token
                                        state=state
                                        set_state=set_state
                                        on_unauthorized=on_unauthorized
                                    />
                                }
                            />
                            <Route
                                path=path!("/interfaces")
                                view=move || view! {
                                    <InterfacesPage
                                        auth_token=auth_token
                                        state=state
                                        on_unauthorized=on_unauthorized
                                    />
                                }
                            />
                            <Route
                                path=path!("/interfaces/:name")
                                view=move || view! {
                                    <InterfaceEditPage
                                        auth_token=auth_token
                                        on_unauthorized=on_unauthorized
                                    />
                                }
                            />
                            <Route
                                path=path!("/firewall")
                                view=move || view! {
                                    <FirewallPage
                                        auth_token=auth_token
                                        on_unauthorized=on_unauthorized
                                    />
                                }
                            />
                            <Route
                                path=path!("/vlans")
                                view=move || view! {
                                    <VlansPage
                                        auth_token=auth_token
                                        on_unauthorized=on_unauthorized
                                    />
                                }
                            />
                            <Route
                                path=path!("/bridges")
                                view=move || view! {
                                    <BridgesPage
                                        auth_token=auth_token
                                        on_unauthorized=on_unauthorized
                                    />
                                }
                            />
                            <Route
                                path=path!("/dnsmasq")
                                view=move || view! {
                                    <DnsmasqPage
                                        auth_token=auth_token
                                        on_unauthorized=on_unauthorized
                                    />
                                }
                            />
                            <Route
                                path=path!("/caddy")
                                view=move || view! {
                                    <CaddyPage
                                        auth_token=auth_token
                                        on_unauthorized=on_unauthorized
                                    />
                                }
                            />
                            <Route
                                path=path!("/networkd-preview")
                                view=move || view! {
                                    <NetworkdPreviewPage
                                        auth_token=auth_token
                                        on_unauthorized=on_unauthorized
                                    />
                                }
                            />
                            <Route
                                path=path!("/settings")
                                view=move || view! {
                                    <SettingsPage
                                        auth_token=auth_token
                                        on_unauthorized=on_unauthorized
                                    />
                                }
                            />
                            <Route
                                path=path!("/services")
                                view=move || view! {
                                    <ServicesPage
                                        auth_token=auth_token
                                        on_unauthorized=on_unauthorized
                                    />
                                }
                            />
                            <Route
                                path=path!("/services/:name")
                                view=move || view! {
                                    <ServiceDetailPage
                                        auth_token=auth_token
                                        on_unauthorized=on_unauthorized
                                    />
                                }
                            />
                            <Route
                                path=path!("/status")
                                view=move || view! {
                                    <StatusPage
                                        auth_token=auth_token
                                        on_setup_complete=on_setup_complete
                                        on_unauthorized=on_unauthorized
                                    />
                                }
                            />
                        </Routes>
                    </AppLayout>
                </Show>
            </Show>
        </Router>
    }
}
