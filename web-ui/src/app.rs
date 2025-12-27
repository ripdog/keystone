//! Keystone Web UI - Leptos Frontend (WASM)
//!
//! This module contains the Leptos components that compile to WASM
//! and run in the browser as a Single Page Application.

use crate::components::{clear_stored_token, get_stored_token, AppLayout, LoginPage};
use crate::pages::{DashboardPage, FirewallPage, InterfaceEditPage, InterfacesPage, SettingsPage};
use keystone_core::SystemState;
use leptos::prelude::*;
use leptos_router::{
    components::{Route, Router, Routes},
    path,
};

#[component]
pub fn App() -> impl IntoView {
    let (auth_token, set_auth_token) = signal(get_stored_token());
    let (state, set_state) = signal(SystemState::default());

    let logout = Callback::new(move |()| {
        clear_stored_token();
        set_auth_token.set(None);
    });

    let on_unauthorized = Callback::new(move |()| {
        clear_stored_token();
        set_auth_token.set(None);
    });

    view! {
        <Router>
            <Show
                when=move || auth_token.get().is_some()
                fallback=move || view! { <LoginPage on_login=set_auth_token/> }
            >
                <AppLayout on_logout=logout>
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
                                <FirewallPage state=state/>
                            }
                        />
                        <Route
                            path=path!("/settings")
                            view=move || view! {
                                <SettingsPage
                                    state=state
                                    auth_token=auth_token
                                    on_unauthorized=on_unauthorized
                                />
                            }
                        />
                    </Routes>
                </AppLayout>
            </Show>
        </Router>
    }
}
