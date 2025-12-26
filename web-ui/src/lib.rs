/// Keystone Web UI Library
/// 
/// This module exports the Leptos app for WASM compilation

pub mod app;

use leptos::*;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn hydrate() {
    console_error_panic_hook::set_once();
    leptos::mount_to_body(|| {
        view! { <app::App/> }
    });
}
