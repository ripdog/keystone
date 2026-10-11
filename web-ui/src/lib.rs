//! Keystone Web UI Library
//!
//! This module exports the Leptos app for WASM compilation

mod api;
mod components;
mod pages;

pub mod app;

use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen(start)]
pub fn main() {
    use crate::app::App;
    console_error_panic_hook::set_once();

    web_sys::console::log_1(&"Keystone WASM initializing...".into());

    // Clear body content before mounting
    if let Some(window) = web_sys::window()
        && let Some(document) = window.document()
        && let Some(body) = document.body()
    {
        body.set_inner_html("");
        // The static error fallback centers its content; the SPA uses a full-width shell.
        body.set_class_name("bg-slate-950 text-slate-100 min-h-screen");
    }

    leptos::mount::mount_to_body(App);
    web_sys::console::log_1(&"Keystone WASM mounted!".into());
}
