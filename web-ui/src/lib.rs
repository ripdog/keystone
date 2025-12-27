//! Keystone Web UI Library
//!
//! This module exports the Leptos app for WASM compilation

pub mod app;

use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen(start)]
pub fn main() {
    use crate::app::App;
    console_error_panic_hook::set_once();

    web_sys::console::log_1(&"Keystone WASM initializing...".into());
    leptos::mount::mount_to_body(App);
    web_sys::console::log_1(&"Keystone WASM mounted!".into());
}
