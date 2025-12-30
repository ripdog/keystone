//! Caddy reverse proxy configuration page
//!
//! Tabbed interface for:
//! - Settings (enabled, server address, interface binding, HTTPS mode)
//! - Preview (generated Caddyfile)
//! - Status (service status, validation)

use crate::api;
use keystone_core::{CaddyConfig, CaddyHttpsMode};
use leptos::prelude::*;
use leptos::task::spawn_local;

/// Active tab in the Caddy UI
#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum CaddyTab {
    #[default]
    Settings,
    Preview,
    Status,
}

#[component]
pub fn CaddyPage(
    auth_token: ReadSignal<Option<String>>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let token = Signal::derive(move || auth_token.get().unwrap_or_default());
    let active_tab = RwSignal::new(CaddyTab::Settings);

    // Global state
    let config = RwSignal::new(CaddyConfig::default());
    let available_interfaces = RwSignal::new(Vec::<String>::new());

    let loading = RwSignal::new(true);
    let error_msg = RwSignal::new(Option::<String>::None);
    let success_msg = RwSignal::new(Option::<String>::None);
    let reload_trigger = RwSignal::new(0u32);

    // Load initial data
    Effect::new(move || {
        let _ = reload_trigger.get();
        let token_val = token.get();
        if token_val.is_empty() {
            return;
        }

        loading.set(true);
        let token_clone = token_val.clone();

        spawn_local(async move {
            match api::fetch_caddy_state(&token_clone).await {
                Ok(state) => {
                    config.set(state.config);
                    available_interfaces.set(state.available_interfaces);
                    loading.set(false);
                }
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        error_msg.set(Some(e));
                        loading.set(false);
                    }
                }
            }
        });
    });

    let tab_class = move |tab: CaddyTab| {
        if active_tab.get() == tab {
            "px-4 py-2 text-blue-300 border-b-2 border-blue-400 font-medium"
        } else {
            "px-4 py-2 text-gray-400 hover:text-gray-200 border-b-2 border-transparent"
        }
    };

    view! {
        <div class="space-y-6">
            <div class="flex justify-between items-start">
                <div>
                    <h1 class="text-2xl font-semibold text-blue-300">"Caddy Web Server"</h1>
                    <p class="text-gray-400">"Reverse proxy configuration for Keystone web UI"</p>
                </div>
                <ApplyButton
                    token=token
                    success_msg=success_msg
                    error_msg=error_msg
                />
            </div>

            <Show when=move || success_msg.get().is_some()>
                <div class="bg-green-900/50 border border-green-500 rounded p-4 text-green-200">
                    {move || success_msg.get().unwrap_or_default()}
                </div>
            </Show>

            <Show when=move || error_msg.get().is_some()>
                <div class="bg-red-900/50 border border-red-500 rounded p-4 text-red-200">
                    {move || error_msg.get().unwrap_or_default()}
                </div>
            </Show>

            <Show when=move || loading.get()>
                <div class="text-center py-8 text-gray-400">"Loading Caddy configuration..."</div>
            </Show>

            <Show when=move || !loading.get()>
                // Tab bar
                <div class="border-b border-gray-700">
                    <nav class="flex -mb-px">
                        <button
                            class=move || tab_class(CaddyTab::Settings)
                            on:click=move |_| active_tab.set(CaddyTab::Settings)
                        >
                            "Settings"
                        </button>
                        <button
                            class=move || tab_class(CaddyTab::Preview)
                            on:click=move |_| active_tab.set(CaddyTab::Preview)
                        >
                            "Preview"
                        </button>
                        <button
                            class=move || tab_class(CaddyTab::Status)
                            on:click=move |_| active_tab.set(CaddyTab::Status)
                        >
                            "Status"
                        </button>
                    </nav>
                </div>

                // Tab content
                <div class="bg-gray-800 rounded-lg shadow-lg p-6">
                    {move || match active_tab.get() {
                        CaddyTab::Settings => view! {
                            <SettingsTab
                                token=token
                                config=config
                                available_interfaces=available_interfaces
                                success_msg=success_msg
                                error_msg=error_msg
                            />
                        }.into_any(),
                        CaddyTab::Preview => view! {
                            <PreviewTab token=token />
                        }.into_any(),
                        CaddyTab::Status => view! {
                            <StatusTab
                                token=token
                                config=config
                                error_msg=error_msg
                            />
                        }.into_any(),
                    }}
                </div>
            </Show>
        </div>
    }
}

// ============================================================================
// Apply Button
// ============================================================================

#[component]
fn ApplyButton(
    token: Signal<String>,
    success_msg: RwSignal<Option<String>>,
    error_msg: RwSignal<Option<String>>,
) -> impl IntoView {
    let applying = RwSignal::new(false);

    let on_apply = move |_| {
        applying.set(true);
        error_msg.set(None);
        success_msg.set(None);
        let token_val = token.get();

        spawn_local(async move {
            match api::apply_caddy(&token_val).await {
                Ok(response) => {
                    if response.success {
                        success_msg.set(Some(response.message));
                    } else {
                        error_msg.set(Some(response.message));
                    }
                }
                Err(e) => {
                    error_msg.set(Some(format!("Error applying config: {}", e)));
                }
            }
            applying.set(false);
        });
    };

    view! {
        <button
            class="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg font-medium disabled:opacity-50"
            on:click=on_apply
            disabled=move || applying.get()
        >
            {move || if applying.get() { "Applying..." } else { "Apply Changes" }}
        </button>
    }
}

// ============================================================================
// Settings Tab
// ============================================================================

#[component]
fn SettingsTab(
    token: Signal<String>,
    config: RwSignal<CaddyConfig>,
    available_interfaces: RwSignal<Vec<String>>,
    success_msg: RwSignal<Option<String>>,
    error_msg: RwSignal<Option<String>>,
) -> impl IntoView {
    let saving = RwSignal::new(false);

    // Local form state
    let enabled = RwSignal::new(config.get().enabled);
    let server_address = RwSignal::new(config.get().server_address.clone());
    let bind_interface = RwSignal::new(config.get().bind_interface.clone());
    let https_mode = RwSignal::new(config.get().https_mode);
    let custom_tls_config = RwSignal::new(config.get().custom_tls_config.clone());
    let https_port = RwSignal::new(config.get().https_port.to_string());
    let http_port = RwSignal::new(config.get().http_port.to_string());

    let save_config = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();
        saving.set(true);
        error_msg.set(None);
        success_msg.set(None);

        let new_config = CaddyConfig {
            enabled: enabled.get(),
            server_address: server_address.get(),
            bind_interface: bind_interface.get(),
            https_mode: https_mode.get(),
            custom_tls_config: custom_tls_config.get(),
            https_port: https_port.get().parse().unwrap_or(443),
            http_port: http_port.get().parse().unwrap_or(80),
            last_validation_status: config.get().last_validation_status.clone(),
            last_validation_time: config.get().last_validation_time,
        };

        let token_val = token.get();
        spawn_local(async move {
            match api::save_caddy_config(&token_val, new_config.clone()).await {
                Ok(()) => {
                    config.set(new_config);
                    success_msg.set(Some("Caddy settings saved".to_string()));
                }
                Err(e) => {
                    error_msg.set(Some(format!("Error: {}", e)));
                }
            }
            saving.set(false);
        });
    };

    view! {
        <form on:submit=save_config class="space-y-6">
            // Enable/Disable
            <div class="flex items-center gap-3">
                <input
                    type="checkbox"
                    id="enabled"
                    prop:checked=move || enabled.get()
                    on:change=move |ev| enabled.set(event_target_checked(&ev))
                    class="w-4 h-4"
                />
                <label for="enabled" class="text-white">"Enable Caddy reverse proxy"</label>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                // Server Address
                <div>
                    <label class="block text-gray-300 mb-2">"Server Address"</label>
                    <input
                        type="text"
                        prop:value=move || server_address.get()
                        on:input=move |ev| server_address.set(event_target_value(&ev))
                        placeholder="e.g., router.lan, 192.168.1.1"
                        class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white"
                    />
                    <p class="text-sm text-gray-500 mt-1">"Domain name or IP address for the server block"</p>
                </div>

                // Bind Interface
                <div>
                    <label class="block text-gray-300 mb-2">"Bind Interface"</label>
                    <select
                        prop:value=move || bind_interface.get()
                        on:change=move |ev| bind_interface.set(event_target_value(&ev))
                        class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white"
                    >
                        <option value="">"Select interface..."</option>
                        <For
                            each=move || available_interfaces.get()
                            key=|iface| iface.clone()
                            children=move |iface: String| {
                                let name = iface.clone();
                                let name_display = iface.clone();
                                view! { <option value=name>{name_display}</option> }
                            }
                        />
                    </select>
                    <p class="text-sm text-gray-500 mt-1">"Caddy will only listen on this interface's IP"</p>
                </div>

                // HTTPS Mode
                <div>
                    <label class="block text-gray-300 mb-2">"HTTPS Mode"</label>
                    <select
                        prop:value=move || https_mode.get().to_string()
                        on:change=move |ev| {
                            let value = event_target_value(&ev);
                            https_mode.set(value.parse().unwrap_or(CaddyHttpsMode::Disabled));
                        }
                        class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white"
                    >
                        <option value="disabled">"Disabled (HTTP only)"</option>
                        <option value="self_signed">"Self-Signed Certificate"</option>
                        <option value="acme_custom">"Custom ACME/TLS Configuration"</option>
                    </select>
                    <p class="text-sm text-gray-500 mt-1">
                        {move || match https_mode.get() {
                            CaddyHttpsMode::Disabled => "Serve over plain HTTP only",
                            CaddyHttpsMode::SelfSigned => "Caddy will generate a self-signed certificate",
                            CaddyHttpsMode::AcmeCustom => "Use custom TLS configuration below",
                        }}
                    </p>
                </div>

                // Ports
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <label class="block text-gray-300 mb-2">"HTTPS Port"</label>
                        <input
                            type="number"
                            prop:value=move || https_port.get()
                            on:input=move |ev| https_port.set(event_target_value(&ev))
                            class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white"
                            disabled=move || https_mode.get() == CaddyHttpsMode::Disabled
                        />
                    </div>
                    <div>
                        <label class="block text-gray-300 mb-2">"HTTP Port"</label>
                        <input
                            type="number"
                            prop:value=move || http_port.get()
                            on:input=move |ev| http_port.set(event_target_value(&ev))
                            class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white"
                        />
                    </div>
                </div>
            </div>

            // Custom TLS Config (only shown for AcmeCustom mode)
            <Show when=move || https_mode.get() == CaddyHttpsMode::AcmeCustom>
                <div>
                    <label class="block text-gray-300 mb-2">"Custom TLS Configuration"</label>
                    <textarea
                        prop:value=move || custom_tls_config.get()
                        on:input=move |ev| custom_tls_config.set(event_target_value(&ev))
                        rows="6"
                        placeholder="tls {\n    dns cloudflare {env.CF_API_TOKEN}\n}"
                        class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white font-mono text-sm"
                    />
                    <p class="text-sm text-gray-500 mt-1">
                        "Raw Caddyfile TLS directives. Examples: dns cloudflare, custom cert files, etc."
                    </p>
                    <div class="mt-2 p-3 bg-gray-900 rounded text-sm text-gray-400">
                        <p class="font-medium text-gray-300 mb-1">"Example for Cloudflare DNS challenge:"</p>
                        <pre class="text-xs font-mono">"tls {\n    dns cloudflare {env.CF_API_TOKEN}\n}"</pre>
                    </div>
                </div>
            </Show>

            <div class="pt-4">
                <button
                    type="submit"
                    class="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded disabled:opacity-50"
                    disabled=move || saving.get()
                >
                    {move || if saving.get() { "Saving..." } else { "Save Settings" }}
                </button>
            </div>
        </form>
    }
}

// ============================================================================
// Preview Tab
// ============================================================================

#[component]
fn PreviewTab(token: Signal<String>) -> impl IntoView {
    let preview_content = RwSignal::new(String::new());
    let loading = RwSignal::new(true);
    let error = RwSignal::new(Option::<String>::None);

    Effect::new(move || {
        let token_val = token.get();
        if token_val.is_empty() {
            return;
        }
        loading.set(true);

        spawn_local(async move {
            match api::fetch_caddy_preview(&token_val).await {
                Ok(content) => {
                    preview_content.set(content);
                    loading.set(false);
                }
                Err(e) => {
                    error.set(Some(e));
                    loading.set(false);
                }
            }
        });
    });

    view! {
        <div class="space-y-4">
            <div class="flex justify-between items-center">
                <h3 class="text-lg font-medium text-white">"Generated Caddyfile"</h3>
                <p class="text-sm text-gray-400">"Preview of /etc/caddy/Caddyfile.d/keystone.conf"</p>
            </div>

            <Show when=move || loading.get()>
                <div class="text-center py-8 text-gray-400">"Loading preview..."</div>
            </Show>

            <Show when=move || error.get().is_some()>
                <div class="bg-red-900/50 border border-red-500 rounded p-4 text-red-200">
                    {move || error.get().unwrap_or_default()}
                </div>
            </Show>

            <Show when=move || !loading.get() && error.get().is_none()>
                <pre class="bg-gray-900 rounded-lg p-4 overflow-x-auto text-sm text-gray-300 font-mono whitespace-pre-wrap">
                    {move || preview_content.get()}
                </pre>
            </Show>
        </div>
    }
}

// ============================================================================
// Status Tab
// ============================================================================

#[component]
fn StatusTab(
    token: Signal<String>,
    config: RwSignal<CaddyConfig>,
    error_msg: RwSignal<Option<String>>,
) -> impl IntoView {
    let status = RwSignal::new(Option::<api::CaddyServiceStatus>::None);
    let validation_result = RwSignal::new(Option::<(bool, String)>::None);
    let loading = RwSignal::new(true);
    let validating = RwSignal::new(false);

    // Load status on mount
    Effect::new(move || {
        let token_val = token.get();
        if token_val.is_empty() {
            return;
        }
        loading.set(true);

        spawn_local(async move {
            match api::fetch_caddy_status(&token_val).await {
                Ok(s) => {
                    status.set(Some(s));
                    loading.set(false);
                }
                Err(e) => {
                    error_msg.set(Some(format!("Failed to fetch status: {}", e)));
                    loading.set(false);
                }
            }
        });
    });

    let validate_config = move |_| {
        validating.set(true);
        validation_result.set(None);
        let token_val = token.get();

        spawn_local(async move {
            match api::validate_caddy(&token_val).await {
                Ok(response) => {
                    let message = if response.output.is_empty() {
                        response.message
                    } else {
                        format!("{}\n\n{}", response.message, response.output)
                    };
                    validation_result.set(Some((response.valid, message)));
                }
                Err(e) => {
                    validation_result.set(Some((false, format!("Validation error: {}", e))));
                }
            }
            validating.set(false);
        });
    };

    view! {
        <div class="space-y-6">
            // Service Status
            <div class="bg-gray-700 rounded-lg p-4">
                <h3 class="text-lg font-medium text-white mb-4">"Service Status"</h3>

                <Show when=move || loading.get()>
                    <div class="text-gray-400">"Loading status..."</div>
                </Show>

                <Show when=move || !loading.get() && status.get().is_some()>
                    {move || {
                        let s = status.get().unwrap();
                        view! {
                            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                                <div class="bg-gray-800 rounded p-3">
                                    <div class="text-gray-400 text-sm">"Running"</div>
                                    <div class="text-xl font-semibold mt-1">
                                        {if s.running {
                                            view! { <span class="text-green-400">"Yes"</span> }.into_any()
                                        } else {
                                            view! { <span class="text-red-400">"No"</span> }.into_any()
                                        }}
                                    </div>
                                </div>
                                <div class="bg-gray-800 rounded p-3">
                                    <div class="text-gray-400 text-sm">"Enabled at Boot"</div>
                                    <div class="text-xl font-semibold mt-1">
                                        {if s.enabled {
                                            view! { <span class="text-green-400">"Yes"</span> }.into_any()
                                        } else {
                                            view! { <span class="text-gray-400">"No"</span> }.into_any()
                                        }}
                                    </div>
                                </div>
                                <div class="bg-gray-800 rounded p-3">
                                    <div class="text-gray-400 text-sm">"Config File Exists"</div>
                                    <div class="text-xl font-semibold mt-1">
                                        {if s.config_exists {
                                            view! { <span class="text-green-400">"Yes"</span> }.into_any()
                                        } else {
                                            view! { <span class="text-gray-400">"No"</span> }.into_any()
                                        }}
                                    </div>
                                </div>
                            </div>
                        }
                    }}
                </Show>
            </div>

            // Last Validation
            <div class="bg-gray-700 rounded-lg p-4">
                <h3 class="text-lg font-medium text-white mb-4">"Configuration Validation"</h3>

                <Show when=move || config.get().last_validation_status.is_some()>
                    <div class="mb-4 p-3 bg-gray-800 rounded">
                        <div class="text-gray-400 text-sm mb-1">"Last Validation"</div>
                        <div class="text-white">
                            {move || config.get().last_validation_status.clone().unwrap_or_default()}
                        </div>
                        <Show when=move || config.get().last_validation_time.is_some()>
                            <div class="text-gray-500 text-sm mt-1">
                                {move || format_timestamp(config.get().last_validation_time.unwrap_or(0))}
                            </div>
                        </Show>
                    </div>
                </Show>

                <button
                    class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded disabled:opacity-50"
                    on:click=validate_config
                    disabled=move || validating.get()
                >
                    {move || if validating.get() { "Validating..." } else { "Validate Configuration" }}
                </button>

                <Show when=move || validation_result.get().is_some()>
                    {move || {
                        let (valid, message) = validation_result.get().unwrap();
                        let class = if valid {
                            "mt-4 p-4 bg-green-900/50 border border-green-500 rounded text-green-200"
                        } else {
                            "mt-4 p-4 bg-red-900/50 border border-red-500 rounded text-red-200"
                        };
                        view! {
                            <div class=class>
                                <pre class="whitespace-pre-wrap text-sm font-mono">{message}</pre>
                            </div>
                        }
                    }}
                </Show>
            </div>

            // Info box
            <div class="bg-gray-700/50 rounded-lg p-4 text-gray-400 text-sm">
                <h4 class="font-medium text-gray-300 mb-2">"About Caddy Configuration"</h4>
                <ul class="list-disc list-inside space-y-1">
                    <li>"Caddy acts as a reverse proxy, forwarding requests to the Keystone web UI"</li>
                    <li>"When HTTPS is enabled, Caddy handles TLS termination"</li>
                    <li>"Self-signed mode generates a certificate trusted by Caddy's internal CA"</li>
                    <li>"Custom ACME mode allows DNS challenges for proper certificates on private networks"</li>
                    <li>"Configuration is written to /etc/caddy/Caddyfile.d/keystone.conf"</li>
                </ul>
            </div>
        </div>
    }
}

/// Format a Unix timestamp as a human-readable string
fn format_timestamp(ts: i64) -> String {
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_namespace = Date)]
        fn now() -> f64;
    }

    if ts == 0 {
        return "Unknown".to_string();
    }

    let now_ts = (now() / 1000.0) as i64;
    let diff = now_ts - ts;

    if diff < 0 {
        "In the future".to_string()
    } else if diff < 60 {
        format!("{} seconds ago", diff)
    } else if diff < 3600 {
        format!("{} minutes ago", diff / 60)
    } else if diff < 86400 {
        format!("{} hours ago", diff / 3600)
    } else {
        format!("{} days ago", diff / 86400)
    }
}
