//! Managed OpenSSH listener settings. Root login is deliberately not a UI option.
use crate::api;
use crate::components::{PendingActions, use_config_changed, use_toasts};
use keystone_core::{SshConfig, SshStateResponse};
use leptos::prelude::*;
use leptos::task::spawn_local;

#[component]
pub fn SshPage(
    auth_token: ReadSignal<Option<String>>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let toasts = use_toasts();
    let config_changed = use_config_changed();
    // Saving is not offered while an applied change awaits confirmation.
    let locked = expect_context::<PendingActions>().locked;
    let config = RwSignal::new(SshConfig::default());
    let port = RwSignal::new("22".to_string());
    let state = RwSignal::new(Option::<SshStateResponse>::None);
    let loading = RwSignal::new(true);
    let busy = RwSignal::new(false);
    let error = RwSignal::new(Option::<String>::None);
    let reload = RwSignal::new(0u32);

    Effect::new(move || {
        let _ = reload.get();
        let Some(token) = auth_token.get() else {
            return;
        };
        spawn_local(async move {
            loading.set(true);
            match api::fetch_ssh(&token).await {
                Ok(response) => {
                    port.set(response.config.port.to_string());
                    config.set(response.config.clone());
                    state.set(Some(response));
                    error.set(None);
                }
                Err(e) if e.contains("Unauthorized") => on_unauthorized.run(()),
                Err(e) => error.set(Some(e)),
            }
            loading.set(false);
        });
    });

    let save = move |_| {
        let Some(token) = auth_token.get() else {
            return;
        };
        let Ok(parsed_port) = port.get().parse::<u16>() else {
            error.set(Some("SSH port must be between 1 and 65535".into()));
            return;
        };
        let mut next = config.get();
        next.port = parsed_port;
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            match api::apply_ssh(&token, &next).await {
                Ok(response) if response.success => {
                    // A firewall change awaits confirmation: the pending bar at
                    // the top of the page shows that, so no message is added here.
                    if response.firewall_session_id.is_none() {
                        toasts.success(response.message);
                    }
                    config_changed.run(());
                    reload.update(|n| *n += 1);
                }
                Ok(response) => error.set(Some(response.message)),
                Err(e) if e.contains("Unauthorized") => on_unauthorized.run(()),
                Err(e) => error.set(Some(e)),
            }
            busy.set(false);
        });
    };

    view! {
        <div class="space-y-6">
            <div>
                <h1 class="text-2xl font-semibold text-blue-300">"SSH Server"</h1>
                <p class="text-gray-400">"Secure shell access to the router. Keystone manages only its own OpenSSH settings."</p>
            </div>
            <Show when=move || error.get().is_some()>
                <div class="bg-red-900/50 border border-red-500 rounded p-4 text-red-200">
                    {move || error.get().unwrap_or_default()}
                </div>
            </Show>
            <Show when=move || loading.get()>
                <p class="text-gray-400">"Loading SSH state..."</p>
            </Show>
            <Show when=move || !loading.get()>
                <div class="bg-gray-800 rounded-lg p-6 space-y-5">
                    <div class="flex items-center justify-between">
                        <label class="flex items-center gap-3">
                            <input type="checkbox" class="w-5 h-5"
                                prop:checked=move || config.get().enabled
                                on:change=move |ev| config.update(|c| c.enabled = event_target_checked(&ev)) />
                            <span class="font-medium">"Enable SSH at boot"</span>
                        </label>
                        <span class=move || if state.get().as_ref().is_some_and(|s| s.running) {
                            "text-green-400"
                        } else { "text-gray-400" }>
                            {move || if state.get().as_ref().is_some_and(|s| s.running) { "Running" } else { "Stopped" }}
                        </span>
                    </div>
                    <div>
                        <label class="block mb-2 text-gray-300" for="ssh-port">"Listening port"</label>
                        <input id="ssh-port" type="number" min="1" max="65535"
                            class="bg-gray-700 rounded px-3 py-2 w-32 border border-gray-600"
                            prop:value=move || port.get()
                            on:input=move |ev| port.set(event_target_value(&ev)) />
                    </div>
                    <div class="border-t border-gray-700 pt-5 space-y-3">
                        <h2 class="text-lg font-medium text-blue-200">"Network exposure"</h2>
                        <p class="text-gray-400 text-sm">
                            "SSH binds to the current addresses on enabled LAN interfaces, plus loopback. WAN listening is disabled by default. IPv6 LAN global addresses can be publicly routable; firewall policy also matters."
                        </p>
                        <label class="flex items-center gap-3">
                            <input type="checkbox" prop:checked=move || config.get().ipv4
                                on:change=move |ev| config.update(|c| c.ipv4 = event_target_checked(&ev)) />
                            "IPv4"
                        </label>
                        <label class="flex items-center gap-3">
                            <input type="checkbox" prop:checked=move || config.get().ipv6
                                on:change=move |ev| config.update(|c| c.ipv6 = event_target_checked(&ev)) />
                            "IPv6"
                        </label>
                        <label class="flex items-center gap-3">
                            <input type="checkbox" prop:checked=move || config.get().wan_access
                                on:change=move |ev| config.update(|c| c.wan_access = event_target_checked(&ev)) />
                            "Allow listening on WAN"
                        </label>
                        <Show when=move || config.get().wan_access>
                            <p class="text-yellow-300 text-sm">
                                "WAN SSH is reachable from the internet. Keystone will add a WAN firewall allow rule; use the Firewall page to restrict source addresses if needed."
                            </p>
                        </Show>
                        <Show when=move || state.get().is_some()>
                            <div class="text-sm text-gray-300">
                                <p class="mb-2 font-medium">"Configured listener addresses"</p>
                                <div class="font-mono text-gray-400 text-xs space-y-1">
                                    {move || state.get().map(|s| s.listening_addresses.join(" · ")).unwrap_or_default()}
                                </div>
                                <Show when=move || state.get().as_ref().is_some_and(|s| !s.managed)>
                                    <p class="text-yellow-300 mt-2">"OpenSSH is not yet managed and may currently listen on WAN. Saving creates a LAN-only Keystone drop-in by default."</p>
                                </Show>
                            </div>
                        </Show>
                    </div>
                    <div class="border-t border-gray-700 pt-5 space-y-3">
                        <h2 class="text-lg font-medium text-blue-200">"Authentication"</h2>
                        <label class="flex items-center gap-3">
                            <input type="checkbox" prop:checked=move || config.get().public_key_authentication
                                on:change=move |ev| config.update(|c| c.public_key_authentication = event_target_checked(&ev)) />
                            "Public-key authentication"
                        </label>
                        <label class="flex items-center gap-3">
                            <input type="checkbox" prop:checked=move || config.get().password_authentication
                                on:change=move |ev| config.update(|c| c.password_authentication = event_target_checked(&ev)) />
                            "Password authentication"
                        </label>
                        <p class="text-sm text-gray-400">
                            "Keystone configures direct root SSH login as disabled. Before saving, ensure you have a usable non-root Linux account and credentials. Keystone does not create Linux users or override administrator-owned SSH configuration."
                        </p>
                    </div>
                    <button class="bg-blue-600 hover:bg-blue-700 disabled:bg-blue-900 disabled:cursor-not-allowed px-5 py-2 rounded font-medium"
                        disabled=move || busy.get() || locked.get()
                        on:click=save>
                        {move || if busy.get() { "Applying..." } else { "Save and apply" }}
                    </button>
                    <Show when=move || state.get().as_ref().and_then(|s| s.warning.clone()).is_some()>
                        <p class="text-yellow-300">{move || state.get().and_then(|s| s.warning).unwrap_or_default()}</p>
                    </Show>
                </div>
            </Show>
        </div>
    }
}
