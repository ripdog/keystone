//! Firewall configuration page
//!
//! Zone-based firewall UI with tabs for:
//! - Zones (define interface groups with default policies)
//! - Zone Forwards (zone-to-zone forwarding policies)
//! - Port Forwards (DNAT rules)
//! - Input Rules (traffic to the router)
//! - Forward Rules (traffic through the router)
//! - Preview (see generated nftables rules)

use crate::api;
use keystone_core::{
    FirewallAction, FirewallGlobalSettings, FirewallPolicy, FirewallZone, ForwardRule, InputRule,
    PortForward, RuleProtocol, ZoneForwardPolicy,
};
use leptos::prelude::*;
use wasm_bindgen::prelude::*;

// JS binding to get current time
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = Date)]
    fn now() -> f64;
}

/// Active tab in the firewall UI
#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum FirewallTab {
    #[default]
    Zones,
    ZoneForwards,
    PortForwards,
    InputRules,
    ForwardRules,
    Settings,
    Preview,
}

#[component]
pub fn FirewallPage(
    auth_token: ReadSignal<Option<String>>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    // Get the token as a derived signal that returns empty string if not set
    let token = Signal::derive(move || auth_token.get().unwrap_or_default());

    let active_tab = RwSignal::new(FirewallTab::Zones);

    // Status message for apply/confirm workflow
    let status_message = RwSignal::new(String::new());
    let pending_session = RwSignal::new(Option::<String>::None);
    let seconds_remaining = RwSignal::new(0u32);

    // Trigger for reloading data
    let reload_trigger = RwSignal::new(0);

    // Tab button helper
    let tab_class = move |tab: FirewallTab| {
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
                    <h1 class="text-2xl font-semibold text-blue-300">"Firewall"</h1>
                    <p class="text-gray-400">"Zone-based firewall configuration"</p>
                </div>
                <div class="flex gap-2">
                    <ApplyButton
                        token=token
                        status_message=status_message
                        pending_session=pending_session
                        seconds_remaining=seconds_remaining
                        on_unauthorized=on_unauthorized
                    />
                </div>
            </div>

            // Status message
            {move || {
                let msg = status_message.get();
                if msg.is_empty() {
                    view! { <div></div> }.into_any()
                } else {
                    view! {
                        <div class="bg-blue-900/50 border border-blue-700 text-blue-200 px-4 py-3 rounded">
                            {msg}
                        </div>
                    }.into_any()
                }
            }}

            // Pending confirmation banner
            {move || {
                if let Some(session_id) = pending_session.get() {
                    let remaining = seconds_remaining.get();
                    view! {
                        <div class="bg-yellow-900/50 border border-yellow-600 text-yellow-200 px-4 py-3 rounded flex items-center justify-between">
                            <div>
                                <span class="font-medium">"Changes pending confirmation!"</span>
                                " Confirm within "
                                <span class="font-bold">{remaining}</span>
                                " seconds or changes will be rolled back."
                            </div>
                            <div class="flex gap-2">
                                <ConfirmButton
                                    token=token.get()
                                    session_id=session_id.clone()
                                    status_message=status_message
                                    pending_session=pending_session
                                    on_unauthorized=on_unauthorized
                                />
                                <RollbackButton
                                    token=token.get()
                                    status_message=status_message
                                    pending_session=pending_session
                                    on_unauthorized=on_unauthorized
                                />
                            </div>
                        </div>
                    }.into_any()
                } else {
                    view! { <div></div> }.into_any()
                }
            }}

            // Tab bar
            <div class="border-b border-gray-700">
                <nav class="flex -mb-px flex-wrap">
                    <button
                        class=move || tab_class(FirewallTab::Zones)
                        on:click=move |_| active_tab.set(FirewallTab::Zones)
                    >
                        "Zones"
                    </button>
                    <button
                        class=move || tab_class(FirewallTab::ZoneForwards)
                        on:click=move |_| active_tab.set(FirewallTab::ZoneForwards)
                    >
                        "Zone Forwards"
                    </button>
                    <button
                        class=move || tab_class(FirewallTab::PortForwards)
                        on:click=move |_| active_tab.set(FirewallTab::PortForwards)
                    >
                        "Port Forwards"
                    </button>
                    <button
                        class=move || tab_class(FirewallTab::InputRules)
                        on:click=move |_| active_tab.set(FirewallTab::InputRules)
                    >
                        "Input Rules"
                    </button>
                    <button
                        class=move || tab_class(FirewallTab::ForwardRules)
                        on:click=move |_| active_tab.set(FirewallTab::ForwardRules)
                    >
                        "Forward Rules"
                    </button>
                    <button
                        class=move || tab_class(FirewallTab::Settings)
                        on:click=move |_| active_tab.set(FirewallTab::Settings)
                    >
                        "Settings"
                    </button>
                    <button
                        class=move || tab_class(FirewallTab::Preview)
                        on:click=move |_| active_tab.set(FirewallTab::Preview)
                    >
                        "Preview"
                    </button>
                </nav>
            </div>

            // Tab content
            <div class="bg-gray-800 rounded-lg shadow-lg p-6">
                {move || match active_tab.get() {
                    FirewallTab::Zones => view! { <ZonesTab token=token reload_trigger=reload_trigger on_unauthorized=on_unauthorized /> }.into_any(),
                    FirewallTab::ZoneForwards => view! { <ZoneForwardsTab token=token reload_trigger=reload_trigger on_unauthorized=on_unauthorized /> }.into_any(),
                    FirewallTab::PortForwards => view! { <PortForwardsTab token=token reload_trigger=reload_trigger on_unauthorized=on_unauthorized /> }.into_any(),
                    FirewallTab::InputRules => view! { <InputRulesTab token=token reload_trigger=reload_trigger on_unauthorized=on_unauthorized /> }.into_any(),
                    FirewallTab::ForwardRules => view! { <ForwardRulesTab token=token reload_trigger=reload_trigger on_unauthorized=on_unauthorized /> }.into_any(),
                    FirewallTab::Settings => view! { <SettingsTab token=token on_unauthorized=on_unauthorized /> }.into_any(),
                    FirewallTab::Preview => view! { <PreviewTab token=token reload_trigger=reload_trigger on_unauthorized=on_unauthorized /> }.into_any(),
                }}
            </div>
        </div>
    }
}

// ============================================================================
// Apply/Confirm/Rollback Buttons
// ============================================================================

#[component]
fn ApplyButton(
    token: Signal<String>,
    status_message: RwSignal<String>,
    pending_session: RwSignal<Option<String>>,
    seconds_remaining: RwSignal<u32>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let applying = RwSignal::new(false);

    let on_apply = move |_| {
        applying.set(true);
        let token = token.get();
        leptos::task::spawn_local(async move {
            match api::apply_firewall(&token).await {
                Ok(response) => {
                    if response.success {
                        status_message.set(response.message);
                        if response.pending_confirmation {
                            pending_session.set(response.session_id);
                            if let Some(deadline) = response.confirm_deadline {
                                let now_ms = now() as u64 / 1000;
                                let remaining = deadline.saturating_sub(now_ms) as u32;
                                seconds_remaining.set(remaining);
                            }
                        }
                    } else {
                        status_message.set(format!("Apply failed: {}", response.message));
                    }
                }
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        status_message.set(format!("Error: {}", e));
                    }
                }
            }
            applying.set(false);
        });
    };

    view! {
        <button
            class="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg font-medium disabled:opacity-50"
            on:click=on_apply
            disabled=move || applying.get() || pending_session.get().is_some()
        >
            {move || if applying.get() { "Applying..." } else { "Apply Changes" }}
        </button>
    }
}

#[component]
fn ConfirmButton(
    token: String,
    session_id: String,
    status_message: RwSignal<String>,
    pending_session: RwSignal<Option<String>>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let confirming = RwSignal::new(false);
    let token = token.clone();
    let session_id = session_id.clone();

    let on_confirm = move |_| {
        confirming.set(true);
        let token = token.clone();
        let session_id = session_id.clone();
        leptos::task::spawn_local(async move {
            match api::confirm_firewall(&token, &session_id).await {
                Ok(response) => {
                    if response.success {
                        status_message.set(response.message);
                        pending_session.set(None);
                    } else {
                        status_message.set(format!("Confirm failed: {}", response.message));
                    }
                }
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        status_message.set(format!("Error: {}", e));
                    }
                }
            }
            confirming.set(false);
        });
    };

    view! {
        <button
            class="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded font-medium disabled:opacity-50"
            on:click=on_confirm
            disabled=move || confirming.get()
        >
            {move || if confirming.get() { "Confirming..." } else { "Confirm" }}
        </button>
    }
}

#[component]
fn RollbackButton(
    token: String,
    status_message: RwSignal<String>,
    pending_session: RwSignal<Option<String>>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let rolling_back = RwSignal::new(false);
    let token = token.clone();

    let on_rollback = move |_| {
        rolling_back.set(true);
        let token = token.clone();
        leptos::task::spawn_local(async move {
            match api::rollback_firewall(&token).await {
                Ok(response) => {
                    if response.success {
                        status_message.set(response.message);
                        pending_session.set(None);
                    } else {
                        status_message.set(format!("Rollback failed: {}", response.message));
                    }
                }
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        status_message.set(format!("Error: {}", e));
                    }
                }
            }
            rolling_back.set(false);
        });
    };

    view! {
        <button
            class="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded font-medium disabled:opacity-50"
            on:click=on_rollback
            disabled=move || rolling_back.get()
        >
            {move || if rolling_back.get() { "Rolling back..." } else { "Rollback" }}
        </button>
    }
}

// ============================================================================
// Zones Tab
// ============================================================================

#[component]
fn ZonesTab(
    token: Signal<String>,
    reload_trigger: RwSignal<i32>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let zones = LocalResource::new(move || {
        let token = token.get();
        let _ = reload_trigger.get();
        async move { api::fetch_firewall_zones(&token).await }
    });

    let editing_zone = RwSignal::new(Option::<FirewallZone>::None);
    let error_message = RwSignal::new(String::new());

    view! {
        <div class="space-y-4">
            <div class="flex justify-between items-center">
                <h2 class="text-lg font-medium text-gray-200">"Firewall Zones"</h2>
                <button
                    class="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm"
                    on:click=move |_| {
                        editing_zone.set(Some(FirewallZone {
                            id: None,
                            name: String::new(),
                            description: None,
                            interfaces: Vec::new(),
                            default_input_policy: FirewallPolicy::Drop,
                            default_forward_policy: FirewallPolicy::Drop,
                        }));
                    }
                >
                    "+ Add Zone"
                </button>
            </div>

            // Error message
            {move || {
                let msg = error_message.get();
                if msg.is_empty() {
                    view! { <div></div> }.into_any()
                } else {
                    view! {
                        <div class="bg-red-900/50 border border-red-700 text-red-200 px-4 py-2 rounded text-sm">
                            {msg}
                        </div>
                    }.into_any()
                }
            }}

            // Zone editor modal
            {move || {
                if let Some(zone) = editing_zone.get() {
                    view! {
                        <ZoneEditor
                            zone=zone
                            token=token.get()
                            on_save=move |_| {
                                editing_zone.set(None);
                                reload_trigger.update(|v| *v += 1);
                            }
                            on_cancel=move || editing_zone.set(None)
                            error_message=error_message
                            on_unauthorized=on_unauthorized
                        />
                    }.into_any()
                } else {
                    view! { <div></div> }.into_any()
                }
            }}

            // Zones list
            <Suspense fallback=move || view! { <p class="text-gray-400">"Loading zones..."</p> }>
                {move || {
                    zones.get().map(|result| match result {
                        Ok(zone_list) => view! {
                            <div class="space-y-2">
                                <For
                                    each=move || zone_list.clone()
                                    key=|z| (z.id, z.name.clone())
                                    children=move |zone| {
                                        let zone_for_edit = zone.clone();
                                        let zone_for_delete = zone.clone();
                                        let token_for_delete = token.get();
                                        view! {
                                            <div class="flex items-center justify-between p-3 bg-gray-700/50 rounded">
                                                <div>
                                                    <span class="font-medium text-gray-200">{zone.name.clone()}</span>
                                                    {zone.description.clone().map(|d| view! {
                                                        <span class="text-gray-400 ml-2">" - "{d}</span>
                                                    })}
                                                    <div class="text-sm text-gray-400 mt-1">
                                                        "Interfaces: "
                                                        {if zone.interfaces.is_empty() {
                                                            "(none)".to_string()
                                                        } else {
                                                            zone.interfaces.join(", ")
                                                        }}
                                                        " | Input: "
                                                        <span class=if zone.default_input_policy == FirewallPolicy::Accept { "text-green-400" } else { "text-red-400" }>
                                                            {format!("{:?}", zone.default_input_policy)}
                                                        </span>
                                                        " | Forward: "
                                                        <span class=if zone.default_forward_policy == FirewallPolicy::Accept { "text-green-400" } else { "text-red-400" }>
                                                            {format!("{:?}", zone.default_forward_policy)}
                                                        </span>
                                                    </div>
                                                </div>
                                                <div class="flex gap-2">
                                                    <button
                                                        class="px-2 py-1 text-sm text-blue-400 hover:text-blue-300"
                                                        on:click=move |_| editing_zone.set(Some(zone_for_edit.clone()))
                                                    >
                                                        "Edit"
                                                    </button>
                                                    <button
                                                        class="px-2 py-1 text-sm text-red-400 hover:text-red-300"
                                                         on:click=move |_| {
                                                            if let Some(id) = zone_for_delete.id {
                                                                let token = token_for_delete.clone();
                                                                leptos::task::spawn_local(async move {
                                                                    match api::delete_firewall_zone(&token, id).await {
                                                                        Ok(_) => reload_trigger.update(|v| *v += 1),
                                                                        Err(e) => {
                                                                            if e.contains("Unauthorized") {
                                                                                on_unauthorized.run(());
                                                                            } else {
                                                                                error_message.set(e);
                                                                            }
                                                                        }
                                                                    }
                                                                });
                                                            }
                                                        }
                                                    >
                                                        "Delete"
                                                    </button>
                                                </div>
                                            </div>
                                        }
                                    }
                                />
                            </div>
                        }.into_any(),
                        Err(e) => {
                            if e.contains("Unauthorized") {
                                on_unauthorized.run(());
                            }
                            view! { <p class="text-red-400">"Error: "{e}</p> }.into_any()
                        }
                    })
                }}
            </Suspense>
        </div>
    }
}

#[component]
fn ZoneEditor(
    zone: FirewallZone,
    token: String,
    on_save: impl Fn(()) + 'static,
    on_cancel: impl Fn() + 'static,
    error_message: RwSignal<String>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let name = RwSignal::new(zone.name.clone());
    let description = RwSignal::new(zone.description.clone().unwrap_or_default());
    let interfaces_str = RwSignal::new(zone.interfaces.join(", "));
    let input_policy = RwSignal::new(zone.default_input_policy);
    let forward_policy = RwSignal::new(zone.default_forward_policy);
    let saving = RwSignal::new(false);
    let zone_id = zone.id;

    let on_save = std::rc::Rc::new(on_save);
    let on_save_clone = on_save.clone();

    let save_zone = move |_| {
        saving.set(true);
        error_message.set(String::new());

        let token = token.clone();
        let on_save = on_save_clone.clone();

        let new_zone = FirewallZone {
            id: zone_id,
            name: name.get(),
            description: if description.get().is_empty() {
                None
            } else {
                Some(description.get())
            },
            interfaces: interfaces_str
                .get()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            default_input_policy: input_policy.get(),
            default_forward_policy: forward_policy.get(),
        };

        leptos::task::spawn_local(async move {
            match api::save_firewall_zone(&token, new_zone).await {
                Ok(_) => {
                    on_save(());
                }
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        error_message.set(e);
                    }
                }
            }
            saving.set(false);
        });
    };

    view! {
        <div class="bg-gray-700 p-4 rounded-lg space-y-4">
            <h3 class="text-lg font-medium text-gray-200">
                {if zone_id.is_some() { "Edit Zone" } else { "New Zone" }}
            </h3>

            <div class="grid grid-cols-2 gap-4">
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Name"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500 focus:border-blue-500 focus:outline-none"
                        prop:value=move || name.get()
                        on:input=move |ev| name.set(event_target_value(&ev))
                        placeholder="e.g., wan, lan, dmz"
                    />
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Description"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500 focus:border-blue-500 focus:outline-none"
                        prop:value=move || description.get()
                        on:input=move |ev| description.set(event_target_value(&ev))
                        placeholder="Optional description"
                    />
                </div>
            </div>

            <div>
                <label class="block text-sm text-gray-400 mb-1">"Interfaces (comma-separated)"</label>
                <input
                    type="text"
                    class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500 focus:border-blue-500 focus:outline-none"
                    prop:value=move || interfaces_str.get()
                    on:input=move |ev| interfaces_str.set(event_target_value(&ev))
                    placeholder="e.g., eth0, eth1"
                />
            </div>

            <div class="grid grid-cols-2 gap-4">
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Default Input Policy"</label>
                    <select
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500 focus:border-blue-500 focus:outline-none"
                        on:change=move |ev| {
                            let value = event_target_value(&ev);
                            input_policy.set(if value == "accept" { FirewallPolicy::Accept } else { FirewallPolicy::Drop });
                        }
                    >
                        <option value="drop" selected=move || input_policy.get() == FirewallPolicy::Drop>"Drop"</option>
                        <option value="accept" selected=move || input_policy.get() == FirewallPolicy::Accept>"Accept"</option>
                    </select>
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Default Forward Policy"</label>
                    <select
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500 focus:border-blue-500 focus:outline-none"
                        on:change=move |ev| {
                            let value = event_target_value(&ev);
                            forward_policy.set(if value == "accept" { FirewallPolicy::Accept } else { FirewallPolicy::Drop });
                        }
                    >
                        <option value="drop" selected=move || forward_policy.get() == FirewallPolicy::Drop>"Drop"</option>
                        <option value="accept" selected=move || forward_policy.get() == FirewallPolicy::Accept>"Accept"</option>
                    </select>
                </div>
            </div>

            <div class="flex gap-2 pt-2">
                <button
                    class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded disabled:opacity-50"
                    on:click=save_zone
                    disabled=move || saving.get() || name.get().is_empty()
                >
                    {move || if saving.get() { "Saving..." } else { "Save" }}
                </button>
                <button
                    class="px-4 py-2 bg-gray-600 hover:bg-gray-500 text-white rounded"
                    on:click=move |_| on_cancel()
                >
                    "Cancel"
                </button>
            </div>
        </div>
    }
}

// ============================================================================
// Zone Forwards Tab (Zone-to-Zone Forwarding Policies)
// ============================================================================

#[component]
fn ZoneForwardsTab(
    token: Signal<String>,
    reload_trigger: RwSignal<i32>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let zone_forwards = LocalResource::new(move || {
        let token = token.get();
        let _ = reload_trigger.get();
        async move { api::fetch_zone_forwards(&token).await }
    });

    let editing = RwSignal::new(Option::<ZoneForwardPolicy>::None);
    let error_message = RwSignal::new(String::new());

    view! {
        <div class="space-y-4">
            <div class="flex justify-between items-center">
                <div>
                    <h2 class="text-lg font-medium text-gray-200">"Zone-to-Zone Forwarding Policies"</h2>
                    <p class="text-sm text-gray-400">"Define default forwarding behavior between zones"</p>
                </div>
                <button
                    class="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm"
                    on:click=move |_| {
                        editing.set(Some(ZoneForwardPolicy {
                            id: None,
                            source_zone: String::new(),
                            dest_zone: String::new(),
                            policy: FirewallAction::Drop,
                            enabled: true,
                        }));
                    }
                >
                    "+ Add Policy"
                </button>
            </div>

            {move || {
                let msg = error_message.get();
                if msg.is_empty() {
                    view! { <div></div> }.into_any()
                } else {
                    view! {
                        <div class="bg-red-900/50 border border-red-700 text-red-200 px-4 py-2 rounded text-sm">
                            {msg}
                        </div>
                    }.into_any()
                }
            }}

            // Editor
            {move || {
                if let Some(policy) = editing.get() {
                    view! {
                        <ZoneForwardEditor
                            policy=policy
                            token=token.get()
                            on_save=move |_| {
                                editing.set(None);
                                reload_trigger.update(|v| *v += 1);
                            }
                            on_cancel=move || editing.set(None)
                            error_message=error_message
                            on_unauthorized=on_unauthorized
                        />
                    }.into_any()
                } else {
                    view! { <div></div> }.into_any()
                }
            }}

            <Suspense fallback=move || view! { <p class="text-gray-400">"Loading..."</p> }>
                {move || {
                    zone_forwards.get().map(|result| match result {
                        Ok(policies) => {
                            let is_empty = policies.is_empty();
                            let policies_for_loop = policies.clone();
                            view! {
                                <div class="overflow-x-auto">
                                    <table class="w-full text-sm">
                                        <thead class="text-gray-400 border-b border-gray-600">
                                            <tr>
                                                <th class="text-left py-2 px-2">"Source Zone"</th>
                                                <th class="text-left py-2 px-2">"Dest Zone"</th>
                                                <th class="text-left py-2 px-2">"Policy"</th>
                                                <th class="text-left py-2 px-2">"Enabled"</th>
                                                <th class="text-right py-2 px-2">"Actions"</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <For
                                                each=move || policies_for_loop.clone()
                                                key=|p| (p.id, p.source_zone.clone(), p.dest_zone.clone())
                                                children=move |policy| {
                                                    let policy_for_edit = policy.clone();
                                                    let policy_for_delete = policy.clone();
                                                    let token_del = token.get();
                                                    view! {
                                                        <tr class="border-b border-gray-700 hover:bg-gray-700/30">
                                                            <td class="py-2 px-2 text-gray-200">{policy.source_zone.clone()}</td>
                                                            <td class="py-2 px-2 text-gray-200">{policy.dest_zone.clone()}</td>
                                                            <td class="py-2 px-2">
                                                                <span class=match policy.policy {
                                                                    FirewallAction::Accept => "text-green-400",
                                                                    FirewallAction::Drop => "text-red-400",
                                                                    FirewallAction::Reject => "text-yellow-400",
                                                                }>
                                                                    {format!("{:?}", policy.policy)}
                                                                </span>
                                                            </td>
                                                            <td class="py-2 px-2">
                                                                {if policy.enabled {
                                                                    view! { <span class="text-green-400">"Yes"</span> }.into_any()
                                                                } else {
                                                                    view! { <span class="text-gray-500">"No"</span> }.into_any()
                                                                }}
                                                            </td>
                                                            <td class="py-2 px-2 text-right whitespace-nowrap">
                                                                <button
                                                                    class="text-blue-400 hover:text-blue-300 mr-2"
                                                                    on:click=move |_| editing.set(Some(policy_for_edit.clone()))
                                                                >
                                                                    "Edit"
                                                                </button>
                                                                <button
                                                                    class="text-red-400 hover:text-red-300"
                                                                     on:click=move |_| {
                                                                        if let Some(id) = policy_for_delete.id {
                                                                            let token = token_del.clone();
                                                                            leptos::task::spawn_local(async move {
                                                                                match api::delete_zone_forward(&token, id).await {
                                                                                    Ok(_) => reload_trigger.update(|v| *v += 1),
                                                                                    Err(e) => {
                                                                                        if e.contains("Unauthorized") {
                                                                                            on_unauthorized.run(());
                                                                                        } else {
                                                                                            error_message.set(e);
                                                                                        }
                                                                                    }
                                                                                }
                                                                            });
                                                                        }
                                                                    }
                                                                >
                                                                    "Delete"
                                                                </button>
                                                            </td>
                                                        </tr>
                                                    }
                                                }
                                            />
                                        </tbody>
                                    </table>
                                    {if is_empty {
                                        view! { <p class="text-gray-500 text-center py-4">"No zone forwarding policies configured"</p> }.into_any()
                                    } else {
                                        view! { <div></div> }.into_any()
                                    }}
                                </div>
                            }.into_any()
                        },
                        Err(e) => {
                            if e.contains("Unauthorized") {
                                on_unauthorized.run(());
                            }
                            view! { <p class="text-red-400">"Error: "{e}</p> }.into_any()
                        }
                    })
                }}
            </Suspense>
        </div>
    }
}

#[component]
fn ZoneForwardEditor(
    policy: ZoneForwardPolicy,
    token: String,
    on_save: impl Fn(()) + 'static,
    on_cancel: impl Fn() + 'static,
    error_message: RwSignal<String>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let source_zone = RwSignal::new(policy.source_zone.clone());
    let dest_zone = RwSignal::new(policy.dest_zone.clone());
    let policy_action = RwSignal::new(policy.policy);
    let enabled = RwSignal::new(policy.enabled);
    let saving = RwSignal::new(false);
    let policy_id = policy.id;

    let on_save = std::rc::Rc::new(on_save);
    let on_save_clone = on_save.clone();

    let save = move |_| {
        saving.set(true);
        error_message.set(String::new());

        let token = token.clone();
        let on_save = on_save_clone.clone();

        let new_policy = ZoneForwardPolicy {
            id: policy_id,
            source_zone: source_zone.get(),
            dest_zone: dest_zone.get(),
            policy: policy_action.get(),
            enabled: enabled.get(),
        };

        leptos::task::spawn_local(async move {
            match api::save_zone_forward(&token, new_policy).await {
                Ok(_) => on_save(()),
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        error_message.set(e);
                    }
                }
            }
            saving.set(false);
        });
    };

    view! {
        <div class="bg-gray-700 p-4 rounded-lg space-y-4">
            <h3 class="text-lg font-medium text-gray-200">
                {if policy_id.is_some() { "Edit Zone Forward Policy" } else { "New Zone Forward Policy" }}
            </h3>

            <div class="grid grid-cols-3 gap-4">
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Source Zone"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || source_zone.get()
                        on:input=move |ev| source_zone.set(event_target_value(&ev))
                        placeholder="e.g., lan"
                    />
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Destination Zone"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || dest_zone.get()
                        on:input=move |ev| dest_zone.set(event_target_value(&ev))
                        placeholder="e.g., wan"
                    />
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Policy"</label>
                    <select
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        on:change=move |ev| {
                            let value = event_target_value(&ev);
                            policy_action.set(match value.as_str() {
                                "accept" => FirewallAction::Accept,
                                "reject" => FirewallAction::Reject,
                                _ => FirewallAction::Drop,
                            });
                        }
                    >
                        <option value="accept" selected=move || policy_action.get() == FirewallAction::Accept>"Accept"</option>
                        <option value="drop" selected=move || policy_action.get() == FirewallAction::Drop>"Drop"</option>
                        <option value="reject" selected=move || policy_action.get() == FirewallAction::Reject>"Reject"</option>
                    </select>
                </div>
            </div>

            <div class="flex items-center gap-2">
                <input
                    type="checkbox"
                    id="zf-enabled"
                    class="w-4 h-4"
                    prop:checked=move || enabled.get()
                    on:change=move |ev| enabled.set(event_target_checked(&ev))
                />
                <label for="zf-enabled" class="text-gray-300">"Enabled"</label>
            </div>

            <div class="flex gap-2 pt-2">
                <button
                    class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded disabled:opacity-50"
                    on:click=save
                    disabled=move || saving.get() || source_zone.get().is_empty() || dest_zone.get().is_empty()
                >
                    {move || if saving.get() { "Saving..." } else { "Save" }}
                </button>
                <button
                    class="px-4 py-2 bg-gray-600 hover:bg-gray-500 text-white rounded"
                    on:click=move |_| on_cancel()
                >
                    "Cancel"
                </button>
            </div>
        </div>
    }
}

// ============================================================================
// Port Forwards Tab
// ============================================================================

#[component]
fn PortForwardsTab(
    token: Signal<String>,
    reload_trigger: RwSignal<i32>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let port_forwards = LocalResource::new(move || {
        let token = token.get();
        let _ = reload_trigger.get();
        async move { api::fetch_port_forwards(&token).await }
    });

    let editing = RwSignal::new(Option::<PortForward>::None);
    let error_message = RwSignal::new(String::new());

    view! {
        <div class="space-y-4">
            <div class="flex justify-between items-center">
                <h2 class="text-lg font-medium text-gray-200">"Port Forwards (DNAT)"</h2>
                <button
                    class="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm"
                    on:click=move |_| {
                        editing.set(Some(PortForward {
                            id: None,
                            name: String::new(),
                            description: None,
                            enabled: true,
                            protocol: RuleProtocol::Tcp,
                            source_zone: None,
                            external_port_start: 0,
                            external_port_end: None,
                            source_ip: None,
                            dest_ip: String::new(),
                            dest_port: None,
                        }));
                    }
                >
                    "+ Add Port Forward"
                </button>
            </div>

            {move || {
                let msg = error_message.get();
                if msg.is_empty() {
                    view! { <div></div> }.into_any()
                } else {
                    view! {
                        <div class="bg-red-900/50 border border-red-700 text-red-200 px-4 py-2 rounded text-sm">
                            {msg}
                        </div>
                    }.into_any()
                }
            }}

            // Editor
            {move || {
                if let Some(pf) = editing.get() {
                    view! {
                        <PortForwardEditor
                            port_forward=pf
                            token=token.get()
                            on_save=move |_| {
                                editing.set(None);
                                reload_trigger.update(|v| *v += 1);
                            }
                            on_cancel=move || editing.set(None)
                            error_message=error_message
                            on_unauthorized=on_unauthorized
                        />
                    }.into_any()
                } else {
                    view! { <div></div> }.into_any()
                }
            }}

            <Suspense fallback=move || view! { <p class="text-gray-400">"Loading..."</p> }>
                {move || {
                    port_forwards.get().map(|result| match result {
                        Ok(pfs) => {
                            let is_empty = pfs.is_empty();
                            let pfs_for_loop = pfs.clone();
                            view! {
                                <div class="overflow-x-auto">
                                    <table class="w-full text-sm">
                                        <thead class="text-gray-400 border-b border-gray-600">
                                            <tr>
                                                <th class="text-left py-2 px-2">"Name"</th>
                                                <th class="text-left py-2 px-2">"Protocol"</th>
                                                <th class="text-left py-2 px-2">"Ext. Port"</th>
                                                <th class="text-left py-2 px-2">"Dest IP"</th>
                                                <th class="text-left py-2 px-2">"Dest Port"</th>
                                                <th class="text-left py-2 px-2">"Enabled"</th>
                                                <th class="text-right py-2 px-2">"Actions"</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <For
                                                each=move || pfs_for_loop.clone()
                                                key=|pf| (pf.id, pf.name.clone())
                                                children=move |pf| {
                                                    let pf_edit = pf.clone();
                                                    let pf_delete = pf.clone();
                                                    let token_del = token.get();
                                                    view! {
                                                        <tr class="border-b border-gray-700">
                                                            <td class="py-2 px-2 text-gray-200">{pf.name.clone()}</td>
                                                            <td class="py-2 px-2 text-gray-300">{format!("{:?}", pf.protocol)}</td>
                                                            <td class="py-2 px-2 text-gray-300">
                                                                {pf.external_port_start}
                                                                {pf.external_port_end.map(|e| format!("-{}", e)).unwrap_or_default()}
                                                            </td>
                                                            <td class="py-2 px-2 text-gray-300">{pf.dest_ip.clone()}</td>
                                                            <td class="py-2 px-2 text-gray-300">
                                                                {pf.dest_port.map(|p| p.to_string()).unwrap_or_else(|| "(same)".to_string())}
                                                            </td>
                                                            <td class="py-2 px-2">
                                                                {if pf.enabled {
                                                                    view! { <span class="text-green-400">"Yes"</span> }.into_any()
                                                                } else {
                                                                    view! { <span class="text-gray-500">"No"</span> }.into_any()
                                                                }}
                                                            </td>
                                                            <td class="py-2 px-2 text-right">
                                                                <button
                                                                    class="text-blue-400 hover:text-blue-300 mr-2"
                                                                    on:click=move |_| editing.set(Some(pf_edit.clone()))
                                                                >
                                                                    "Edit"
                                                                </button>
                                                                <button
                                                                    class="text-red-400 hover:text-red-300"
                                                                     on:click=move |_| {
                                                                        if let Some(id) = pf_delete.id {
                                                                            let token = token_del.clone();
                                                                            leptos::task::spawn_local(async move {
                                                                                match api::delete_port_forward(&token, id).await {
                                                                                    Ok(_) => reload_trigger.update(|v| *v += 1),
                                                                                    Err(e) => {
                                                                                        if e.contains("Unauthorized") {
                                                                                            on_unauthorized.run(());
                                                                                        } else {
                                                                                            error_message.set(e);
                                                                                        }
                                                                                    }
                                                                                }
                                                                            });
                                                                        }
                                                                    }
                                                                >
                                                                    "Delete"
                                                                </button>
                                                            </td>
                                                        </tr>
                                                    }
                                                }
                                            />
                                        </tbody>
                                    </table>
                                    {if is_empty {
                                        view! { <p class="text-gray-500 text-center py-4">"No port forwards configured"</p> }.into_any()
                                    } else {
                                        view! { <div></div> }.into_any()
                                    }}
                                </div>
                            }.into_any()
                        },
                        Err(e) => {
                            if e.contains("Unauthorized") {
                                on_unauthorized.run(());
                            }
                            view! { <p class="text-red-400">"Error: "{e}</p> }.into_any()
                        }
                    })
                }}
            </Suspense>
        </div>
    }
}

#[component]
fn PortForwardEditor(
    port_forward: PortForward,
    token: String,
    on_save: impl Fn(()) + 'static,
    on_cancel: impl Fn() + 'static,
    error_message: RwSignal<String>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let name = RwSignal::new(port_forward.name.clone());
    let protocol = RwSignal::new(port_forward.protocol);
    let external_port = RwSignal::new(port_forward.external_port_start.to_string());
    let dest_ip = RwSignal::new(port_forward.dest_ip.clone());
    let dest_port = RwSignal::new(
        port_forward
            .dest_port
            .map(|p| p.to_string())
            .unwrap_or_default(),
    );
    let enabled = RwSignal::new(port_forward.enabled);
    let saving = RwSignal::new(false);
    let pf_id = port_forward.id;

    let on_save = std::rc::Rc::new(on_save);
    let on_save_clone = on_save.clone();

    let save = move |_| {
        saving.set(true);
        error_message.set(String::new());

        let token = token.clone();
        let on_save = on_save_clone.clone();

        let ext_port: u16 = external_port.get().parse().unwrap_or(0);
        let dst_port: Option<u16> = dest_port.get().parse().ok();

        let pf = PortForward {
            id: pf_id,
            name: name.get(),
            description: None,
            enabled: enabled.get(),
            protocol: protocol.get(),
            source_zone: None,
            external_port_start: ext_port,
            external_port_end: None,
            source_ip: None,
            dest_ip: dest_ip.get(),
            dest_port: dst_port,
        };

        leptos::task::spawn_local(async move {
            match api::save_port_forward(&token, pf).await {
                Ok(_) => on_save(()),
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        error_message.set(e);
                    }
                }
            }
            saving.set(false);
        });
    };

    view! {
        <div class="bg-gray-700 p-4 rounded-lg space-y-4">
            <h3 class="text-lg font-medium text-gray-200">
                {if pf_id.is_some() { "Edit Port Forward" } else { "New Port Forward" }}
            </h3>

            <div class="grid grid-cols-2 gap-4">
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Name"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || name.get()
                        on:input=move |ev| name.set(event_target_value(&ev))
                    />
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Protocol"</label>
                    <select
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        on:change=move |ev| {
                            let value = event_target_value(&ev);
                            protocol.set(match value.as_str() {
                                "tcp" => RuleProtocol::Tcp,
                                "udp" => RuleProtocol::Udp,
                                "tcp+udp" => RuleProtocol::TcpUdp,
                                _ => RuleProtocol::Tcp,
                            });
                        }
                    >
                        <option value="tcp" selected=move || protocol.get() == RuleProtocol::Tcp>"TCP"</option>
                        <option value="udp" selected=move || protocol.get() == RuleProtocol::Udp>"UDP"</option>
                        <option value="tcp+udp" selected=move || protocol.get() == RuleProtocol::TcpUdp>"TCP+UDP"</option>
                    </select>
                </div>
            </div>

            <div class="grid grid-cols-3 gap-4">
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"External Port"</label>
                    <input
                        type="number"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || external_port.get()
                        on:input=move |ev| external_port.set(event_target_value(&ev))
                    />
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Destination IP"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || dest_ip.get()
                        on:input=move |ev| dest_ip.set(event_target_value(&ev))
                        placeholder="e.g., 192.168.1.100"
                    />
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Dest Port (blank=same)"</label>
                    <input
                        type="number"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || dest_port.get()
                        on:input=move |ev| dest_port.set(event_target_value(&ev))
                    />
                </div>
            </div>

            <div class="flex items-center gap-2">
                <input
                    type="checkbox"
                    id="pf-enabled"
                    class="w-4 h-4"
                    prop:checked=move || enabled.get()
                    on:change=move |ev| enabled.set(event_target_checked(&ev))
                />
                <label for="pf-enabled" class="text-gray-300">"Enabled"</label>
            </div>

            <div class="flex gap-2 pt-2">
                <button
                    class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded disabled:opacity-50"
                    on:click=save
                    disabled=move || saving.get()
                >
                    {move || if saving.get() { "Saving..." } else { "Save" }}
                </button>
                <button
                    class="px-4 py-2 bg-gray-600 hover:bg-gray-500 text-white rounded"
                    on:click=move |_| on_cancel()
                >
                    "Cancel"
                </button>
            </div>
        </div>
    }
}

// ============================================================================
// Input Rules Tab
// ============================================================================

#[component]
fn InputRulesTab(
    token: Signal<String>,
    reload_trigger: RwSignal<i32>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let rules = LocalResource::new(move || {
        let token = token.get();
        let _ = reload_trigger.get();
        async move { api::fetch_input_rules(&token).await }
    });

    let editing = RwSignal::new(Option::<InputRule>::None);
    let error_message = RwSignal::new(String::new());

    // Create a new default rule
    let new_rule = move || InputRule {
        id: None,
        name: String::new(),
        description: None,
        enabled: true,
        position: 100,
        zone: None,
        protocol: None,
        port_start: None,
        port_end: None,
        source_ip: None,
        action: FirewallAction::Accept,
        log_enabled: false,
        log_prefix: None,
        rate_limit: None,
    };

    // Clone a rule (create copy with no ID)
    let clone_rule = move |rule: &InputRule| -> InputRule {
        InputRule {
            id: None,
            name: format!("{} (copy)", rule.name),
            ..rule.clone()
        }
    };

    view! {
        <div class="space-y-4">
            <div class="flex justify-between items-center">
                <div>
                    <h2 class="text-lg font-medium text-gray-200">"Input Rules (Traffic to Router)"</h2>
                    <p class="text-sm text-gray-400">"Rules are evaluated in order; first match wins"</p>
                </div>
                <button
                    class="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm"
                    on:click=move |_| editing.set(Some(new_rule()))
                >
                    "+ Add Rule"
                </button>
            </div>

            {move || {
                let msg = error_message.get();
                if msg.is_empty() {
                    view! { <div></div> }.into_any()
                } else {
                    view! {
                        <div class="bg-red-900/50 border border-red-700 text-red-200 px-4 py-2 rounded text-sm">
                            {msg}
                        </div>
                    }.into_any()
                }
            }}

            // Editor modal
            {move || {
                if let Some(rule) = editing.get() {
                    view! {
                        <InputRuleEditor
                            rule=rule
                            token=token.get()
                            on_save=move |_| {
                                editing.set(None);
                                reload_trigger.update(|v| *v += 1);
                            }
                            on_cancel=move || editing.set(None)
                            error_message=error_message
                            on_unauthorized=on_unauthorized
                        />
                    }.into_any()
                } else {
                    view! { <div></div> }.into_any()
                }
            }}

            <Suspense fallback=move || view! { <p class="text-gray-400">"Loading..."</p> }>
                {move || {
                    rules.get().map(|result| match result {
                        Ok(rule_list) => {
                            let is_empty = rule_list.is_empty();
                            let rules_for_loop = rule_list.clone();
                            view! {
                                <div class="overflow-x-auto">
                                    <table class="w-full text-sm">
                                        <thead class="text-gray-400 border-b border-gray-600">
                                            <tr>
                                                <th class="text-left py-2 px-2">"#"</th>
                                                <th class="text-left py-2 px-2">"Name"</th>
                                                <th class="text-left py-2 px-2">"Zone"</th>
                                                <th class="text-left py-2 px-2">"Protocol"</th>
                                                <th class="text-left py-2 px-2">"Port"</th>
                                                <th class="text-left py-2 px-2">"Action"</th>
                                                <th class="text-left py-2 px-2">"Enabled"</th>
                                                <th class="text-right py-2 px-2">"Actions"</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <For
                                                each=move || rules_for_loop.clone()
                                                key=|r| (r.id, r.name.clone(), r.enabled)
                                                children=move |rule| {
                                                    let rule_for_edit = rule.clone();
                                                    let rule_for_clone = rule.clone();
                                                    let rule_for_delete = rule.clone();
                                                    let token_del = token.get();
                                                    view! {
                                                        <tr class="border-b border-gray-700 hover:bg-gray-700/30">
                                                            <td class="py-2 px-2 text-gray-400">{rule.position}</td>
                                                            <td class="py-2 px-2 text-gray-200">{rule.name.clone()}</td>
                                                            <td class="py-2 px-2 text-gray-300">{rule.zone.clone().unwrap_or_else(|| "any".to_string())}</td>
                                                            <td class="py-2 px-2 text-gray-300">
                                                                {rule.protocol.as_ref().map(|p| format!("{:?}", p)).unwrap_or_else(|| "any".to_string())}
                                                            </td>
                                                            <td class="py-2 px-2 text-gray-300">
                                                                {rule.port_start.map(|p| {
                                                                    if let Some(end) = rule.port_end {
                                                                        format!("{}-{}", p, end)
                                                                    } else {
                                                                        p.to_string()
                                                                    }
                                                                }).unwrap_or_else(|| "any".to_string())}
                                                            </td>
                                                            <td class="py-2 px-2">
                                                                <span class=match rule.action {
                                                                    FirewallAction::Accept => "text-green-400",
                                                                    FirewallAction::Drop => "text-red-400",
                                                                    FirewallAction::Reject => "text-yellow-400",
                                                                }>
                                                                    {format!("{:?}", rule.action)}
                                                                </span>
                                                            </td>
                                                            <td class="py-2 px-2">
                                                                {if rule.enabled {
                                                                    view! { <span class="text-green-400">"Yes"</span> }.into_any()
                                                                } else {
                                                                    view! { <span class="text-gray-500">"No"</span> }.into_any()
                                                                }}
                                                            </td>
                                                            <td class="py-2 px-2 text-right whitespace-nowrap">
                                                                <button
                                                                    class="text-blue-400 hover:text-blue-300 mr-2"
                                                                    title="Edit"
                                                                    on:click=move |_| editing.set(Some(rule_for_edit.clone()))
                                                                >
                                                                    "Edit"
                                                                </button>
                                                                <button
                                                                    class="text-purple-400 hover:text-purple-300 mr-2"
                                                                    title="Clone"
                                                                    on:click=move |_| editing.set(Some(clone_rule(&rule_for_clone)))
                                                                >
                                                                    "Clone"
                                                                </button>
                                                                <button
                                                                    class="text-red-400 hover:text-red-300"
                                                                    title="Delete"
                                                                     on:click=move |_| {
                                                                        if let Some(id) = rule_for_delete.id {
                                                                            let token = token_del.clone();
                                                                            leptos::task::spawn_local(async move {
                                                                                match api::delete_input_rule(&token, id).await {
                                                                                    Ok(_) => reload_trigger.update(|v| *v += 1),
                                                                                    Err(e) => {
                                                                                        if e.contains("Unauthorized") {
                                                                                            on_unauthorized.run(());
                                                                                        } else {
                                                                                            error_message.set(e);
                                                                                        }
                                                                                    }
                                                                                }
                                                                            });
                                                                        }
                                                                    }
                                                                >
                                                                    "Delete"
                                                                </button>
                                                            </td>
                                                        </tr>
                                                    }
                                                }
                                            />
                                        </tbody>
                                    </table>
                                    {if is_empty {
                                        view! { <p class="text-gray-500 text-center py-4">"No input rules configured"</p> }.into_any()
                                    } else {
                                        view! { <div></div> }.into_any()
                                    }}
                                </div>
                            }.into_any()
                        },
                        Err(e) => {
                            if e.contains("Unauthorized") {
                                on_unauthorized.run(());
                            }
                            view! { <p class="text-red-400">"Error: "{e}</p> }.into_any()
                        }
                    })
                }}
            </Suspense>
        </div>
    }
}

#[component]
fn InputRuleEditor(
    rule: InputRule,
    token: String,
    on_save: impl Fn(()) + 'static,
    on_cancel: impl Fn() + 'static,
    error_message: RwSignal<String>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let name = RwSignal::new(rule.name.clone());
    let description = RwSignal::new(rule.description.clone().unwrap_or_default());
    let enabled = RwSignal::new(rule.enabled);
    let position = RwSignal::new(rule.position.to_string());
    let zone = RwSignal::new(rule.zone.clone().unwrap_or_default());
    let protocol = RwSignal::new(rule.protocol);
    let port_start = RwSignal::new(rule.port_start.map(|p| p.to_string()).unwrap_or_default());
    let port_end = RwSignal::new(rule.port_end.map(|p| p.to_string()).unwrap_or_default());
    let source_ip = RwSignal::new(rule.source_ip.clone().unwrap_or_default());
    let action = RwSignal::new(rule.action);
    let log_enabled = RwSignal::new(rule.log_enabled);
    let log_prefix = RwSignal::new(rule.log_prefix.clone().unwrap_or_default());
    let rate_limit = RwSignal::new(rule.rate_limit.clone().unwrap_or_default());
    let saving = RwSignal::new(false);
    let rule_id = rule.id;

    let on_save = std::rc::Rc::new(on_save);
    let on_save_clone = on_save.clone();

    let save = move |_| {
        saving.set(true);
        error_message.set(String::new());

        let token = token.clone();
        let on_save = on_save_clone.clone();

        let new_rule = InputRule {
            id: rule_id,
            name: name.get(),
            description: if description.get().is_empty() {
                None
            } else {
                Some(description.get())
            },
            enabled: enabled.get(),
            position: position.get().parse().unwrap_or(100),
            zone: if zone.get().is_empty() {
                None
            } else {
                Some(zone.get())
            },
            protocol: protocol.get(),
            port_start: port_start.get().parse().ok(),
            port_end: port_end.get().parse().ok(),
            source_ip: if source_ip.get().is_empty() {
                None
            } else {
                Some(source_ip.get())
            },
            action: action.get(),
            log_enabled: log_enabled.get(),
            log_prefix: if log_prefix.get().is_empty() {
                None
            } else {
                Some(log_prefix.get())
            },
            rate_limit: if rate_limit.get().is_empty() {
                None
            } else {
                Some(rate_limit.get())
            },
        };

        leptos::task::spawn_local(async move {
            match api::save_input_rule(&token, new_rule).await {
                Ok(_) => on_save(()),
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        error_message.set(e);
                    }
                }
            }
            saving.set(false);
        });
    };

    view! {
        <div class="bg-gray-700 p-4 rounded-lg space-y-4">
            <h3 class="text-lg font-medium text-gray-200">
                {if rule_id.is_some() { "Edit Input Rule" } else { "New Input Rule" }}
            </h3>

            <div class="grid grid-cols-2 gap-4">
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Name"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || name.get()
                        on:input=move |ev| name.set(event_target_value(&ev))
                        placeholder="e.g., Allow SSH"
                    />
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Position (lower = higher priority)"</label>
                    <input
                        type="number"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || position.get()
                        on:input=move |ev| position.set(event_target_value(&ev))
                    />
                </div>
            </div>

            <div>
                <label class="block text-sm text-gray-400 mb-1">"Description"</label>
                <input
                    type="text"
                    class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                    prop:value=move || description.get()
                    on:input=move |ev| description.set(event_target_value(&ev))
                    placeholder="Optional description"
                />
            </div>

            <div class="grid grid-cols-3 gap-4">
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Zone (blank = any)"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || zone.get()
                        on:input=move |ev| zone.set(event_target_value(&ev))
                        placeholder="e.g., wan"
                    />
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Protocol"</label>
                    <select
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        on:change=move |ev| {
                            let value = event_target_value(&ev);
                            protocol.set(match value.as_str() {
                                "tcp" => Some(RuleProtocol::Tcp),
                                "udp" => Some(RuleProtocol::Udp),
                                "tcp+udp" => Some(RuleProtocol::TcpUdp),
                                "icmp" => Some(RuleProtocol::Icmp),
                                "icmpv6" => Some(RuleProtocol::Icmpv6),
                                _ => None,
                            });
                        }
                    >
                        <option value="" selected=move || protocol.get().is_none()>"Any"</option>
                        <option value="tcp" selected=move || protocol.get() == Some(RuleProtocol::Tcp)>"TCP"</option>
                        <option value="udp" selected=move || protocol.get() == Some(RuleProtocol::Udp)>"UDP"</option>
                        <option value="tcp+udp" selected=move || protocol.get() == Some(RuleProtocol::TcpUdp)>"TCP+UDP"</option>
                        <option value="icmp" selected=move || protocol.get() == Some(RuleProtocol::Icmp)>"ICMP"</option>
                        <option value="icmpv6" selected=move || protocol.get() == Some(RuleProtocol::Icmpv6)>"ICMPv6"</option>
                    </select>
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Action"</label>
                    <select
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        on:change=move |ev| {
                            let value = event_target_value(&ev);
                            action.set(match value.as_str() {
                                "accept" => FirewallAction::Accept,
                                "reject" => FirewallAction::Reject,
                                _ => FirewallAction::Drop,
                            });
                        }
                    >
                        <option value="accept" selected=move || action.get() == FirewallAction::Accept>"Accept"</option>
                        <option value="drop" selected=move || action.get() == FirewallAction::Drop>"Drop"</option>
                        <option value="reject" selected=move || action.get() == FirewallAction::Reject>"Reject"</option>
                    </select>
                </div>
            </div>

            <div class="grid grid-cols-3 gap-4">
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Port Start"</label>
                    <input
                        type="number"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || port_start.get()
                        on:input=move |ev| port_start.set(event_target_value(&ev))
                        placeholder="e.g., 22"
                    />
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Port End (for range)"</label>
                    <input
                        type="number"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || port_end.get()
                        on:input=move |ev| port_end.set(event_target_value(&ev))
                        placeholder="blank = single port"
                    />
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Source IP/CIDR"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || source_ip.get()
                        on:input=move |ev| source_ip.set(event_target_value(&ev))
                        placeholder="e.g., 192.168.1.0/24"
                    />
                </div>
            </div>

            <div class="grid grid-cols-3 gap-4">
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Rate Limit"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || rate_limit.get()
                        on:input=move |ev| rate_limit.set(event_target_value(&ev))
                        placeholder="e.g., 10/minute"
                    />
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Log Prefix"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || log_prefix.get()
                        on:input=move |ev| log_prefix.set(event_target_value(&ev))
                        placeholder="e.g., INPUT_DROP"
                    />
                </div>
                <div class="flex items-end gap-4">
                    <div class="flex items-center gap-2">
                        <input
                            type="checkbox"
                            id="input-enabled"
                            class="w-4 h-4"
                            prop:checked=move || enabled.get()
                            on:change=move |ev| enabled.set(event_target_checked(&ev))
                        />
                        <label for="input-enabled" class="text-gray-300">"Enabled"</label>
                    </div>
                    <div class="flex items-center gap-2">
                        <input
                            type="checkbox"
                            id="input-log"
                            class="w-4 h-4"
                            prop:checked=move || log_enabled.get()
                            on:change=move |ev| log_enabled.set(event_target_checked(&ev))
                        />
                        <label for="input-log" class="text-gray-300">"Log"</label>
                    </div>
                </div>
            </div>

            <div class="flex gap-2 pt-2">
                <button
                    class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded disabled:opacity-50"
                    on:click=save
                    disabled=move || saving.get() || name.get().is_empty()
                >
                    {move || if saving.get() { "Saving..." } else { "Save" }}
                </button>
                <button
                    class="px-4 py-2 bg-gray-600 hover:bg-gray-500 text-white rounded"
                    on:click=move |_| on_cancel()
                >
                    "Cancel"
                </button>
            </div>
        </div>
    }
}

// ============================================================================
// Forward Rules Tab
// ============================================================================

#[component]
fn ForwardRulesTab(
    token: Signal<String>,
    reload_trigger: RwSignal<i32>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let rules = LocalResource::new(move || {
        let token = token.get();
        let _ = reload_trigger.get();
        async move { api::fetch_forward_rules(&token).await }
    });

    let editing = RwSignal::new(Option::<ForwardRule>::None);
    let error_message = RwSignal::new(String::new());

    // Create a new default rule
    let new_rule = move || ForwardRule {
        id: None,
        name: String::new(),
        description: None,
        enabled: true,
        position: 100,
        source_zone: None,
        dest_zone: None,
        protocol: None,
        dest_port_start: None,
        dest_port_end: None,
        source_ip: None,
        dest_ip: None,
        action: FirewallAction::Accept,
        log_enabled: false,
        log_prefix: None,
        rate_limit: None,
    };

    // Clone a rule
    let clone_rule = move |rule: &ForwardRule| -> ForwardRule {
        ForwardRule {
            id: None,
            name: format!("{} (copy)", rule.name),
            ..rule.clone()
        }
    };

    view! {
        <div class="space-y-4">
            <div class="flex justify-between items-center">
                <div>
                    <h2 class="text-lg font-medium text-gray-200">"Forward Rules (Traffic Through Router)"</h2>
                    <p class="text-sm text-gray-400">"Rules are evaluated in order; first match wins"</p>
                </div>
                <button
                    class="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm"
                    on:click=move |_| editing.set(Some(new_rule()))
                >
                    "+ Add Rule"
                </button>
            </div>

            {move || {
                let msg = error_message.get();
                if msg.is_empty() {
                    view! { <div></div> }.into_any()
                } else {
                    view! {
                        <div class="bg-red-900/50 border border-red-700 text-red-200 px-4 py-2 rounded text-sm">
                            {msg}
                        </div>
                    }.into_any()
                }
            }}

            // Editor modal
            {move || {
                if let Some(rule) = editing.get() {
                    view! {
                        <ForwardRuleEditor
                            rule=rule
                            token=token.get()
                            on_save=move |_| {
                                editing.set(None);
                                reload_trigger.update(|v| *v += 1);
                            }
                            on_cancel=move || editing.set(None)
                            error_message=error_message
                            on_unauthorized=on_unauthorized
                        />
                    }.into_any()
                } else {
                    view! { <div></div> }.into_any()
                }
            }}

            <Suspense fallback=move || view! { <p class="text-gray-400">"Loading..."</p> }>
                {move || {
                    rules.get().map(|result| match result {
                        Ok(rule_list) => {
                            let is_empty = rule_list.is_empty();
                            let rules_for_loop = rule_list.clone();
                            view! {
                                <div class="overflow-x-auto">
                                    <table class="w-full text-sm">
                                        <thead class="text-gray-400 border-b border-gray-600">
                                            <tr>
                                                <th class="text-left py-2 px-2">"#"</th>
                                                <th class="text-left py-2 px-2">"Name"</th>
                                                <th class="text-left py-2 px-2">"Src Zone"</th>
                                                <th class="text-left py-2 px-2">"Dst Zone"</th>
                                                <th class="text-left py-2 px-2">"Protocol"</th>
                                                <th class="text-left py-2 px-2">"Action"</th>
                                                <th class="text-left py-2 px-2">"Enabled"</th>
                                                <th class="text-right py-2 px-2">"Actions"</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <For
                                                each=move || rules_for_loop.clone()
                                                key=|r| (r.id, r.name.clone(), r.enabled)
                                                children=move |rule| {
                                                    let rule_for_edit = rule.clone();
                                                    let rule_for_clone = rule.clone();
                                                    let rule_for_delete = rule.clone();
                                                    let token_del = token.get();
                                                    view! {
                                                        <tr class="border-b border-gray-700 hover:bg-gray-700/30">
                                                            <td class="py-2 px-2 text-gray-400">{rule.position}</td>
                                                            <td class="py-2 px-2 text-gray-200">{rule.name.clone()}</td>
                                                            <td class="py-2 px-2 text-gray-300">{rule.source_zone.clone().unwrap_or_else(|| "any".to_string())}</td>
                                                            <td class="py-2 px-2 text-gray-300">{rule.dest_zone.clone().unwrap_or_else(|| "any".to_string())}</td>
                                                            <td class="py-2 px-2 text-gray-300">
                                                                {rule.protocol.as_ref().map(|p| format!("{:?}", p)).unwrap_or_else(|| "any".to_string())}
                                                            </td>
                                                            <td class="py-2 px-2">
                                                                <span class=match rule.action {
                                                                    FirewallAction::Accept => "text-green-400",
                                                                    FirewallAction::Drop => "text-red-400",
                                                                    FirewallAction::Reject => "text-yellow-400",
                                                                }>
                                                                    {format!("{:?}", rule.action)}
                                                                </span>
                                                            </td>
                                                            <td class="py-2 px-2">
                                                                {if rule.enabled {
                                                                    view! { <span class="text-green-400">"Yes"</span> }.into_any()
                                                                } else {
                                                                    view! { <span class="text-gray-500">"No"</span> }.into_any()
                                                                }}
                                                            </td>
                                                            <td class="py-2 px-2 text-right whitespace-nowrap">
                                                                <button
                                                                    class="text-blue-400 hover:text-blue-300 mr-2"
                                                                    title="Edit"
                                                                    on:click=move |_| editing.set(Some(rule_for_edit.clone()))
                                                                >
                                                                    "Edit"
                                                                </button>
                                                                <button
                                                                    class="text-purple-400 hover:text-purple-300 mr-2"
                                                                    title="Clone"
                                                                    on:click=move |_| editing.set(Some(clone_rule(&rule_for_clone)))
                                                                >
                                                                    "Clone"
                                                                </button>
                                                                <button
                                                                    class="text-red-400 hover:text-red-300"
                                                                    title="Delete"
                                                                     on:click=move |_| {
                                                                        if let Some(id) = rule_for_delete.id {
                                                                            let token = token_del.clone();
                                                                            leptos::task::spawn_local(async move {
                                                                                match api::delete_forward_rule(&token, id).await {
                                                                                    Ok(_) => reload_trigger.update(|v| *v += 1),
                                                                                    Err(e) => {
                                                                                        if e.contains("Unauthorized") {
                                                                                            on_unauthorized.run(());
                                                                                        } else {
                                                                                            error_message.set(e);
                                                                                        }
                                                                                    }
                                                                                }
                                                                            });
                                                                        }
                                                                    }
                                                                >
                                                                    "Delete"
                                                                </button>
                                                            </td>
                                                        </tr>
                                                    }
                                                }
                                            />
                                        </tbody>
                                    </table>
                                    {if is_empty {
                                        view! { <p class="text-gray-500 text-center py-4">"No forward rules configured"</p> }.into_any()
                                    } else {
                                        view! { <div></div> }.into_any()
                                    }}
                                </div>
                            }.into_any()
                        },
                        Err(e) => {
                            if e.contains("Unauthorized") {
                                on_unauthorized.run(());
                            }
                            view! { <p class="text-red-400">"Error: "{e}</p> }.into_any()
                        }
                    })
                }}
            </Suspense>
        </div>
    }
}

#[component]
fn ForwardRuleEditor(
    rule: ForwardRule,
    token: String,
    on_save: impl Fn(()) + 'static,
    on_cancel: impl Fn() + 'static,
    error_message: RwSignal<String>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let name = RwSignal::new(rule.name.clone());
    let description = RwSignal::new(rule.description.clone().unwrap_or_default());
    let enabled = RwSignal::new(rule.enabled);
    let position = RwSignal::new(rule.position.to_string());
    let source_zone = RwSignal::new(rule.source_zone.clone().unwrap_or_default());
    let dest_zone = RwSignal::new(rule.dest_zone.clone().unwrap_or_default());
    let protocol = RwSignal::new(rule.protocol);
    let dest_port_start = RwSignal::new(
        rule.dest_port_start
            .map(|p| p.to_string())
            .unwrap_or_default(),
    );
    let dest_port_end = RwSignal::new(
        rule.dest_port_end
            .map(|p| p.to_string())
            .unwrap_or_default(),
    );
    let source_ip = RwSignal::new(rule.source_ip.clone().unwrap_or_default());
    let dest_ip = RwSignal::new(rule.dest_ip.clone().unwrap_or_default());
    let action = RwSignal::new(rule.action);
    let log_enabled = RwSignal::new(rule.log_enabled);
    let log_prefix = RwSignal::new(rule.log_prefix.clone().unwrap_or_default());
    let rate_limit = RwSignal::new(rule.rate_limit.clone().unwrap_or_default());
    let saving = RwSignal::new(false);
    let rule_id = rule.id;

    let on_save = std::rc::Rc::new(on_save);
    let on_save_clone = on_save.clone();

    let save = move |_| {
        saving.set(true);
        error_message.set(String::new());

        let token = token.clone();
        let on_save = on_save_clone.clone();

        let new_rule = ForwardRule {
            id: rule_id,
            name: name.get(),
            description: if description.get().is_empty() {
                None
            } else {
                Some(description.get())
            },
            enabled: enabled.get(),
            position: position.get().parse().unwrap_or(100),
            source_zone: if source_zone.get().is_empty() {
                None
            } else {
                Some(source_zone.get())
            },
            dest_zone: if dest_zone.get().is_empty() {
                None
            } else {
                Some(dest_zone.get())
            },
            protocol: protocol.get(),
            dest_port_start: dest_port_start.get().parse().ok(),
            dest_port_end: dest_port_end.get().parse().ok(),
            source_ip: if source_ip.get().is_empty() {
                None
            } else {
                Some(source_ip.get())
            },
            dest_ip: if dest_ip.get().is_empty() {
                None
            } else {
                Some(dest_ip.get())
            },
            action: action.get(),
            log_enabled: log_enabled.get(),
            log_prefix: if log_prefix.get().is_empty() {
                None
            } else {
                Some(log_prefix.get())
            },
            rate_limit: if rate_limit.get().is_empty() {
                None
            } else {
                Some(rate_limit.get())
            },
        };

        leptos::task::spawn_local(async move {
            match api::save_forward_rule(&token, new_rule).await {
                Ok(_) => on_save(()),
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        error_message.set(e);
                    }
                }
            }
            saving.set(false);
        });
    };

    view! {
        <div class="bg-gray-700 p-4 rounded-lg space-y-4">
            <h3 class="text-lg font-medium text-gray-200">
                {if rule_id.is_some() { "Edit Forward Rule" } else { "New Forward Rule" }}
            </h3>

            <div class="grid grid-cols-2 gap-4">
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Name"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || name.get()
                        on:input=move |ev| name.set(event_target_value(&ev))
                        placeholder="e.g., Allow LAN to WAN"
                    />
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Position (lower = higher priority)"</label>
                    <input
                        type="number"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || position.get()
                        on:input=move |ev| position.set(event_target_value(&ev))
                    />
                </div>
            </div>

            <div>
                <label class="block text-sm text-gray-400 mb-1">"Description"</label>
                <input
                    type="text"
                    class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                    prop:value=move || description.get()
                    on:input=move |ev| description.set(event_target_value(&ev))
                    placeholder="Optional description"
                />
            </div>

            <div class="grid grid-cols-4 gap-4">
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Source Zone"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || source_zone.get()
                        on:input=move |ev| source_zone.set(event_target_value(&ev))
                        placeholder="e.g., lan (blank=any)"
                    />
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Dest Zone"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || dest_zone.get()
                        on:input=move |ev| dest_zone.set(event_target_value(&ev))
                        placeholder="e.g., wan (blank=any)"
                    />
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Protocol"</label>
                    <select
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        on:change=move |ev| {
                            let value = event_target_value(&ev);
                            protocol.set(match value.as_str() {
                                "tcp" => Some(RuleProtocol::Tcp),
                                "udp" => Some(RuleProtocol::Udp),
                                "tcp+udp" => Some(RuleProtocol::TcpUdp),
                                "icmp" => Some(RuleProtocol::Icmp),
                                "icmpv6" => Some(RuleProtocol::Icmpv6),
                                _ => None,
                            });
                        }
                    >
                        <option value="" selected=move || protocol.get().is_none()>"Any"</option>
                        <option value="tcp" selected=move || protocol.get() == Some(RuleProtocol::Tcp)>"TCP"</option>
                        <option value="udp" selected=move || protocol.get() == Some(RuleProtocol::Udp)>"UDP"</option>
                        <option value="tcp+udp" selected=move || protocol.get() == Some(RuleProtocol::TcpUdp)>"TCP+UDP"</option>
                        <option value="icmp" selected=move || protocol.get() == Some(RuleProtocol::Icmp)>"ICMP"</option>
                        <option value="icmpv6" selected=move || protocol.get() == Some(RuleProtocol::Icmpv6)>"ICMPv6"</option>
                    </select>
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Action"</label>
                    <select
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        on:change=move |ev| {
                            let value = event_target_value(&ev);
                            action.set(match value.as_str() {
                                "accept" => FirewallAction::Accept,
                                "reject" => FirewallAction::Reject,
                                _ => FirewallAction::Drop,
                            });
                        }
                    >
                        <option value="accept" selected=move || action.get() == FirewallAction::Accept>"Accept"</option>
                        <option value="drop" selected=move || action.get() == FirewallAction::Drop>"Drop"</option>
                        <option value="reject" selected=move || action.get() == FirewallAction::Reject>"Reject"</option>
                    </select>
                </div>
            </div>

            <div class="grid grid-cols-4 gap-4">
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Dest Port Start"</label>
                    <input
                        type="number"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || dest_port_start.get()
                        on:input=move |ev| dest_port_start.set(event_target_value(&ev))
                        placeholder="e.g., 80"
                    />
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Dest Port End"</label>
                    <input
                        type="number"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || dest_port_end.get()
                        on:input=move |ev| dest_port_end.set(event_target_value(&ev))
                        placeholder="blank = single port"
                    />
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Source IP/CIDR"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || source_ip.get()
                        on:input=move |ev| source_ip.set(event_target_value(&ev))
                        placeholder="blank = any"
                    />
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Dest IP/CIDR"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || dest_ip.get()
                        on:input=move |ev| dest_ip.set(event_target_value(&ev))
                        placeholder="blank = any"
                    />
                </div>
            </div>

            <div class="grid grid-cols-3 gap-4">
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Rate Limit"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || rate_limit.get()
                        on:input=move |ev| rate_limit.set(event_target_value(&ev))
                        placeholder="e.g., 10/minute"
                    />
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Log Prefix"</label>
                    <input
                        type="text"
                        class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500"
                        prop:value=move || log_prefix.get()
                        on:input=move |ev| log_prefix.set(event_target_value(&ev))
                        placeholder="e.g., FORWARD_DROP"
                    />
                </div>
                <div class="flex items-end gap-4">
                    <div class="flex items-center gap-2">
                        <input
                            type="checkbox"
                            id="fwd-enabled"
                            class="w-4 h-4"
                            prop:checked=move || enabled.get()
                            on:change=move |ev| enabled.set(event_target_checked(&ev))
                        />
                        <label for="fwd-enabled" class="text-gray-300">"Enabled"</label>
                    </div>
                    <div class="flex items-center gap-2">
                        <input
                            type="checkbox"
                            id="fwd-log"
                            class="w-4 h-4"
                            prop:checked=move || log_enabled.get()
                            on:change=move |ev| log_enabled.set(event_target_checked(&ev))
                        />
                        <label for="fwd-log" class="text-gray-300">"Log"</label>
                    </div>
                </div>
            </div>

            <div class="flex gap-2 pt-2">
                <button
                    class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded disabled:opacity-50"
                    on:click=save
                    disabled=move || saving.get() || name.get().is_empty()
                >
                    {move || if saving.get() { "Saving..." } else { "Save" }}
                </button>
                <button
                    class="px-4 py-2 bg-gray-600 hover:bg-gray-500 text-white rounded"
                    on:click=move |_| on_cancel()
                >
                    "Cancel"
                </button>
            </div>
        </div>
    }
}

// ============================================================================
// Settings Tab
// ============================================================================

#[component]
fn SettingsTab(token: Signal<String>, on_unauthorized: Callback<()>) -> impl IntoView {
    let settings = LocalResource::new(move || {
        let token = token.get();
        async move { api::fetch_firewall_global_settings(&token).await }
    });

    // Local state for form
    let ping_wan_enabled = RwSignal::new(false);
    let ping_lan_enabled = RwSignal::new(true);
    let hairpin_nat_enabled = RwSignal::new(true);

    let status_message = RwSignal::new(String::new());
    let is_saving = RwSignal::new(false);
    let initialized = RwSignal::new(false);

    // Initialize form values when settings load
    Effect::new(move |_| {
        if let Some(Ok(s)) = settings.get()
            && !initialized.get()
        {
            ping_wan_enabled.set(s.ping_wan_enabled);
            ping_lan_enabled.set(s.ping_lan_enabled);
            hairpin_nat_enabled.set(s.hairpin_nat_enabled);
            initialized.set(true);
        }
    });

    let save_settings = move |_| {
        let token = token.get();
        let settings = FirewallGlobalSettings {
            ping_wan_enabled: ping_wan_enabled.get(),
            ping_lan_enabled: ping_lan_enabled.get(),
            hairpin_nat_enabled: hairpin_nat_enabled.get(),
        };

        is_saving.set(true);
        status_message.set(String::new());

        leptos::task::spawn_local(async move {
            match api::save_firewall_global_settings(&token, settings).await {
                Ok(response) => {
                    if response.success {
                        status_message.set("Settings saved successfully".to_string());
                    } else {
                        status_message.set(format!("Error: {}", response.message));
                    }
                }
                Err(e) => {
                    if e.contains("Unauthorized") {
                        on_unauthorized.run(());
                    } else {
                        status_message.set(format!("Error: {}", e));
                    }
                }
            }
            is_saving.set(false);
        });
    };

    view! {
        <div class="space-y-6">
            <h2 class="text-lg font-medium text-gray-200">"Global Firewall Settings"</h2>

            <Suspense fallback=move || view! { <p class="text-gray-400">"Loading settings..."</p> }>
                {move || {
                    settings.get().map(|result| match result {
                        Ok(_) => view! {
                            <div class="space-y-6 max-w-xl">
                                // ICMP / Ping Settings
                                <div class="bg-gray-700/50 rounded-lg p-4 space-y-4">
                                    <h3 class="text-md font-medium text-gray-300">"ICMP Settings"</h3>
                                    <p class="text-sm text-gray-400">
                                        "Control whether the router responds to ping requests. "
                                        "Dangerous ICMP types (timestamp, redirect, address-mask) are always blocked."
                                    </p>

                                    <div class="space-y-3">
                                        <label class="flex items-center gap-3 cursor-pointer">
                                            <input
                                                type="checkbox"
                                                class="w-4 h-4 rounded bg-gray-600 border-gray-500 text-blue-500 focus:ring-blue-500"
                                                prop:checked=move || ping_lan_enabled.get()
                                                on:change=move |ev| ping_lan_enabled.set(event_target_checked(&ev))
                                            />
                                            <span class="text-gray-200">"Allow ping from LAN"</span>
                                        </label>

                                        <label class="flex items-center gap-3 cursor-pointer">
                                            <input
                                                type="checkbox"
                                                class="w-4 h-4 rounded bg-gray-600 border-gray-500 text-blue-500 focus:ring-blue-500"
                                                prop:checked=move || ping_wan_enabled.get()
                                                on:change=move |ev| ping_wan_enabled.set(event_target_checked(&ev))
                                            />
                                            <span class="text-gray-200">"Allow ping from WAN"</span>
                                            <span class="text-sm text-gray-500">"(less secure)"</span>
                                        </label>
                                    </div>
                                </div>

                                // Hairpin NAT Settings
                                <div class="bg-gray-700/50 rounded-lg p-4 space-y-4">
                                    <h3 class="text-md font-medium text-gray-300">"NAT Settings"</h3>
                                    <p class="text-sm text-gray-400">
                                        "Hairpin NAT (NAT reflection) allows LAN clients to access port-forwarded "
                                        "services using the router's external IP address."
                                    </p>

                                    <label class="flex items-center gap-3 cursor-pointer">
                                        <input
                                            type="checkbox"
                                            class="w-4 h-4 rounded bg-gray-600 border-gray-500 text-blue-500 focus:ring-blue-500"
                                            prop:checked=move || hairpin_nat_enabled.get()
                                            on:change=move |ev| hairpin_nat_enabled.set(event_target_checked(&ev))
                                        />
                                        <span class="text-gray-200">"Enable Hairpin NAT"</span>
                                    </label>
                                </div>

                                // Status message
                                {move || {
                                    let msg = status_message.get();
                                    if msg.is_empty() {
                                        view! { <div></div> }.into_any()
                                    } else if msg.starts_with("Error") {
                                        view! {
                                            <div class="bg-red-900/50 border border-red-700 text-red-200 px-4 py-2 rounded">
                                                {msg}
                                            </div>
                                        }.into_any()
                                    } else {
                                        view! {
                                            <div class="bg-green-900/50 border border-green-700 text-green-200 px-4 py-2 rounded">
                                                {msg}
                                            </div>
                                        }.into_any()
                                    }
                                }}

                                // Save button
                                <div class="pt-2">
                                    <button
                                        class="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-600/50 text-white rounded font-medium"
                                        on:click=save_settings
                                        disabled=move || is_saving.get()
                                    >
                                        {move || if is_saving.get() { "Saving..." } else { "Save Settings" }}
                                    </button>
                                    <p class="text-sm text-gray-500 mt-2">
                                        "Note: Changes take effect when you apply the firewall configuration."
                                    </p>
                                </div>
                            </div>
                        }.into_any(),
                        Err(e) => {
                            if e.contains("Unauthorized") {
                                on_unauthorized.run(());
                            }
                            view! { <p class="text-red-400">"Error loading settings: "{e}</p> }.into_any()
                        }
                    })
                }}
            </Suspense>
        </div>
    }
}

// ============================================================================
// Preview Tab
// ============================================================================

#[component]
fn PreviewTab(
    token: Signal<String>,
    reload_trigger: RwSignal<i32>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let preview = LocalResource::new(move || {
        let token = token.get();
        let _ = reload_trigger.get();
        async move { api::fetch_firewall_preview(&token).await }
    });

    view! {
        <div class="space-y-4">
            <div class="flex justify-between items-center">
                <h2 class="text-lg font-medium text-gray-200">"Generated nftables Rules"</h2>
                <button
                    class="px-3 py-1.5 bg-gray-600 hover:bg-gray-500 text-white rounded text-sm"
                    on:click=move |_| reload_trigger.update(|v| *v += 1)
                >
                    "Refresh"
                </button>
            </div>

            <Suspense fallback=move || view! { <p class="text-gray-400">"Loading preview..."</p> }>
                {move || {
                    preview.get().map(|result| match result {
                        Ok(ruleset) => view! {
                            <pre class="bg-gray-900 p-4 rounded-lg text-sm text-gray-300 overflow-auto max-h-[600px] font-mono whitespace-pre-wrap">
                                {ruleset}
                            </pre>
                        }.into_any(),
                        Err(e) => {
                            if e.contains("Unauthorized") {
                                on_unauthorized.run(());
                            }
                            view! { <p class="text-red-400">"Error: "{e}</p> }.into_any()
                        }
                    })
                }}
            </Suspense>
        </div>
    }
}
