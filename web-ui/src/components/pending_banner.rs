//! Global banner for network changes awaiting confirmation.
//!
//! Changing the LAN address can disconnect the administrator, so the banner
//! polls the daemon and survives page reloads: after reconnecting on the new
//! address, the pending change can still be confirmed (or it rolls back).

use crate::api;
use gloo_timers::callback::Interval;
use leptos::prelude::*;
use leptos::task::spawn_local;

#[component]
pub fn PendingConfirmBanner(auth_token: ReadSignal<Option<String>>) -> impl IntoView {
    let status = RwSignal::new(Option::<(String, u32)>::None);
    let message = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let location = leptos_router::hooks::use_location();

    let poll = move || {
        let Some(token) = auth_token.get_untracked() else {
            return;
        };
        spawn_local(async move {
            if let Ok(response) = api::fetch_pending_status(&token).await {
                status.set(match (response.networkd_pending, response.session_id) {
                    (true, Some(session)) => {
                        Some((session, response.seconds_remaining.unwrap_or(0)))
                    }
                    _ => None,
                });
            }
        });
    };
    // The Effect keeps the Interval alive and drops it on unmount.
    Effect::new(move |_prev: Option<Option<Interval>>| {
        if auth_token.get().is_some() {
            poll();
            Some(Interval::new(2000, poll))
        } else {
            None
        }
    });

    let resolve = move |confirm: bool| {
        let Some(token) = auth_token.get_untracked() else {
            return;
        };
        let Some((session, _)) = status.get_untracked() else {
            return;
        };
        busy.set(true);
        spawn_local(async move {
            let result = if confirm {
                api::confirm_firewall(&token, &session)
                    .await
                    .map(|r| (r.success, r.message))
            } else {
                api::rollback_firewall(&token)
                    .await
                    .map(|r| (r.success, r.message))
            };
            match result {
                Ok((true, text)) => {
                    status.set(None);
                    message.set(text);
                }
                Ok((false, text)) => message.set(text),
                Err(e) => message.set(e),
            }
            busy.set(false);
        });
    };

    view! {
        {move || {
            // The Firewall page already shows its own confirmation banner.
            let on_firewall_page = location.pathname.get().starts_with("/firewall");
            match status.get() {
                Some((_, remaining)) if !on_firewall_page => view! {
                    <div class="mb-5 bg-yellow-900/50 border border-yellow-600 text-yellow-200 px-4 py-3 rounded flex flex-wrap items-center justify-between gap-3">
                        <div>
                            <span class="font-medium">"Network changes pending confirmation!"</span>
                            " Confirm within "
                            <span class="font-bold">{remaining}</span>
                            " seconds or the previous network configuration is restored."
                            {move || {
                                let text = message.get();
                                (!text.is_empty()).then(|| view! { <div class="mt-1 text-sm">{text}</div> })
                            }}
                        </div>
                        <div class="flex gap-2">
                            <button
                                class="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded font-medium disabled:opacity-50"
                                disabled=move || busy.get()
                                on:click=move |_| resolve(true)
                            >"Confirm"</button>
                            <button
                                class="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded font-medium disabled:opacity-50"
                                disabled=move || busy.get()
                                on:click=move |_| resolve(false)
                            >"Roll back"</button>
                        </div>
                    </div>
                }.into_any(),
                _ => view! { <div></div> }.into_any(),
            }
        }}
    }
}
