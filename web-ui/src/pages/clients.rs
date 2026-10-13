//! Clients page: one live list of every device seen on the LAN.
//!
//! Merges neighbour presence, DHCP leases and static reservations from the
//! daemon's `/clients` endpoint. The list refreshes in place, keyed by MAC, so
//! the filter text and an open reservation form survive each refresh.

use crate::api;
use gloo_timers::callback::Interval;
use keystone_core::{Client, DnsmasqStaticLease};
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::components::A;

const REFRESH_MS: u32 = 5_000;

const CHIP: &str = "inline-flex items-center gap-2 rounded-full bg-gray-800 px-3 py-1.5 text-sm text-gray-300 ring-1 ring-inset ring-gray-700";
const BADGE_STATIC: &str = "inline-flex items-center rounded-md bg-sky-400/10 px-2 py-0.5 text-xs font-medium text-sky-200 ring-1 ring-inset ring-sky-400/20";
const BADGE_FORWARDS: &str = "inline-flex items-center rounded-md bg-amber-400/10 px-2 py-0.5 text-xs font-medium text-amber-200 ring-1 ring-inset ring-amber-400/20";
const ACTION: &str =
    "text-blue-300 hover:text-blue-200 hover:underline underline-offset-2 disabled:opacity-50";
const INPUT: &str = "w-full px-3 py-2 bg-gray-600 text-gray-100 rounded border border-gray-500";

/// Reservation form state. It lives on the page rather than in a row, so a
/// refresh cannot reset what the user has typed.
#[derive(Clone, Copy)]
struct ReserveForm {
    /// MAC of the device being reserved, while the form is open.
    mac: RwSignal<Option<String>>,
    ip: RwSignal<String>,
    hostname: RwSignal<String>,
    error: RwSignal<Option<String>>,
    saving: RwSignal<bool>,
}

/// Everything a device row needs. Every member is `Copy`, so rows capture it cheaply.
#[derive(Clone, Copy)]
struct PageContext {
    clients: RwSignal<Option<Vec<Client>>>,
    reserve: ReserveForm,
    save: Callback<()>,
}

#[component]
pub fn ClientsPage(
    auth_token: ReadSignal<Option<String>>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let clients = RwSignal::new(None::<Vec<Client>>);
    let load_error = RwSignal::new(None::<String>);
    let notice = RwSignal::new(None::<String>);
    let filter = RwSignal::new(String::new());
    let show_offline = RwSignal::new(true);
    let reserve = ReserveForm {
        mac: RwSignal::new(None),
        ip: RwSignal::new(String::new()),
        hostname: RwSignal::new(String::new()),
        error: RwSignal::new(None),
        saving: RwSignal::new(false),
    };

    let poll = move || {
        let Some(token) = auth_token.get_untracked() else {
            return;
        };
        spawn_local(async move {
            match api::fetch_clients(&token).await {
                Ok(list) => {
                    load_error.set(None);
                    clients.set(Some(list));
                }
                Err(e) if e == "Unauthorized" => on_unauthorized.run(()),
                Err(e) => load_error.set(Some(e)),
            }
        });
    };

    // The Effect owns the Interval, which is dropped on unmount and stops polling.
    Effect::new(move |_prev: Option<Option<Interval>>| {
        if auth_token.get().is_some() {
            poll();
            Some(Interval::new(REFRESH_MS, poll))
        } else {
            None
        }
    });

    let save_reservation = move || {
        if reserve.saving.get_untracked() {
            return;
        }
        let Some(mac) = reserve.mac.get_untracked() else {
            return;
        };
        let ip = reserve.ip.get_untracked().trim().to_owned();
        let hostname = reserve.hostname.get_untracked().trim().to_owned();
        if ip.is_empty() {
            reserve
                .error
                .set(Some("Enter the IPv4 address to reserve".into()));
            return;
        }
        let Some(token) = auth_token.get_untracked() else {
            return;
        };
        reserve.error.set(None);
        reserve.saving.set(true);
        let lease = DnsmasqStaticLease {
            id: None,
            mac_address: mac.clone(),
            ip_address: ip,
            hostname: (!hostname.is_empty()).then_some(hostname),
            lease_time: None,
            client_id: None,
            set_tags: Vec::new(),
            enabled: true,
        };
        spawn_local(async move {
            match api::save_static_lease(&token, lease).await {
                Ok(_) => {
                    reserve.mac.set(None);
                    notice.set(Some(format!(
                        "Reservation saved for {mac}. Click Apply Changes on the DNS & DHCP page to activate it."
                    )));
                    poll();
                }
                Err(e) if e == "Unauthorized" => on_unauthorized.run(()),
                Err(e) => reserve.error.set(Some(e)),
            }
            reserve.saving.set(false);
        });
    };

    let ctx = PageContext {
        clients,
        reserve,
        save: Callback::new(move |()| save_reservation()),
    };

    let visible_macs = move || {
        let needle = filter.get().trim().to_ascii_lowercase();
        let include_offline = show_offline.get();
        clients
            .get()
            .unwrap_or_default()
            .into_iter()
            .filter(|c| include_offline || c.online)
            .filter(|c| needle.is_empty() || matches_filter(c, &needle))
            .map(|c| c.mac)
            .collect::<Vec<String>>()
    };

    // (total, online, static reservations) across every known device.
    let totals = move || {
        clients.with(|list| {
            let list = list.as_deref().unwrap_or_default();
            (
                list.len(),
                list.iter().filter(|c| c.online).count(),
                list.iter().filter(|c| c.static_lease_id.is_some()).count(),
            )
        })
    };

    view! {
        <div class="space-y-6">
            <div class="flex flex-wrap justify-between items-start gap-3">
                <div>
                    <h1 class="text-2xl font-semibold text-blue-300">"Clients"</h1>
                    <p class="text-gray-400">"Every device seen on the LAN, from the neighbour table, DHCP leases and reservations"</p>
                </div>
                <span class="text-xs text-gray-500 pt-2">"Refreshes every 5 seconds"</span>
            </div>

            {move || notice.get().map(|text| view! {
                <div class="bg-green-900/50 border border-green-500 rounded p-4 text-green-200 flex justify-between items-start gap-3">
                    <span>{text}</span>
                    <button class="text-green-200/70 hover:text-green-100" on:click=move |_| notice.set(None)>"×"</button>
                </div>
            })}
            {move || load_error.get().map(|text| view! {
                <div class="bg-red-900/50 border border-red-500 rounded p-4 text-red-200">
                    {format!("Failed to load clients: {text}")}
                </div>
            })}

            <div class="flex flex-wrap gap-2 text-sm">
                <span class=CHIP><span class="font-semibold text-white">{move || totals().0}</span>"devices"</span>
                <span class=CHIP>
                    <span class="w-2 h-2 rounded-full bg-green-400"></span>
                    <span class="font-semibold text-white">{move || totals().1}</span>"online"
                </span>
                <span class=CHIP>
                    <span class="font-semibold text-white">{move || totals().2}</span>"static reservations"
                </span>
            </div>

            <div class="bg-gray-800 rounded-xl p-5 sm:p-6 shadow-lg space-y-4">
                <div class="flex flex-col sm:flex-row sm:items-center gap-3">
                    <input
                        type="search"
                        placeholder="Filter by name, MAC, vendor or IP"
                        class="flex-1 px-3 py-2 bg-gray-900 text-gray-100 rounded-lg border border-gray-700 focus:border-sky-400 focus:outline-none placeholder:text-gray-500"
                        prop:value=move || filter.get()
                        on:input=move |ev| filter.set(event_target_value(&ev))
                    />
                    <label class="inline-flex items-center gap-2 text-sm text-gray-300 cursor-pointer select-none whitespace-nowrap">
                        <input
                            type="checkbox"
                            class="rounded bg-gray-900 border-gray-600 text-sky-500 focus:ring-sky-400"
                            prop:checked=move || show_offline.get()
                            on:change=move |ev| show_offline.set(event_target_checked(&ev))
                        />
                        "Show offline"
                    </label>
                </div>

                <div class="hidden md:grid md:grid-cols-12 md:gap-x-4 pb-2 border-b border-gray-600 text-xs uppercase tracking-wide text-gray-400">
                    <div class="md:col-span-3">"Device"</div>
                    <div class="md:col-span-3">"Addresses"</div>
                    <div class="md:col-span-2">"MAC"</div>
                    <div class="md:col-span-2">"Network"</div>
                    <div class="md:col-span-2">"Actions"</div>
                </div>

                <div>
                    <For
                        each=visible_macs
                        key=|mac: &String| mac.clone()
                        children=move |mac: String| client_row(mac, ctx)
                    />
                </div>

                {move || {
                    let message = if clients.with(Option::is_none) {
                        if load_error.with(Option::is_some) {
                            "Could not load clients."
                        } else {
                            "Loading clients..."
                        }
                    } else if totals().0 == 0 {
                        "No devices seen yet. Devices appear once they are on the network."
                    } else if visible_macs().is_empty() {
                        "No devices match the current filter."
                    } else {
                        return None;
                    };
                    Some(view! { <p class="text-center py-8 text-gray-400">{message}</p> }.into_any())
                }}
            </div>
        </div>
    }
}

/// Case-insensitive match against name, MAC, vendor and any address. `needle` is lower-case.
fn matches_filter(client: &Client, needle: &str) -> bool {
    let contains = |text: &str| text.to_ascii_lowercase().contains(needle);
    client.hostname.as_deref().is_some_and(contains)
        || contains(&client.mac)
        || client.vendor.as_deref().is_some_and(contains)
        || client
            .ipv4
            .iter()
            .chain(&client.ipv6)
            .any(|address| contains(address))
}

/// One device. Its cells sit directly in the grid row on medium screens and
/// stack as a card on narrow ones.
fn client_row(mac: String, ctx: PageContext) -> impl IntoView {
    let form_mac = mac.clone();
    let find = move || {
        ctx.clients.with(|list| {
            list.as_ref()
                .and_then(|list| list.iter().find(|c| c.mac == mac).cloned())
        })
    };
    view! {
        <div class="py-3 md:py-2.5 md:grid md:grid-cols-12 md:gap-x-4 md:items-center border-b border-gray-700/70 text-sm text-gray-200">
            {move || find().map(|client| client_cells(client, ctx))}
            {move || {
                (ctx.reserve.mac.get().as_deref() == Some(form_mac.as_str()))
                    .then(|| reserve_form(ctx))
            }}
        </div>
    }
}

fn client_cells(client: Client, ctx: PageContext) -> impl IntoView {
    let known = client.hostname.is_some();
    let name = client
        .hostname
        .clone()
        .unwrap_or_else(|| "Unknown device".to_owned());
    let dot = if client.online {
        "bg-green-400"
    } else {
        "bg-slate-500"
    };
    let status = status_title(&client);
    let has_static = client.static_lease_id.is_some();
    let static_title = client
        .static_ip
        .as_deref()
        .map(|ip| format!("Reserved address {ip}"))
        .unwrap_or_default();
    let forwards = client.port_forward_count;
    let forwards_label = if forwards == 1 {
        "1 forward".to_owned()
    } else {
        format!("{forwards} forwards")
    };

    let has_v4 = !client.ipv4.is_empty();
    let has_v6 = !client.ipv6.is_empty();
    let v4 = client.ipv4.clone();
    let v6 = client.ipv6.clone();

    let network = match (client.zone.clone(), client.interface.clone()) {
        (Some(zone), Some(iface)) => (zone, iface),
        (Some(zone), None) => (zone, String::new()),
        (None, Some(iface)) => ("No zone".to_owned(), iface),
        (None, None) => ("—".to_owned(), String::new()),
    };

    let can_reserve = !has_static && has_v4;
    let open_reserve = {
        let reserve = ctx.reserve;
        let mac = client.mac.clone();
        let ip = client.ipv4.first().cloned().unwrap_or_default();
        let hostname = client.hostname.clone().unwrap_or_default();
        move |_| {
            reserve.ip.set(ip.clone());
            reserve.hostname.set(hostname.clone());
            reserve.error.set(None);
            reserve.mac.set(Some(mac.clone()));
        }
    };
    let forward_href = format!("/firewall/port-forwards?mac={}", client.mac);
    let mac = client.mac.clone();

    view! {
        <div class="flex items-start gap-3 min-w-0 mb-2 md:mb-0 md:col-span-3">
            <span class=format!("mt-1.5 w-2.5 h-2.5 rounded-full shrink-0 {dot}") title=status></span>
            <div class="min-w-0">
                <div class={if known { "font-medium text-gray-100 break-words" } else { "italic text-gray-400" }}>{name}</div>
                {client.vendor.clone().map(|vendor| view! {
                    <div class="text-xs text-gray-500 break-words">{vendor}</div>
                })}
                <div class="flex flex-wrap gap-1.5 mt-1.5">
                    {has_static.then(|| view! {
                        <span class=BADGE_STATIC title=static_title>"Static"</span>
                    })}
                    {(forwards > 0).then(|| view! {
                        <span class=BADGE_FORWARDS>{forwards_label}</span>
                    })}
                </div>
            </div>
        </div>

        <div class="min-w-0 mb-2 md:mb-0 md:col-span-3">
            {v4.into_iter().map(|address| view! {
                <div class="font-mono text-gray-100 break-all">{address}</div>
            }).collect_view()}
            {v6.into_iter().map(|address| view! {
                <div class="font-mono text-xs text-gray-400 break-all">{address}</div>
            }).collect_view()}
            {(!has_v4 && !has_v6).then(|| view! {
                <div class="text-xs text-gray-500">"No address"</div>
            })}
        </div>

        <div class="font-mono text-xs text-gray-300 break-all mb-2 md:mb-0 md:col-span-2">{mac}</div>

        <div class="min-w-0 text-xs mb-2 md:mb-0 md:col-span-2">
            <div class="text-gray-300 break-words">{network.0}</div>
            <div class="text-gray-500 break-all">{network.1}</div>
        </div>

        <div class="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs md:col-span-2">
            {can_reserve.then(|| view! {
                <button class=ACTION on:click=open_reserve>"Reserve IP"</button>
            })}
            {has_static.then(|| view! {
                <A href="/dnsmasq/static-leases" attr:class=ACTION>"Edit reservation"</A>
            })}
            <A href=forward_href attr:class=ACTION>"Port forward"</A>
        </div>
    }
}

fn reserve_form(ctx: PageContext) -> impl IntoView {
    let reserve = ctx.reserve;
    view! {
        <div class="md:col-span-12 mt-3 md:mt-2 bg-gray-700 p-4 rounded-lg space-y-3">
            <div class="text-gray-100">
                "Reserve an address for "
                <span class="font-mono text-sm">{move || reserve.mac.get().unwrap_or_default()}</span>
            </div>
            <p class="text-xs text-gray-400">
                "DHCP will always give this device the IPv4 address below. Click Apply Changes on the DNS & DHCP page to activate it."
            </p>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"IPv4 address"</label>
                    <input
                        type="text"
                        placeholder="192.168.1.100"
                        class=INPUT
                        prop:value=move || reserve.ip.get()
                        on:input=move |ev| reserve.ip.set(event_target_value(&ev))
                    />
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-1">"Hostname (optional)"</label>
                    <input
                        type="text"
                        placeholder="e.g. laptop"
                        class=INPUT
                        prop:value=move || reserve.hostname.get()
                        on:input=move |ev| reserve.hostname.set(event_target_value(&ev))
                    />
                </div>
            </div>
            {move || reserve.error.get().map(|text| view! {
                <p class="text-sm text-red-300">{text}</p>
            })}
            <div class="flex gap-2">
                <button
                    class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded disabled:opacity-50"
                    disabled=move || reserve.saving.get()
                    on:click=move |_| ctx.save.run(())
                >
                    {move || if reserve.saving.get() { "Saving..." } else { "Save reservation" }}
                </button>
                <button
                    class="px-4 py-2 bg-gray-600 hover:bg-gray-500 text-gray-200 rounded"
                    on:click=move |_| reserve.mac.set(None)
                >
                    "Cancel"
                </button>
            </div>
        </div>
    }
}

/// Tooltip for the status dot: presence, neighbour state and lease time left.
fn status_title(client: &Client) -> String {
    let presence = if client.online {
        format!(
            "Online ({})",
            client
                .neighbour_state
                .as_deref()
                .unwrap_or("reachable")
                .to_ascii_lowercase()
        )
    } else {
        "Offline".to_owned()
    };
    match client.lease_expires_at {
        Some(expires_at) => format!("{presence} · lease {}", lease_remaining(expires_at)),
        None => presence,
    }
}

fn lease_remaining(expires_at: u64) -> String {
    let now = (js_sys::Date::now() / 1000.0) as u64;
    if expires_at <= now {
        return "expired".to_owned();
    }
    let remaining = expires_at - now;
    let (days, hours, minutes) = (
        remaining / 86_400,
        (remaining % 86_400) / 3_600,
        (remaining % 3_600) / 60,
    );
    if days > 0 {
        format!("ends in {days}d {hours}h")
    } else if hours > 0 {
        format!("ends in {hours}h {minutes}m")
    } else {
        format!("ends in {minutes}m")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(hostname: Option<&str>, vendor: Option<&str>) -> Client {
        Client {
            mac: "aa:bb:cc:00:00:01".into(),
            hostname: hostname.map(Into::into),
            vendor: vendor.map(Into::into),
            interface: None,
            zone: None,
            ipv4: vec!["192.168.1.20".into()],
            ipv6: vec!["2001:db8::20".into()],
            online: true,
            neighbour_state: None,
            lease_expires_at: None,
            static_lease_id: None,
            static_ip: None,
            port_forward_count: 0,
        }
    }

    #[test]
    fn filter_matches_name_mac_vendor_and_addresses() {
        let laptop = client(Some("Laptop"), Some("Intel Corporate"));
        assert!(matches_filter(&laptop, "lap"));
        assert!(matches_filter(&laptop, "aa:bb:cc"));
        assert!(matches_filter(&laptop, "intel"));
        assert!(matches_filter(&laptop, "192.168.1"));
        assert!(matches_filter(&laptop, "2001:db8::20"));
        assert!(!matches_filter(&laptop, "printer"));
    }

    #[test]
    fn filter_does_not_match_unnamed_devices_by_hostname() {
        let unnamed = client(None, None);
        assert!(!matches_filter(&unnamed, "unknown"));
        assert!(matches_filter(&unnamed, "192.168"));
    }
}
