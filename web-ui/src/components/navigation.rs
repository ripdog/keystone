//! Sidebar navigation and canonical routes for multi-page sections.

use leptos::prelude::*;
use leptos_router::{components::A, hooks::use_location};

#[derive(Clone, Copy)]
pub struct NavItem {
    pub title: &'static str,
    pub href: &'static str,
}

const FIREWALL: &[NavItem] = &[
    NavItem {
        title: "Zones",
        href: "/firewall/zones",
    },
    NavItem {
        title: "Zone Forwards",
        href: "/firewall/zone-forwards",
    },
    NavItem {
        title: "Port Forwards",
        href: "/firewall/port-forwards",
    },
    NavItem {
        title: "Input Rules",
        href: "/firewall/input-rules",
    },
    NavItem {
        title: "Forward Rules",
        href: "/firewall/forward-rules",
    },
    NavItem {
        title: "Settings",
        href: "/firewall/settings",
    },
    NavItem {
        title: "Preview",
        href: "/firewall/preview",
    },
];

const DNSMASQ: &[NavItem] = &[
    NavItem {
        title: "Overview",
        href: "/dnsmasq/overview",
    },
    NavItem {
        title: "DNS Settings",
        href: "/dnsmasq/dns-settings",
    },
    NavItem {
        title: "DHCP Ranges",
        href: "/dnsmasq/dhcp-ranges",
    },
    NavItem {
        title: "Static Leases",
        href: "/dnsmasq/static-leases",
    },
    NavItem {
        title: "Active Leases",
        href: "/dnsmasq/active-leases",
    },
    NavItem {
        title: "DHCP Options",
        href: "/dnsmasq/dhcp-options",
    },
    NavItem {
        title: "Host Records",
        href: "/dnsmasq/host-records",
    },
    NavItem {
        title: "CNAME Records",
        href: "/dnsmasq/cname-records",
    },
    NavItem {
        title: "Address Overrides",
        href: "/dnsmasq/address-overrides",
    },
    NavItem {
        title: "Preview",
        href: "/dnsmasq/preview",
    },
];

const CADDY: &[NavItem] = &[
    NavItem {
        title: "Settings",
        href: "/caddy/settings",
    },
    NavItem {
        title: "Preview",
        href: "/caddy/preview",
    },
    NavItem {
        title: "Status",
        href: "/caddy/status",
    },
];

const SETTINGS: &[NavItem] = &[
    NavItem {
        title: "General",
        href: "/settings/general",
    },
    NavItem {
        title: "Configuration history",
        href: "/settings/history",
    },
];

/// The old section URLs remain usable, opening their default page.
pub fn group_for_path(path: &str) -> Option<&'static str> {
    ["/firewall", "/dnsmasq", "/caddy", "/settings"]
        .into_iter()
        .find(|base| path == *base || path.starts_with(&format!("{base}/")))
}

fn group_info(base: &str) -> (&'static str, &'static [NavItem]) {
    match base {
        "/firewall" => ("Firewall", FIREWALL),
        "/dnsmasq" => ("DNS & DHCP", DNSMASQ),
        "/caddy" => ("Web Server", CADDY),
        "/settings" => ("Settings", SETTINGS),
        _ => ("", &[]),
    }
}

/// Current section and page for the workspace toolbar.
pub fn breadcrumb(path: &str) -> String {
    if let Some(base) = group_for_path(path) {
        let (title, items) = group_info(base);
        let page = items
            .iter()
            .find(|item| item.href == path)
            .or_else(|| if path == base { items.first() } else { None });
        return match page {
            Some(page) => format!("{title} / {}", page.title),
            None => title.to_string(),
        };
    }

    match path {
        "/" => "Dashboard".to_string(),
        "/clients" => "Clients".to_string(),
        "/interfaces" => "Interfaces".to_string(),
        "/vlans" => "VLANs".to_string(),
        "/bridges" => "Bridges".to_string(),
        "/ssh" => "SSH Server".to_string(),
        "/services" => "Services".to_string(),
        "/networkd-preview" => "Networkd Preview".to_string(),
        p if p.starts_with("/interfaces/") => "Interfaces / Edit".to_string(),
        p if p.starts_with("/services/") => "Services / Detail".to_string(),
        _ => "Keystone".to_string(),
    }
}

fn icon_path(kind: &str) -> &'static str {
    match kind {
        "dashboard" => "M3 3h8v8H3zM13 3h8v5h-8zM13 10h8v11h-8zM3 13h8v8H3z",
        "devices" => "M3 4h18v12H3zM8 20h8M12 16v4",
        "network" => "M12 3v5M5 21h14M5 16v5M19 16v5M5 16h14M12 8l-7 8M12 8l7 8",
        "layers" => "m12 2 9 5-9 5-9-5 9-5Zm-9 10 9 5 9-5M3 17l9 5 9-5",
        "bridge" => "M3 18h18M5 18V9m14 9V9M3 9h18M7 9c0 5 10 5 10 0",
        "dns" => "M4 7h16M4 12h16M4 17h16M7 7v.01M7 12v.01M7 17v.01",
        "globe" => {
            "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20ZM2 12h20M12 2c-6 6-6 14 0 20M12 2c6 6 6 14 0 20"
        }
        "shield" => "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Zm-4-10 3 3 5-6",
        "terminal" => "m4 7 5 5-5 5M12 18h8",
        "services" => "M4 4h16v6H4zM4 14h16v6H4zM7 7h.01M7 17h.01",
        "settings" => {
            "M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1m8.6 8.6 2.1 2.1m0-12.8-2.1 2.1m-8.6 8.6-2.1 2.1M16 12a4 4 0 1 1-8 0 4 4 0 0 1 8 0Z"
        }
        _ => "M4 12h16",
    }
}

#[component]
fn NavLink(
    href: &'static str,
    title: &'static str,
    icon: &'static str,
    on_navigate: Callback<()>,
) -> impl IntoView {
    let location = use_location();
    view! {
        <A href=href
            attr:class=move || {
                let path = location.pathname.get();
                let active = path == href
                    || (href == "/interfaces" && path.starts_with("/interfaces/"))
                    || (href == "/services" && path.starts_with("/services/"));
                if active {
                    "flex items-center gap-3 px-3 py-2.5 rounded-xl bg-sky-400/10 text-sky-200 ring-1 ring-inset ring-sky-400/20 font-medium"
                } else {
                    "flex items-center gap-3 px-3 py-2.5 rounded-xl text-slate-400 hover:text-white hover:bg-white/5 transition-colors"
                }
            }
            on:click=move |_| on_navigate.run(())
        >
            <svg class="w-[18px] h-[18px] shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d=icon_path(icon) />
            </svg>
            <span class="text-sm">{title}</span>
        </A>
    }
}

#[component]
fn NavSection(
    base: &'static str,
    title: &'static str,
    icon: &'static str,
    items: &'static [NavItem],
    expanded: RwSignal<Option<&'static str>>,
    on_navigate: Callback<()>,
) -> impl IntoView {
    let location = use_location();
    view! {
        <div>
            <button type="button"
                class=move || {
                    let active = group_for_path(&location.pathname.get()) == Some(base);
                    if active {
                        "flex w-full items-center gap-3 px-3 py-2.5 rounded-xl text-sky-200 bg-white/5 font-medium transition-colors"
                    } else {
                        "flex w-full items-center gap-3 px-3 py-2.5 rounded-xl text-slate-400 hover:bg-white/5 hover:text-white transition-colors"
                    }
                }
                aria-expanded=move || expanded.get() == Some(base)
                on:click=move |_| expanded.update(|current| {
                    *current = if *current == Some(base) { None } else { Some(base) };
                })
            >
                <svg class="w-[18px] h-[18px] shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <path d=icon_path(icon) />
                </svg>
                <span class="text-sm flex-1 text-left">{title}</span>
                <svg class=move || if expanded.get() == Some(base) { "w-4 h-4 rotate-90 transition-transform" } else { "w-4 h-4 transition-transform" } viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" aria-hidden="true">
                    <path d="m9 6 6 6-6 6" />
                </svg>
            </button>
            <Show when=move || expanded.get() == Some(base)>
                <div class="ml-5 pl-3 mt-1 mb-2 border-l border-slate-700/70 space-y-0.5">
                    <For each=move || items.iter().copied() key=|item| item.href children=move |item| {
                        let href = item.href;
                        let is_default = items.first().is_some_and(|first| first.href == href);
                        view! {
                            <A href=href
                                attr:class=move || {
                                    let path = location.pathname.get();
                                    let active = path == href || (is_default && path == base);
                                    if active {
                                        "block rounded-lg px-3 py-2 text-sm bg-sky-400/10 text-sky-200 font-medium"
                                    } else {
                                        "block rounded-lg px-3 py-2 text-sm text-slate-400 hover:text-white hover:bg-white/5 transition-colors"
                                    }
                                }
                                on:click=move |_| on_navigate.run(())
                            >{item.title}</A>
                        }
                    } />
                </div>
            </Show>
        </div>
    }
}

/// Shared between the fixed desktop sidebar and the mobile drawer.
#[component]
pub fn SidebarNavigation(on_navigate: Callback<()>) -> impl IntoView {
    let location = use_location();
    let expanded = RwSignal::new(group_for_path(&location.pathname.get_untracked()));

    // A direct link or browser back/forward must reveal the selected child.
    Effect::new(move || {
        let path = location.pathname.get();
        expanded.set(group_for_path(&path));
    });

    view! {
        <nav aria-label="Main navigation" class="space-y-6">
            <div class="space-y-1">
                <p class="px-3 mb-2 text-[10px] uppercase tracking-[0.22em] font-semibold text-slate-500">"Overview"</p>
                <NavLink href="/" title="Dashboard" icon="dashboard" on_navigate=on_navigate />
                <NavLink href="/clients" title="Clients" icon="devices" on_navigate=on_navigate />
                <NavLink href="/interfaces" title="Interfaces" icon="network" on_navigate=on_navigate />
                <NavLink href="/vlans" title="VLANs" icon="layers" on_navigate=on_navigate />
                <NavLink href="/bridges" title="Bridges" icon="bridge" on_navigate=on_navigate />
            </div>
            <div class="space-y-1">
                <p class="px-3 mb-2 text-[10px] uppercase tracking-[0.22em] font-semibold text-slate-500">"Connectivity"</p>
                <NavSection base="/dnsmasq" title="DNS & DHCP" icon="dns" items=DNSMASQ expanded=expanded on_navigate=on_navigate />
                <NavSection base="/caddy" title="Web Server" icon="globe" items=CADDY expanded=expanded on_navigate=on_navigate />
                <NavLink href="/ssh" title="SSH Server" icon="terminal" on_navigate=on_navigate />
                <NavLink href="/services" title="Services" icon="services" on_navigate=on_navigate />
            </div>
            <div class="space-y-1">
                <p class="px-3 mb-2 text-[10px] uppercase tracking-[0.22em] font-semibold text-slate-500">"Security & System"</p>
                <NavSection base="/firewall" title="Firewall" icon="shield" items=FIREWALL expanded=expanded on_navigate=on_navigate />
                <NavLink href="/networkd-preview" title="Networkd Preview" icon="network" on_navigate=on_navigate />
                <NavSection base="/settings" title="Settings" icon="settings" items=SETTINGS expanded=expanded on_navigate=on_navigate />
            </div>
        </nav>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_section_items_are_unique_and_have_correct_prefixes() {
        let mut seen = std::collections::HashSet::new();
        for (base, items) in [
            ("/firewall", FIREWALL),
            ("/dnsmasq", DNSMASQ),
            ("/caddy", CADDY),
            ("/settings", SETTINGS),
        ] {
            for item in items {
                assert!(item.href.starts_with(&format!("{base}/")));
                assert!(seen.insert(item.href), "duplicate route: {}", item.href);
                assert_eq!(group_for_path(item.href), Some(base));
                assert!(breadcrumb(item.href).contains(item.title));
            }
            assert_eq!(group_for_path(base), Some(base));
        }
        assert_eq!(group_for_path("/firewallish"), None);
        assert_eq!(group_for_path("/"), None);
    }
}
