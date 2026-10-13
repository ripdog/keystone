//! Sidebar navigation and the single list of navigable pages.
//!
//! [`NAV_ITEMS`] is the only list of pages. The sidebar and the command
//! palette both read it, so a page is added or renamed in one place.

use leptos::prelude::*;
use leptos_router::{components::A, hooks::use_location};

/// Sidebar headings, in display order.
pub const SECTIONS: &[&str] = &["Overview", "Connectivity", "Security & System"];

const OVERVIEW: &str = "Overview";
const CONNECTIVITY: &str = "Connectivity";
const SECURITY: &str = "Security & System";

/// Collapsible groups. Pages in a group share one sidebar section.
const DNSMASQ: &str = "DNS & DHCP";
const CADDY: &str = "Web Server";
const FIREWALL: &str = "Firewall";
const SETTINGS: &str = "Settings";

/// A navigable page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NavItem {
    pub title: &'static str,
    pub href: &'static str,
    /// Sidebar heading the page sits under; one of [`SECTIONS`].
    pub section: &'static str,
    /// Collapsible group such as "Firewall". Empty for top-level pages.
    pub group: &'static str,
    /// Icon key understood by `icon_path`.
    pub icon: &'static str,
    /// Space-separated synonyms that the command palette also searches.
    pub keywords: &'static str,
}

const fn page(
    title: &'static str,
    href: &'static str,
    section: &'static str,
    group: &'static str,
    icon: &'static str,
    keywords: &'static str,
) -> NavItem {
    NavItem {
        title,
        href,
        section,
        group,
        icon,
        keywords,
    }
}

/// Every page in sidebar order. Pages of one group must be contiguous.
pub const NAV_ITEMS: &[NavItem] = &[
    page(
        "Dashboard",
        "/",
        OVERVIEW,
        "",
        "dashboard",
        "home overview status summary",
    ),
    page(
        "Clients",
        "/clients",
        OVERVIEW,
        "",
        "devices",
        "devices lan hosts mac ip neighbours leases",
    ),
    page(
        "Interfaces",
        "/interfaces",
        OVERVIEW,
        "",
        "network",
        "nic ethernet link address wan lan",
    ),
    page(
        "VLANs",
        "/vlans",
        OVERVIEW,
        "",
        "layers",
        "vlan 802.1q tag trunk",
    ),
    page(
        "Bridges",
        "/bridges",
        OVERVIEW,
        "",
        "bridge",
        "bridge br switch lan",
    ),
    page(
        "Overview",
        "/dnsmasq/overview",
        CONNECTIVITY,
        DNSMASQ,
        "dns",
        "dnsmasq summary status",
    ),
    page(
        "DNS Settings",
        "/dnsmasq/dns-settings",
        CONNECTIVITY,
        DNSMASQ,
        "dns",
        "upstream resolver forwarders cache dnssec",
    ),
    page(
        "DHCP Ranges",
        "/dnsmasq/dhcp-ranges",
        CONNECTIVITY,
        DNSMASQ,
        "dns",
        "pool scope range dhcp lease",
    ),
    page(
        "Static Leases",
        "/dnsmasq/static-leases",
        CONNECTIVITY,
        DNSMASQ,
        "dns",
        "reservation dhcp fixed ip mac",
    ),
    page(
        "Active Leases",
        "/dnsmasq/active-leases",
        CONNECTIVITY,
        DNSMASQ,
        "dns",
        "lease dhcp current clients",
    ),
    page(
        "DHCP Options",
        "/dnsmasq/dhcp-options",
        CONNECTIVITY,
        DNSMASQ,
        "dns",
        "option gateway router dns server dhcp",
    ),
    page(
        "Host Records",
        "/dnsmasq/host-records",
        CONNECTIVITY,
        DNSMASQ,
        "dns",
        "hostname dns a record local name",
    ),
    page(
        "CNAME Records",
        "/dnsmasq/cname-records",
        CONNECTIVITY,
        DNSMASQ,
        "dns",
        "alias cname dns",
    ),
    page(
        "Address Overrides",
        "/dnsmasq/address-overrides",
        CONNECTIVITY,
        DNSMASQ,
        "dns",
        "override wildcard address dns",
    ),
    page(
        "Preview",
        "/dnsmasq/preview",
        CONNECTIVITY,
        DNSMASQ,
        "dns",
        "generated config file dnsmasq",
    ),
    page(
        "Settings",
        "/caddy/settings",
        CONNECTIVITY,
        CADDY,
        "globe",
        "caddy reverse proxy https tls domain",
    ),
    page(
        "Preview",
        "/caddy/preview",
        CONNECTIVITY,
        CADDY,
        "globe",
        "caddyfile generated config",
    ),
    page(
        "Status",
        "/caddy/status",
        CONNECTIVITY,
        CADDY,
        "globe",
        "caddy service running health",
    ),
    page(
        "SSH Server",
        "/ssh",
        CONNECTIVITY,
        "",
        "terminal",
        "sshd openssh remote login keys",
    ),
    page(
        "Services",
        "/services",
        CONNECTIVITY,
        "",
        "services",
        "systemd units daemon start stop restart enable",
    ),
    page(
        "Zones",
        "/firewall/zones",
        SECURITY,
        FIREWALL,
        "shield",
        "zone interface network",
    ),
    page(
        "Groups",
        "/firewall/groups",
        SECURITY,
        FIREWALL,
        "shield",
        "alias address port group set ipset nft",
    ),
    page(
        "Zone Forwards",
        "/firewall/zone-forwards",
        SECURITY,
        FIREWALL,
        "shield",
        "zone policy between allow deny",
    ),
    page(
        "Port Forwards",
        "/firewall/port-forwards",
        SECURITY,
        FIREWALL,
        "shield",
        "nat dnat open port forward",
    ),
    page(
        "Input Rules",
        "/firewall/input-rules",
        SECURITY,
        FIREWALL,
        "shield",
        "input router access allow block ssh",
    ),
    page(
        "Forward Rules",
        "/firewall/forward-rules",
        SECURITY,
        FIREWALL,
        "shield",
        "forward traffic between zones allow drop",
    ),
    page(
        "Settings",
        "/firewall/settings",
        SECURITY,
        FIREWALL,
        "shield",
        "global options logging",
    ),
    page(
        "Preview",
        "/firewall/preview",
        SECURITY,
        FIREWALL,
        "shield",
        "nftables ruleset generated",
    ),
    page(
        "Packet Tester",
        "/firewall/packet-tester",
        SECURITY,
        FIREWALL,
        "shield",
        "what happens to this packet trace simulate route drop accept nat",
    ),
    page(
        "Live Log",
        "/firewall/live-log",
        SECURITY,
        FIREWALL,
        "shield",
        "log logged packets kernel dropped accepted live tail",
    ),
    page(
        "Connections",
        "/firewall/connections",
        SECURITY,
        FIREWALL,
        "shield",
        "connections conntrack tracking nat state flows table",
    ),
    page(
        "Traffic Shaping",
        "/sqm",
        SECURITY,
        "",
        "gauge",
        "sqm cake bufferbloat qos shaping latency",
    ),
    page(
        "UPnP / NAT-PMP",
        "/upnp",
        SECURITY,
        "",
        "plug",
        "upnp nat-pmp pcp igd port mapping game console",
    ),
    page(
        "Networkd Preview",
        "/networkd-preview",
        SECURITY,
        "",
        "network",
        "systemd-networkd preview generated config",
    ),
    page(
        "General",
        "/settings/general",
        SECURITY,
        SETTINGS,
        "settings",
        "hostname timezone system global",
    ),
    page(
        "Configuration history",
        "/settings/history",
        SECURITY,
        SETTINGS,
        "settings",
        "backup snapshot restore export import",
    ),
];

/// Route prefix of a grouped page, e.g. "/firewall" for "/firewall/zones".
fn group_base(href: &'static str) -> &'static str {
    match href[1..].find('/') {
        Some(index) => &href[..index + 1],
        None => href,
    }
}

/// Pages of the group whose route prefix is `base`, in sidebar order.
fn group_items(base: &str) -> Vec<NavItem> {
    NAV_ITEMS
        .iter()
        .copied()
        .filter(|item| !item.group.is_empty() && group_base(item.href) == base)
        .collect()
}

/// Collapsible group that contains the path, if any. Old section URLs such as
/// `/firewall` count as part of their group.
pub fn group_for_path(path: &str) -> Option<&'static str> {
    NAV_ITEMS
        .iter()
        .filter(|item| !item.group.is_empty())
        .map(|item| group_base(item.href))
        .find(|base| path == *base || path.starts_with(&format!("{base}/")))
}

/// Current section and page for the workspace toolbar.
pub fn breadcrumb(path: &str) -> String {
    if let Some(base) = group_for_path(path) {
        let items = group_items(base);
        let group = items.first().map_or("", |item| item.group);
        let page = items
            .iter()
            .find(|item| item.href == path)
            .or_else(|| if path == base { items.first() } else { None });
        return match page {
            Some(page) => format!("{group} / {}", page.title),
            None => group.to_string(),
        };
    }

    if let Some(item) = NAV_ITEMS
        .iter()
        .find(|item| item.group.is_empty() && item.href == path)
    {
        return item.title.to_string();
    }

    match path {
        p if p.starts_with("/interfaces/") => "Interfaces / Edit".to_string(),
        p if p.starts_with("/services/") => "Services / Detail".to_string(),
        _ => "Keystone".to_string(),
    }
}

/// Icon path for a key used by [`NavItem::icon`] and the command palette.
pub fn icon_path(kind: &str) -> &'static str {
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
        "gauge" => "M4 15a8 8 0 1 1 16 0M12 15l3.5-3.5M4 15h1.5M18.5 15H20",
        "plug" => "M9 2v5M15 2v5M7 7h10v3a5 5 0 0 1-10 0V7ZM12 15v7",
        "settings" => {
            "M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1m8.6 8.6 2.1 2.1m0-12.8-2.1 2.1m-8.6 8.6-2.1 2.1M16 12a4 4 0 1 1-8 0 4 4 0 0 1 8 0Z"
        }
        "search" => "M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14ZM20 20l-4.2-4.2",
        "check" => "M5 12.5l4.5 4.5L19 7.5",
        "eye" => {
            "M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7Zm10 3a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z"
        }
        "undo" => "M9 14 4 9l5-5M4 9h10.5a5.5 5.5 0 0 1 0 11H11",
        "camera" => "M4 7h3l2-3h6l2 3h3v12H4zM12 10.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7Z",
        "power" => "M12 3v8M6.4 6.4a8 8 0 1 0 11.2 0",
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
    items: Vec<NavItem>,
    expanded: RwSignal<Option<&'static str>>,
    on_navigate: Callback<()>,
) -> impl IntoView {
    let location = use_location();
    // The first page of a group is also what the bare group URL opens.
    let default_href = items.first().map(|first| first.href);
    // Stored so the reactive children below can copy the list without moving it.
    let items = StoredValue::new(items);
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
                    <For each=move || items.get_value() key=|item| item.href children=move |item| {
                        let href = item.href;
                        let is_default = default_href == Some(href);
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

/// A sidebar entry: a top-level page, or a collapsible group of pages.
enum SidebarEntry {
    Page(NavItem),
    Group {
        base: &'static str,
        title: &'static str,
        icon: &'static str,
        items: Vec<NavItem>,
    },
}

/// Entries of one sidebar section, in `NAV_ITEMS` order.
fn sidebar_entries(section: &str) -> Vec<SidebarEntry> {
    let mut entries: Vec<SidebarEntry> = Vec::new();
    for item in NAV_ITEMS
        .iter()
        .copied()
        .filter(|item| item.section == section)
    {
        if item.group.is_empty() {
            entries.push(SidebarEntry::Page(item));
            continue;
        }
        let base = group_base(item.href);
        if let Some(SidebarEntry::Group {
            base: last, items, ..
        }) = entries.last_mut()
            && *last == base
        {
            items.push(item);
            continue;
        }
        entries.push(SidebarEntry::Group {
            base,
            title: item.group,
            icon: item.icon,
            items: vec![item],
        });
    }
    entries
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
            {SECTIONS
                .iter()
                .map(|&section| {
                    let entries = sidebar_entries(section);
                    view! {
                        <div class="space-y-1">
                            <p class="px-3 mb-2 text-[10px] uppercase tracking-[0.22em] font-semibold text-slate-500">{section}</p>
                            {entries
                                .into_iter()
                                .map(|entry| match entry {
                                    SidebarEntry::Page(item) => view! {
                                        <NavLink href=item.href title=item.title icon=item.icon on_navigate=on_navigate />
                                    }
                                    .into_any(),
                                    SidebarEntry::Group { base, title, icon, items } => view! {
                                        <NavSection base=base title=title icon=icon items=items expanded=expanded on_navigate=on_navigate />
                                    }
                                    .into_any(),
                                })
                                .collect_view()}
                        </div>
                    }
                })
                .collect_view()}
        </nav>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn every_page_is_unique_and_placed_consistently() {
        let mut seen = HashSet::new();
        for item in NAV_ITEMS {
            assert!(seen.insert(item.href), "duplicate route: {}", item.href);
            assert!(
                SECTIONS.contains(&item.section),
                "unknown section for {}",
                item.title
            );
            if item.group.is_empty() {
                assert_eq!(group_for_path(item.href), None, "{}", item.href);
            } else {
                let base = group_base(item.href);
                assert!(item.href.starts_with(&format!("{base}/")), "{}", item.href);
                assert_eq!(group_for_path(item.href), Some(base));
            }
            assert!(breadcrumb(item.href).contains(item.title));
        }
    }

    #[test]
    fn grouped_pages_are_contiguous_so_the_sidebar_can_nest_them() {
        let mut closed = HashSet::new();
        let mut previous = "";
        for item in NAV_ITEMS.iter().filter(|item| !item.group.is_empty()) {
            if item.group != previous {
                assert!(closed.insert(item.group), "group split: {}", item.group);
                previous = item.group;
            }
        }
    }

    #[test]
    fn bare_group_urls_belong_to_their_group_but_lookalikes_do_not() {
        assert_eq!(group_for_path("/firewall"), Some("/firewall"));
        assert_eq!(group_for_path("/firewall/zones"), Some("/firewall"));
        assert_eq!(group_for_path("/firewallish"), None);
        assert_eq!(group_for_path("/"), None);
        assert_eq!(breadcrumb("/settings"), "Settings / General");
    }

    #[test]
    fn sidebar_nests_each_group_once_and_keeps_page_order() {
        for section in SECTIONS {
            let mut seen_groups = HashSet::new();
            let mut flattened = Vec::new();
            for entry in sidebar_entries(section) {
                match entry {
                    SidebarEntry::Page(item) => {
                        assert!(item.group.is_empty(), "{} not nested", item.href);
                        flattened.push(item.href);
                    }
                    SidebarEntry::Group { title, items, .. } => {
                        assert!(seen_groups.insert(title), "group {title} split");
                        assert!(items.iter().all(|item| item.group == title));
                        flattened.extend(items.iter().map(|item| item.href));
                    }
                }
            }
            let expected: Vec<_> = NAV_ITEMS
                .iter()
                .filter(|item| item.section == *section)
                .map(|item| item.href)
                .collect();
            assert_eq!(flattened, expected, "section {section}");
        }
    }
}
