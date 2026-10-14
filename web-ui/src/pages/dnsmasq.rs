//! Dnsmasq DNS & DHCP configuration page
//!
//! Routed sections:
//! - Overview (status, quick stats)
//! - DNS Settings (upstream mode, cache, local domain)
//! - DHCP Ranges (per-interface DHCP pools)
//! - Static Leases (MAC-to-IP reservations)
//! - Active Leases (current DHCP leases from lease file)
//! - DHCP Options (custom DHCP options)
//! - Host Records and CNAME Records (separate pages)
//! - Address Overrides (domain blocking/redirects)
//! - Preview (generated config file)

use crate::api;
use crate::components::use_config_changed;
use crate::components::use_toasts;
use keystone_core::{
    DhcpLease, DnsmasqAddressAction, DnsmasqAddressOverride, DnsmasqCnameRecord, DnsmasqConfig,
    DnsmasqDhcpOption, DnsmasqDhcpRange, DnsmasqHostRecord, DnsmasqStaticLease,
    DnsmasqUpstreamMode, ManagedInterface,
};
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::hooks::use_location;

/// Active DNS & DHCP section selected by URL
#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum DnsmasqTab {
    #[default]
    Overview,
    DnsSettings,
    DhcpRanges,
    StaticLeases,
    ActiveLeases,
    DhcpOptions,
    HostRecords,
    CnameRecords,
    AddressOverrides,
    Preview,
}

impl DnsmasqTab {
    fn from_path(path: &str) -> Self {
        match path.rsplit('/').next().unwrap_or_default() {
            "dns-settings" => Self::DnsSettings,
            "dhcp-ranges" => Self::DhcpRanges,
            "static-leases" => Self::StaticLeases,
            "active-leases" => Self::ActiveLeases,
            "dhcp-options" => Self::DhcpOptions,
            "host-records" | "dns-records" => Self::HostRecords,
            "cname-records" => Self::CnameRecords,
            "address-overrides" => Self::AddressOverrides,
            "preview" => Self::Preview,
            _ => Self::Overview,
        }
    }
}

#[cfg(test)]
mod route_tests {
    use super::*;

    #[test]
    fn selects_each_section_from_its_url() {
        assert!(matches!(
            DnsmasqTab::from_path("/dnsmasq/overview"),
            DnsmasqTab::Overview
        ));
        assert!(matches!(
            DnsmasqTab::from_path("/dnsmasq/dns-settings"),
            DnsmasqTab::DnsSettings
        ));
        assert!(matches!(
            DnsmasqTab::from_path("/dnsmasq/dhcp-ranges"),
            DnsmasqTab::DhcpRanges
        ));
        assert!(matches!(
            DnsmasqTab::from_path("/dnsmasq/static-leases"),
            DnsmasqTab::StaticLeases
        ));
        assert!(matches!(
            DnsmasqTab::from_path("/dnsmasq/active-leases"),
            DnsmasqTab::ActiveLeases
        ));
        assert!(matches!(
            DnsmasqTab::from_path("/dnsmasq/dhcp-options"),
            DnsmasqTab::DhcpOptions
        ));
        assert!(matches!(
            DnsmasqTab::from_path("/dnsmasq/dns-records"),
            DnsmasqTab::HostRecords
        ));
        assert!(matches!(
            DnsmasqTab::from_path("/dnsmasq/host-records"),
            DnsmasqTab::HostRecords
        ));
        assert!(matches!(
            DnsmasqTab::from_path("/dnsmasq/cname-records"),
            DnsmasqTab::CnameRecords
        ));
        assert!(matches!(
            DnsmasqTab::from_path("/dnsmasq/address-overrides"),
            DnsmasqTab::AddressOverrides
        ));
        assert!(matches!(
            DnsmasqTab::from_path("/dnsmasq/preview"),
            DnsmasqTab::Preview
        ));
        assert!(matches!(
            DnsmasqTab::from_path("/dnsmasq"),
            DnsmasqTab::Overview
        ));
    }
}

#[component]
pub fn DnsmasqPage(
    auth_token: ReadSignal<Option<String>>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let token = Signal::derive(move || auth_token.get().unwrap_or_default());
    let location = use_location();

    // Global state
    let config = RwSignal::new(DnsmasqConfig::default());
    let dhcp_ranges = RwSignal::new(Vec::<DnsmasqDhcpRange>::new());
    let static_leases = RwSignal::new(Vec::<DnsmasqStaticLease>::new());
    let active_leases = RwSignal::new(Vec::<DhcpLease>::new());
    let dhcp_options = RwSignal::new(Vec::<DnsmasqDhcpOption>::new());
    let host_records = RwSignal::new(Vec::<DnsmasqHostRecord>::new());
    let cname_records = RwSignal::new(Vec::<DnsmasqCnameRecord>::new());
    let address_overrides = RwSignal::new(Vec::<DnsmasqAddressOverride>::new());
    let managed_interfaces = RwSignal::new(Vec::<ManagedInterface>::new());

    let loading = RwSignal::new(true);
    let error_msg = RwSignal::new(Option::<String>::None);
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
            match api::fetch_dnsmasq_state(&token_clone).await {
                Ok(state) => {
                    config.set(state.config);
                    dhcp_ranges.set(state.dhcp_ranges);
                    static_leases.set(state.static_leases);
                    dhcp_options.set(state.dhcp_options);
                    host_records.set(state.host_records);
                    cname_records.set(state.cname_records);
                    address_overrides.set(state.address_overrides);
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

        let token_clone2 = token_val.clone();
        spawn_local(async move {
            if let Ok(interfaces) = api::fetch_managed_interfaces(&token_clone2).await {
                managed_interfaces.set(interfaces);
            }
        });

        let token_clone3 = token_val.clone();
        spawn_local(async move {
            if let Ok(leases) = api::fetch_active_leases(&token_clone3).await {
                active_leases.set(leases);
            }
        });
    });

    view! {
        <div class="space-y-6">
            <div>
                <div>
                    <h1 class="text-2xl font-semibold text-blue-300">"DNS & DHCP"</h1>
                    <p class="text-gray-400">"Dnsmasq configuration for DNS and DHCP services"</p>
                </div>
            </div>

            <Show when=move || error_msg.get().is_some()>
                <div class="bg-red-900/50 border border-red-500 rounded p-4 text-red-200">
                    {move || error_msg.get().unwrap_or_default()}
                </div>
            </Show>

            <Show when=move || loading.get()>
                <div class="text-center py-8 text-gray-400">"Loading dnsmasq configuration..."</div>
            </Show>

            <Show when=move || !loading.get()>
                // Tab content
                <div class="bg-gray-800 rounded-lg shadow-lg p-6">
                    {move || match DnsmasqTab::from_path(&location.pathname.get()) {
                        DnsmasqTab::Overview => view! {
                            <OverviewTab
                                config=config
                                dhcp_ranges=dhcp_ranges
                                static_leases=static_leases
                                active_leases=active_leases
                            />
                        }.into_any(),
                        DnsmasqTab::DnsSettings => view! {
                            <DnsSettingsTab
                                token=token
                                config=config
                                error_msg=error_msg
                            />
                        }.into_any(),
                        DnsmasqTab::DhcpRanges => view! {
                            <DhcpRangesTab
                                token=token
                                dhcp_ranges=dhcp_ranges
                                managed_interfaces=managed_interfaces
                                error_msg=error_msg
                                reload_trigger=reload_trigger
                            />
                        }.into_any(),
                        DnsmasqTab::StaticLeases => view! {
                            <StaticLeasesTab
                                token=token
                                static_leases=static_leases
                                error_msg=error_msg
                                reload_trigger=reload_trigger
                            />
                        }.into_any(),
                        DnsmasqTab::ActiveLeases => view! {
                            <ActiveLeasesTab
                                token=token
                                active_leases=active_leases
                                static_leases=static_leases
                                error_msg=error_msg
                                reload_trigger=reload_trigger
                            />
                        }.into_any(),
                        DnsmasqTab::DhcpOptions => view! {
                            <DhcpOptionsTab
                                token=token
                                dhcp_options=dhcp_options
                                error_msg=error_msg
                                reload_trigger=reload_trigger
                            />
                        }.into_any(),
                        DnsmasqTab::HostRecords => view! {
                            <HostRecordsSection
                                token=token
                                host_records=host_records
                                error_msg=error_msg
                                reload_trigger=reload_trigger
                            />
                        }.into_any(),
                        DnsmasqTab::CnameRecords => view! {
                            <CnameRecordsSection
                                token=token
                                cname_records=cname_records
                                error_msg=error_msg
                                reload_trigger=reload_trigger
                            />
                        }.into_any(),
                        DnsmasqTab::AddressOverrides => view! {
                            <AddressOverridesTab
                                token=token
                                address_overrides=address_overrides
                                error_msg=error_msg
                                reload_trigger=reload_trigger
                            />
                        }.into_any(),
                        DnsmasqTab::Preview => view! {
                            <PreviewTab token=token />
                        }.into_any(),
                    }}
                </div>
            </Show>
        </div>
    }
}

// ============================================================================
// Overview Tab
// ============================================================================

#[component]
fn OverviewTab(
    config: RwSignal<DnsmasqConfig>,
    dhcp_ranges: RwSignal<Vec<DnsmasqDhcpRange>>,
    static_leases: RwSignal<Vec<DnsmasqStaticLease>>,
    active_leases: RwSignal<Vec<DhcpLease>>,
) -> impl IntoView {
    view! {
        <div class="space-y-6">
            // Status card
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <div class="bg-gray-700 rounded-lg p-4">
                    <div class="text-gray-400 text-sm">"Service Status"</div>
                    <div class="text-xl font-semibold mt-1">
                        {move || if config.get().enabled {
                            view! { <span class="text-green-400">"Enabled"</span> }.into_any()
                        } else {
                            view! { <span class="text-red-400">"Disabled"</span> }.into_any()
                        }}
                    </div>
                </div>
                <div class="bg-gray-700 rounded-lg p-4">
                    <div class="text-gray-400 text-sm">"DHCP Ranges"</div>
                    <div class="text-xl font-semibold text-white mt-1">
                        {move || dhcp_ranges.get().len()}
                    </div>
                </div>
                <div class="bg-gray-700 rounded-lg p-4">
                    <div class="text-gray-400 text-sm">"Static Leases"</div>
                    <div class="text-xl font-semibold text-white mt-1">
                        {move || static_leases.get().len()}
                    </div>
                </div>
                <div class="bg-gray-700 rounded-lg p-4">
                    <div class="text-gray-400 text-sm">"Active Leases"</div>
                    <div class="text-xl font-semibold text-white mt-1">
                        {move || active_leases.get().len()}
                    </div>
                </div>
            </div>

            // DNS Settings Summary
            <div class="bg-gray-700 rounded-lg p-4">
                <h3 class="text-lg font-medium text-white mb-3">"DNS Configuration"</h3>
                <div class="grid grid-cols-2 gap-4 text-sm">
                    <div>
                        <span class="text-gray-400">"Upstream Mode: "</span>
                        <span class="text-white">{move || format!("{}", config.get().upstream_mode)}</span>
                    </div>
                    <div>
                        <span class="text-gray-400">"Cache Size: "</span>
                        <span class="text-white">{move || config.get().cache_size}</span>
                    </div>
                    <div>
                        <span class="text-gray-400">"Local Domain: "</span>
                        <span class="text-white">{move || config.get().local_domain.clone().unwrap_or_else(|| "-".to_string())}</span>
                    </div>
                    <div>
                        <span class="text-gray-400">"DNSSEC: "</span>
                        <span class="text-white">{move || if config.get().dnssec_enabled { "Enabled" } else { "Disabled" }}</span>
                    </div>
                </div>
            </div>

            // DHCP Ranges Summary
            <div class="bg-gray-700 rounded-lg p-4">
                <h3 class="text-lg font-medium text-white mb-3">"DHCP Ranges"</h3>
                <Show when=move || dhcp_ranges.get().is_empty()>
                    <p class="text-gray-400">"No DHCP ranges configured."</p>
                </Show>
                <Show when=move || !dhcp_ranges.get().is_empty()>
                    <div class="space-y-2">
                        <For
                            each=move || dhcp_ranges.get()
                            key=|range| (range.id, range.name.clone())
                            children=move |range: DnsmasqDhcpRange| {
                                let enabled_class = if range.enabled { "text-green-400" } else { "text-gray-500" };
                                view! {
                                    <div class="flex justify-between items-center text-sm">
                                        <span class="text-white">{range.name.clone()}</span>
                                        <span class="text-gray-400">{range.interface.clone()}</span>
                                        <span class="text-gray-300">{format!("{} - {}", range.start_address, range.end_address)}</span>
                                        <span class=enabled_class>{if range.enabled { "Active" } else { "Disabled" }}</span>
                                    </div>
                                }
                            }
                        />
                    </div>
                </Show>
            </div>
        </div>
    }
}

// ============================================================================
// DNS Settings Tab
// ============================================================================

#[component]
fn DnsSettingsTab(
    token: Signal<String>,
    config: RwSignal<DnsmasqConfig>,
    error_msg: RwSignal<Option<String>>,
) -> impl IntoView {
    let toasts = use_toasts();
    let config_changed = use_config_changed();
    let saving = RwSignal::new(false);

    // Local form state
    let enabled = RwSignal::new(config.get().enabled);
    let dns_port = RwSignal::new(config.get().dns_port.to_string());
    let cache_size = RwSignal::new(config.get().cache_size.to_string());
    let dnssec_enabled = RwSignal::new(config.get().dnssec_enabled);
    let domain_needed = RwSignal::new(config.get().domain_needed);
    let bogus_priv = RwSignal::new(config.get().bogus_priv);
    let local_domain = RwSignal::new(config.get().local_domain.clone().unwrap_or_default());
    let expand_hosts = RwSignal::new(config.get().expand_hosts);
    let upstream_mode = RwSignal::new(config.get().upstream_mode);
    let log_queries = RwSignal::new(config.get().log_queries);
    let log_dhcp = RwSignal::new(config.get().log_dhcp);

    let save_config = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();
        saving.set(true);
        error_msg.set(None);

        let new_config = DnsmasqConfig {
            enabled: enabled.get(),
            dns_port: dns_port.get().parse().unwrap_or(53),
            cache_size: cache_size.get().parse().unwrap_or(1000),
            dnssec_enabled: dnssec_enabled.get(),
            domain_needed: domain_needed.get(),
            bogus_priv: bogus_priv.get(),
            local_domain: if local_domain.get().is_empty() {
                None
            } else {
                Some(local_domain.get())
            },
            expand_hosts: expand_hosts.get(),
            upstream_mode: upstream_mode.get(),
            upstream_servers: config.get().upstream_servers.clone(),
            listen_interfaces: config.get().listen_interfaces.clone(),
            except_interfaces: config.get().except_interfaces.clone(),
            no_dhcp_interfaces: config.get().no_dhcp_interfaces.clone(),
            bind_dynamic: config.get().bind_dynamic,
            log_queries: log_queries.get(),
            log_dhcp: log_dhcp.get(),
        };

        let token_val = token.get();
        spawn_local(async move {
            match api::save_dnsmasq_config(&token_val, new_config.clone()).await {
                Ok(()) => {
                    config.set(new_config);
                    config_changed.run(());
                    toasts.success("DNS settings saved".to_string());
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
                <label for="enabled" class="text-white">"Enable dnsmasq service"</label>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                // DNS Port
                <div>
                    <label class="block text-gray-300 mb-2">"DNS Port"</label>
                    <input
                        type="number"
                        prop:value=move || dns_port.get()
                        on:input=move |ev| dns_port.set(event_target_value(&ev))
                        class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white"
                    />
                    <p class="text-sm text-gray-500 mt-1">"53 = standard DNS, 0 = disable DNS"</p>
                </div>

                // Cache Size
                <div>
                    <label class="block text-gray-300 mb-2">"DNS Cache Size"</label>
                    <input
                        type="number"
                        prop:value=move || cache_size.get()
                        on:input=move |ev| cache_size.set(event_target_value(&ev))
                        class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white"
                    />
                    <p class="text-sm text-gray-500 mt-1">"Number of DNS records to cache (0 = disable)"</p>
                </div>

                // Local Domain
                <div>
                    <label class="block text-gray-300 mb-2">"Local Domain"</label>
                    <input
                        type="text"
                        prop:value=move || local_domain.get()
                        on:input=move |ev| local_domain.set(event_target_value(&ev))
                        placeholder="e.g., lan, home.local"
                        class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white"
                    />
                    <p class="text-sm text-gray-500 mt-1">"Domain for local hostnames"</p>
                </div>

                // Upstream Mode
                <div>
                    <label class="block text-gray-300 mb-2">"Upstream DNS Mode"</label>
                    <select
                        prop:value=move || upstream_mode.get().to_string()
                        on:change=move |ev| {
                            let value = event_target_value(&ev);
                            upstream_mode.set(value.parse().unwrap_or(DnsmasqUpstreamMode::System));
                        }
                        class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white"
                    >
                        <option value="system">"System (use /etc/resolv.conf)"</option>
                        <option value="custom">"Custom upstream servers"</option>
                        <option value="localadguard">"Local AdGuard Home (localhost:5353)"</option>
                        <option value="blocky">"Blocky (ad-blocking, encrypted upstream)"</option>
                    </select>
                </div>
            </div>

            // Checkboxes
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div class="flex items-center gap-3">
                    <input
                        type="checkbox"
                        id="dnssec"
                        prop:checked=move || dnssec_enabled.get()
                        on:change=move |ev| dnssec_enabled.set(event_target_checked(&ev))
                        class="w-4 h-4"
                    />
                    <label for="dnssec" class="text-gray-300">"Enable DNSSEC validation"</label>
                </div>
                <div class="flex items-center gap-3">
                    <input
                        type="checkbox"
                        id="domain_needed"
                        prop:checked=move || domain_needed.get()
                        on:change=move |ev| domain_needed.set(event_target_checked(&ev))
                        class="w-4 h-4"
                    />
                    <label for="domain_needed" class="text-gray-300">"Never forward plain names"</label>
                </div>
                <div class="flex items-center gap-3">
                    <input
                        type="checkbox"
                        id="bogus_priv"
                        prop:checked=move || bogus_priv.get()
                        on:change=move |ev| bogus_priv.set(event_target_checked(&ev))
                        class="w-4 h-4"
                    />
                    <label for="bogus_priv" class="text-gray-300">"Never forward private reverse lookups"</label>
                </div>
                <div class="flex items-center gap-3">
                    <input
                        type="checkbox"
                        id="expand_hosts"
                        prop:checked=move || expand_hosts.get()
                        on:change=move |ev| expand_hosts.set(event_target_checked(&ev))
                        class="w-4 h-4"
                    />
                    <label for="expand_hosts" class="text-gray-300">"Expand hostnames with local domain"</label>
                </div>
                <div class="flex items-center gap-3">
                    <input
                        type="checkbox"
                        id="log_queries"
                        prop:checked=move || log_queries.get()
                        on:change=move |ev| log_queries.set(event_target_checked(&ev))
                        class="w-4 h-4"
                    />
                    <label for="log_queries" class="text-gray-300">"Log DNS queries"</label>
                </div>
                <div class="flex items-center gap-3">
                    <input
                        type="checkbox"
                        id="log_dhcp"
                        prop:checked=move || log_dhcp.get()
                        on:change=move |ev| log_dhcp.set(event_target_checked(&ev))
                        class="w-4 h-4"
                    />
                    <label for="log_dhcp" class="text-gray-300">"Log DHCP transactions"</label>
                </div>
            </div>

            <div class="pt-4">
                <button
                    type="submit"
                    class="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded disabled:opacity-50"
                    disabled=move || saving.get()
                >
                    {move || if saving.get() { "Saving..." } else { "Save DNS Settings" }}
                </button>
            </div>
        </form>
    }
}

// ============================================================================
// DHCP Ranges Tab
// ============================================================================

#[component]
fn DhcpRangesTab(
    token: Signal<String>,
    dhcp_ranges: RwSignal<Vec<DnsmasqDhcpRange>>,
    managed_interfaces: RwSignal<Vec<ManagedInterface>>,
    error_msg: RwSignal<Option<String>>,
    reload_trigger: RwSignal<u32>,
) -> impl IntoView {
    let toasts = use_toasts();
    let config_changed = use_config_changed();
    // Modal state
    let show_modal = RwSignal::new(false);
    let editing_range = RwSignal::new(Option::<DnsmasqDhcpRange>::None);
    let modal_name = RwSignal::new(String::new());
    let modal_interface = RwSignal::new(String::new());
    let modal_start = RwSignal::new(String::new());
    let modal_end = RwSignal::new(String::new());
    let modal_netmask = RwSignal::new(String::new());
    let modal_lease_time = RwSignal::new("24h".to_string());
    let modal_enabled = RwSignal::new(true);
    let modal_error = RwSignal::new(Option::<String>::None);

    let open_new_modal = move |_| {
        editing_range.set(None);
        modal_name.set(String::new());
        modal_interface.set(String::new());
        modal_start.set(String::new());
        modal_end.set(String::new());
        modal_netmask.set(String::new());
        modal_lease_time.set("24h".to_string());
        modal_enabled.set(true);
        modal_error.set(None);
        show_modal.set(true);
    };

    let open_edit_modal = move |range: DnsmasqDhcpRange| {
        editing_range.set(Some(range.clone()));
        modal_name.set(range.name.clone());
        modal_interface.set(range.interface.clone());
        modal_start.set(range.start_address.clone());
        modal_end.set(range.end_address.clone());
        modal_netmask.set(range.netmask.clone().unwrap_or_default());
        modal_lease_time.set(range.lease_time.clone());
        modal_enabled.set(range.enabled);
        modal_error.set(None);
        show_modal.set(true);
    };

    let close_modal = move |_| {
        show_modal.set(false);
    };

    let save_range = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();

        let name = modal_name.get();
        let interface = modal_interface.get();
        let start = modal_start.get();
        let end = modal_end.get();

        if name.is_empty() || interface.is_empty() || start.is_empty() || end.is_empty() {
            modal_error.set(Some("All fields except netmask are required".to_string()));
            return;
        }

        let range = DnsmasqDhcpRange {
            id: editing_range.get().and_then(|r| r.id),
            name,
            interface,
            start_address: start,
            end_address: end,
            netmask: if modal_netmask.get().is_empty() {
                None
            } else {
                Some(modal_netmask.get())
            },
            lease_time: modal_lease_time.get(),
            enabled: modal_enabled.get(),
            ipv6_mode: None,
            ipv6_prefix: None,
        };

        let token_val = token.get();
        spawn_local(async move {
            match api::save_dhcp_range(&token_val, range).await {
                Ok(_) => {
                    show_modal.set(false);
                    config_changed.run(());
                    toasts.success("DHCP range saved".to_string());
                    reload_trigger.update(|v| *v += 1);
                }
                Err(e) => {
                    modal_error.set(Some(format!("Error: {}", e)));
                }
            }
        });
    };

    let delete_range = move |id: i64| {
        if !web_sys::window()
            .and_then(|w| w.confirm_with_message("Delete this DHCP range?").ok())
            .unwrap_or(false)
        {
            return;
        }

        let token_val = token.get();
        spawn_local(async move {
            match api::delete_dhcp_range(&token_val, id).await {
                Ok(()) => {
                    config_changed.run(());
                    toasts.success("DHCP range deleted".to_string());
                    reload_trigger.update(|v| *v += 1);
                }
                Err(e) => {
                    error_msg.set(Some(format!("Error: {}", e)));
                }
            }
        });
    };

    view! {
        <div class="space-y-4">
            <div class="flex justify-between items-center">
                <h3 class="text-lg font-medium text-white">"DHCP Ranges"</h3>
                <button
                    on:click=open_new_modal
                    class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
                >
                    "+ Add Range"
                </button>
            </div>

            <Show when=move || dhcp_ranges.get().is_empty()>
                <div class="text-center py-8 text-gray-400">
                    "No DHCP ranges configured. Add a range to enable DHCP on an interface."
                </div>
            </Show>

            <Show when=move || !dhcp_ranges.get().is_empty()>
                <table class="w-full">
                    <thead class="bg-gray-700">
                        <tr>
                            <th class="px-4 py-3 text-left text-gray-300 font-medium">"Name"</th>
                            <th class="px-4 py-3 text-left text-gray-300 font-medium">"Interface"</th>
                            <th class="px-4 py-3 text-left text-gray-300 font-medium">"Range"</th>
                            <th class="px-4 py-3 text-left text-gray-300 font-medium">"Lease Time"</th>
                            <th class="px-4 py-3 text-left text-gray-300 font-medium">"Status"</th>
                            <th class="px-4 py-3 text-right text-gray-300 font-medium">"Actions"</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-700">
                        <For
                            each=move || dhcp_ranges.get()
                            key=|range| (range.id, range.name.clone(), range.enabled)
                            children=move |range: DnsmasqDhcpRange| {
                                let range_for_edit = range.clone();
                                let range_id = range.id.unwrap_or(0);
                                view! {
                                    <tr class="hover:bg-gray-700/30">
                                        <td class="px-4 py-3 text-white">{range.name.clone()}</td>
                                        <td class="px-4 py-3 text-gray-300">{range.interface.clone()}</td>
                                        <td class="px-4 py-3 text-gray-300">
                                            {format!("{} - {}", range.start_address, range.end_address)}
                                        </td>
                                        <td class="px-4 py-3 text-gray-300">{range.lease_time.clone()}</td>
                                        <td class="px-4 py-3">
                                            {if range.enabled {
                                                view! { <span class="text-green-400">"Active"</span> }.into_any()
                                            } else {
                                                view! { <span class="text-gray-500">"Disabled"</span> }.into_any()
                                            }}
                                        </td>
                                        <td class="px-4 py-3 text-right">
                                            <div class="flex gap-2 justify-end">
                                                <button
                                                    on:click=move |_| open_edit_modal(range_for_edit.clone())
                                                    class="bg-yellow-600 hover:bg-yellow-700 text-white px-3 py-1 rounded text-sm"
                                                >
                                                    "Edit"
                                                </button>
                                                <button
                                                    on:click=move |_| delete_range(range_id)
                                                    class="bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded text-sm"
                                                >
                                                    "Delete"
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                }
                            }
                        />
                    </tbody>
                </table>
            </Show>

            // Modal
            <Show when=move || show_modal.get()>
                <div class="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
                    <div class="bg-gray-800 rounded-lg p-6 max-w-lg w-full">
                        <h2 class="text-xl font-semibold text-white mb-4">
                            {move || if editing_range.get().is_some() { "Edit DHCP Range" } else { "Add DHCP Range" }}
                        </h2>

                        <form on:submit=save_range class="space-y-4">
                            <div>
                                <label class="block text-gray-300 mb-2">"Name"</label>
                                <input
                                    type="text"
                                    prop:value=move || modal_name.get()
                                    on:input=move |ev| modal_name.set(event_target_value(&ev))
                                    placeholder="e.g., LAN Pool"
                                    class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white"
                                    required
                                />
                            </div>

                            <div>
                                <label class="block text-gray-300 mb-2">"Interface"</label>
                                <select
                                    prop:value=move || modal_interface.get()
                                    on:change=move |ev| modal_interface.set(event_target_value(&ev))
                                    class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white"
                                    required
                                >
                                    <option value="" disabled=true>"Select interface..."</option>
                                    <For
                                        each=move || managed_interfaces.get()
                                        key=|iface| iface.name.clone()
                                        children=move |iface: ManagedInterface| {
                                            let name = iface.name.clone();
                                            let name_display = name.clone();
                                            view! { <option value=name>{name_display}</option> }
                                        }
                                    />
                                </select>
                            </div>

                            <div class="grid grid-cols-2 gap-4">
                                <div>
                                    <label class="block text-gray-300 mb-2">"Start Address"</label>
                                    <input
                                        type="text"
                                        prop:value=move || modal_start.get()
                                        on:input=move |ev| modal_start.set(event_target_value(&ev))
                                        placeholder="192.168.1.100"
                                        class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white"
                                        required
                                    />
                                </div>
                                <div>
                                    <label class="block text-gray-300 mb-2">"End Address"</label>
                                    <input
                                        type="text"
                                        prop:value=move || modal_end.get()
                                        on:input=move |ev| modal_end.set(event_target_value(&ev))
                                        placeholder="192.168.1.200"
                                        class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white"
                                        required
                                    />
                                </div>
                            </div>

                            <div class="grid grid-cols-2 gap-4">
                                <div>
                                    <label class="block text-gray-300 mb-2">"Netmask (optional)"</label>
                                    <input
                                        type="text"
                                        prop:value=move || modal_netmask.get()
                                        on:input=move |ev| modal_netmask.set(event_target_value(&ev))
                                        placeholder="255.255.255.0"
                                        class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white"
                                    />
                                </div>
                                <div>
                                    <label class="block text-gray-300 mb-2">"Lease Time"</label>
                                    <input
                                        type="text"
                                        prop:value=move || modal_lease_time.get()
                                        on:input=move |ev| modal_lease_time.set(event_target_value(&ev))
                                        placeholder="24h"
                                        class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white"
                                    />
                                </div>
                            </div>

                            <div class="flex items-center gap-3">
                                <input
                                    type="checkbox"
                                    id="range_enabled"
                                    prop:checked=move || modal_enabled.get()
                                    on:change=move |ev| modal_enabled.set(event_target_checked(&ev))
                                    class="w-4 h-4"
                                />
                                <label for="range_enabled" class="text-gray-300">"Enable this range"</label>
                            </div>

                            <Show when=move || modal_error.get().is_some()>
                                <div class="bg-red-900/50 border border-red-500 rounded p-3 text-red-200 text-sm">
                                    {move || modal_error.get().unwrap_or_default()}
                                </div>
                            </Show>

                            <div class="flex gap-2 pt-2">
                                <button
                                    type="submit"
                                    class="flex-1 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
                                >
                                    "Save"
                                </button>
                                <button
                                    type="button"
                                    on:click=close_modal
                                    class="flex-1 bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded"
                                >
                                    "Cancel"
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </Show>
        </div>
    }
}

// ============================================================================
// Static Leases Tab
// ============================================================================

#[component]
fn StaticLeasesTab(
    token: Signal<String>,
    static_leases: RwSignal<Vec<DnsmasqStaticLease>>,
    error_msg: RwSignal<Option<String>>,
    reload_trigger: RwSignal<u32>,
) -> impl IntoView {
    let toasts = use_toasts();
    let config_changed = use_config_changed();
    // Modal state
    let show_modal = RwSignal::new(false);
    let editing_lease = RwSignal::new(Option::<DnsmasqStaticLease>::None);
    let modal_mac = RwSignal::new(String::new());
    let modal_ip = RwSignal::new(String::new());
    let modal_hostname = RwSignal::new(String::new());
    let modal_enabled = RwSignal::new(true);
    let modal_error = RwSignal::new(Option::<String>::None);

    let open_new_modal = move |_| {
        editing_lease.set(None);
        modal_mac.set(String::new());
        modal_ip.set(String::new());
        modal_hostname.set(String::new());
        modal_enabled.set(true);
        modal_error.set(None);
        show_modal.set(true);
    };

    let open_edit_modal = move |lease: DnsmasqStaticLease| {
        editing_lease.set(Some(lease.clone()));
        modal_mac.set(lease.mac_address.clone());
        modal_ip.set(lease.ip_address.clone());
        modal_hostname.set(lease.hostname.clone().unwrap_or_default());
        modal_enabled.set(lease.enabled);
        modal_error.set(None);
        show_modal.set(true);
    };

    let close_modal = move |_| {
        show_modal.set(false);
    };

    let save_lease = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();

        let mac = modal_mac.get();
        let ip = modal_ip.get();

        if mac.is_empty() || ip.is_empty() {
            modal_error.set(Some("MAC address and IP address are required".to_string()));
            return;
        }

        let lease = DnsmasqStaticLease {
            id: editing_lease.get().and_then(|l| l.id),
            mac_address: mac,
            ip_address: ip,
            hostname: if modal_hostname.get().is_empty() {
                None
            } else {
                Some(modal_hostname.get())
            },
            lease_time: None,
            client_id: None,
            set_tags: Vec::new(),
            enabled: modal_enabled.get(),
        };

        let token_val = token.get();
        spawn_local(async move {
            match api::save_static_lease(&token_val, lease).await {
                Ok(_) => {
                    show_modal.set(false);
                    config_changed.run(());
                    toasts.success("Static lease saved".to_string());
                    reload_trigger.update(|v| *v += 1);
                }
                Err(e) => {
                    modal_error.set(Some(format!("Error: {}", e)));
                }
            }
        });
    };

    let delete_lease = move |id: i64| {
        if !web_sys::window()
            .and_then(|w| w.confirm_with_message("Delete this static lease?").ok())
            .unwrap_or(false)
        {
            return;
        }

        let token_val = token.get();
        spawn_local(async move {
            match api::delete_static_lease(&token_val, id).await {
                Ok(()) => {
                    config_changed.run(());
                    toasts.success("Static lease deleted".to_string());
                    reload_trigger.update(|v| *v += 1);
                }
                Err(e) => {
                    error_msg.set(Some(format!("Error: {}", e)));
                }
            }
        });
    };

    view! {
        <div class="space-y-4">
            <div class="flex justify-between items-center">
                <h3 class="text-lg font-medium text-white">"Static Leases"</h3>
                <button
                    on:click=open_new_modal
                    class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
                >
                    "+ Add Static Lease"
                </button>
            </div>

            <Show when=move || static_leases.get().is_empty()>
                <div class="text-center py-8 text-gray-400">
                    "No static leases configured. Add a static lease to reserve an IP for a device."
                </div>
            </Show>

            <Show when=move || !static_leases.get().is_empty()>
                <table class="w-full">
                    <thead class="bg-gray-700">
                        <tr>
                            <th class="px-4 py-3 text-left text-gray-300 font-medium">"MAC Address"</th>
                            <th class="px-4 py-3 text-left text-gray-300 font-medium">"IP Address"</th>
                            <th class="px-4 py-3 text-left text-gray-300 font-medium">"Hostname"</th>
                            <th class="px-4 py-3 text-left text-gray-300 font-medium">"Status"</th>
                            <th class="px-4 py-3 text-right text-gray-300 font-medium">"Actions"</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-700">
                        <For
                            each=move || static_leases.get()
                            key=|lease| (lease.id, lease.mac_address.clone(), lease.enabled)
                            children=move |lease: DnsmasqStaticLease| {
                                let lease_for_edit = lease.clone();
                                let lease_id = lease.id.unwrap_or(0);
                                view! {
                                    <tr class="hover:bg-gray-700/30">
                                        <td class="px-4 py-3 text-white font-mono">{lease.mac_address.clone()}</td>
                                        <td class="px-4 py-3 text-gray-300 font-mono">{lease.ip_address.clone()}</td>
                                        <td class="px-4 py-3 text-gray-300">{lease.hostname.clone().unwrap_or_else(|| "-".to_string())}</td>
                                        <td class="px-4 py-3">
                                            {if lease.enabled {
                                                view! { <span class="text-green-400">"Active"</span> }.into_any()
                                            } else {
                                                view! { <span class="text-gray-500">"Disabled"</span> }.into_any()
                                            }}
                                        </td>
                                        <td class="px-4 py-3 text-right">
                                            <div class="flex gap-2 justify-end">
                                                <button
                                                    on:click=move |_| open_edit_modal(lease_for_edit.clone())
                                                    class="bg-yellow-600 hover:bg-yellow-700 text-white px-3 py-1 rounded text-sm"
                                                >
                                                    "Edit"
                                                </button>
                                                <button
                                                    on:click=move |_| delete_lease(lease_id)
                                                    class="bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded text-sm"
                                                >
                                                    "Delete"
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                }
                            }
                        />
                    </tbody>
                </table>
            </Show>

            // Modal
            <Show when=move || show_modal.get()>
                <div class="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
                    <div class="bg-gray-800 rounded-lg p-6 max-w-lg w-full">
                        <h2 class="text-xl font-semibold text-white mb-4">
                            {move || if editing_lease.get().is_some() { "Edit Static Lease" } else { "Add Static Lease" }}
                        </h2>

                        <form on:submit=save_lease class="space-y-4">
                            <div>
                                <label class="block text-gray-300 mb-2">"MAC Address"</label>
                                <input
                                    type="text"
                                    prop:value=move || modal_mac.get()
                                    on:input=move |ev| modal_mac.set(event_target_value(&ev))
                                    placeholder="00:11:22:33:44:55"
                                    class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white font-mono"
                                    required
                                />
                            </div>

                            <div>
                                <label class="block text-gray-300 mb-2">"IP Address"</label>
                                <input
                                    type="text"
                                    prop:value=move || modal_ip.get()
                                    on:input=move |ev| modal_ip.set(event_target_value(&ev))
                                    placeholder="192.168.1.50"
                                    class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white font-mono"
                                    required
                                />
                            </div>

                            <div>
                                <label class="block text-gray-300 mb-2">"Hostname (optional)"</label>
                                <input
                                    type="text"
                                    prop:value=move || modal_hostname.get()
                                    on:input=move |ev| modal_hostname.set(event_target_value(&ev))
                                    placeholder="e.g., my-server"
                                    class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white"
                                />
                            </div>

                            <div class="flex items-center gap-3">
                                <input
                                    type="checkbox"
                                    id="lease_enabled"
                                    prop:checked=move || modal_enabled.get()
                                    on:change=move |ev| modal_enabled.set(event_target_checked(&ev))
                                    class="w-4 h-4"
                                />
                                <label for="lease_enabled" class="text-gray-300">"Enable this reservation"</label>
                            </div>

                            <Show when=move || modal_error.get().is_some()>
                                <div class="bg-red-900/50 border border-red-500 rounded p-3 text-red-200 text-sm">
                                    {move || modal_error.get().unwrap_or_default()}
                                </div>
                            </Show>

                            <div class="flex gap-2 pt-2">
                                <button
                                    type="submit"
                                    class="flex-1 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
                                >
                                    "Save"
                                </button>
                                <button
                                    type="button"
                                    on:click=close_modal
                                    class="flex-1 bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded"
                                >
                                    "Cancel"
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </Show>
        </div>
    }
}

// ============================================================================
// Active Leases Tab
// ============================================================================

#[component]
fn ActiveLeasesTab(
    token: Signal<String>,
    active_leases: RwSignal<Vec<DhcpLease>>,
    static_leases: RwSignal<Vec<DnsmasqStaticLease>>,
    error_msg: RwSignal<Option<String>>,
    reload_trigger: RwSignal<u32>,
) -> impl IntoView {
    let toasts = use_toasts();
    let config_changed = use_config_changed();
    let refreshing = RwSignal::new(false);

    let refresh_leases = move |_| {
        refreshing.set(true);
        let token_val = token.get();
        spawn_local(async move {
            match api::fetch_active_leases(&token_val).await {
                Ok(leases) => {
                    active_leases.set(leases);
                }
                Err(e) => {
                    error_msg.set(Some(format!("Error refreshing leases: {}", e)));
                }
            }
            refreshing.set(false);
        });
    };

    let make_static = move |lease: DhcpLease| {
        let new_lease = DnsmasqStaticLease {
            id: None,
            mac_address: lease.mac_address.clone(),
            ip_address: lease.ip_address.clone(),
            hostname: lease.hostname.clone(),
            lease_time: None,
            client_id: lease.client_id.clone(),
            set_tags: Vec::new(),
            enabled: true,
        };

        let token_val = token.get();
        spawn_local(async move {
            match api::save_static_lease(&token_val, new_lease).await {
                Ok(_) => {
                    config_changed.run(());
                    toasts.success("Static lease created from active lease".to_string());
                    reload_trigger.update(|v| *v += 1);
                }
                Err(e) => {
                    error_msg.set(Some(format!("Error: {}", e)));
                }
            }
        });
    };

    // Check if a lease is already static
    let is_already_static = move |mac: &str| -> bool {
        static_leases
            .get()
            .iter()
            .any(|s| s.mac_address.to_lowercase() == mac.to_lowercase())
    };

    view! {
        <div class="space-y-4">
            <div class="flex justify-between items-center">
                <h3 class="text-lg font-medium text-white">"Active DHCP Leases"</h3>
                <button
                    on:click=refresh_leases
                    class="bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded"
                    disabled=move || refreshing.get()
                >
                    {move || if refreshing.get() { "Refreshing..." } else { "Refresh" }}
                </button>
            </div>

            <Show when=move || active_leases.get().is_empty()>
                <div class="text-center py-8 text-gray-400">
                    "No active DHCP leases found."
                </div>
            </Show>

            <Show when=move || !active_leases.get().is_empty()>
                <table class="w-full">
                    <thead class="bg-gray-700">
                        <tr>
                            <th class="px-4 py-3 text-left text-gray-300 font-medium">"MAC Address"</th>
                            <th class="px-4 py-3 text-left text-gray-300 font-medium">"IP Address"</th>
                            <th class="px-4 py-3 text-left text-gray-300 font-medium">"Hostname"</th>
                            <th class="px-4 py-3 text-left text-gray-300 font-medium">"Expires"</th>
                            <th class="px-4 py-3 text-right text-gray-300 font-medium">"Actions"</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-700">
                        <For
                            each=move || active_leases.get()
                            key=|lease| (lease.mac_address.clone(), lease.ip_address.clone())
                            children=move |lease: DhcpLease| {
                                let lease_for_static = lease.clone();
                                let mac_for_check = lease.mac_address.clone();
                                let expires = format_timestamp(lease.expires_at);
                                view! {
                                    <tr class="hover:bg-gray-700/30">
                                        <td class="px-4 py-3 text-white font-mono">{lease.mac_address.clone()}</td>
                                        <td class="px-4 py-3 text-gray-300 font-mono">{lease.ip_address.clone()}</td>
                                        <td class="px-4 py-3 text-gray-300">{lease.hostname.clone().unwrap_or_else(|| "-".to_string())}</td>
                                        <td class="px-4 py-3 text-gray-300">{expires}</td>
                                        <td class="px-4 py-3 text-right">
                                            {move || {
                                                if is_already_static(&mac_for_check) {
                                                    view! {
                                                        <span class="text-gray-500 text-sm">"Already Static"</span>
                                                    }.into_any()
                                                } else {
                                                    let lease_clone = lease_for_static.clone();
                                                    view! {
                                                        <button
                                                            on:click=move |_| make_static(lease_clone.clone())
                                                            class="bg-blue-600 hover:bg-blue-700 text-white px-3 py-1 rounded text-sm"
                                                        >
                                                            "Make Static"
                                                        </button>
                                                    }.into_any()
                                                }
                                            }}
                                        </td>
                                    </tr>
                                }
                            }
                        />
                    </tbody>
                </table>
            </Show>
        </div>
    }
}

/// Format a Unix timestamp as a human-readable string
fn format_timestamp(ts: u64) -> String {
    // Simple relative time formatting using wasm_bindgen
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_namespace = Date)]
        fn now() -> f64;
    }

    let now_ts = (now() / 1000.0) as u64;
    if ts <= now_ts {
        "Expired".to_string()
    } else {
        let remaining = ts - now_ts;
        if remaining < 60 {
            format!("{}s", remaining)
        } else if remaining < 3600 {
            format!("{}m", remaining / 60)
        } else if remaining < 86400 {
            format!("{}h", remaining / 3600)
        } else {
            format!("{}d", remaining / 86400)
        }
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
            match api::fetch_dnsmasq_preview(&token_val).await {
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
                <h3 class="text-lg font-medium text-white">"Generated Configuration"</h3>
                <p class="text-sm text-gray-400">"Preview of /etc/dnsmasq.d/50-keystone.conf"</p>
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
// DHCP Options Tab
// ============================================================================

#[component]
fn DhcpOptionsTab(
    token: Signal<String>,
    dhcp_options: RwSignal<Vec<DnsmasqDhcpOption>>,
    error_msg: RwSignal<Option<String>>,
    reload_trigger: RwSignal<u32>,
) -> impl IntoView {
    let toasts = use_toasts();
    let config_changed = use_config_changed();
    // Modal state
    let show_modal = RwSignal::new(false);
    let editing_option = RwSignal::new(Option::<DnsmasqDhcpOption>::None);
    let modal_description = RwSignal::new(String::new());
    let modal_option = RwSignal::new(String::new());
    let modal_value = RwSignal::new(String::new());
    let modal_enabled = RwSignal::new(true);
    let modal_ipv6 = RwSignal::new(false);
    let modal_force = RwSignal::new(false);
    let modal_error = RwSignal::new(Option::<String>::None);

    let open_new_modal = move |_| {
        editing_option.set(None);
        modal_description.set(String::new());
        modal_option.set(String::new());
        modal_value.set(String::new());
        modal_enabled.set(true);
        modal_ipv6.set(false);
        modal_force.set(false);
        modal_error.set(None);
        show_modal.set(true);
    };

    let open_edit_modal = move |opt: DnsmasqDhcpOption| {
        editing_option.set(Some(opt.clone()));
        modal_description.set(opt.description.clone().unwrap_or_default());
        modal_option.set(opt.option.clone());
        modal_value.set(opt.value.clone());
        modal_enabled.set(opt.enabled);
        modal_ipv6.set(opt.ipv6);
        modal_force.set(opt.force);
        modal_error.set(None);
        show_modal.set(true);
    };

    let close_modal = move |_| {
        show_modal.set(false);
    };

    let save_option = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();

        let option = modal_option.get();
        let value = modal_value.get();

        if option.is_empty() {
            modal_error.set(Some("Option name/number is required".to_string()));
            return;
        }

        let opt = DnsmasqDhcpOption {
            id: editing_option.get().and_then(|o| o.id),
            description: if modal_description.get().is_empty() {
                None
            } else {
                Some(modal_description.get())
            },
            option,
            value,
            match_tags: Vec::new(),
            enabled: modal_enabled.get(),
            ipv6: modal_ipv6.get(),
            force: modal_force.get(),
        };

        let token_val = token.get();
        spawn_local(async move {
            match api::save_dhcp_option(&token_val, opt).await {
                Ok(_) => {
                    show_modal.set(false);
                    config_changed.run(());
                    toasts.success("DHCP option saved".to_string());
                    reload_trigger.update(|v| *v += 1);
                }
                Err(e) => {
                    modal_error.set(Some(format!("Error: {}", e)));
                }
            }
        });
    };

    let delete_option = move |id: i64| {
        if !web_sys::window()
            .and_then(|w| w.confirm_with_message("Delete this DHCP option?").ok())
            .unwrap_or(false)
        {
            return;
        }

        let token_val = token.get();
        spawn_local(async move {
            match api::delete_dhcp_option(&token_val, id).await {
                Ok(()) => {
                    config_changed.run(());
                    toasts.success("DHCP option deleted".to_string());
                    reload_trigger.update(|v| *v += 1);
                }
                Err(e) => {
                    error_msg.set(Some(format!("Error: {}", e)));
                }
            }
        });
    };

    view! {
        <div class="space-y-4">
            <div class="flex justify-between items-center">
                <div>
                    <h3 class="text-lg font-medium text-white">"DHCP Options"</h3>
                    <p class="text-sm text-gray-400">"Custom DHCP options sent to clients"</p>
                </div>
                <button
                    on:click=open_new_modal
                    class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
                >
                    "+ Add Option"
                </button>
            </div>

            <Show when=move || dhcp_options.get().is_empty()>
                <div class="text-center py-8 text-gray-400">
                    "No custom DHCP options configured."
                </div>
            </Show>

            <Show when=move || !dhcp_options.get().is_empty()>
                <table class="w-full">
                    <thead class="bg-gray-700">
                        <tr>
                            <th class="px-4 py-3 text-left text-gray-300 font-medium">"Description"</th>
                            <th class="px-4 py-3 text-left text-gray-300 font-medium">"Option"</th>
                            <th class="px-4 py-3 text-left text-gray-300 font-medium">"Value"</th>
                            <th class="px-4 py-3 text-left text-gray-300 font-medium">"Flags"</th>
                            <th class="px-4 py-3 text-left text-gray-300 font-medium">"Status"</th>
                            <th class="px-4 py-3 text-right text-gray-300 font-medium">"Actions"</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-700">
                        <For
                            each=move || dhcp_options.get()
                            key=|opt| (opt.id, opt.option.clone(), opt.enabled)
                            children=move |opt: DnsmasqDhcpOption| {
                                let opt_for_edit = opt.clone();
                                let opt_id = opt.id.unwrap_or(0);
                                let flags = {
                                    let mut f = Vec::new();
                                    if opt.ipv6 { f.push("IPv6"); }
                                    if opt.force { f.push("Force"); }
                                    if f.is_empty() { "-".to_string() } else { f.join(", ") }
                                };
                                view! {
                                    <tr class="hover:bg-gray-700/30">
                                        <td class="px-4 py-3 text-white">{opt.description.clone().unwrap_or_else(|| "-".to_string())}</td>
                                        <td class="px-4 py-3 text-gray-300 font-mono">{opt.option.clone()}</td>
                                        <td class="px-4 py-3 text-gray-300 font-mono max-w-xs truncate">{opt.value.clone()}</td>
                                        <td class="px-4 py-3 text-gray-400 text-sm">{flags}</td>
                                        <td class="px-4 py-3">
                                            {if opt.enabled {
                                                view! { <span class="text-green-400">"Active"</span> }.into_any()
                                            } else {
                                                view! { <span class="text-gray-500">"Disabled"</span> }.into_any()
                                            }}
                                        </td>
                                        <td class="px-4 py-3 text-right">
                                            <div class="flex gap-2 justify-end">
                                                <button
                                                    on:click=move |_| open_edit_modal(opt_for_edit.clone())
                                                    class="bg-yellow-600 hover:bg-yellow-700 text-white px-3 py-1 rounded text-sm"
                                                >
                                                    "Edit"
                                                </button>
                                                <button
                                                    on:click=move |_| delete_option(opt_id)
                                                    class="bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded text-sm"
                                                >
                                                    "Delete"
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                }
                            }
                        />
                    </tbody>
                </table>
            </Show>

            // Modal
            <Show when=move || show_modal.get()>
                <div class="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
                    <div class="bg-gray-800 rounded-lg p-6 max-w-lg w-full">
                        <h2 class="text-xl font-semibold text-white mb-4">
                            {move || if editing_option.get().is_some() { "Edit DHCP Option" } else { "Add DHCP Option" }}
                        </h2>

                        <form on:submit=save_option class="space-y-4">
                            <div>
                                <label class="block text-gray-300 mb-2">"Description (optional)"</label>
                                <input
                                    type="text"
                                    prop:value=move || modal_description.get()
                                    on:input=move |ev| modal_description.set(event_target_value(&ev))
                                    placeholder="e.g., NTP Server"
                                    class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white"
                                />
                            </div>

                            <div>
                                <label class="block text-gray-300 mb-2">"Option (name or number)"</label>
                                <input
                                    type="text"
                                    prop:value=move || modal_option.get()
                                    on:input=move |ev| modal_option.set(event_target_value(&ev))
                                    placeholder="e.g., option:ntp-server or 42"
                                    class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white font-mono"
                                    required
                                />
                                <p class="text-sm text-gray-500 mt-1">"Use 'option:name' format or option number"</p>
                            </div>

                            <div>
                                <label class="block text-gray-300 mb-2">"Value"</label>
                                <input
                                    type="text"
                                    prop:value=move || modal_value.get()
                                    on:input=move |ev| modal_value.set(event_target_value(&ev))
                                    placeholder="e.g., 192.168.1.1"
                                    class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white font-mono"
                                />
                            </div>

                            <div class="grid grid-cols-3 gap-4">
                                <div class="flex items-center gap-3">
                                    <input
                                        type="checkbox"
                                        id="opt_enabled"
                                        prop:checked=move || modal_enabled.get()
                                        on:change=move |ev| modal_enabled.set(event_target_checked(&ev))
                                        class="w-4 h-4"
                                    />
                                    <label for="opt_enabled" class="text-gray-300">"Enabled"</label>
                                </div>
                                <div class="flex items-center gap-3">
                                    <input
                                        type="checkbox"
                                        id="opt_ipv6"
                                        prop:checked=move || modal_ipv6.get()
                                        on:change=move |ev| modal_ipv6.set(event_target_checked(&ev))
                                        class="w-4 h-4"
                                    />
                                    <label for="opt_ipv6" class="text-gray-300">"IPv6"</label>
                                </div>
                                <div class="flex items-center gap-3">
                                    <input
                                        type="checkbox"
                                        id="opt_force"
                                        prop:checked=move || modal_force.get()
                                        on:change=move |ev| modal_force.set(event_target_checked(&ev))
                                        class="w-4 h-4"
                                    />
                                    <label for="opt_force" class="text-gray-300">"Force"</label>
                                </div>
                            </div>

                            <Show when=move || modal_error.get().is_some()>
                                <div class="bg-red-900/50 border border-red-500 rounded p-3 text-red-200 text-sm">
                                    {move || modal_error.get().unwrap_or_default()}
                                </div>
                            </Show>

                            <div class="flex gap-2 pt-2">
                                <button
                                    type="submit"
                                    class="flex-1 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
                                >
                                    "Save"
                                </button>
                                <button
                                    type="button"
                                    on:click=close_modal
                                    class="flex-1 bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded"
                                >
                                    "Cancel"
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </Show>
        </div>
    }
}

// ============================================================================
// Host Records Section
// ============================================================================

#[component]
fn HostRecordsSection(
    token: Signal<String>,
    host_records: RwSignal<Vec<DnsmasqHostRecord>>,
    error_msg: RwSignal<Option<String>>,
    reload_trigger: RwSignal<u32>,
) -> impl IntoView {
    let toasts = use_toasts();
    let config_changed = use_config_changed();
    let show_modal = RwSignal::new(false);
    let editing_record = RwSignal::new(Option::<DnsmasqHostRecord>::None);
    let modal_hostnames = RwSignal::new(String::new()); // comma-separated
    let modal_ipv4 = RwSignal::new(String::new());
    let modal_ipv6 = RwSignal::new(String::new());
    let modal_enabled = RwSignal::new(true);
    let modal_error = RwSignal::new(Option::<String>::None);

    let open_new_modal = move |_| {
        editing_record.set(None);
        modal_hostnames.set(String::new());
        modal_ipv4.set(String::new());
        modal_ipv6.set(String::new());
        modal_enabled.set(true);
        modal_error.set(None);
        show_modal.set(true);
    };

    let open_edit_modal = move |rec: DnsmasqHostRecord| {
        editing_record.set(Some(rec.clone()));
        modal_hostnames.set(rec.hostnames.join(", "));
        modal_ipv4.set(rec.ipv4_address.clone().unwrap_or_default());
        modal_ipv6.set(rec.ipv6_address.clone().unwrap_or_default());
        modal_enabled.set(rec.enabled);
        modal_error.set(None);
        show_modal.set(true);
    };

    let close_modal = move |_| {
        show_modal.set(false);
    };

    let save_record = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();

        let hostnames_str = modal_hostnames.get();
        let hostnames: Vec<String> = hostnames_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let ipv4 = modal_ipv4.get();
        let ipv6 = modal_ipv6.get();

        if hostnames.is_empty() {
            modal_error.set(Some("At least one hostname is required".to_string()));
            return;
        }
        if ipv4.is_empty() && ipv6.is_empty() {
            modal_error.set(Some(
                "At least one IP address (v4 or v6) is required".to_string(),
            ));
            return;
        }

        let record = DnsmasqHostRecord {
            id: editing_record.get().and_then(|r| r.id),
            hostnames,
            ipv4_address: if ipv4.is_empty() { None } else { Some(ipv4) },
            ipv6_address: if ipv6.is_empty() { None } else { Some(ipv6) },
            ttl: None,
            enabled: modal_enabled.get(),
        };

        let token_val = token.get();
        spawn_local(async move {
            match api::save_host_record(&token_val, record).await {
                Ok(_) => {
                    show_modal.set(false);
                    config_changed.run(());
                    toasts.success("Host record saved".to_string());
                    reload_trigger.update(|v| *v += 1);
                }
                Err(e) => {
                    modal_error.set(Some(format!("Error: {}", e)));
                }
            }
        });
    };

    let delete_record = move |id: i64| {
        if !web_sys::window()
            .and_then(|w| w.confirm_with_message("Delete this host record?").ok())
            .unwrap_or(false)
        {
            return;
        }

        let token_val = token.get();
        spawn_local(async move {
            match api::delete_host_record(&token_val, id).await {
                Ok(()) => {
                    config_changed.run(());
                    toasts.success("Host record deleted".to_string());
                    reload_trigger.update(|v| *v += 1);
                }
                Err(e) => {
                    error_msg.set(Some(format!("Error: {}", e)));
                }
            }
        });
    };

    view! {
        <div class="space-y-4">
            <div class="flex justify-between items-center">
                <div>
                    <h3 class="text-lg font-medium text-white">"Host Records"</h3>
                    <p class="text-sm text-gray-400">"Map hostnames to IP addresses"</p>
                </div>
                <button
                    on:click=open_new_modal
                    class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
                >
                    "+ Add Host Record"
                </button>
            </div>

            <Show when=move || host_records.get().is_empty()>
                <div class="text-center py-8 text-gray-400">
                    "No host records configured."
                </div>
            </Show>

            <Show when=move || !host_records.get().is_empty()>
                <table class="w-full">
                    <thead class="bg-gray-700">
                        <tr>
                            <th class="px-4 py-3 text-left text-gray-300 font-medium">"Hostnames"</th>
                            <th class="px-4 py-3 text-left text-gray-300 font-medium">"IPv4"</th>
                            <th class="px-4 py-3 text-left text-gray-300 font-medium">"IPv6"</th>
                            <th class="px-4 py-3 text-left text-gray-300 font-medium">"Status"</th>
                            <th class="px-4 py-3 text-right text-gray-300 font-medium">"Actions"</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-700">
                        <For
                            each=move || host_records.get()
                            key=|rec| (rec.id, rec.hostnames.join(","), rec.enabled)
                            children=move |rec: DnsmasqHostRecord| {
                                let rec_for_edit = rec.clone();
                                let rec_id = rec.id.unwrap_or(0);
                                view! {
                                    <tr class="hover:bg-gray-700/30">
                                        <td class="px-4 py-3 text-white">{rec.hostnames.join(", ")}</td>
                                        <td class="px-4 py-3 text-gray-300 font-mono">{rec.ipv4_address.clone().unwrap_or_else(|| "-".to_string())}</td>
                                        <td class="px-4 py-3 text-gray-300 font-mono">{rec.ipv6_address.clone().unwrap_or_else(|| "-".to_string())}</td>
                                        <td class="px-4 py-3">
                                            {if rec.enabled {
                                                view! { <span class="text-green-400">"Active"</span> }.into_any()
                                            } else {
                                                view! { <span class="text-gray-500">"Disabled"</span> }.into_any()
                                            }}
                                        </td>
                                        <td class="px-4 py-3 text-right">
                                            <div class="flex gap-2 justify-end">
                                                <button
                                                    on:click=move |_| open_edit_modal(rec_for_edit.clone())
                                                    class="bg-yellow-600 hover:bg-yellow-700 text-white px-3 py-1 rounded text-sm"
                                                >
                                                    "Edit"
                                                </button>
                                                <button
                                                    on:click=move |_| delete_record(rec_id)
                                                    class="bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded text-sm"
                                                >
                                                    "Delete"
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                }
                            }
                        />
                    </tbody>
                </table>
            </Show>

            // Modal
            <Show when=move || show_modal.get()>
                <div class="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
                    <div class="bg-gray-800 rounded-lg p-6 max-w-lg w-full">
                        <h2 class="text-xl font-semibold text-white mb-4">
                            {move || if editing_record.get().is_some() { "Edit Host Record" } else { "Add Host Record" }}
                        </h2>

                        <form on:submit=save_record class="space-y-4">
                            <div>
                                <label class="block text-gray-300 mb-2">"Hostnames (comma-separated)"</label>
                                <input
                                    type="text"
                                    prop:value=move || modal_hostnames.get()
                                    on:input=move |ev| modal_hostnames.set(event_target_value(&ev))
                                    placeholder="e.g., server, server.lan"
                                    class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white"
                                    required
                                />
                            </div>

                            <div class="grid grid-cols-2 gap-4">
                                <div>
                                    <label class="block text-gray-300 mb-2">"IPv4 Address"</label>
                                    <input
                                        type="text"
                                        prop:value=move || modal_ipv4.get()
                                        on:input=move |ev| modal_ipv4.set(event_target_value(&ev))
                                        placeholder="192.168.1.100"
                                        class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white font-mono"
                                    />
                                </div>
                                <div>
                                    <label class="block text-gray-300 mb-2">"IPv6 Address"</label>
                                    <input
                                        type="text"
                                        prop:value=move || modal_ipv6.get()
                                        on:input=move |ev| modal_ipv6.set(event_target_value(&ev))
                                        placeholder="fd00::1"
                                        class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white font-mono"
                                    />
                                </div>
                            </div>

                            <div class="flex items-center gap-3">
                                <input
                                    type="checkbox"
                                    id="host_enabled"
                                    prop:checked=move || modal_enabled.get()
                                    on:change=move |ev| modal_enabled.set(event_target_checked(&ev))
                                    class="w-4 h-4"
                                />
                                <label for="host_enabled" class="text-gray-300">"Enable this record"</label>
                            </div>

                            <Show when=move || modal_error.get().is_some()>
                                <div class="bg-red-900/50 border border-red-500 rounded p-3 text-red-200 text-sm">
                                    {move || modal_error.get().unwrap_or_default()}
                                </div>
                            </Show>

                            <div class="flex gap-2 pt-2">
                                <button
                                    type="submit"
                                    class="flex-1 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
                                >
                                    "Save"
                                </button>
                                <button
                                    type="button"
                                    on:click=close_modal
                                    class="flex-1 bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded"
                                >
                                    "Cancel"
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </Show>
        </div>
    }
}

// ============================================================================
// CNAME Records Section
// ============================================================================

#[component]
fn CnameRecordsSection(
    token: Signal<String>,
    cname_records: RwSignal<Vec<DnsmasqCnameRecord>>,
    error_msg: RwSignal<Option<String>>,
    reload_trigger: RwSignal<u32>,
) -> impl IntoView {
    let toasts = use_toasts();
    let config_changed = use_config_changed();
    let show_modal = RwSignal::new(false);
    let editing_record = RwSignal::new(Option::<DnsmasqCnameRecord>::None);
    let modal_alias = RwSignal::new(String::new());
    let modal_target = RwSignal::new(String::new());
    let modal_enabled = RwSignal::new(true);
    let modal_error = RwSignal::new(Option::<String>::None);

    let open_new_modal = move |_| {
        editing_record.set(None);
        modal_alias.set(String::new());
        modal_target.set(String::new());
        modal_enabled.set(true);
        modal_error.set(None);
        show_modal.set(true);
    };

    let open_edit_modal = move |rec: DnsmasqCnameRecord| {
        editing_record.set(Some(rec.clone()));
        modal_alias.set(rec.alias.clone());
        modal_target.set(rec.target.clone());
        modal_enabled.set(rec.enabled);
        modal_error.set(None);
        show_modal.set(true);
    };

    let close_modal = move |_| {
        show_modal.set(false);
    };

    let save_record = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();

        let alias = modal_alias.get();
        let target = modal_target.get();

        if alias.is_empty() || target.is_empty() {
            modal_error.set(Some("Alias and target are required".to_string()));
            return;
        }

        let record = DnsmasqCnameRecord {
            id: editing_record.get().and_then(|r| r.id),
            alias,
            target,
            ttl: None,
            enabled: modal_enabled.get(),
        };

        let token_val = token.get();
        spawn_local(async move {
            match api::save_cname_record(&token_val, record).await {
                Ok(_) => {
                    show_modal.set(false);
                    config_changed.run(());
                    toasts.success("CNAME record saved".to_string());
                    reload_trigger.update(|v| *v += 1);
                }
                Err(e) => {
                    modal_error.set(Some(format!("Error: {}", e)));
                }
            }
        });
    };

    let delete_record = move |id: i64| {
        if !web_sys::window()
            .and_then(|w| w.confirm_with_message("Delete this CNAME record?").ok())
            .unwrap_or(false)
        {
            return;
        }

        let token_val = token.get();
        spawn_local(async move {
            match api::delete_cname_record(&token_val, id).await {
                Ok(()) => {
                    config_changed.run(());
                    toasts.success("CNAME record deleted".to_string());
                    reload_trigger.update(|v| *v += 1);
                }
                Err(e) => {
                    error_msg.set(Some(format!("Error: {}", e)));
                }
            }
        });
    };

    view! {
        <div class="space-y-4">
            <div class="flex justify-between items-center">
                <div>
                    <h3 class="text-lg font-medium text-white">"CNAME Records"</h3>
                    <p class="text-sm text-gray-400">"Alias one hostname to another"</p>
                </div>
                <button
                    on:click=open_new_modal
                    class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
                >
                    "+ Add CNAME"
                </button>
            </div>

            <Show when=move || cname_records.get().is_empty()>
                <div class="text-center py-8 text-gray-400">
                    "No CNAME records configured."
                </div>
            </Show>

            <Show when=move || !cname_records.get().is_empty()>
                <table class="w-full">
                    <thead class="bg-gray-700">
                        <tr>
                            <th class="px-4 py-3 text-left text-gray-300 font-medium">"Alias"</th>
                            <th class="px-4 py-3 text-left text-gray-300 font-medium">"Target"</th>
                            <th class="px-4 py-3 text-left text-gray-300 font-medium">"Status"</th>
                            <th class="px-4 py-3 text-right text-gray-300 font-medium">"Actions"</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-700">
                        <For
                            each=move || cname_records.get()
                            key=|rec| (rec.id, rec.alias.clone(), rec.enabled)
                            children=move |rec: DnsmasqCnameRecord| {
                                let rec_for_edit = rec.clone();
                                let rec_id = rec.id.unwrap_or(0);
                                view! {
                                    <tr class="hover:bg-gray-700/30">
                                        <td class="px-4 py-3 text-white">{rec.alias.clone()}</td>
                                        <td class="px-4 py-3 text-gray-300">{rec.target.clone()}</td>
                                        <td class="px-4 py-3">
                                            {if rec.enabled {
                                                view! { <span class="text-green-400">"Active"</span> }.into_any()
                                            } else {
                                                view! { <span class="text-gray-500">"Disabled"</span> }.into_any()
                                            }}
                                        </td>
                                        <td class="px-4 py-3 text-right">
                                            <div class="flex gap-2 justify-end">
                                                <button
                                                    on:click=move |_| open_edit_modal(rec_for_edit.clone())
                                                    class="bg-yellow-600 hover:bg-yellow-700 text-white px-3 py-1 rounded text-sm"
                                                >
                                                    "Edit"
                                                </button>
                                                <button
                                                    on:click=move |_| delete_record(rec_id)
                                                    class="bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded text-sm"
                                                >
                                                    "Delete"
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                }
                            }
                        />
                    </tbody>
                </table>
            </Show>

            // Modal
            <Show when=move || show_modal.get()>
                <div class="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
                    <div class="bg-gray-800 rounded-lg p-6 max-w-lg w-full">
                        <h2 class="text-xl font-semibold text-white mb-4">
                            {move || if editing_record.get().is_some() { "Edit CNAME Record" } else { "Add CNAME Record" }}
                        </h2>

                        <form on:submit=save_record class="space-y-4">
                            <div>
                                <label class="block text-gray-300 mb-2">"Alias"</label>
                                <input
                                    type="text"
                                    prop:value=move || modal_alias.get()
                                    on:input=move |ev| modal_alias.set(event_target_value(&ev))
                                    placeholder="e.g., www"
                                    class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white"
                                    required
                                />
                                <p class="text-sm text-gray-500 mt-1">"The name to alias"</p>
                            </div>

                            <div>
                                <label class="block text-gray-300 mb-2">"Target"</label>
                                <input
                                    type="text"
                                    prop:value=move || modal_target.get()
                                    on:input=move |ev| modal_target.set(event_target_value(&ev))
                                    placeholder="e.g., server.lan"
                                    class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white"
                                    required
                                />
                                <p class="text-sm text-gray-500 mt-1">"The canonical name this alias points to"</p>
                            </div>

                            <div class="flex items-center gap-3">
                                <input
                                    type="checkbox"
                                    id="cname_enabled"
                                    prop:checked=move || modal_enabled.get()
                                    on:change=move |ev| modal_enabled.set(event_target_checked(&ev))
                                    class="w-4 h-4"
                                />
                                <label for="cname_enabled" class="text-gray-300">"Enable this record"</label>
                            </div>

                            <Show when=move || modal_error.get().is_some()>
                                <div class="bg-red-900/50 border border-red-500 rounded p-3 text-red-200 text-sm">
                                    {move || modal_error.get().unwrap_or_default()}
                                </div>
                            </Show>

                            <div class="flex gap-2 pt-2">
                                <button
                                    type="submit"
                                    class="flex-1 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
                                >
                                    "Save"
                                </button>
                                <button
                                    type="button"
                                    on:click=close_modal
                                    class="flex-1 bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded"
                                >
                                    "Cancel"
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </Show>
        </div>
    }
}

// ============================================================================
// Address Overrides Tab
// ============================================================================

#[component]
fn AddressOverridesTab(
    token: Signal<String>,
    address_overrides: RwSignal<Vec<DnsmasqAddressOverride>>,
    error_msg: RwSignal<Option<String>>,
    reload_trigger: RwSignal<u32>,
) -> impl IntoView {
    let toasts = use_toasts();
    let config_changed = use_config_changed();
    let show_modal = RwSignal::new(false);
    let editing_override = RwSignal::new(Option::<DnsmasqAddressOverride>::None);
    let modal_domain = RwSignal::new(String::new());
    let modal_action = RwSignal::new(DnsmasqAddressAction::Block);
    let modal_redirect_address = RwSignal::new(String::new());
    let modal_enabled = RwSignal::new(true);
    let modal_error = RwSignal::new(Option::<String>::None);

    let open_new_modal = move |_| {
        editing_override.set(None);
        modal_domain.set(String::new());
        modal_action.set(DnsmasqAddressAction::Block);
        modal_redirect_address.set(String::new());
        modal_enabled.set(true);
        modal_error.set(None);
        show_modal.set(true);
    };

    let open_edit_modal = move |ovr: DnsmasqAddressOverride| {
        editing_override.set(Some(ovr.clone()));
        modal_domain.set(ovr.domain.clone());
        modal_action.set(ovr.action);
        modal_redirect_address.set(ovr.redirect_address.clone().unwrap_or_default());
        modal_enabled.set(ovr.enabled);
        modal_error.set(None);
        show_modal.set(true);
    };

    let close_modal = move |_| {
        show_modal.set(false);
    };

    let save_override = move |ev: web_sys::SubmitEvent| {
        ev.prevent_default();

        let domain = modal_domain.get();
        let action = modal_action.get();
        let redirect_address = modal_redirect_address.get();

        if domain.is_empty() {
            modal_error.set(Some("Domain is required".to_string()));
            return;
        }

        if matches!(action, DnsmasqAddressAction::Redirect) && redirect_address.is_empty() {
            modal_error.set(Some(
                "Redirect address is required for Redirect action".to_string(),
            ));
            return;
        }

        let ovr = DnsmasqAddressOverride {
            id: editing_override.get().and_then(|o| o.id),
            domain,
            action,
            redirect_address: if redirect_address.is_empty() {
                None
            } else {
                Some(redirect_address)
            },
            enabled: modal_enabled.get(),
        };

        let token_val = token.get();
        spawn_local(async move {
            match api::save_address_override(&token_val, ovr).await {
                Ok(_) => {
                    show_modal.set(false);
                    config_changed.run(());
                    toasts.success("Address override saved".to_string());
                    reload_trigger.update(|v| *v += 1);
                }
                Err(e) => {
                    modal_error.set(Some(format!("Error: {}", e)));
                }
            }
        });
    };

    let delete_override = move |id: i64| {
        if !web_sys::window()
            .and_then(|w| w.confirm_with_message("Delete this address override?").ok())
            .unwrap_or(false)
        {
            return;
        }

        let token_val = token.get();
        spawn_local(async move {
            match api::delete_address_override(&token_val, id).await {
                Ok(()) => {
                    config_changed.run(());
                    toasts.success("Address override deleted".to_string());
                    reload_trigger.update(|v| *v += 1);
                }
                Err(e) => {
                    error_msg.set(Some(format!("Error: {}", e)));
                }
            }
        });
    };

    let action_display = |action: &DnsmasqAddressAction| -> &'static str {
        match action {
            DnsmasqAddressAction::Block => "Block (NXDOMAIN)",
            DnsmasqAddressAction::Redirect => "Redirect",
            DnsmasqAddressAction::Null => "Null (0.0.0.0)",
        }
    };

    view! {
        <div class="space-y-4">
            <div class="flex justify-between items-center">
                <div>
                    <h3 class="text-lg font-medium text-white">"Address Overrides"</h3>
                    <p class="text-sm text-gray-400">"Block domains or redirect them to specific addresses"</p>
                </div>
                <button
                    on:click=open_new_modal
                    class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
                >
                    "+ Add Override"
                </button>
            </div>

            <Show when=move || address_overrides.get().is_empty()>
                <div class="text-center py-8 text-gray-400">
                    "No address overrides configured."
                </div>
            </Show>

            <Show when=move || !address_overrides.get().is_empty()>
                <table class="w-full">
                    <thead class="bg-gray-700">
                        <tr>
                            <th class="px-4 py-3 text-left text-gray-300 font-medium">"Domain"</th>
                            <th class="px-4 py-3 text-left text-gray-300 font-medium">"Action"</th>
                            <th class="px-4 py-3 text-left text-gray-300 font-medium">"Redirect To"</th>
                            <th class="px-4 py-3 text-left text-gray-300 font-medium">"Status"</th>
                            <th class="px-4 py-3 text-right text-gray-300 font-medium">"Actions"</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-700">
                        <For
                            each=move || address_overrides.get()
                            key=|ovr| (ovr.id, ovr.domain.clone(), ovr.enabled)
                            children=move |ovr: DnsmasqAddressOverride| {
                                let ovr_for_edit = ovr.clone();
                                let ovr_id = ovr.id.unwrap_or(0);
                                let action_text = action_display(&ovr.action);
                                view! {
                                    <tr class="hover:bg-gray-700/30">
                                        <td class="px-4 py-3 text-white">{ovr.domain.clone()}</td>
                                        <td class="px-4 py-3 text-gray-300">{action_text}</td>
                                        <td class="px-4 py-3 text-gray-300 font-mono">{ovr.redirect_address.clone().unwrap_or_else(|| "-".to_string())}</td>
                                        <td class="px-4 py-3">
                                            {if ovr.enabled {
                                                view! { <span class="text-green-400">"Active"</span> }.into_any()
                                            } else {
                                                view! { <span class="text-gray-500">"Disabled"</span> }.into_any()
                                            }}
                                        </td>
                                        <td class="px-4 py-3 text-right">
                                            <div class="flex gap-2 justify-end">
                                                <button
                                                    on:click=move |_| open_edit_modal(ovr_for_edit.clone())
                                                    class="bg-yellow-600 hover:bg-yellow-700 text-white px-3 py-1 rounded text-sm"
                                                >
                                                    "Edit"
                                                </button>
                                                <button
                                                    on:click=move |_| delete_override(ovr_id)
                                                    class="bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded text-sm"
                                                >
                                                    "Delete"
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                }
                            }
                        />
                    </tbody>
                </table>
            </Show>

            // Modal
            <Show when=move || show_modal.get()>
                <div class="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
                    <div class="bg-gray-800 rounded-lg p-6 max-w-lg w-full">
                        <h2 class="text-xl font-semibold text-white mb-4">
                            {move || if editing_override.get().is_some() { "Edit Address Override" } else { "Add Address Override" }}
                        </h2>

                        <form on:submit=save_override class="space-y-4">
                            <div>
                                <label class="block text-gray-300 mb-2">"Domain"</label>
                                <input
                                    type="text"
                                    prop:value=move || modal_domain.get()
                                    on:input=move |ev| modal_domain.set(event_target_value(&ev))
                                    placeholder="e.g., ads.example.com or .example.com"
                                    class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white"
                                    required
                                />
                                <p class="text-sm text-gray-500 mt-1">"Use .domain to match domain and all subdomains"</p>
                            </div>

                            <div>
                                <label class="block text-gray-300 mb-2">"Action"</label>
                                <select
                                    prop:value=move || format!("{:?}", modal_action.get())
                                    on:change=move |ev| {
                                        let value = event_target_value(&ev);
                                        modal_action.set(match value.as_str() {
                                            "Block" => DnsmasqAddressAction::Block,
                                            "Redirect" => DnsmasqAddressAction::Redirect,
                                            "Null" => DnsmasqAddressAction::Null,
                                            _ => DnsmasqAddressAction::Block,
                                        });
                                    }
                                    class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white"
                                >
                                    <option value="Block">"Block (NXDOMAIN) - Return 'not found'"</option>
                                    <option value="Redirect">"Redirect - Point to custom address"</option>
                                    <option value="Null">"Null (0.0.0.0) - Return null address"</option>
                                </select>
                            </div>

                            <Show when=move || matches!(modal_action.get(), DnsmasqAddressAction::Redirect)>
                                <div>
                                    <label class="block text-gray-300 mb-2">"Redirect Address"</label>
                                    <input
                                        type="text"
                                        prop:value=move || modal_redirect_address.get()
                                        on:input=move |ev| modal_redirect_address.set(event_target_value(&ev))
                                        placeholder="e.g., 192.168.1.1"
                                        class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded text-white font-mono"
                                    />
                                </div>
                            </Show>

                            <div class="flex items-center gap-3">
                                <input
                                    type="checkbox"
                                    id="override_enabled"
                                    prop:checked=move || modal_enabled.get()
                                    on:change=move |ev| modal_enabled.set(event_target_checked(&ev))
                                    class="w-4 h-4"
                                />
                                <label for="override_enabled" class="text-gray-300">"Enable this override"</label>
                            </div>

                            <Show when=move || modal_error.get().is_some()>
                                <div class="bg-red-900/50 border border-red-500 rounded p-3 text-red-200 text-sm">
                                    {move || modal_error.get().unwrap_or_default()}
                                </div>
                            </Show>

                            <div class="flex gap-2 pt-2">
                                <button
                                    type="submit"
                                    class="flex-1 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
                                >
                                    "Save"
                                </button>
                                <button
                                    type="button"
                                    on:click=close_modal
                                    class="flex-1 bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded"
                                >
                                    "Cancel"
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </Show>
        </div>
    }
}
