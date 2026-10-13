//! Interface edit page for configuring individual interface settings

use keystone_core::{
    ActivationPolicy, AddressScope, DhcpMode, DhcpPrefixDelegationConfig, Dhcpv4ClientConfig,
    Dhcpv4ClientIdentifier, Dhcpv6ClientConfig, InterfaceConfig, InterfaceRole, IpForwardMode,
    IpMasqueradeMode, Ipv6AcceptRaConfig, LinkLocalMode, RouteType, StaticAddress, StaticRoute,
};
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::hooks::use_params_map;

use crate::api;
use crate::components::form_utils::{event_target_checked, event_target_value};
use crate::components::{StaticIpSettings, use_config_changed};

#[component]
pub fn InterfaceEditPage(
    auth_token: ReadSignal<Option<String>>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let params = use_params_map();

    // Page state
    let (interface_name, set_interface_name) = signal(String::new());
    let (config, set_config) = signal::<Option<InterfaceConfig>>(None);
    let (loading, set_loading) = signal(true);
    let (saving, set_saving) = signal(false);
    let (error, set_error) = signal::<Option<String>>(None);
    let (success, set_success) = signal::<Option<String>>(None);
    let (is_new, set_is_new) = signal(false);
    // Saving only updates the database. The pending-changes bar writes the
    // networkd files; this tracks the follow-up that re-reads them on this link.
    let (needs_apply, set_needs_apply) = signal(false);
    let (reconfiguring, set_reconfiguring) = signal(false);
    let config_changed = use_config_changed();

    // Form fields
    let (role, set_role) = signal(InterfaceRole::LAN);
    let (description, set_description) = signal(String::new());
    let (dhcp_mode, set_dhcp_mode) = signal(DhcpMode::No);
    let (addresses, set_addresses) = signal::<Vec<StaticAddress>>(vec![]);
    let (new_address, set_new_address) = signal(String::new());
    let (gateway, set_gateway) = signal(String::new());
    let (dns_servers, set_dns_servers) = signal::<Vec<String>>(vec![]);
    let (new_dns, set_new_dns) = signal(String::new());
    let (search_domains, set_search_domains) = signal::<Vec<String>>(vec![]);
    let (new_domain, set_new_domain) = signal(String::new());
    let (routes, set_routes) = signal::<Vec<StaticRoute>>(vec![]);
    let (new_route_dest, set_new_route_dest) = signal(String::new());
    let (new_route_gw, set_new_route_gw) = signal(String::new());
    let (new_route_metric, set_new_route_metric) = signal(String::new());
    let (ipv6_accept_ra, set_ipv6_accept_ra) = signal(true);
    let (ipv6_ra_use_dns, set_ipv6_ra_use_dns) = signal(true);
    let (ipv6_ra_use_gateway, set_ipv6_ra_use_gateway) = signal(true);
    let (ipv6_ra_use_route_prefix, set_ipv6_ra_use_route_prefix) = signal(true);
    let (ipv6_ra_use_autonomous, set_ipv6_ra_use_autonomous) = signal(true);
    let (ipv6_send_ra, set_ipv6_send_ra) = signal(false);
    let (pd_enabled, set_pd_enabled) = signal(false);
    let (pd_uplink, set_pd_uplink) = signal(String::new());
    let (pd_subnet_id, set_pd_subnet_id) = signal(String::new());
    let (pd_ipv6_token, set_pd_ipv6_token) = signal(String::new());
    let (pd_announce, set_pd_announce) = signal(true);
    let (ip_forward, set_ip_forward) = signal(IpForwardMode::No);
    let (link_mtu, set_link_mtu) = signal(String::new());

    // DHCPv4 client settings
    let (dhcp_use_dns, set_dhcp_use_dns) = signal(true);
    let (dhcp_use_ntp, set_dhcp_use_ntp) = signal(true);
    let (dhcp_use_routes, set_dhcp_use_routes) = signal(true);
    let (dhcp_use_gateway, set_dhcp_use_gateway) = signal(true);
    let (dhcp_use_mtu, set_dhcp_use_mtu) = signal(true);
    let (dhcp_send_hostname, set_dhcp_send_hostname) = signal(true);
    let (dhcp_route_metric, set_dhcp_route_metric) = signal(String::new());
    let (dhcp_client_identifier, set_dhcp_client_identifier) =
        signal::<Option<Dhcpv4ClientIdentifier>>(None);

    // DHCPv6 client settings
    let (dhcp6_use_dns, set_dhcp6_use_dns) = signal(true);
    let (dhcp6_use_ntp, set_dhcp6_use_ntp) = signal(true);
    let (dhcp6_use_delegated_prefix, set_dhcp6_use_delegated_prefix) = signal(true);
    let (dhcp6_rapid_commit, set_dhcp6_rapid_commit) = signal(true);
    let (dhcp6_prefix_hint, set_dhcp6_prefix_hint) = signal(String::new());
    let (dhcp6_without_ra, set_dhcp6_without_ra) = signal("no".to_string());

    // Interface state settings (P2)
    let (link_local, set_link_local) = signal(LinkLocalMode::default());
    let (required_for_online, set_required_for_online) = signal(true);
    let (activation_policy, set_activation_policy) = signal(ActivationPolicy::default());

    // UI state
    let (show_advanced, set_show_advanced) = signal(false);
    let (show_interface_state, set_show_interface_state) = signal(false);

    // Load interface configuration
    Effect::new(move |_| {
        let name = params.read().get("name").unwrap_or_default();
        set_interface_name.set(name.clone());

        if let Some(token) = auth_token.get() {
            let name = name.clone();
            spawn_local(async move {
                match api::fetch_interface_config(&token, &name).await {
                    Ok(Some(cfg)) => {
                        // Populate form fields from config
                        set_role.set(cfg.role);
                        set_description.set(cfg.description.clone().unwrap_or_default());
                        set_dhcp_mode.set(cfg.dhcp_mode);
                        set_addresses.set(cfg.addresses.clone());
                        set_gateway.set(cfg.gateway.clone().unwrap_or_default());
                        set_dns_servers.set(cfg.dns_servers.clone());
                        set_search_domains.set(cfg.search_domains.clone());
                        set_routes.set(cfg.routes.clone());
                        set_ipv6_accept_ra.set(cfg.ipv6_accept_ra);
                        if let Some(ra_cfg) = &cfg.ipv6_accept_ra_config {
                            set_ipv6_ra_use_dns.set(ra_cfg.use_dns);
                            set_ipv6_ra_use_gateway.set(ra_cfg.use_gateway);
                            set_ipv6_ra_use_route_prefix.set(ra_cfg.use_route_prefix);
                            set_ipv6_ra_use_autonomous.set(ra_cfg.use_autonomous_prefix);
                        }
                        set_ipv6_send_ra.set(cfg.ipv6_send_ra);
                        if let Some(pd_cfg) = &cfg.dhcp_prefix_delegation {
                            set_pd_enabled.set(true);
                            set_pd_uplink.set(pd_cfg.uplink_interface.clone().unwrap_or_default());
                            set_pd_subnet_id.set(
                                pd_cfg
                                    .subnet_id
                                    .map(|id| id.to_string())
                                    .unwrap_or_default(),
                            );
                            set_pd_ipv6_token.set(pd_cfg.ipv6_token.clone().unwrap_or_default());
                            set_pd_announce.set(pd_cfg.announce);
                        }
                        set_ip_forward.set(cfg.ip_forward);
                        set_link_mtu.set(cfg.mtu.map(|v| v.to_string()).unwrap_or_default());

                        // DHCPv4 client settings
                        if let Some(dhcp_cfg) = &cfg.dhcpv4_client {
                            set_dhcp_client_identifier.set(dhcp_cfg.client_identifier);
                            set_dhcp_use_dns.set(dhcp_cfg.use_dns);
                            set_dhcp_use_ntp.set(dhcp_cfg.use_ntp);
                            set_dhcp_use_routes.set(dhcp_cfg.use_routes);
                            set_dhcp_use_gateway.set(dhcp_cfg.use_gateway);
                            set_dhcp_use_mtu.set(dhcp_cfg.use_mtu);
                            set_dhcp_send_hostname.set(dhcp_cfg.send_hostname);
                            set_dhcp_route_metric.set(
                                dhcp_cfg
                                    .route_metric
                                    .map(|m| m.to_string())
                                    .unwrap_or_default(),
                            );
                        }

                        // DHCPv6 client settings
                        if let Some(dhcp6_cfg) = &cfg.dhcpv6_client {
                            set_dhcp6_use_dns.set(dhcp6_cfg.use_dns);
                            set_dhcp6_use_ntp.set(dhcp6_cfg.use_ntp);
                            set_dhcp6_use_delegated_prefix.set(dhcp6_cfg.use_delegated_prefix);
                            set_dhcp6_rapid_commit.set(dhcp6_cfg.rapid_commit);
                            set_dhcp6_prefix_hint
                                .set(dhcp6_cfg.prefix_delegation_hint.clone().unwrap_or_default());
                            set_dhcp6_without_ra.set(dhcp6_cfg.without_ra.clone());
                        }

                        // Interface state settings (P2)
                        set_link_local.set(cfg.link_local);
                        set_required_for_online.set(cfg.required_for_online);
                        set_activation_policy.set(cfg.activation_policy);

                        set_config.set(Some(cfg));
                        set_is_new.set(false);
                    }
                    Ok(None) => {
                        // New interface - create default config
                        let new_cfg = InterfaceConfig {
                            id: None,
                            name: name.clone(),
                            role: InterfaceRole::LAN,
                            enabled: true,
                            description: None,
                            dhcp_mode: DhcpMode::Ipv4,
                            addresses: vec![],
                            routes: vec![],
                            dns_servers: vec![],
                            search_domains: vec![],
                            gateway: None,
                            link_local: LinkLocalMode::default(),
                            required_for_online: true,
                            activation_policy: ActivationPolicy::default(),
                            dhcpv4_client: None,
                            dhcpv6_client: None,
                            ipv6_accept_ra: true,
                            ipv6_accept_ra_config: None,
                            ipv6_send_ra: false,
                            dhcp_prefix_delegation: None,
                            ip_forward: IpForwardMode::No,
                            ip_masquerade: IpMasqueradeMode::No,
                            mtu: None,
                            vlans: vec![],
                        };
                        set_dhcp_mode.set(DhcpMode::Ipv4);
                        set_config.set(Some(new_cfg));
                        set_is_new.set(true);
                    }
                    Err(e) => {
                        if e == "Unauthorized" {
                            on_unauthorized.run(());
                        } else {
                            set_error.set(Some(e));
                        }
                    }
                }
                set_loading.set(false);
            });
        }
    });

    // Add static address (inner logic)
    let do_add_address = move || {
        let addr = new_address.get();
        if !addr.is_empty() {
            set_addresses.update(|list| {
                list.push(StaticAddress {
                    address: addr,
                    label: None,
                    scope: AddressScope::default(),
                });
            });
            set_new_address.set(String::new());
        }
    };

    // Remove static address
    let remove_address = move |index: usize| {
        set_addresses.update(|list| {
            if index < list.len() {
                list.remove(index);
            }
        });
    };

    // Add DNS server (inner logic)
    let do_add_dns = move || {
        let dns = new_dns.get();
        if !dns.is_empty() {
            set_dns_servers.update(|list| {
                list.push(dns);
            });
            set_new_dns.set(String::new());
        }
    };

    // Remove DNS server
    let remove_dns = move |index: usize| {
        set_dns_servers.update(|list| {
            if index < list.len() {
                list.remove(index);
            }
        });
    };

    // Add static route (inner logic)
    let do_add_route = move || {
        let gw = new_route_gw.get();
        if !gw.is_empty() {
            let dest = new_route_dest.get();
            let metric_str = new_route_metric.get();
            let metric = metric_str.parse::<u32>().ok();

            set_routes.update(|list| {
                list.push(StaticRoute {
                    destination: if dest.is_empty() { None } else { Some(dest) },
                    gateway: gw,
                    metric,
                    table: None,
                    route_type: RouteType::default(),
                });
            });
            set_new_route_dest.set(String::new());
            set_new_route_gw.set(String::new());
            set_new_route_metric.set(String::new());
        }
    };

    // Remove static route
    let remove_route = move |index: usize| {
        set_routes.update(|list| {
            if index < list.len() {
                list.remove(index);
            }
        });
    };

    // Add search domain (inner logic)
    let do_add_domain = move || {
        let domain = new_domain.get();
        if !domain.is_empty() {
            set_search_domains.update(|list| {
                list.push(domain);
            });
            set_new_domain.set(String::new());
        }
    };

    // Remove search domain
    let remove_domain = move |index: usize| {
        set_search_domains.update(|list| {
            if index < list.len() {
                list.remove(index);
            }
        });
    };

    // Save configuration
    let save_changes = move |_| {
        spawn_local(async move {
            set_saving.set(true);
            set_error.set(None);
            set_success.set(None);

            if let Some(token) = auth_token.get()
                && let Some(current) = config.get()
            {
                let ipv6_token = pd_ipv6_token.get().trim().to_string();
                if !ipv6_token.is_empty() && ipv6_token.parse::<std::net::Ipv6Addr>().is_err() {
                    set_error.set(Some(
                        "IPv6 token must be a valid IPv6 address, such as ::1".to_string(),
                    ));
                    set_saving.set(false);
                    return;
                }
                let gw = gateway.get();
                let desc = description.get();
                let current_dhcp_mode = dhcp_mode.get();

                // Build DHCPv4 client config if DHCP includes IPv4
                let dhcpv4_client =
                    if current_dhcp_mode == DhcpMode::Yes || current_dhcp_mode == DhcpMode::Ipv4 {
                        Some(Dhcpv4ClientConfig {
                            client_identifier: dhcp_client_identifier.get(),
                            send_hostname: dhcp_send_hostname.get(),
                            hostname: None,
                            use_dns: dhcp_use_dns.get(),
                            use_ntp: dhcp_use_ntp.get(),
                            use_routes: dhcp_use_routes.get(),
                            use_gateway: dhcp_use_gateway.get(),
                            use_mtu: dhcp_use_mtu.get(),
                            use_domains: "yes".to_string(),
                            route_metric: dhcp_route_metric.get().parse::<u32>().ok(),
                        })
                    } else {
                        None
                    };

                // Build DHCPv6 client config if DHCP includes IPv6
                let dhcpv6_client =
                    if current_dhcp_mode == DhcpMode::Yes || current_dhcp_mode == DhcpMode::Ipv6 {
                        let hint = dhcp6_prefix_hint.get();
                        Some(Dhcpv6ClientConfig {
                            use_dns: dhcp6_use_dns.get(),
                            use_ntp: dhcp6_use_ntp.get(),
                            use_domains: "yes".to_string(),
                            use_delegated_prefix: dhcp6_use_delegated_prefix.get(),
                            prefix_delegation_hint: if hint.is_empty() { None } else { Some(hint) },
                            rapid_commit: dhcp6_rapid_commit.get(),
                            without_ra: dhcp6_without_ra.get(),
                        })
                    } else {
                        None
                    };

                let updated = InterfaceConfig {
                    id: current.id,
                    name: current.name.clone(),
                    role: role.get(),
                    enabled: true,
                    description: if desc.is_empty() { None } else { Some(desc) },
                    dhcp_mode: current_dhcp_mode,
                    addresses: addresses.get(),
                    routes: routes.get(),
                    dns_servers: dns_servers.get(),
                    search_domains: search_domains.get(),
                    gateway: if gw.is_empty() { None } else { Some(gw) },
                    link_local: link_local.get(),
                    required_for_online: required_for_online.get(),
                    activation_policy: activation_policy.get(),
                    dhcpv4_client,
                    dhcpv6_client,
                    ipv6_accept_ra: ipv6_accept_ra.get(),
                    ipv6_accept_ra_config: if ipv6_accept_ra.get() {
                        Some(Ipv6AcceptRaConfig {
                            use_dns: ipv6_ra_use_dns.get(),
                            use_gateway: ipv6_ra_use_gateway.get(),
                            use_route_prefix: ipv6_ra_use_route_prefix.get(),
                            use_autonomous_prefix: ipv6_ra_use_autonomous.get(),
                        })
                    } else {
                        None
                    },
                    ipv6_send_ra: ipv6_send_ra.get(),
                    dhcp_prefix_delegation: if pd_enabled.get() {
                        let uplink = pd_uplink.get();
                        Some(DhcpPrefixDelegationConfig {
                            uplink_interface: if uplink.is_empty() {
                                None
                            } else {
                                Some(uplink)
                            },
                            subnet_id: pd_subnet_id.get().parse::<u64>().ok(),
                            ipv6_token: {
                                let value = pd_ipv6_token.get().trim().to_string();
                                if value.is_empty() { None } else { Some(value) }
                            },
                            announce: pd_announce.get(),
                        })
                    } else {
                        None
                    },
                    ip_forward: ip_forward.get(),
                    ip_masquerade: current.ip_masquerade,
                    mtu: link_mtu.get().parse().ok(),
                    vlans: current.vlans.clone(),
                };

                match api::save_interface_config(&token, updated.clone()).await {
                    Ok(response) => {
                        if response.success {
                            set_config.set(Some(InterfaceConfig {
                                id: response.config_id,
                                ..updated
                            }));
                            set_is_new.set(false);
                            set_success.set(Some("Configuration saved".to_string()));
                            set_needs_apply.set(true);
                            config_changed.run(());
                        } else {
                            set_error.set(Some(response.message));
                        }
                    }
                    Err(e) => {
                        if e == "Unauthorized" {
                            on_unauthorized.run(());
                        } else {
                            set_error.set(Some(e));
                        }
                    }
                }
            }
            set_saving.set(false);
        });
    };

    let reconfigure_link = move |_| {
        let Some(token) = auth_token.get_untracked() else {
            return;
        };
        let name = interface_name.get_untracked();
        set_reconfiguring.set(true);
        set_error.set(None);
        set_success.set(None);
        spawn_local(async move {
            match api::reconfigure_interface(&token, &name).await {
                Ok(response) if response.success => {
                    set_success.set(Some(response.message));
                    set_needs_apply.set(false);
                }
                Ok(response) => set_error.set(Some(response.message)),
                Err(e) if e == "Unauthorized" => on_unauthorized.run(()),
                Err(e) => set_error.set(Some(format!("Failed to reconfigure {name}: {e}"))),
            }
            set_reconfiguring.set(false);
        });
    };

    let go_back = move |_| {
        if let Some(window) = web_sys::window() {
            let _ = window.location().set_href("/interfaces");
        }
    };

    // Derived signals for For components to avoid complex expressions in view
    let addresses_indexed = move || addresses.get().into_iter().enumerate().collect::<Vec<_>>();
    let dns_indexed = move || {
        dns_servers
            .get()
            .into_iter()
            .enumerate()
            .collect::<Vec<_>>()
    };
    let domains_indexed = move || {
        search_domains
            .get()
            .into_iter()
            .enumerate()
            .collect::<Vec<_>>()
    };
    let routes_indexed = move || routes.get().into_iter().enumerate().collect::<Vec<_>>();

    view! {
        <div class="space-y-6">
            // Header
            <div class="flex items-center gap-4">
                <button class="text-gray-400 hover:text-white" on:click=go_back>
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/>
                    </svg>
                </button>
                <div>
                    <h1 class="text-2xl font-semibold text-blue-300">
                        "Configure " {move || interface_name.get()}
                    </h1>
                    <p class="text-gray-400">
                        {move || if is_new.get() { "New interface configuration" } else { "Edit interface settings" }}
                    </p>
                </div>
            </div>

            // Messages
            <Show when=move || error.get().is_some()>
                <div class="bg-red-900/50 border border-red-500 text-red-200 px-4 py-3 rounded">
                    {move || error.get().unwrap_or_default()}
                </div>
            </Show>
            <Show when=move || success.get().is_some()>
                <div class="bg-green-900/50 border border-green-500 text-green-200 px-4 py-3 rounded">
                    {move || success.get().unwrap_or_default()}
                </div>
            </Show>
            <Show when=move || needs_apply.get() && !is_new.get()>
                <div class="bg-yellow-900/30 border border-yellow-600 text-yellow-200 px-4 py-3 rounded flex items-center gap-3 flex-wrap">
                    <span class="flex-1">
                        "Saved, but not live yet. Apply all in the pending changes bar writes the networkd files; then Reconfigure Link makes networkd re-read them on this link (a link with DHCP may briefly lose its lease)."
                    </span>
                    <button
                        class="bg-gray-600 hover:bg-gray-500 disabled:opacity-50 text-white px-3 py-1.5 rounded text-sm"
                        disabled=move || reconfiguring.get()
                        on:click=reconfigure_link
                    >
                        {move || if reconfiguring.get() { "Reconfiguring..." } else { "Reconfigure Link" }}
                    </button>
                </div>
            </Show>

            // Loading state
            <Show when=move || loading.get()>
                <div class="text-gray-400">"Loading..."</div>
            </Show>

            // Main form
            <Show when=move || !loading.get() && config.get().is_some()>
                <div class="bg-gray-800 rounded-lg p-6 shadow-lg space-y-6">
                    // Role
                    <div>
                        <label class="block text-gray-300 mb-2 font-medium">"Role"</label>
                        <select
                            class="w-full bg-gray-700 text-white rounded px-4 py-2.5 border border-gray-600"
                            on:change=move |ev| {
                                set_role.set(match event_target_value(&ev).as_str() {
                                    "WAN" => InterfaceRole::WAN,
                                    _ => InterfaceRole::LAN,
                                });
                            }
                        >
                            <option value="LAN" selected=move || role.get() == InterfaceRole::LAN>"LAN"</option>
                            <option value="WAN" selected=move || role.get() == InterfaceRole::WAN>"WAN"</option>
                        </select>
                    </div>

                    // Description
                    <div>
                        <label class="block text-gray-300 mb-2 font-medium">"Description"</label>
                        <input
                            type="text"
                            placeholder="e.g., Main WAN connection"
                            prop:value=move || description.get()
                            on:input=move |ev| set_description.set(event_target_value(&ev))
                            class="w-full bg-gray-700 text-white rounded px-4 py-2.5 border border-gray-600"
                        />
                        <p class="text-gray-500 text-sm mt-1">"Optional human-readable description"</p>
                    </div>

                    // DHCP Client Mode
                    <div>
                        <label class="block text-gray-300 mb-2 font-medium">"DHCP Client Mode"</label>
                        <select
                            class="w-full bg-gray-700 text-white rounded px-4 py-2.5 border border-gray-600"
                            on:change=move |ev| {
                                set_dhcp_mode.set(match event_target_value(&ev).as_str() {
                                    "yes" => DhcpMode::Yes,
                                    "ipv4" => DhcpMode::Ipv4,
                                    "ipv6" => DhcpMode::Ipv6,
                                    _ => DhcpMode::No,
                                });
                            }
                        >
                            <option value="no" selected=move || dhcp_mode.get() == DhcpMode::No>"Disabled"</option>
                            <option value="ipv4" selected=move || dhcp_mode.get() == DhcpMode::Ipv4>"IPv4 Only"</option>
                            <option value="ipv6" selected=move || dhcp_mode.get() == DhcpMode::Ipv6>"IPv6 Only"</option>
                            <option value="yes" selected=move || dhcp_mode.get() == DhcpMode::Yes>"IPv4 + IPv6"</option>
                        </select>
                    </div>

                    // DHCPv4 Client Settings (only show when DHCP includes IPv4)
                    <Show when=move || dhcp_mode.get() == DhcpMode::Yes || dhcp_mode.get() == DhcpMode::Ipv4>
                        <div class="bg-gray-700/50 rounded-lg p-4 space-y-4">
                            <h3 class="text-gray-200 font-medium">"DHCPv4 Client Options"</h3>
                            <div>
                                <label class="block text-gray-400 text-sm mb-1">"Client Identifier (DHCP option 61)"</label>
                                <select
                                    class="bg-gray-700 text-white rounded px-3 py-1.5 border border-gray-600"
                                    on:change=move |ev| {
                                        set_dhcp_client_identifier.set(match event_target_value(&ev).as_str() {
                                            "mac" => Some(Dhcpv4ClientIdentifier::Mac),
                                            "duid" => Some(Dhcpv4ClientIdentifier::Duid),
                                            _ => None,
                                        })
                                    }
                                >
                                    <option value="default" selected=move || dhcp_client_identifier.get().is_none()>"System default (DUID)"</option>
                                    <option value="mac" selected=move || dhcp_client_identifier.get() == Some(Dhcpv4ClientIdentifier::Mac)>"MAC address (common for ISP WAN)"</option>
                                    <option value="duid" selected=move || dhcp_client_identifier.get() == Some(Dhcpv4ClientIdentifier::Duid)>"DUID"</option>
                                </select>
                            </div>
                            <div class="grid grid-cols-2 gap-4">
                                <label class="flex items-center gap-2 cursor-pointer">
                                    <input
                                        type="checkbox"
                                        checked=move || dhcp_use_dns.get()
                                        on:change=move |ev| set_dhcp_use_dns.set(event_target_checked(&ev))
                                        class="w-4 h-4 rounded"
                                    />
                                    <span class="text-gray-300">"Use DHCP DNS"</span>
                                </label>
                                <label class="flex items-center gap-2 cursor-pointer">
                                    <input
                                        type="checkbox"
                                        checked=move || dhcp_use_ntp.get()
                                        on:change=move |ev| set_dhcp_use_ntp.set(event_target_checked(&ev))
                                        class="w-4 h-4 rounded"
                                    />
                                    <span class="text-gray-300">"Use DHCP NTP"</span>
                                </label>
                                <label class="flex items-center gap-2 cursor-pointer">
                                    <input
                                        type="checkbox"
                                        checked=move || dhcp_use_gateway.get()
                                        on:change=move |ev| set_dhcp_use_gateway.set(event_target_checked(&ev))
                                        class="w-4 h-4 rounded"
                                    />
                                    <span class="text-gray-300">"Use DHCP Gateway"</span>
                                </label>
                                <label class="flex items-center gap-2 cursor-pointer">
                                    <input
                                        type="checkbox"
                                        checked=move || dhcp_use_routes.get()
                                        on:change=move |ev| set_dhcp_use_routes.set(event_target_checked(&ev))
                                        class="w-4 h-4 rounded"
                                    />
                                    <span class="text-gray-300">"Use DHCP Routes"</span>
                                </label>
                                <label class="flex items-center gap-2 cursor-pointer">
                                    <input
                                        type="checkbox"
                                        checked=move || dhcp_use_mtu.get()
                                        on:change=move |ev| set_dhcp_use_mtu.set(event_target_checked(&ev))
                                        class="w-4 h-4 rounded"
                                    />
                                    <span class="text-gray-300">"Use DHCP MTU"</span>
                                </label>
                                <label class="flex items-center gap-2 cursor-pointer">
                                    <input
                                        type="checkbox"
                                        checked=move || dhcp_send_hostname.get()
                                        on:change=move |ev| set_dhcp_send_hostname.set(event_target_checked(&ev))
                                        class="w-4 h-4 rounded"
                                    />
                                    <span class="text-gray-300">"Send Hostname"</span>
                                </label>
                            </div>
                            <div>
                                <label class="block text-gray-400 text-sm mb-1">"Route Metric (optional)"</label>
                                <input
                                    type="text"
                                    placeholder="e.g., 100"
                                    prop:value=move || dhcp_route_metric.get()
                                    on:input=move |ev| set_dhcp_route_metric.set(event_target_value(&ev))
                                    class="w-32 bg-gray-700 text-white rounded px-3 py-1.5 border border-gray-600"
                                />
                            </div>
                        </div>
                    </Show>

                    // DHCPv6 Client Settings (only show when DHCP includes IPv6)
                    <Show when=move || dhcp_mode.get() == DhcpMode::Yes || dhcp_mode.get() == DhcpMode::Ipv6>
                        <div class="bg-gray-700/50 rounded-lg p-4 space-y-4">
                            <h3 class="text-gray-200 font-medium">"DHCPv6 Client Options"</h3>
                            <div class="grid grid-cols-2 gap-4">
                                <label class="flex items-center gap-2 cursor-pointer">
                                    <input
                                        type="checkbox"
                                        checked=move || dhcp6_use_dns.get()
                                        on:change=move |ev| set_dhcp6_use_dns.set(event_target_checked(&ev))
                                        class="w-4 h-4 rounded"
                                    />
                                    <span class="text-gray-300">"Use DHCPv6 DNS"</span>
                                </label>
                                <label class="flex items-center gap-2 cursor-pointer">
                                    <input
                                        type="checkbox"
                                        checked=move || dhcp6_use_ntp.get()
                                        on:change=move |ev| set_dhcp6_use_ntp.set(event_target_checked(&ev))
                                        class="w-4 h-4 rounded"
                                    />
                                    <span class="text-gray-300">"Use DHCPv6 NTP"</span>
                                </label>
                                <label class="flex items-center gap-2 cursor-pointer">
                                    <input
                                        type="checkbox"
                                        checked=move || dhcp6_use_delegated_prefix.get()
                                        on:change=move |ev| set_dhcp6_use_delegated_prefix.set(event_target_checked(&ev))
                                        class="w-4 h-4 rounded"
                                    />
                                    <span class="text-gray-300">"Request delegated prefix"</span>
                                </label>
                                <label class="flex items-center gap-2 cursor-pointer">
                                    <input
                                        type="checkbox"
                                        checked=move || dhcp6_rapid_commit.get()
                                        on:change=move |ev| set_dhcp6_rapid_commit.set(event_target_checked(&ev))
                                        class="w-4 h-4 rounded"
                                    />
                                    <span class="text-gray-300">"Rapid Commit"</span>
                                </label>
                            </div>
                            <div>
                                <label class="block text-gray-400 text-sm mb-1">"DHCPv6 without Router Advertisement"</label>
                                <select
                                    class="bg-gray-700 text-white rounded px-3 py-1.5 border border-gray-600"
                                    prop:value=move || dhcp6_without_ra.get()
                                    on:change=move |ev| set_dhcp6_without_ra.set(event_target_value(&ev))
                                >
                                    <option value="no">"Wait for RA flags (default)"</option>
                                    <option value="solicit">"Solicit immediately (recommended for prefix delegation)"</option>
                                    <option value="information-request">"Information-request only"</option>
                                </select>
                                <p class="text-gray-500 text-xs mt-1">"Some ISPs offer DHCPv6-PD without setting the RA M/O flags."</p>
                            </div>
                            <div>
                                <label class="block text-gray-400 text-sm mb-1">"Prefix Delegation Hint (optional)"</label>
                                <input
                                    type="text"
                                    placeholder="e.g., ::1/64"
                                    prop:value=move || dhcp6_prefix_hint.get()
                                    on:input=move |ev| set_dhcp6_prefix_hint.set(event_target_value(&ev))
                                    class="w-48 bg-gray-700 text-white rounded px-3 py-1.5 border border-gray-600"
                                />
                                <p class="text-gray-500 text-xs mt-1">"Request specific prefix for prefix delegation"</p>
                            </div>
                        </div>
                    </Show>

                    // Advanced Options expando when DHCP is enabled
                    <Show when=move || dhcp_mode.get() != DhcpMode::No>
                        <div class="border border-gray-600 rounded-lg overflow-hidden">
                            <button
                                type="button"
                                class="w-full flex items-center justify-between px-4 py-3 bg-gray-700/50 hover:bg-gray-700 text-left"
                                on:click=move |_| set_show_advanced.update(|v| *v = !*v)
                            >
                                <span class="text-gray-200 font-medium">"Advanced Options (Static IPs, DNS, Routes)"</span>
                                <svg
                                    class="w-5 h-5 text-gray-400 transition-transform"
                                    class:rotate-180=move || show_advanced.get()
                                    fill="none"
                                    stroke="currentColor"
                                    viewBox="0 0 24 24"
                                >
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
                                </svg>
                            </button>
                            <Show when=move || show_advanced.get()>
                                <div class="p-4 space-y-6 border-t border-gray-600">
                                    <div class="bg-yellow-900/30 border border-yellow-600 text-yellow-200 px-3 py-2 rounded text-sm">
                                        <strong>"Note:"</strong> " DHCP is enabled. These static settings will be used in addition to DHCP-assigned values."
                                    </div>
                                    <StaticIpSettings
                                        addresses_indexed=addresses_indexed
                                        new_address=new_address
                                        set_new_address=set_new_address
                                        add_address=do_add_address
                                        remove_address=remove_address
                                        gateway=gateway
                                        set_gateway=set_gateway
                                        dns_indexed=dns_indexed
                                        new_dns=new_dns
                                        set_new_dns=set_new_dns
                                        add_dns=do_add_dns
                                        remove_dns=remove_dns
                                        domains_indexed=domains_indexed
                                        new_domain=new_domain
                                        set_new_domain=set_new_domain
                                        add_domain=do_add_domain
                                        remove_domain=remove_domain
                                        routes_indexed=routes_indexed
                                        new_route_dest=new_route_dest
                                        set_new_route_dest=set_new_route_dest
                                        new_route_gw=new_route_gw
                                        set_new_route_gw=set_new_route_gw
                                        new_route_metric=new_route_metric
                                        set_new_route_metric=set_new_route_metric
                                        add_route=do_add_route
                                        remove_route=remove_route
                                        show_dhcp_warnings=true
                                        dhcp_use_dns=dhcp_use_dns
                                        dhcp_use_gateway=dhcp_use_gateway
                                        link_mtu=link_mtu
                                        set_link_mtu=set_link_mtu
                                    />
                                </div>
                            </Show>
                        </div>
                    </Show>

                    // Static IP settings shown directly when DHCP is off
                    <Show when=move || dhcp_mode.get() == DhcpMode::No>
                        <StaticIpSettings
                            addresses_indexed=addresses_indexed
                            new_address=new_address
                            set_new_address=set_new_address
                            add_address=do_add_address
                            remove_address=remove_address
                            gateway=gateway
                            set_gateway=set_gateway
                            dns_indexed=dns_indexed
                            new_dns=new_dns
                            set_new_dns=set_new_dns
                            add_dns=do_add_dns
                            remove_dns=remove_dns
                            domains_indexed=domains_indexed
                            new_domain=new_domain
                            set_new_domain=set_new_domain
                            add_domain=do_add_domain
                            remove_domain=remove_domain
                            routes_indexed=routes_indexed
                            new_route_dest=new_route_dest
                            set_new_route_dest=set_new_route_dest
                            new_route_gw=new_route_gw
                            set_new_route_gw=set_new_route_gw
                            new_route_metric=new_route_metric
                            set_new_route_metric=set_new_route_metric
                            add_route=do_add_route
                            remove_route=remove_route
                            show_dhcp_warnings=false
                            dhcp_use_dns=dhcp_use_dns
                            dhcp_use_gateway=dhcp_use_gateway
                            link_mtu=link_mtu
                            set_link_mtu=set_link_mtu
                        />
                    </Show>

                    // IPv6 Accept RA
                    <div>
                        <label class="flex items-center gap-3 cursor-pointer">
                            <input
                                type="checkbox"
                                checked=move || ipv6_accept_ra.get()
                                on:change=move |ev| set_ipv6_accept_ra.set(event_target_checked(&ev))
                                class="w-5 h-5 rounded"
                            />
                            <span class="text-gray-200">"Accept IPv6 Router Advertisements"</span>
                        </label>

                        // Show RA client options when enabled
                        <Show when=move || ipv6_accept_ra.get()>
                            <div class="mt-3 ml-8 space-y-2 text-sm">
                                <label class="flex items-center gap-2 cursor-pointer">
                                    <input
                                        type="checkbox"
                                        checked=move || ipv6_ra_use_dns.get()
                                        on:change=move |ev| set_ipv6_ra_use_dns.set(event_target_checked(&ev))
                                        class="w-4 h-4 rounded"
                                    />
                                    <span class="text-gray-300">"Use DNS from RA (RDNSS)"</span>
                                </label>
                                <label class="flex items-center gap-2 cursor-pointer">
                                    <input
                                        type="checkbox"
                                        checked=move || ipv6_ra_use_gateway.get()
                                        on:change=move |ev| set_ipv6_ra_use_gateway.set(event_target_checked(&ev))
                                        class="w-4 h-4 rounded"
                                    />
                                    <span class="text-gray-300">"Use default gateway from RA"</span>
                                </label>
                                <label class="flex items-center gap-2 cursor-pointer">
                                    <input
                                        type="checkbox"
                                        checked=move || ipv6_ra_use_route_prefix.get()
                                        on:change=move |ev| set_ipv6_ra_use_route_prefix.set(event_target_checked(&ev))
                                        class="w-4 h-4 rounded"
                                    />
                                    <span class="text-gray-300">"Use route prefixes from RA"</span>
                                </label>
                                <label class="flex items-center gap-2 cursor-pointer">
                                    <input
                                        type="checkbox"
                                        checked=move || ipv6_ra_use_autonomous.get()
                                        on:change=move |ev| set_ipv6_ra_use_autonomous.set(event_target_checked(&ev))
                                        class="w-4 h-4 rounded"
                                    />
                                    <span class="text-gray-300">"Use SLAAC addresses"</span>
                                </label>
                            </div>
                        </Show>
                    </div>

                    // IPv6 Router Advertisement and delegated-prefix distribution
                    <div class="bg-gray-700/50 rounded-lg p-4 space-y-3">
                        <label class="flex items-center gap-3 cursor-pointer">
                            <input
                                type="checkbox"
                                checked=move || ipv6_send_ra.get()
                                on:change=move |ev| set_ipv6_send_ra.set(event_target_checked(&ev))
                                class="w-5 h-5 rounded"
                            />
                            <span class="text-gray-200">"Send IPv6 Router Advertisements"</span>
                        </label>
                        <label class="flex items-center gap-3 cursor-pointer">
                            <input
                                type="checkbox"
                                checked=move || pd_enabled.get()
                                on:change=move |ev| set_pd_enabled.set(event_target_checked(&ev))
                                class="w-5 h-5 rounded"
                            />
                            <span class="text-gray-200">"Use an upstream delegated prefix"</span>
                        </label>
                        <Show when=move || pd_enabled.get()>
                            <div class="grid grid-cols-2 gap-4 ml-8">
                                <div>
                                    <label class="block text-gray-400 text-sm mb-1">"Uplink Interface"</label>
                                    <input
                                        type="text"
                                        placeholder="e.g., enp1s0"
                                        prop:value=move || pd_uplink.get()
                                        on:input=move |ev| set_pd_uplink.set(event_target_value(&ev))
                                        class="w-full bg-gray-700 text-white rounded px-3 py-1.5 border border-gray-600"
                                    />
                                </div>
                                <div>
                                    <label class="block text-gray-400 text-sm mb-1">"Subnet ID (optional)"</label>
                                    <input
                                        type="text"
                                        placeholder="e.g., 0"
                                        prop:value=move || pd_subnet_id.get()
                                        on:input=move |ev| set_pd_subnet_id.set(event_target_value(&ev))
                                        class="w-full bg-gray-700 text-white rounded px-3 py-1.5 border border-gray-600"
                                    />
                                </div>
                                <div class="col-span-2">
                                    <label class="block text-gray-400 text-sm mb-1">"Router IPv6 Address Token (optional)"</label>
                                    <input
                                        type="text"
                                        placeholder="::1 (leave blank for automatic EUI-64)"
                                        prop:value=move || pd_ipv6_token.get()
                                        on:input=move |ev| set_pd_ipv6_token.set(event_target_value(&ev))
                                        class="w-full bg-gray-700 text-white rounded px-3 py-1.5 border border-gray-600"
                                    />
                                    <p class="text-xs text-gray-500 mt-1">"Uses this IPv6 interface identifier within the delegated prefix. For example, ::1 makes the router address end in ::1."</p>
                                </div>
                                <label class="flex items-center gap-2 cursor-pointer col-span-2">
                                    <input
                                        type="checkbox"
                                        checked=move || pd_announce.get()
                                        on:change=move |ev| set_pd_announce.set(event_target_checked(&ev))
                                        class="w-4 h-4 rounded"
                                    />
                                    <span class="text-gray-300">"Announce the delegated subnet"</span>
                                </label>
                            </div>
                        </Show>
                    </div>

                    // IP Forwarding
                    <div>
                        <label class="block text-gray-300 mb-2 font-medium">"IP Forwarding"</label>
                        <select
                            class="w-full bg-gray-700 text-white rounded px-4 py-2.5 border border-gray-600"
                            on:change=move |ev| {
                                set_ip_forward.set(match event_target_value(&ev).as_str() {
                                    "yes" => IpForwardMode::Yes,
                                    "ipv4" => IpForwardMode::Ipv4,
                                    "ipv6" => IpForwardMode::Ipv6,
                                    _ => IpForwardMode::No,
                                });
                            }
                        >
                            <option value="no" selected=move || ip_forward.get() == IpForwardMode::No>"Disabled"</option>
                            <option value="ipv4" selected=move || ip_forward.get() == IpForwardMode::Ipv4>"IPv4 Only"</option>
                            <option value="ipv6" selected=move || ip_forward.get() == IpForwardMode::Ipv6>"IPv6 Only"</option>
                            <option value="yes" selected=move || ip_forward.get() == IpForwardMode::Yes>"IPv4 + IPv6"</option>
                        </select>
                    </div>

                    <div class="bg-blue-900/20 border border-blue-700/50 rounded-lg p-3 text-sm text-blue-200">
                        "NAT is configured per firewall zone (enable IPv4 NAT on the zone under Firewall, Zones)."
                    </div>

                    // Interface State Settings (collapsible advanced section)
                    <div class="border border-gray-600 rounded-lg overflow-hidden">
                        <button
                            type="button"
                            class="w-full flex items-center justify-between px-4 py-3 bg-gray-700/50 hover:bg-gray-700 text-left"
                            on:click=move |_| set_show_interface_state.update(|v| *v = !*v)
                        >
                            <span class="text-gray-200 font-medium">"Interface State Settings"</span>
                            <svg
                                class="w-5 h-5 text-gray-400 transition-transform"
                                class:rotate-180=move || show_interface_state.get()
                                fill="none"
                                stroke="currentColor"
                                viewBox="0 0 24 24"
                            >
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
                            </svg>
                        </button>
                        <Show when=move || show_interface_state.get()>
                            <div class="p-4 space-y-4 border-t border-gray-600">
                                // Link-Local Addressing
                                <div>
                                    <label class="block text-gray-300 mb-2 font-medium">"Link-Local Addressing"</label>
                                    <select
                                        class="w-full bg-gray-700 text-white rounded px-4 py-2.5 border border-gray-600"
                                        on:change=move |ev| {
                                            set_link_local.set(match event_target_value(&ev).as_str() {
                                                "no" => LinkLocalMode::No,
                                                "ipv4" => LinkLocalMode::Ipv4,
                                                "ipv6" => LinkLocalMode::Ipv6,
                                                _ => LinkLocalMode::Yes,
                                            });
                                        }
                                    >
                                        <option value="yes" selected=move || link_local.get() == LinkLocalMode::Yes>"IPv4 + IPv6"</option>
                                        <option value="ipv6" selected=move || link_local.get() == LinkLocalMode::Ipv6>"IPv6 Only"</option>
                                        <option value="ipv4" selected=move || link_local.get() == LinkLocalMode::Ipv4>"IPv4 Only"</option>
                                        <option value="no" selected=move || link_local.get() == LinkLocalMode::No>"Disabled"</option>
                                    </select>
                                    <p class="text-gray-500 text-sm mt-1">"Configure link-local address assignment"</p>
                                </div>

                                // Required for Online
                                <div>
                                    <label class="flex items-center gap-3 cursor-pointer">
                                        <input
                                            type="checkbox"
                                            checked=move || required_for_online.get()
                                            on:change=move |ev| set_required_for_online.set(event_target_checked(&ev))
                                            class="w-5 h-5 rounded"
                                        />
                                        <span class="text-gray-200">"Required for Online"</span>
                                    </label>
                                    <p class="text-gray-500 text-sm mt-1 ml-8">"Wait for this interface before system is considered online"</p>
                                </div>

                                // Activation Policy
                                <div>
                                    <label class="block text-gray-300 mb-2 font-medium">"Activation Policy"</label>
                                    <select
                                        class="w-full bg-gray-700 text-white rounded px-4 py-2.5 border border-gray-600"
                                        on:change=move |ev| {
                                            set_activation_policy.set(match event_target_value(&ev).as_str() {
                                                "always-up" => ActivationPolicy::AlwaysUp,
                                                "manual" => ActivationPolicy::Manual,
                                                "always-down" => ActivationPolicy::AlwaysDown,
                                                "down" => ActivationPolicy::Down,
                                                "bound" => ActivationPolicy::Bound,
                                                _ => ActivationPolicy::Up,
                                            });
                                        }
                                    >
                                        <option value="up" selected=move || activation_policy.get() == ActivationPolicy::Up>"Up (default)"</option>
                                        <option value="always-up" selected=move || activation_policy.get() == ActivationPolicy::AlwaysUp>"Always Up"</option>
                                        <option value="manual" selected=move || activation_policy.get() == ActivationPolicy::Manual>"Manual"</option>
                                        <option value="bound" selected=move || activation_policy.get() == ActivationPolicy::Bound>"Bound to Carrier"</option>
                                        <option value="down" selected=move || activation_policy.get() == ActivationPolicy::Down>"Down"</option>
                                        <option value="always-down" selected=move || activation_policy.get() == ActivationPolicy::AlwaysDown>"Always Down"</option>
                                    </select>
                                    <p class="text-gray-500 text-sm mt-1">"How to manage the interface state at boot and runtime"</p>
                                </div>
                            </div>
                        </Show>
                    </div>

                    // Keep save failures beside the Save button: this long
                    // form may be scrolled far below the page-level banner.
                    <Show when=move || error.get().is_some()>
                        <div role="alert" class="bg-red-900/50 border border-red-500 text-red-200 px-4 py-3 rounded">
                            {move || error.get().unwrap_or_default()}
                        </div>
                    </Show>

                    // Save/Cancel buttons
                    <div class="flex gap-3 pt-4 border-t border-gray-700">
                        <button
                            class="bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 text-white px-6 py-2.5 rounded font-medium"
                            disabled=move || saving.get()
                            on:click=save_changes
                        >
                            {move || if saving.get() { "Saving..." } else { "Save" }}
                        </button>
                        <button
                            class="bg-gray-600 hover:bg-gray-700 text-white px-6 py-2.5 rounded"
                            on:click=go_back
                        >
                            "Cancel"
                        </button>
                    </div>
                </div>
            </Show>
        </div>
    }
}
