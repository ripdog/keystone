//! Interface edit page for configuring individual interface settings

use keystone_core::{
    ActivationPolicy, AddressScope, DhcpMode, DhcpServerConfig, DhcpStaticLease,
    Dhcpv4ClientConfig, Dhcpv6ClientConfig, InterfaceConfig, InterfaceRole, IpForwardMode,
    IpMasqueradeMode, Ipv6RaConfig, Ipv6RaPrefix, LinkLocalMode, RouteType, StaticAddress,
    StaticRoute,
};
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::hooks::use_params_map;

use crate::api;
use crate::components::form_utils::{event_target_checked, event_target_value};
use crate::components::StaticIpSettings;

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
    let (ip_forward, set_ip_forward) = signal(IpForwardMode::No);
    let (ip_masquerade, set_ip_masquerade) = signal(IpMasqueradeMode::No);
    let (link_mtu, set_link_mtu) = signal(String::new());
    
    // DHCPv4 client settings
    let (dhcp_use_dns, set_dhcp_use_dns) = signal(true);
    let (dhcp_use_ntp, set_dhcp_use_ntp) = signal(true);
    let (dhcp_use_routes, set_dhcp_use_routes) = signal(true);
    let (dhcp_use_gateway, set_dhcp_use_gateway) = signal(true);
    let (dhcp_use_mtu, set_dhcp_use_mtu) = signal(true);
    let (dhcp_send_hostname, set_dhcp_send_hostname) = signal(true);
    let (dhcp_route_metric, set_dhcp_route_metric) = signal(String::new());
    
    // DHCPv6 client settings
    let (dhcp6_use_dns, set_dhcp6_use_dns) = signal(true);
    let (dhcp6_use_ntp, set_dhcp6_use_ntp) = signal(true);
    let (dhcp6_rapid_commit, set_dhcp6_rapid_commit) = signal(true);
    let (dhcp6_prefix_hint, set_dhcp6_prefix_hint) = signal(String::new());
    
    // Interface state settings (P2)
    let (link_local, set_link_local) = signal(LinkLocalMode::default());
    let (required_for_online, set_required_for_online) = signal(true);
    let (activation_policy, set_activation_policy) = signal(ActivationPolicy::default());
    
    // DHCP Server settings (for LAN interfaces)
    let (dhcp_server_enabled, set_dhcp_server_enabled) = signal(false);
    let (dhcp_pool_offset, set_dhcp_pool_offset) = signal(String::from("100"));
    let (dhcp_pool_size, set_dhcp_pool_size) = signal(String::from("100"));
    let (dhcp_lease_time, set_dhcp_lease_time) = signal(String::from("3600"));
    let (dhcp_emit_dns, set_dhcp_emit_dns) = signal(true);
    let (dhcp_emit_router, set_dhcp_emit_router) = signal(true);
    let (dhcp_static_leases, set_dhcp_static_leases) = signal::<Vec<DhcpStaticLease>>(vec![]);
    let (new_lease_mac, set_new_lease_mac) = signal(String::new());
    let (new_lease_ip, set_new_lease_ip) = signal(String::new());
    let (new_lease_hostname, set_new_lease_hostname) = signal(String::new());
    
    // IPv6 RA settings (for LAN interfaces)
    let (ipv6_ra_enabled, set_ipv6_ra_enabled) = signal(false);
    let (ipv6_ra_managed, set_ipv6_ra_managed) = signal(false);
    let (ipv6_ra_other_info, set_ipv6_ra_other_info) = signal(false);
    let (ipv6_ra_router_lifetime, set_ipv6_ra_router_lifetime) = signal(String::from("1800"));
    let (ipv6_ra_router_pref, set_ipv6_ra_router_pref) = signal(String::from("medium"));
    let (ipv6_ra_emit_dns, set_ipv6_ra_emit_dns) = signal(true);
    let (ipv6_ra_dns_servers, set_ipv6_ra_dns_servers) = signal::<Vec<String>>(vec![]);
    let (new_ra_dns, set_new_ra_dns) = signal(String::new());
    let (ipv6_ra_search_domains, set_ipv6_ra_search_domains) = signal::<Vec<String>>(vec![]);
    let (new_ra_domain, set_new_ra_domain) = signal(String::new());
    let (ipv6_ra_prefixes, set_ipv6_ra_prefixes) = signal::<Vec<keystone_core::Ipv6RaPrefix>>(vec![]);
    let (new_prefix, set_new_prefix) = signal(String::new());
    let (new_prefix_preferred, set_new_prefix_preferred) = signal(String::new());
    let (new_prefix_valid, set_new_prefix_valid) = signal(String::new());
    
    // UI state
    let (show_advanced, set_show_advanced) = signal(false);
    let (show_interface_state, set_show_interface_state) = signal(false);
    let (show_dhcp_server, set_show_dhcp_server) = signal(false);
    let (show_ipv6_ra, set_show_ipv6_ra) = signal(false);

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
                        set_ip_forward.set(cfg.ip_forward);
                        set_ip_masquerade.set(cfg.ip_masquerade);
                        set_link_mtu.set(cfg.mtu.map(|v| v.to_string()).unwrap_or_default());
                        
                        // DHCPv4 client settings
                        if let Some(dhcp_cfg) = &cfg.dhcpv4_client {
                            set_dhcp_use_dns.set(dhcp_cfg.use_dns);
                            set_dhcp_use_ntp.set(dhcp_cfg.use_ntp);
                            set_dhcp_use_routes.set(dhcp_cfg.use_routes);
                            set_dhcp_use_gateway.set(dhcp_cfg.use_gateway);
                            set_dhcp_use_mtu.set(dhcp_cfg.use_mtu);
                            set_dhcp_send_hostname.set(dhcp_cfg.send_hostname);
                            set_dhcp_route_metric.set(dhcp_cfg.route_metric.map(|m| m.to_string()).unwrap_or_default());
                        }
                        
                        // DHCPv6 client settings
                        if let Some(dhcp6_cfg) = &cfg.dhcpv6_client {
                            set_dhcp6_use_dns.set(dhcp6_cfg.use_dns);
                            set_dhcp6_use_ntp.set(dhcp6_cfg.use_ntp);
                            set_dhcp6_rapid_commit.set(dhcp6_cfg.rapid_commit);
                            set_dhcp6_prefix_hint.set(dhcp6_cfg.prefix_delegation_hint.clone().unwrap_or_default());
                        }
                        
                        // Interface state settings (P2)
                        set_link_local.set(cfg.link_local);
                        set_required_for_online.set(cfg.required_for_online);
                        set_activation_policy.set(cfg.activation_policy);
                        
                        // DHCP Server settings
                        if let Some(dhcp_srv) = &cfg.dhcp_server {
                            set_dhcp_server_enabled.set(dhcp_srv.enabled);
                            set_dhcp_pool_offset.set(dhcp_srv.pool_offset.map(|v| v.to_string()).unwrap_or_default());
                            set_dhcp_pool_size.set(dhcp_srv.pool_size.map(|v| v.to_string()).unwrap_or_default());
                            set_dhcp_lease_time.set(dhcp_srv.default_lease_time_secs.map(|v| v.to_string()).unwrap_or_default());
                            set_dhcp_emit_dns.set(dhcp_srv.emit_dns);
                            set_dhcp_emit_router.set(dhcp_srv.emit_router);
                            set_dhcp_static_leases.set(dhcp_srv.static_leases.clone());
                        }
                        
                        // IPv6 RA settings
                        if let Some(ra_cfg) = &cfg.ipv6_ra {
                            set_ipv6_ra_enabled.set(ra_cfg.enabled);
                            set_ipv6_ra_managed.set(ra_cfg.managed);
                            set_ipv6_ra_other_info.set(ra_cfg.other_information);
                            set_ipv6_ra_router_lifetime.set(ra_cfg.router_lifetime_secs.map(|v| v.to_string()).unwrap_or_default());
                            set_ipv6_ra_router_pref.set(ra_cfg.router_preference.clone().unwrap_or_else(|| "medium".to_string()));
                            set_ipv6_ra_emit_dns.set(ra_cfg.emit_dns);
                            set_ipv6_ra_dns_servers.set(ra_cfg.dns_servers.clone());
                            set_ipv6_ra_search_domains.set(ra_cfg.search_domains.clone());
                            set_ipv6_ra_prefixes.set(ra_cfg.prefixes.clone());
                        }
                        
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
                            dhcp_server: None,
                            ipv6_accept_ra: true,
                            ipv6_ra: None,
                            ip_forward: IpForwardMode::No,
                            ip_masquerade: IpMasqueradeMode::No,
                            mtu: None,
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
                let gw = gateway.get();
                let desc = description.get();
                let current_dhcp_mode = dhcp_mode.get();
                
                // Build DHCPv4 client config if DHCP includes IPv4
                let dhcpv4_client = if current_dhcp_mode == DhcpMode::Yes || current_dhcp_mode == DhcpMode::Ipv4 {
                    Some(Dhcpv4ClientConfig {
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
                let dhcpv6_client = if current_dhcp_mode == DhcpMode::Yes || current_dhcp_mode == DhcpMode::Ipv6 {
                    let hint = dhcp6_prefix_hint.get();
                    Some(Dhcpv6ClientConfig {
                        use_dns: dhcp6_use_dns.get(),
                        use_ntp: dhcp6_use_ntp.get(),
                        use_domains: "yes".to_string(),
                        prefix_delegation_hint: if hint.is_empty() { None } else { Some(hint) },
                        rapid_commit: dhcp6_rapid_commit.get(),
                        without_ra: "no".to_string(),
                    })
                } else {
                    None
                };
                
                // Build DHCP server config (for LAN interfaces)
                let dhcp_server = if dhcp_server_enabled.get() {
                    Some(DhcpServerConfig {
                        enabled: true,
                        pool_offset: dhcp_pool_offset.get().parse().ok(),
                        pool_size: dhcp_pool_size.get().parse().ok(),
                        default_lease_time_secs: dhcp_lease_time.get().parse().ok(),
                        max_lease_time_secs: dhcp_lease_time.get().parse::<u32>().ok().map(|v| v * 24), // Max = 24x default
                        emit_dns: dhcp_emit_dns.get(),
                        dns_servers: vec![], // Uses interface DNS by default
                        emit_ntp: false,
                        ntp_servers: vec![],
                        emit_router: dhcp_emit_router.get(),
                        router_address: None, // Uses interface address by default
                        static_leases: dhcp_static_leases.get(),
                    })
                } else {
                    None
                };
                
                let ipv6_ra = if ipv6_ra_enabled.get() {
                    Some(Ipv6RaConfig {
                        enabled: true,
                        router_lifetime_secs: ipv6_ra_router_lifetime.get().parse().ok(),
                        router_preference: Some(ipv6_ra_router_pref.get()),
                        managed: ipv6_ra_managed.get(),
                        other_information: ipv6_ra_other_info.get(),
                        emit_dns: ipv6_ra_emit_dns.get(),
                        dns_servers: ipv6_ra_dns_servers.get(),
                        search_domains: ipv6_ra_search_domains.get(),
                        prefixes: ipv6_ra_prefixes.get(),
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
                    dhcp_server,
                    ipv6_accept_ra: ipv6_accept_ra.get(),
                    ipv6_ra,
                    ip_forward: ip_forward.get(),
                    ip_masquerade: ip_masquerade.get(),
                    mtu: link_mtu.get().parse().ok(),
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
    let static_leases_indexed = move || {
        dhcp_static_leases
            .get()
            .into_iter()
            .enumerate()
            .collect::<Vec<_>>()
    };

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

                    // DHCP Mode
                    <div>
                        <label class="block text-gray-300 mb-2 font-medium">"DHCP Mode"</label>
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
                                        checked=move || dhcp6_rapid_commit.get()
                                        on:change=move |ev| set_dhcp6_rapid_commit.set(event_target_checked(&ev))
                                        class="w-4 h-4 rounded"
                                    />
                                    <span class="text-gray-300">"Rapid Commit"</span>
                                </label>
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

                    // IP Masquerade (NAT)
                    <div>
                        <label class="block text-gray-300 mb-2 font-medium">"IP Masquerade (NAT)"</label>
                        <select
                            class="w-full bg-gray-700 text-white rounded px-4 py-2.5 border border-gray-600"
                            on:change=move |ev| {
                                set_ip_masquerade.set(match event_target_value(&ev).as_str() {
                                    "both" => IpMasqueradeMode::Both,
                                    "ipv4" => IpMasqueradeMode::Ipv4,
                                    "ipv6" => IpMasqueradeMode::Ipv6,
                                    _ => IpMasqueradeMode::No,
                                });
                            }
                        >
                            <option value="no" selected=move || ip_masquerade.get() == IpMasqueradeMode::No>"Disabled"</option>
                            <option value="ipv4" selected=move || ip_masquerade.get() == IpMasqueradeMode::Ipv4>"IPv4 Only"</option>
                            <option value="ipv6" selected=move || ip_masquerade.get() == IpMasqueradeMode::Ipv6>"IPv6 Only"</option>
                            <option value="both" selected=move || ip_masquerade.get() == IpMasqueradeMode::Both>"IPv4 + IPv6"</option>
                        </select>
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

                    // DHCP Server Settings (only shown for LAN interfaces)
                    <Show when=move || role.get() == InterfaceRole::LAN>
                        <div class="border border-gray-600 rounded-lg overflow-hidden">
                            <button
                                type="button"
                                class="w-full flex items-center justify-between px-4 py-3 bg-gray-700/50 hover:bg-gray-700 text-left"
                                on:click=move |_| set_show_dhcp_server.update(|v| *v = !*v)
                            >
                                <div class="flex items-center gap-3">
                                    <span class="text-gray-200 font-medium">"DHCP Server"</span>
                                    <Show when=move || dhcp_server_enabled.get()>
                                        <span class="text-xs bg-green-600 text-white px-2 py-0.5 rounded">"Enabled"</span>
                                    </Show>
                                </div>
                                <svg
                                    class="w-5 h-5 text-gray-400 transition-transform"
                                    class:rotate-180=move || show_dhcp_server.get()
                                    fill="none"
                                    stroke="currentColor"
                                    viewBox="0 0 24 24"
                                >
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
                                </svg>
                            </button>
                            <Show when=move || show_dhcp_server.get()>
                                <div class="p-4 space-y-4 border-t border-gray-600">
                                    // Enable DHCP Server
                                    <div>
                                        <label class="flex items-center gap-3 cursor-pointer">
                                            <input
                                                type="checkbox"
                                                checked=move || dhcp_server_enabled.get()
                                                on:change=move |ev| set_dhcp_server_enabled.set(event_target_checked(&ev))
                                                class="w-5 h-5 rounded"
                                            />
                                            <span class="text-gray-200 font-medium">"Enable DHCP Server"</span>
                                        </label>
                                        <p class="text-gray-500 text-sm mt-1 ml-8">"Provide IP addresses to clients on this network"</p>
                                    </div>

                                    <Show when=move || dhcp_server_enabled.get()>
                                        // Pool Settings
                                        <div class="grid grid-cols-2 gap-4">
                                            <div>
                                                <label class="block text-gray-300 mb-2 text-sm">"Pool Offset"</label>
                                                <input
                                                    type="text"
                                                    placeholder="100"
                                                    prop:value=move || dhcp_pool_offset.get()
                                                    on:input=move |ev| set_dhcp_pool_offset.set(event_target_value(&ev))
                                                    class="w-full bg-gray-700 text-white rounded px-3 py-2 border border-gray-600"
                                                />
                                                <p class="text-gray-500 text-xs mt-1">"Start offset from network (e.g., 100 = .100)"</p>
                                            </div>
                                            <div>
                                                <label class="block text-gray-300 mb-2 text-sm">"Pool Size"</label>
                                                <input
                                                    type="text"
                                                    placeholder="100"
                                                    prop:value=move || dhcp_pool_size.get()
                                                    on:input=move |ev| set_dhcp_pool_size.set(event_target_value(&ev))
                                                    class="w-full bg-gray-700 text-white rounded px-3 py-2 border border-gray-600"
                                                />
                                                <p class="text-gray-500 text-xs mt-1">"Number of addresses in pool"</p>
                                            </div>
                                        </div>

                                        // Lease Time
                                        <div>
                                            <label class="block text-gray-300 mb-2 text-sm">"Default Lease Time (seconds)"</label>
                                            <input
                                                type="text"
                                                placeholder="3600"
                                                prop:value=move || dhcp_lease_time.get()
                                                on:input=move |ev| set_dhcp_lease_time.set(event_target_value(&ev))
                                                class="w-48 bg-gray-700 text-white rounded px-3 py-2 border border-gray-600"
                                            />
                                            <p class="text-gray-500 text-xs mt-1">"How long clients keep their address (3600 = 1 hour)"</p>
                                        </div>

                                        // Emit Options
                                        <div class="grid grid-cols-2 gap-4">
                                            <label class="flex items-center gap-2 cursor-pointer">
                                                <input
                                                    type="checkbox"
                                                    checked=move || dhcp_emit_dns.get()
                                                    on:change=move |ev| set_dhcp_emit_dns.set(event_target_checked(&ev))
                                                    class="w-4 h-4 rounded"
                                                />
                                                <span class="text-gray-300">"Provide DNS servers"</span>
                                            </label>
                                            <label class="flex items-center gap-2 cursor-pointer">
                                                <input
                                                    type="checkbox"
                                                    checked=move || dhcp_emit_router.get()
                                                    on:change=move |ev| set_dhcp_emit_router.set(event_target_checked(&ev))
                                                    class="w-4 h-4 rounded"
                                                />
                                                <span class="text-gray-300">"Provide gateway/router"</span>
                                            </label>
                                        </div>

                                        // Static Leases section
                                        <div class="border-t border-gray-600 pt-4">
                                            <h4 class="text-gray-200 font-medium mb-3">"Static Leases (Reserved Addresses)"</h4>
                                            <div class="space-y-2">
                                                <For
                                                    each=static_leases_indexed
                                                    key=|(i, lease)| (*i, lease.mac_address.clone(), lease.ip_address.clone())
                                                    children=move |(i, lease)| {
                                                        let hostname_display = lease.hostname.clone().unwrap_or_default();
                                                        let hostname_for_show = hostname_display.clone();
                                                        view! {
                                                            <div class="flex items-center gap-2 bg-gray-700/50 rounded px-3 py-2">
                                                                <span class="flex-1 text-sm font-mono">{lease.mac_address}</span>
                                                                <span class="text-gray-400">"→"</span>
                                                                <span class="text-sm">{lease.ip_address}</span>
                                                                <Show when=move || !hostname_for_show.is_empty()>
                                                                    <span class="text-gray-400 text-sm">"("{hostname_display.clone()}")"</span>
                                                                </Show>
                                                                <button
                                                                    class="text-red-400 hover:text-red-300 px-2"
                                                                    on:click=move |_| {
                                                                        set_dhcp_static_leases.update(|list| {
                                                                            if i < list.len() {
                                                                                list.remove(i);
                                                                            }
                                                                        });
                                                                    }
                                                                >
                                                                    "✕"
                                                                </button>
                                                            </div>
                                                        }
                                                    }
                                                />
                                                // Add new lease form
                                                <div class="flex gap-2 flex-wrap">
                                                    <input
                                                        type="text"
                                                        placeholder="MAC (00:11:22:33:44:55)"
                                                        prop:value=move || new_lease_mac.get()
                                                        on:input=move |ev| set_new_lease_mac.set(event_target_value(&ev))
                                                        class="flex-1 min-w-40 bg-gray-700 text-white rounded px-3 py-2 border border-gray-600 font-mono text-sm"
                                                    />
                                                    <input
                                                        type="text"
                                                        placeholder="IP (192.168.1.200)"
                                                        prop:value=move || new_lease_ip.get()
                                                        on:input=move |ev| set_new_lease_ip.set(event_target_value(&ev))
                                                        class="w-36 bg-gray-700 text-white rounded px-3 py-2 border border-gray-600 text-sm"
                                                    />
                                                    <input
                                                        type="text"
                                                        placeholder="Hostname (optional)"
                                                        prop:value=move || new_lease_hostname.get()
                                                        on:input=move |ev| set_new_lease_hostname.set(event_target_value(&ev))
                                                        class="w-32 bg-gray-700 text-white rounded px-3 py-2 border border-gray-600 text-sm"
                                                    />
                                                    <button
                                                        class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded text-sm"
                                                        on:click=move |_| {
                                                            let mac = new_lease_mac.get();
                                                            let ip = new_lease_ip.get();
                                                            if !mac.is_empty() && !ip.is_empty() {
                                                                let hostname = new_lease_hostname.get();
                                                                set_dhcp_static_leases.update(|list| {
                                                                    list.push(DhcpStaticLease {
                                                                        mac_address: mac,
                                                                        ip_address: ip,
                                                                        hostname: if hostname.is_empty() { None } else { Some(hostname) },
                                                                    });
                                                                });
                                                                set_new_lease_mac.set(String::new());
                                                                set_new_lease_ip.set(String::new());
                                                                set_new_lease_hostname.set(String::new());
                                                            }
                                                        }
                                                    >
                                                        "Add"
                                                    </button>
                                                </div>
                                            </div>
                                        </div>
                                    </Show>
                                </div>
                            </Show>
                        </div>
                    </Show>

                    // IPv6 Router Advertisement Settings (only shown for LAN interfaces)
                    <Show when=move || role.get() == InterfaceRole::LAN>
                        <div class="bg-gray-800 rounded-lg p-6 mb-4">
                            <button
                                class="w-full flex justify-between items-center text-left"
                                on:click=move |_| set_show_ipv6_ra.update(|v| *v = !*v)
                            >
                                <div>
                                    <span class="text-gray-200 font-medium">"IPv6 Router Advertisement"</span>
                                    <p class="text-sm text-gray-400 mt-1">
                                        "Advertise IPv6 prefixes and act as an IPv6 gateway (SLAAC)"
                                    </p>
                                </div>
                                <span class="text-gray-400">
                                    {move || if show_ipv6_ra.get() { "▼" } else { "▶" }}
                                </span>
                            </button>

                            <Show when=move || show_ipv6_ra.get()>
                                <div class="mt-4 space-y-4 pt-4 border-t border-gray-700">
                                    // Enable IPv6 RA
                                    <label class="flex items-center gap-3 cursor-pointer">
                                        <input
                                            type="checkbox"
                                            class="w-4 h-4"
                                            prop:checked=move || ipv6_ra_enabled.get()
                                            on:change=move |e| set_ipv6_ra_enabled.set(event_target_checked(&e))
                                        />
                                        <span class="text-gray-200">"Send Router Advertisements"</span>
                                    </label>

                                    <Show when=move || ipv6_ra_enabled.get()>
                                        <div class="space-y-4 pl-7">
                                            // Router Lifetime
                                            <div>
                                                <label class="block text-sm text-gray-300 mb-1">"Router Lifetime (seconds)"</label>
                                                <input
                                                    type="text"
                                                    class="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-gray-200"
                                                    placeholder="1800"
                                                    prop:value=move || ipv6_ra_router_lifetime.get()
                                                    on:input=move |e| set_ipv6_ra_router_lifetime.set(event_target_value(&e))
                                                />
                                            </div>

                                            // Router Preference
                                            <div>
                                                <label class="block text-sm text-gray-300 mb-1">"Router Preference"</label>
                                                <select
                                                    class="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-gray-200"
                                                    on:change=move |e| set_ipv6_ra_router_pref.set(event_target_value(&e))
                                                >
                                                    <option value="low" selected=move || ipv6_ra_router_pref.get() == "low">"Low"</option>
                                                    <option value="medium" selected=move || ipv6_ra_router_pref.get() == "medium">"Medium"</option>
                                                    <option value="high" selected=move || ipv6_ra_router_pref.get() == "high">"High"</option>
                                                </select>
                                            </div>

                                            // Managed/Other flags
                                            <div class="space-y-2">
                                                <label class="flex items-center gap-3 cursor-pointer">
                                                    <input
                                                        type="checkbox"
                                                        class="w-4 h-4"
                                                        prop:checked=move || ipv6_ra_managed.get()
                                                        on:change=move |e| set_ipv6_ra_managed.set(event_target_checked(&e))
                                                    />
                                                    <div>
                                                        <span class="text-gray-200">"Managed (M flag)"</span>
                                                        <p class="text-xs text-gray-400">"Clients should use DHCPv6 for addresses"</p>
                                                    </div>
                                                </label>
                                                <label class="flex items-center gap-3 cursor-pointer">
                                                    <input
                                                        type="checkbox"
                                                        class="w-4 h-4"
                                                        prop:checked=move || ipv6_ra_other_info.get()
                                                        on:change=move |e| set_ipv6_ra_other_info.set(event_target_checked(&e))
                                                    />
                                                    <div>
                                                        <span class="text-gray-200">"Other Information (O flag)"</span>
                                                        <p class="text-xs text-gray-400">"Clients should use DHCPv6 for other config (DNS, etc)"</p>
                                                    </div>
                                                </label>
                                            </div>

                                            // Emit DNS
                                            <label class="flex items-center gap-3 cursor-pointer">
                                                <input
                                                    type="checkbox"
                                                    class="w-4 h-4"
                                                    prop:checked=move || ipv6_ra_emit_dns.get()
                                                    on:change=move |e| set_ipv6_ra_emit_dns.set(event_target_checked(&e))
                                                />
                                                <span class="text-gray-200">"Advertise DNS servers in RA"</span>
                                            </label>

                                            // DNS servers for RA
                                            <Show when=move || ipv6_ra_emit_dns.get()>
                                                <div>
                                                    <label class="block text-sm text-gray-300 mb-2">"DNS Servers (RDNSS)"</label>
                                                    <div class="space-y-2">
                                                        <For
                                                            each=move || ipv6_ra_dns_servers.get().into_iter().enumerate()
                                                            key=|(i, dns)| (*i, dns.clone())
                                                            children=move |(i, dns)| {
                                                                view! {
                                                                    <div class="flex gap-2">
                                                                        <input
                                                                            type="text"
                                                                            class="flex-1 bg-gray-900 border border-gray-700 rounded px-3 py-2 text-gray-200"
                                                                            value=dns.clone()
                                                                            disabled=true
                                                                        />
                                                                        <button
                                                                            class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded"
                                                                            on:click=move |_| {
                                                                                set_ipv6_ra_dns_servers.update(|servers| {
                                                                                    servers.remove(i);
                                                                                });
                                                                            }
                                                                        >
                                                                            "Remove"
                                                                        </button>
                                                                    </div>
                                                                }
                                                            }
                                                        />
                                                        <div class="flex gap-2">
                                                            <input
                                                                type="text"
                                                                class="flex-1 bg-gray-900 border border-gray-700 rounded px-3 py-2 text-gray-200"
                                                                placeholder="2001:db8::1"
                                                                prop:value=move || new_ra_dns.get()
                                                                on:input=move |e| set_new_ra_dns.set(event_target_value(&e))
                                                            />
                                                            <button
                                                                class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
                                                                on:click=move |_| {
                                                                    let dns = new_ra_dns.get().trim().to_string();
                                                                    if !dns.is_empty() {
                                                                        set_ipv6_ra_dns_servers.update(|servers| servers.push(dns));
                                                                        set_new_ra_dns.set(String::new());
                                                                    }
                                                                }
                                                            >
                                                                "Add"
                                                            </button>
                                                        </div>
                                                    </div>
                                                </div>
                                            </Show>

                                            // Search domains for RA
                                            <div>
                                                <label class="block text-sm text-gray-300 mb-2">"Search Domains (DNSSL)"</label>
                                                <div class="space-y-2">
                                                    <For
                                                        each=move || ipv6_ra_search_domains.get().into_iter().enumerate()
                                                        key=|(i, domain)| (*i, domain.clone())
                                                        children=move |(i, domain)| {
                                                            view! {
                                                                <div class="flex gap-2">
                                                                    <input
                                                                        type="text"
                                                                        class="flex-1 bg-gray-900 border border-gray-700 rounded px-3 py-2 text-gray-200"
                                                                        value=domain.clone()
                                                                        disabled=true
                                                                    />
                                                                    <button
                                                                        class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded"
                                                                        on:click=move |_| {
                                                                            set_ipv6_ra_search_domains.update(|domains| {
                                                                                domains.remove(i);
                                                                            });
                                                                        }
                                                                    >
                                                                        "Remove"
                                                                    </button>
                                                                </div>
                                                            }
                                                        }
                                                    />
                                                    <div class="flex gap-2">
                                                        <input
                                                            type="text"
                                                            class="flex-1 bg-gray-900 border border-gray-700 rounded px-3 py-2 text-gray-200"
                                                            placeholder="example.com"
                                                            prop:value=move || new_ra_domain.get()
                                                            on:input=move |e| set_new_ra_domain.set(event_target_value(&e))
                                                        />
                                                        <button
                                                            class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
                                                            on:click=move |_| {
                                                                let domain = new_ra_domain.get().trim().to_string();
                                                                if !domain.is_empty() {
                                                                    set_ipv6_ra_search_domains.update(|domains| domains.push(domain));
                                                                    set_new_ra_domain.set(String::new());
                                                                }
                                                            }
                                                        >
                                                            "Add"
                                                        </button>
                                                    </div>
                                                </div>
                                            </div>

                                            // IPv6 Prefixes
                                            <div>
                                                <label class="block text-sm text-gray-300 mb-2">"IPv6 Prefixes to Advertise"</label>
                                                <div class="space-y-2">
                                                    <For
                                                        each=move || ipv6_ra_prefixes.get().into_iter().enumerate()
                                                        key=|(i, prefix)| (*i, prefix.prefix.clone())
                                                        children=move |(i, prefix)| {
                                                            view! {
                                                                <div class="bg-gray-900 rounded p-3">
                                                                    <div class="flex justify-between items-start mb-2">
                                                                        <span class="text-gray-200 font-mono">{prefix.prefix.clone()}</span>
                                                                        <button
                                                                            class="bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded text-sm"
                                                                            on:click=move |_| {
                                                                                set_ipv6_ra_prefixes.update(|prefixes| {
                                                                                    prefixes.remove(i);
                                                                                });
                                                                            }
                                                                        >
                                                                            "Remove"
                                                                        </button>
                                                                    </div>
                                                                    <div class="text-xs text-gray-400 space-y-1">
                                                                        {prefix.preferred_lifetime_secs.map(|s| format!("Preferred: {}s", s))}
                                                                        " | "
                                                                        {prefix.valid_lifetime_secs.map(|s| format!("Valid: {}s", s))}
                                                                        <br/>
                                                                        {if prefix.on_link { "On-link" } else { "" }}
                                                                        " "
                                                                        {if prefix.autonomous { "Autonomous (SLAAC)" } else { "" }}
                                                                    </div>
                                                                </div>
                                                            }
                                                        }
                                                    />
                                                    <div class="bg-gray-900 rounded p-3 space-y-2">
                                                        <input
                                                            type="text"
                                                            class="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-200"
                                                            placeholder="2001:db8::/64"
                                                            prop:value=move || new_prefix.get()
                                                            on:input=move |e| set_new_prefix.set(event_target_value(&e))
                                                        />
                                                        <div class="grid grid-cols-2 gap-2">
                                                            <input
                                                                type="text"
                                                                class="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-200"
                                                                placeholder="Preferred lifetime (s)"
                                                                prop:value=move || new_prefix_preferred.get()
                                                                on:input=move |e| set_new_prefix_preferred.set(event_target_value(&e))
                                                            />
                                                            <input
                                                                type="text"
                                                                class="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-gray-200"
                                                                placeholder="Valid lifetime (s)"
                                                                prop:value=move || new_prefix_valid.get()
                                                                on:input=move |e| set_new_prefix_valid.set(event_target_value(&e))
                                                            />
                                                        </div>
                                                        <button
                                                            class="w-full bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
                                                            on:click=move |_| {
                                                                let prefix_str = new_prefix.get().trim().to_string();
                                                                if !prefix_str.is_empty() {
                                                                    let preferred = new_prefix_preferred.get().parse().ok();
                                                                    let valid = new_prefix_valid.get().parse().ok();
                                                                    set_ipv6_ra_prefixes.update(|prefixes| {
                                                                        prefixes.push(Ipv6RaPrefix {
                                                                            prefix: prefix_str,
                                                                            preferred_lifetime_secs: preferred,
                                                                            valid_lifetime_secs: valid,
                                                                            on_link: true,
                                                                            autonomous: true,
                                                                        });
                                                                    });
                                                                    set_new_prefix.set(String::new());
                                                                    set_new_prefix_preferred.set(String::new());
                                                                    set_new_prefix_valid.set(String::new());
                                                                }
                                                            }
                                                        >
                                                            "Add Prefix"
                                                        </button>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </Show>
                                </div>
                            </Show>
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
