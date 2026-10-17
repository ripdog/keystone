use console::style;
use keystone_core::changes::*;
use keystone_core::*;
use std::path::PathBuf;

use crate::token::{get_token_path, save_token};

pub fn health(json: &serde_json::Value) {
    if let Some(status) = json.get("status").and_then(|s| s.as_str()) {
        let emoji = if status == "healthy" { "✓" } else { "✗" };
        println!("{} Daemon status: {}", emoji, status);
    }
}

pub fn login(response: &LoginResponse) {
    if response.success {
        println!("✓ Login successful");
        if let Some(token) = &response.token {
            // Save token to file
            if let Err(e) = save_token(token) {
                eprintln!("Warning: Failed to save token: {}", e);
                println!("\nManually export token:");
                println!("  export KEYSTONE_TOKEN=\"{}\"", token);
            } else {
                let token_path = get_token_path()
                    .unwrap_or_else(|_| PathBuf::from("~/.local/state/keystone/token"));
                println!("\n✓ Token saved to {}", token_path.display());
                println!("  You can now run commands without specifying a token");
            }
        }
    } else {
        println!("✗ Login failed: {}", response.message);
    }
}

pub fn state(state: &SystemState) {
    println!("=== System State ===\n");

    println!("Interfaces ({}):", state.interfaces.len());
    for iface in &state.interfaces {
        let status = if iface.enabled { "UP" } else { "DOWN" };
        let addr = iface.address.as_deref().unwrap_or("no address");
        let dhcp = if iface.dhcp_enabled { "DHCP" } else { "static" };
        println!(
            "  {} [{}] {} ({}, {})",
            iface.name, iface.role, addr, dhcp, status
        );
    }

    println!("\nFirewall: Zone-based firewall (run 'keystonectl firewall' for details)");
}

pub fn dashboard(dashboard: &DashboardResponse) {
    state(&dashboard.state);

    println!("\nInterface Counters:");
    for counter in &dashboard.interface_counters {
        println!(
            "  {}: RX {} bytes ({} pkts), TX {} bytes ({} pkts)",
            counter.name,
            format_bytes(counter.rx_bytes),
            counter.rx_packets,
            format_bytes(counter.tx_bytes),
            counter.tx_packets
        );
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.2}G", bytes as f64 / 1_000_000_000.0)
    } else if bytes >= 1_000_000 {
        format!("{:.2}M", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.2}K", bytes as f64 / 1_000.0)
    } else {
        format!("{}", bytes)
    }
}

/// `show_pending` is false when the caller confirms right away, so the
/// "pending confirmation" notice would be stale by the time it is read.
pub fn apply_all(response: &ApplyAllResponse, show_pending: bool) {
    if response.success {
        println!("✓ {}", response.message);
    } else {
        println!("✗ {}", response.message);
    }
    let components = [
        ("networkd", &response.components.networkd),
        ("firewall", &response.components.firewall),
        ("sqm", &response.components.sqm),
        ("upnp", &response.components.upnp),
        ("blocky", &response.components.blocky),
        ("wireless", &response.components.wireless),
        ("dnsmasq", &response.components.dnsmasq),
        ("caddy", &response.components.caddy),
    ];
    for (name, result) in components {
        let mark = if result.skipped {
            "-"
        } else if result.success {
            "✓"
        } else {
            "✗"
        };
        let suffix = if result.skipped { " (skipped)" } else { "" };
        println!("  {mark} {name}{suffix}: {}", result.message);
    }
    if show_pending && response.firewall_pending_confirmation {
        println!();
        let what = if response.networkd_pending_confirmation {
            "Network and firewall changes are"
        } else {
            "Firewall changes are"
        };
        println!("{what} pending confirmation and will be rolled back if not confirmed.");
        if let Some(deadline) = response.firewall_confirm_deadline {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            println!(
                "  Deadline: {} (in {}s)",
                deadline,
                deadline.saturating_sub(now)
            );
        }
        if let Some(session_id) = &response.firewall_session_id {
            println!("  Session ID: {}", session_id);
            println!("  Run 'keystonectl confirm' (session {})", session_id);
        }
    }
}

pub fn users(response: &UsersResponse) {
    println!("=== Users ===\n");
    println!("{:<6} {:<20} {:<30}", "ID", "Username", "Email");
    println!("{}", "-".repeat(60));
    for user in &response.users {
        let email = user.email.as_deref().unwrap_or("-");
        println!("{:<6} {:<20} {:<30}", user.id, user.username, email);
    }
}

pub fn save_user(response: &SaveUserResponse) {
    if response.success {
        println!("✓ {}", response.message);
        if let Some(id) = response.user_id {
            println!("  User ID: {}", id);
        }
    } else {
        println!("✗ {}", response.message);
    }
}

pub fn delete_user(response: &DeleteUserResponse) {
    if response.success {
        println!("✓ {}", response.message);
    } else {
        println!("✗ {}", response.message);
    }
}

pub fn managed_interfaces(response: &ManagedInterfacesResponse) {
    println!("=== Managed Interfaces ===\n");
    println!(
        "{:<15} {:<6} {:<20} {:<8}",
        "Name", "Role", "Static IP", "Enabled"
    );
    println!("{}", "-".repeat(55));
    for iface in &response.interfaces {
        let ip = iface.static_ip.as_deref().unwrap_or("DHCP");
        let enabled = if iface.enabled { "yes" } else { "no" };
        println!(
            "{:<15} {:<6} {:<20} {:<8}",
            iface.name, iface.role, ip, enabled
        );
    }
}

pub fn save_interfaces(response: &SaveManagedInterfacesResponse) {
    if response.success {
        println!("✓ {}", response.message);
    } else {
        println!("✗ {}", response.message);
    }
}

// Firewall pretty printing

pub fn firewall_zones(response: &FirewallZonesResponse) {
    println!("=== Firewall Zones ===\n");
    if response.zones.is_empty() {
        println!("No zones configured.");
        return;
    }
    println!(
        "{:<6} {:<15} {:<25} {:<10}",
        "ID", "Name", "Interfaces", "Input"
    );
    println!("{}", "-".repeat(70));
    for zone in &response.zones {
        let id = zone.id.map(|i| i.to_string()).unwrap_or("-".to_string());
        let interfaces = if zone.interfaces.is_empty() {
            "(none)".to_string()
        } else {
            zone.interfaces.join(", ")
        };
        println!(
            "{:<6} {:<15} {:<25} {:<10}",
            id, zone.name, interfaces, zone.default_input_policy
        );
    }
}

pub fn save_zone(response: &SaveFirewallZoneResponse) {
    if response.success {
        println!("✓ {}", response.message);
        if let Some(id) = response.zone_id {
            println!("  Zone ID: {}", id);
        }
    } else {
        println!("✗ {}", response.message);
    }
}

pub fn delete_zone(response: &DeleteFirewallZoneResponse) {
    if response.success {
        println!("✓ {}", response.message);
    } else {
        println!("✗ {}", response.message);
    }
}

pub fn zone_forwards(response: &ZoneForwardsResponse) {
    println!("=== Zone Forward Policies ===\n");
    if response.forwards.is_empty() {
        println!("No zone forwarding policies configured.");
        return;
    }
    println!(
        "{:<6} {:<15} {:<15} {:<10} {:<8}",
        "ID", "Source", "Destination", "Policy", "Enabled"
    );
    println!("{}", "-".repeat(60));
    for fwd in &response.forwards {
        let id = fwd.id.map(|i| i.to_string()).unwrap_or("-".to_string());
        let enabled = if fwd.enabled { "yes" } else { "no" };
        println!(
            "{:<6} {:<15} {:<15} {:<10} {:<8}",
            id, fwd.source_zone, fwd.dest_zone, fwd.policy, enabled
        );
    }
}

pub fn save_zone_forward(response: &SaveZoneForwardResponse) {
    if response.success {
        println!("✓ {}", response.message);
        if let Some(id) = response.forward_id {
            println!("  Forward Policy ID: {}", id);
        }
    } else {
        println!("✗ {}", response.message);
    }
}

pub fn delete_zone_forward(response: &DeleteZoneForwardResponse) {
    if response.success {
        println!("✓ {}", response.message);
    } else {
        println!("✗ {}", response.message);
    }
}

pub fn port_forwards(response: &PortForwardsResponse) {
    println!("=== Port Forwards ===\n");
    if response.port_forwards.is_empty() {
        println!("No port forwards configured.");
        return;
    }
    println!(
        "{:<6} {:<20} {:<8} {:<12} {:<18} {:<8}",
        "ID", "Name", "Proto", "Ext Port", "Destination", "Enabled"
    );
    println!("{}", "-".repeat(80));
    for pf in &response.port_forwards {
        let id = pf.id.map(|i| i.to_string()).unwrap_or("-".to_string());
        let ext_port = match pf.external_port_end {
            Some(end) => format!("{}-{}", pf.external_port_start, end),
            None => pf.external_port_start.to_string(),
        };
        let dest_port = pf.dest_port.unwrap_or(pf.external_port_start);
        let proto = match pf.protocol {
            RuleProtocol::Tcp => "tcp",
            RuleProtocol::Udp => "udp",
            RuleProtocol::TcpUdp => "tcp+udp",
            RuleProtocol::Icmp => "icmp",
            RuleProtocol::Icmpv6 => "icmpv6",
            RuleProtocol::Any => "any",
        };
        let enabled = if pf.enabled { "yes" } else { "no" };
        let mut targets = Vec::new();
        if !pf.dest_ip.is_empty() {
            targets.push(format!("{}:{}", pf.dest_ip, dest_port));
        }
        if let Some(suffix) = &pf.dest_ipv6_suffix {
            targets.push(format!("[{suffix}]:{ext_port}"));
        }
        println!(
            "{:<6} {:<20} {:<8} {:<12} {:<18} {:<8}",
            id,
            pf.name,
            proto,
            ext_port,
            targets.join(" "),
            enabled
        );
    }
}

pub fn save_port_forward(response: &SavePortForwardResponse) {
    if response.success {
        println!("✓ {}", response.message);
        if let Some(id) = response.port_forward_id {
            println!("  Port Forward ID: {}", id);
        }
    } else {
        println!("✗ {}", response.message);
    }
}

pub fn delete_port_forward(response: &DeletePortForwardResponse) {
    if response.success {
        println!("✓ {}", response.message);
    } else {
        println!("✗ {}", response.message);
    }
}

pub fn input_rules(response: &InputRulesResponse) {
    println!("=== Input Rules ===\n");
    if response.rules.is_empty() {
        println!("No input rules configured.");
        return;
    }
    for rule in &response.rules {
        let id = rule.id.map(|i| i.to_string()).unwrap_or("-".to_string());
        let enabled = if rule.enabled { "yes" } else { "no" };
        let port = match (rule.port_start, rule.port_end) {
            (Some(start), Some(end)) => format!("{}-{}", start, end),
            (Some(start), None) => start.to_string(),
            _ => "-".to_string(),
        };
        let proto = rule
            .protocol
            .map(|p| p.to_string())
            .unwrap_or_else(|| "any".to_string());
        println!(
            "{}: {} proto={} port={} action={} enabled={}",
            id, rule.name, proto, port, rule.action, enabled
        );
    }
}

pub fn save_input_rule(response: &SaveInputRuleResponse) {
    if response.success {
        println!("✓ {}", response.message);
        if let Some(id) = response.rule_id {
            println!("  Rule ID: {}", id);
        }
    } else {
        println!("✗ {}", response.message);
    }
}

pub fn delete_input_rule(response: &DeleteInputRuleResponse) {
    if response.success {
        println!("✓ {}", response.message);
    } else {
        println!("✗ {}", response.message);
    }
}

pub fn forward_rules(response: &ForwardRulesResponse) {
    println!("=== Forward Rules ===\n");
    if response.rules.is_empty() {
        println!("No forward rules configured.");
        return;
    }
    for rule in &response.rules {
        let id = rule.id.map(|i| i.to_string()).unwrap_or("-".to_string());
        let enabled = if rule.enabled { "yes" } else { "no" };
        println!(
            "{}: {} action={} enabled={} src={:?} dest={:?}",
            id, rule.name, rule.action, enabled, rule.source_zone, rule.dest_zone
        );
    }
}

pub fn save_forward_rule(response: &SaveForwardRuleResponse) {
    if response.success {
        println!("✓ {}", response.message);
        if let Some(id) = response.rule_id {
            println!("  Rule ID: {}", id);
        }
    } else {
        println!("✗ {}", response.message);
    }
}

pub fn delete_forward_rule(response: &DeleteForwardRuleResponse) {
    if response.success {
        println!("✓ {}", response.message);
    } else {
        println!("✗ {}", response.message);
    }
}

pub fn firewall_settings(response: &FirewallGlobalSettingsResponse) {
    println!("=== Firewall Settings ===\n");
    println!("Ping WAN: {}", response.settings.ping_wan_enabled);
    println!("Ping LAN: {}", response.settings.ping_lan_enabled);
    println!("Hairpin NAT: {}", response.settings.hairpin_nat_enabled);
    println!("Force local DNS: {}", response.settings.force_local_dns);
    println!(
        "Block DNS-over-TLS: {}",
        response.settings.block_dns_over_tls
    );
    println!(
        "DNS exempt group: {}",
        response
            .settings
            .dns_exempt_group
            .as_deref()
            .unwrap_or("none")
    );
}

pub fn save_firewall_settings(response: &SaveFirewallGlobalSettingsResponse) {
    if response.success {
        println!("✓ {}", response.message);
    } else {
        println!("✗ {}", response.message);
    }
}

pub fn firewall_preview(response: &FirewallPreviewResponse) {
    println!("=== Firewall Preview ===\n");
    println!("{}", response.ruleset);
}

pub fn firewall_apply(response: &FirewallApplyResponse, show_pending: bool) {
    if response.success {
        println!("✓ {}", response.message);
        if let Some(session_id) = response.session_id.as_ref().filter(|_| show_pending) {
            println!("  Session ID: {}", session_id);
            println!("  Run 'keystonectl confirm' (session {})", session_id);
        }
    } else {
        println!("✗ {}", response.message);
    }
}

pub fn firewall_confirm(response: &FirewallConfirmResponse) {
    if response.success {
        println!("✓ {}", response.message);
    } else {
        println!("✗ {}", response.message);
    }
}

pub fn firewall_rollback(response: &FirewallRollbackResponse) {
    if response.success {
        println!("✓ {}", response.message);
    } else {
        println!("✗ {}", response.message);
    }
}

pub fn firewall_status(response: &FirewallStatusResponse) {
    println!("=== Firewall Status ===\n");
    println!("Pending confirmation: {}", response.pending_confirmation);
    if response.networkd_pending {
        println!("Includes a pending network (networkd) change");
    }
    if let Some(session_id) = &response.session_id {
        println!("Session ID: {}", session_id);
    }
}

// dnsmasq

pub fn dnsmasq_state(response: &DnsmasqStateResponse) {
    dnsmasq_config(&response.config);
    println!();
    dhcp_ranges(&response.dhcp_ranges);
    println!();
    static_leases(&response.static_leases);
    println!();
    dhcp_options(&response.dhcp_options);
    println!();
    host_records(&response.host_records);
    println!();
    cname_records(&response.cname_records);
    println!();
    address_overrides(&response.address_overrides);
}

pub fn dnsmasq_config(config: &DnsmasqConfig) {
    println!("=== DNS Configuration ===\n");
    println!(
        "Service: {}",
        if config.enabled {
            "Enabled"
        } else {
            "Disabled"
        }
    );
    println!("DNS Port: {}", config.dns_port);
    println!("Upstream Mode: {}", config.upstream_mode);
    println!("Cache Size: {}", config.cache_size);
    println!(
        "Local Domain: {}",
        config.local_domain.as_deref().unwrap_or("-")
    );
    println!(
        "DNSSEC: {}",
        if config.dnssec_enabled {
            "Enabled"
        } else {
            "Disabled"
        }
    );
    println!(
        "Domain Needed: {}",
        if config.domain_needed { "Yes" } else { "No" }
    );
    println!(
        "Bogus Priv: {}",
        if config.bogus_priv { "Yes" } else { "No" }
    );
    println!(
        "Expand Hosts: {}",
        if config.expand_hosts { "Yes" } else { "No" }
    );
    println!(
        "Log Queries: {}",
        if config.log_queries { "Yes" } else { "No" }
    );
    println!("Log DHCP: {}", if config.log_dhcp { "Yes" } else { "No" });
}

pub fn save_dnsmasq_config(response: &SaveDnsmasqConfigResponse) {
    if response.success {
        println!("✓ {}", response.message);
    } else {
        println!("✗ {}", response.message);
    }
}

pub fn dhcp_ranges(ranges: &[DnsmasqDhcpRange]) {
    println!("=== DHCP Ranges ===\n");
    if ranges.is_empty() {
        println!("No DHCP ranges configured.");
        return;
    }
    for r in ranges {
        let id = r.id.map(|i| i.to_string()).unwrap_or("-".to_string());
        let enabled = if r.enabled { "yes" } else { "no" };
        println!(
            "{}: {} iface={} {}-{} enabled={}",
            id, r.name, r.interface, r.start_address, r.end_address, enabled
        );
    }
}

pub fn save_dhcp_range(response: &SaveDhcpRangeResponse) {
    if response.success {
        println!("✓ {}", response.message);
        if let Some(id) = response.range_id {
            println!("  Range ID: {}", id);
        }
    } else {
        println!("✗ {}", response.message);
    }
}

pub fn static_leases(leases: &[DnsmasqStaticLease]) {
    println!("=== Static Leases ===\n");
    if leases.is_empty() {
        println!("No static leases configured.");
        return;
    }
    for l in leases {
        let id = l.id.map(|i| i.to_string()).unwrap_or("-".to_string());
        let enabled = if l.enabled { "yes" } else { "no" };
        println!(
            "{}: mac={} ip={} hostname={:?} enabled={}",
            id, l.mac_address, l.ip_address, l.hostname, enabled
        );
    }
}

pub fn save_static_lease(response: &SaveStaticLeaseResponse) {
    if response.success {
        println!("✓ {}", response.message);
        if let Some(id) = response.lease_id {
            println!("  Lease ID: {}", id);
        }
    } else {
        println!("✗ {}", response.message);
    }
}

pub fn dhcp_options(options: &[DnsmasqDhcpOption]) {
    println!("=== DHCP Options ===\n");
    if options.is_empty() {
        println!("No DHCP options configured.");
        return;
    }
    for o in options {
        let id = o.id.map(|i| i.to_string()).unwrap_or("-".to_string());
        let enabled = if o.enabled { "yes" } else { "no" };
        println!(
            "{}: opt={} val={} ipv6={} enabled={}",
            id, o.option, o.value, o.ipv6, enabled
        );
    }
}

pub fn save_dhcp_option(response: &SaveDhcpOptionResponse) {
    if response.success {
        println!("✓ {}", response.message);
        if let Some(id) = response.option_id {
            println!("  Option ID: {}", id);
        }
    } else {
        println!("✗ {}", response.message);
    }
}

pub fn host_records(records: &[DnsmasqHostRecord]) {
    println!("=== Host Records ===\n");
    if records.is_empty() {
        println!("No host records configured.");
        return;
    }
    for r in records {
        let id = r.id.map(|i| i.to_string()).unwrap_or("-".to_string());
        let enabled = if r.enabled { "yes" } else { "no" };
        println!(
            "{}: hosts={:?} ipv4={:?} ipv6={:?} enabled={}",
            id, r.hostnames, r.ipv4_address, r.ipv6_address, enabled
        );
    }
}

pub fn save_host_record(response: &SaveHostRecordResponse) {
    if response.success {
        println!("✓ {}", response.message);
        if let Some(id) = response.record_id {
            println!("  Record ID: {}", id);
        }
    } else {
        println!("✗ {}", response.message);
    }
}

pub fn cname_records(records: &[DnsmasqCnameRecord]) {
    println!("=== CNAME Records ===\n");
    if records.is_empty() {
        println!("No CNAME records configured.");
        return;
    }
    for r in records {
        let id = r.id.map(|i| i.to_string()).unwrap_or("-".to_string());
        let enabled = if r.enabled { "yes" } else { "no" };
        println!("{}: {} -> {} enabled={}", id, r.alias, r.target, enabled);
    }
}

pub fn save_cname_record(response: &SaveCnameRecordResponse) {
    if response.success {
        println!("✓ {}", response.message);
        if let Some(id) = response.record_id {
            println!("  Record ID: {}", id);
        }
    } else {
        println!("✗ {}", response.message);
    }
}

pub fn address_overrides(overrides: &[DnsmasqAddressOverride]) {
    println!("=== Address Overrides ===\n");
    if overrides.is_empty() {
        println!("No address overrides configured.");
        return;
    }
    for o in overrides {
        let id = o.id.map(|i| i.to_string()).unwrap_or("-".to_string());
        let enabled = if o.enabled { "yes" } else { "no" };
        let action = match o.action {
            DnsmasqAddressAction::Block => "block",
            DnsmasqAddressAction::Redirect => "redirect",
            DnsmasqAddressAction::Null => "null",
        };
        println!(
            "{}: domain={} action={} redirect_to={:?} enabled={}",
            id, o.domain, action, o.redirect_address, enabled
        );
    }
}

pub fn save_address_override(response: &SaveAddressOverrideResponse) {
    if response.success {
        println!("✓ {}", response.message);
        if let Some(id) = response.override_id {
            println!("  Override ID: {}", id);
        }
    } else {
        println!("✗ {}", response.message);
    }
}

pub fn active_leases(response: &DhcpLeasesResponse) {
    println!("=== Active DHCP Leases ===\n");
    if response.leases.is_empty() {
        println!("No active leases.");
        return;
    }
    for l in &response.leases {
        println!(
            "- mac={} ip={} host={:?} expires={}",
            l.mac_address, l.ip_address, l.hostname, l.expires_at
        );
    }
}

pub fn dnsmasq_preview(response: &DnsmasqPreviewResponse) {
    println!("=== dnsmasq Configuration Preview ===\n");
    println!("{}", response.config_content);
}

pub fn dnsmasq_apply(response: &DnsmasqApplyResponse) {
    if response.success {
        println!("✓ {}", response.message);
    } else {
        println!("✗ {}", response.message);
    }
}

pub fn delete_success(success: bool, message: &str) {
    if success {
        println!("✓ Deleted successfully");
    } else {
        println!("✗ {}", message);
    }
}

/// Pending configuration changes, per component, with unified diffs.
pub fn pending_changes(response: &PendingChangesResponse) {
    component_diffs("Pending configuration changes", response);
}

/// Per-component diffs under `heading`. Colour is used only on a terminal.
pub fn component_diffs(heading: &str, response: &PendingChangesResponse) {
    println!("=== {heading} ===\n");
    let mut any_difference = false;
    for diff in &response.components {
        let baseline = match response.baseline_ids.get(diff.component) {
            Some(id) => format!("snapshot {id}"),
            None => "never applied".to_string(),
        };
        if let Some(error) = &diff.error {
            any_difference |= diff.changed;
            println!(
                "{}: cannot be generated (against {baseline}): {error}",
                diff.component
            );
        }
        if !diff.changed {
            if diff.error.is_none() {
                println!("{}: no changes (against {baseline})", diff.component);
            }
            continue;
        }
        any_difference = true;
        if diff.error.is_none() {
            println!("{}: changed (against {baseline})", diff.component);
        }
        for file in &diff.files {
            let status = match file.status {
                FileChangeStatus::Added => "added",
                FileChangeStatus::Removed => "removed",
                FileChangeStatus::Modified => "modified",
            };
            println!("  {status} {}", file.path);
            for line in file.unified_diff.lines() {
                if line.starts_with("---") || line.starts_with("+++") {
                    continue;
                }
                println!("    {}", colour_diff_line(line));
            }
        }
        println!();
    }
    if !any_difference {
        println!("No differences.");
    }
}

fn colour_diff_line(line: &str) -> String {
    if line.starts_with("@@") {
        style(line).cyan().to_string()
    } else if line.starts_with('+') {
        style(line).green().to_string()
    } else if line.starts_with('-') {
        style(line).red().to_string()
    } else {
        line.to_string()
    }
}

pub fn discard_changes(response: &DiscardChangesResponse) {
    println!("{}", response.message);
}

pub fn restore_snapshot(response: &RestoreSnapshotResponse) {
    println!("{}", response.message);
}

pub fn snapshot_response(response: &SnapshotResponse) {
    if response.success {
        println!("✓ {}", response.message);
    } else {
        println!("✗ {}", response.message);
    }
}

pub fn snapshot_list(response: &SnapshotListResponse) {
    println!("=== Configuration snapshots ===\n");
    if response.snapshots.is_empty() {
        println!("No snapshots.");
        return;
    }
    println!(
        "ID     Created (UTC)     Kind         Status              Applied for                    Size     Actor      Note"
    );
    println!("{}", "-".repeat(118));
    for snapshot in &response.snapshots {
        let components = if snapshot.components.is_empty() {
            "-".to_string()
        } else {
            snapshot
                .components
                .iter()
                .map(|component| component.as_str())
                .collect::<Vec<_>>()
                .join(",")
        };
        println!(
            "{:<6} {:<17} {:<12} {:<19} {:<30} {:<8} {:<10} {}",
            snapshot.id,
            format_utc_datetime(snapshot.created_at),
            snapshot.kind.as_str(),
            snapshot.status.as_str(),
            components,
            crate::format_bytes(snapshot.size_bytes),
            snapshot.actor.as_deref().unwrap_or("-"),
            snapshot.note.as_deref().unwrap_or("")
        );
    }
}
