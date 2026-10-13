//! Validation and generation of the miniupnpd configuration.
//!
//! Everything here is a pure function of the typed configuration, so the same
//! text is shown in the pending-changes diff and written on apply.
//!
//! The generated file is `key=value` lines, followed by the permission rules.
//! miniupnpd checks each rule in order and the final `deny` rule ends the list.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use keystone_core::InterfaceConfig;
use keystone_core::upnp::{
    PortRange, UPNP_MAX_LEASE_SECS_LIMIT, UPNP_MAX_NOTIFY_SECS, UPNP_MIN_LEASE_SECS,
    UPNP_MIN_NOTIFY_SECS, UpnpConfig, UpnpForwardAccept,
};
use keystone_core::validation::{interface_name, is_single_line};

/// Where Keystone writes the miniupnpd configuration.
pub const MINIUPNPD_CONF_PATH: &str = "/etc/miniupnpd/miniupnpd.conf";

/// Lease file miniupnpd keeps its mappings in. Its directory is created by
/// `StateDirectory=miniupnpd` in the packaged unit.
pub const UPNP_LEASE_FILE: &str = "/var/lib/miniupnpd/upnp.leases";

/// Longest friendly name accepted. Names are limited to a safe character set.
const FRIENDLY_NAME_MAX: usize = 64;

/// Check a configuration against the interfaces that exist. The candidate
/// lists are the configured LAN-role and WAN-role interfaces.
pub fn validate_config(
    config: &UpnpConfig,
    lan_candidates: &[String],
    wan_candidates: &[String],
) -> Result<(), String> {
    let mut errors = Vec::new();
    let mut seen = BTreeSet::new();
    for lan in &config.lan_interfaces {
        if let Err(error) = interface_name(lan) {
            errors.push(error);
            continue;
        }
        if !lan_candidates.contains(lan) {
            errors.push(format!("{lan} is not a LAN interface"));
        }
        if lan == &config.wan_interface {
            errors.push(format!("{lan} cannot be both the WAN and a LAN interface"));
        }
        if !seen.insert(lan.as_str()) {
            errors.push(format!("{lan} is listed more than once"));
        }
    }
    if !config.wan_interface.is_empty() {
        match interface_name(&config.wan_interface) {
            Err(error) => errors.push(error),
            Ok(()) if !wan_candidates.contains(&config.wan_interface) => {
                errors.push(format!("{} is not a WAN interface", config.wan_interface));
            }
            Ok(()) => {}
        }
    }

    if config.enabled {
        if config.lan_interfaces.is_empty() {
            errors.push("choose at least one LAN interface".to_string());
        }
        if config.wan_interface.is_empty() {
            errors.push("choose the WAN interface".to_string());
        }
        if !config.enable_igd && !config.enable_natpmp_pcp {
            errors.push("enable UPnP IGD, NAT-PMP / PCP, or both".to_string());
        }
    }

    if let Err(error) = validate_port_range("external ports", config.external_ports) {
        errors.push(error);
    }
    if let Err(error) = validate_port_range("internal ports", config.internal_ports) {
        errors.push(error);
    }
    if !(UPNP_MIN_LEASE_SECS..=UPNP_MAX_LEASE_SECS_LIMIT).contains(&config.max_lease_secs) {
        errors.push(format!(
            "maximum lease must be between {UPNP_MIN_LEASE_SECS} and {UPNP_MAX_LEASE_SECS_LIMIT} seconds"
        ));
    }
    if !(UPNP_MIN_NOTIFY_SECS..=UPNP_MAX_NOTIFY_SECS).contains(&config.notify_interval_secs) {
        errors.push(format!(
            "announcement interval must be between {UPNP_MIN_NOTIFY_SECS} and {UPNP_MAX_NOTIFY_SECS} seconds"
        ));
    }
    if let Err(error) = validate_friendly_name(&config.friendly_name) {
        errors.push(error);
    }

    let mut subnets = BTreeSet::new();
    for subnet in &config.allowed_client_subnets {
        match normalize_subnet(subnet) {
            Ok(normalized) if normalized == *subnet => {
                subnets.insert(normalized);
            }
            Ok(_) => errors.push(format!(
                "{subnet} is not a network address; write its network instead"
            )),
            Err(error) => errors.push(error),
        }
    }
    if subnets.len() != config.allowed_client_subnets.len() {
        errors.push("an allowed client subnet is listed more than once".to_string());
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn validate_port_range(label: &str, range: PortRange) -> Result<(), String> {
    if range.min == 0 || range.min > range.max {
        return Err(format!(
            "{label} must be a range from 1 to 65535, with the lower port first"
        ));
    }
    Ok(())
}

/// The friendly name is written into the configuration file, so it is limited
/// to letters, digits, spaces and a few punctuation marks.
pub fn validate_friendly_name(name: &str) -> Result<(), String> {
    let valid = !name.is_empty()
        && name.len() <= FRIENDLY_NAME_MAX
        && name == name.trim()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b" _.()-".contains(&b));
    if valid {
        Ok(())
    } else {
        Err(format!(
            "friendly name must be 1 to {FRIENDLY_NAME_MAX} letters, digits, spaces or _.()- with no leading or trailing space"
        ))
    }
}

/// Parse an IPv4 `address/prefix` and return its network as `network/prefix`.
pub fn normalize_subnet(value: &str) -> Result<String, String> {
    let invalid = || format!("{value:?} is not an IPv4 subnet in a.b.c.d/nn form");
    let (address, prefix) = value.split_once('/').ok_or_else(invalid)?;
    let address: Ipv4Addr = address.parse().map_err(|_| invalid())?;
    let prefix: u8 = prefix.parse().map_err(|_| invalid())?;
    if prefix > 32 {
        return Err(invalid());
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    let network = Ipv4Addr::from(u32::from(address) & mask);
    Ok(format!("{network}/{prefix}"))
}

/// The client subnets to allow: the configured list, or when that is empty,
/// the network of every static IPv4 address on the selected LAN interfaces.
pub fn resolve_client_subnets(
    config: &UpnpConfig,
    interfaces: &[InterfaceConfig],
) -> Result<Vec<String>, String> {
    if !config.allowed_client_subnets.is_empty() {
        return Ok(config.allowed_client_subnets.clone());
    }
    derive_client_subnets(&config.lan_interfaces, interfaces)
}

fn derive_client_subnets(
    lan_interfaces: &[String],
    interfaces: &[InterfaceConfig],
) -> Result<Vec<String>, String> {
    let mut subnets = BTreeSet::new();
    for lan in lan_interfaces {
        let mut found = false;
        if let Some(interface) = interfaces.iter().find(|iface| &iface.name == lan) {
            for address in &interface.addresses {
                if let Ok(network) = normalize_subnet(&address.address) {
                    subnets.insert(network);
                    found = true;
                }
            }
        }
        if !found {
            return Err(format!(
                "{lan} has no static IPv4 address to take client subnets from; list the allowed client subnets explicitly"
            ));
        }
    }
    Ok(subnets.into_iter().collect())
}

/// The UUID miniupnpd advertises. The packaged unit passes the machine-id as
/// `-u`, which overrides this value, so the two are kept identical.
pub fn uuid_from_machine_id(machine_id: &str) -> Result<String, String> {
    let hex = machine_id.trim();
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("machine-id is not 32 hexadecimal digits".to_string());
    }
    let hex = hex.to_ascii_lowercase();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

/// The firewall accept rule for UPnP mappings, when UPnP is enabled.
pub fn forward_accept(config: &UpnpConfig) -> Option<UpnpForwardAccept> {
    if !config.enabled || config.wan_interface.is_empty() || config.lan_interfaces.is_empty() {
        return None;
    }
    Some(UpnpForwardAccept {
        wan_interface: config.wan_interface.clone(),
        lan_interfaces: config.lan_interfaces.clone(),
    })
}

/// Render `/etc/miniupnpd/miniupnpd.conf`. The configuration must already be
/// validated; the values are re-checked here so that no value can add a line.
pub fn render_miniupnpd_conf(
    config: &UpnpConfig,
    client_subnets: &[String],
    uuid: &str,
) -> Result<String, String> {
    interface_name(&config.wan_interface)?;
    for lan in &config.lan_interfaces {
        interface_name(lan)?;
    }
    validate_friendly_name(&config.friendly_name)?;
    for subnet in client_subnets {
        if normalize_subnet(subnet)? != *subnet {
            return Err(format!("{subnet} is not a network address"));
        }
    }
    if !is_single_line(uuid) || uuid.len() != 36 {
        return Err("UUID is malformed".to_string());
    }

    let yes_no = |flag: bool| if flag { "yes" } else { "no" };
    let mut out = String::new();
    out.push_str("# Generated by Keystone. Edits are overwritten when UPnP is applied.\n");
    out.push_str(&format!("ext_ifname={}\n", config.wan_interface));
    for lan in &config.lan_interfaces {
        out.push_str(&format!("listening_ip={lan}\n"));
    }
    out.push_str(&format!("enable_upnp={}\n", yes_no(config.enable_igd)));
    out.push_str(&format!(
        "enable_pcp_pmp={}\n",
        yes_no(config.enable_natpmp_pcp)
    ));
    out.push_str(&format!("secure_mode={}\n", yes_no(config.secure_mode)));
    out.push_str(&format!("lease_file={UPNP_LEASE_FILE}\n"));
    // Rules are kept in Keystone's own table, which is not the firewall's
    // table, so a firewall apply never removes them. The chain names are the
    // ones miniupnpd uses by default; the table is created by Keystone.
    out.push_str(&format!("upnp_table_name={}\n", super::nft::UPNP_TABLE));
    out.push_str(&format!("upnp_nat_table_name={}\n", super::nft::UPNP_TABLE));
    out.push_str(&format!(
        "upnp_forward_chain={}\n",
        super::nft::FORWARD_CHAIN
    ));
    out.push_str(&format!(
        "upnp_nat_chain={}\n",
        super::nft::PREROUTING_CHAIN
    ));
    out.push_str(&format!(
        "upnp_nat_postrouting_chain={}\n",
        super::nft::POSTROUTING_CHAIN
    ));
    out.push_str("upnp_nftables_family_split=yes\n");
    out.push_str(&format!("friendly_name={}\n", config.friendly_name));
    out.push_str(&format!("system_uptime={}\n", yes_no(config.system_uptime)));
    out.push_str(&format!(
        "notify_interval={}\n",
        config.notify_interval_secs
    ));
    out.push_str(&format!("max_lifetime={}\n", config.max_lease_secs));
    out.push_str(&format!("uuid={uuid}\n"));
    out.push_str("# Permission rules: allow|deny external-ports client-subnet internal-ports.\n");
    for subnet in client_subnets {
        out.push_str(&format!(
            "allow {} {} {}\n",
            port_range_text(config.external_ports),
            subnet,
            port_range_text(config.internal_ports)
        ));
    }
    out.push_str("deny 0-65535 0.0.0.0/0 0-65535\n");
    Ok(out)
}

fn port_range_text(range: PortRange) -> String {
    format!("{}-{}", range.min, range.max)
}

#[cfg(test)]
mod tests {
    use super::*;
    use keystone_core::{DhcpMode, InterfaceRole, StaticAddress};

    fn lan_candidates() -> Vec<String> {
        vec!["eth1".to_string(), "eth2".to_string()]
    }

    fn wan_candidates() -> Vec<String> {
        vec!["eth0".to_string()]
    }

    fn enabled_config() -> UpnpConfig {
        UpnpConfig {
            enabled: true,
            lan_interfaces: vec!["eth1".to_string()],
            wan_interface: "eth0".to_string(),
            ..UpnpConfig::default()
        }
    }

    fn interface(name: &str, role: InterfaceRole, addresses: &[&str]) -> InterfaceConfig {
        InterfaceConfig {
            id: None,
            name: name.to_string(),
            role,
            enabled: true,
            description: None,
            dhcp_mode: DhcpMode::No,
            addresses: addresses
                .iter()
                .map(|address| StaticAddress {
                    address: address.to_string(),
                    label: None,
                    scope: Default::default(),
                })
                .collect(),
            routes: Vec::new(),
            dns_servers: Vec::new(),
            search_domains: Vec::new(),
            gateway: None,
            link_local: Default::default(),
            ..Default::default()
        }
    }

    #[test]
    fn a_valid_enabled_configuration_passes() {
        assert_eq!(
            validate_config(&enabled_config(), &lan_candidates(), &wan_candidates()),
            Ok(())
        );
    }

    #[test]
    fn a_wan_interface_is_never_accepted_as_a_lan_interface() {
        let mut config = enabled_config();
        config.lan_interfaces = vec!["eth0".to_string()];
        let error = validate_config(&config, &lan_candidates(), &wan_candidates()).unwrap_err();
        assert!(error.contains("eth0 is not a LAN interface"), "{error}");
        assert!(error.contains("cannot be both"), "{error}");
    }

    #[test]
    fn the_wan_must_be_a_configured_wan_interface() {
        let mut config = enabled_config();
        config.wan_interface = "eth1".to_string();
        let error = validate_config(&config, &lan_candidates(), &wan_candidates()).unwrap_err();
        assert!(error.contains("eth1 is not a WAN interface"), "{error}");
    }

    #[test]
    fn an_enabled_configuration_needs_lan_wan_and_a_protocol() {
        let mut config = enabled_config();
        config.lan_interfaces.clear();
        config.enable_igd = false;
        config.enable_natpmp_pcp = false;
        let error = validate_config(&config, &lan_candidates(), &wan_candidates()).unwrap_err();
        assert!(error.contains("at least one LAN"), "{error}");
        assert!(error.contains("enable UPnP IGD"), "{error}");

        let disabled = UpnpConfig::default();
        assert_eq!(
            validate_config(&disabled, &lan_candidates(), &wan_candidates()),
            Ok(())
        );
    }

    #[test]
    fn port_ranges_must_be_ordered_and_non_zero() {
        let mut config = enabled_config();
        config.external_ports = PortRange {
            min: 2000,
            max: 1000,
        };
        config.internal_ports = PortRange { min: 0, max: 80 };
        let error = validate_config(&config, &lan_candidates(), &wan_candidates()).unwrap_err();
        assert!(error.contains("external ports"), "{error}");
        assert!(error.contains("internal ports"), "{error}");
    }

    #[test]
    fn lease_limit_is_bounded_and_zero_is_refused() {
        for lease in [0, 120, 86_401, u32::MAX] {
            let mut config = enabled_config();
            config.max_lease_secs = lease;
            assert!(
                validate_config(&config, &lan_candidates(), &wan_candidates()).is_err(),
                "lease {lease} accepted"
            );
        }
        let mut config = enabled_config();
        config.max_lease_secs = 86_400;
        assert_eq!(
            validate_config(&config, &lan_candidates(), &wan_candidates()),
            Ok(())
        );
    }

    #[test]
    fn friendly_name_rejects_control_characters_and_config_syntax() {
        for name in [
            "",
            "a\nallow 0-65535 0.0.0.0/0 0-65535",
            "x#y",
            "x=y",
            " lead",
            "trail ",
        ] {
            assert!(validate_friendly_name(name).is_err(), "{name:?} accepted");
        }
        assert!(validate_friendly_name("Keystone router (lab)").is_ok());
        assert!(validate_friendly_name(&"a".repeat(65)).is_err());
    }

    #[test]
    fn subnets_are_normalised_to_their_network_and_checked() {
        assert_eq!(
            normalize_subnet("192.168.1.77/24").unwrap(),
            "192.168.1.0/24"
        );
        assert_eq!(normalize_subnet("10.1.2.3/0").unwrap(), "0.0.0.0/0");
        assert_eq!(normalize_subnet("10.1.2.3/32").unwrap(), "10.1.2.3/32");
        for bad in [
            "192.168.1.0",
            "192.168.1.0/33",
            "fd00::/64",
            "x/24",
            "1.2.3.4/-1",
        ] {
            assert!(normalize_subnet(bad).is_err(), "{bad} accepted");
        }
    }

    #[test]
    fn a_subnet_that_is_not_a_network_address_is_refused_when_saved() {
        let mut config = enabled_config();
        config.allowed_client_subnets = vec!["192.168.1.77/24".to_string()];
        let error = validate_config(&config, &lan_candidates(), &wan_candidates()).unwrap_err();
        assert!(error.contains("not a network address"), "{error}");
    }

    #[test]
    fn client_subnets_default_to_the_static_networks_of_the_lan_interfaces() {
        let interfaces = [
            interface(
                "eth1",
                InterfaceRole::LAN,
                &["192.168.1.1/24", "fd00::1/64"],
            ),
            interface("eth2", InterfaceRole::LAN, &["10.20.0.254/16"]),
        ];
        let mut config = enabled_config();
        config.lan_interfaces = vec!["eth1".to_string(), "eth2".to_string()];
        assert_eq!(
            resolve_client_subnets(&config, &interfaces).unwrap(),
            vec!["10.20.0.0/16".to_string(), "192.168.1.0/24".to_string()]
        );

        config.allowed_client_subnets = vec!["192.168.1.0/24".to_string()];
        assert_eq!(
            resolve_client_subnets(&config, &interfaces).unwrap(),
            vec!["192.168.1.0/24".to_string()]
        );
    }

    #[test]
    fn a_lan_without_a_static_address_needs_explicit_subnets() {
        let interfaces = [interface("eth1", InterfaceRole::LAN, &[])];
        let error = resolve_client_subnets(&enabled_config(), &interfaces).unwrap_err();
        assert!(error.contains("eth1 has no static IPv4 address"), "{error}");
    }

    #[test]
    fn uuid_is_derived_from_the_machine_id_in_the_systemd_format() {
        assert_eq!(
            uuid_from_machine_id("0123456789ABCDEF0123456789abcdef\n").unwrap(),
            "01234567-89ab-cdef-0123-456789abcdef"
        );
        assert!(uuid_from_machine_id("short").is_err());
        assert!(uuid_from_machine_id("0123456789abcdef0123456789abcdeg").is_err());
    }

    #[test]
    fn forward_accept_exists_only_while_upnp_is_enabled() {
        assert_eq!(forward_accept(&UpnpConfig::default()), None);
        let accept = forward_accept(&enabled_config()).unwrap();
        assert_eq!(accept.wan_interface, "eth0");
        assert_eq!(accept.lan_interfaces, vec!["eth1".to_string()]);
    }

    #[test]
    fn rendered_configuration_matches_the_golden_text() {
        let mut config = enabled_config();
        config.lan_interfaces = vec!["eth1".to_string(), "eth2".to_string()];
        config.wan_interface = "eth0".to_string();
        config.enable_natpmp_pcp = false;
        config.secure_mode = false;
        config.friendly_name = "Lab router".to_string();
        config.system_uptime = false;
        config.notify_interval_secs = 600;
        config.max_lease_secs = 3600;
        config.external_ports = PortRange {
            min: 1024,
            max: 65535,
        };
        config.internal_ports = PortRange { min: 1, max: 65535 };
        let subnets = vec!["192.168.1.0/24".to_string(), "10.20.0.0/16".to_string()];

        let text = render_miniupnpd_conf(&config, &subnets, "01234567-89ab-cdef-0123-456789abcdef")
            .unwrap();
        let expected = "\
# Generated by Keystone. Edits are overwritten when UPnP is applied.
ext_ifname=eth0
listening_ip=eth1
listening_ip=eth2
enable_upnp=yes
enable_pcp_pmp=no
secure_mode=no
lease_file=/var/lib/miniupnpd/upnp.leases
upnp_table_name=keystone_upnp
upnp_nat_table_name=keystone_upnp
upnp_forward_chain=miniupnpd
upnp_nat_chain=prerouting_miniupnpd
upnp_nat_postrouting_chain=postrouting_miniupnpd
upnp_nftables_family_split=yes
friendly_name=Lab router
system_uptime=no
notify_interval=600
max_lifetime=3600
uuid=01234567-89ab-cdef-0123-456789abcdef
# Permission rules: allow|deny external-ports client-subnet internal-ports.
allow 1024-65535 192.168.1.0/24 1-65535
allow 1024-65535 10.20.0.0/16 1-65535
deny 0-65535 0.0.0.0/0 0-65535
";
        assert_eq!(text, expected);
    }

    #[test]
    fn the_final_rule_is_always_the_catch_all_deny() {
        let text = render_miniupnpd_conf(
            &enabled_config(),
            &["192.168.1.0/24".to_string()],
            "01234567-89ab-cdef-0123-456789abcdef",
        )
        .unwrap();
        let rules: Vec<&str> = text
            .lines()
            .filter(|l| l.starts_with("allow ") || l.starts_with("deny "))
            .collect();
        assert_eq!(rules.last(), Some(&"deny 0-65535 0.0.0.0/0 0-65535"));
        // Every rule before the catch-all is an allow, and the file ends on it.
        let (_, allows) = rules.split_last().unwrap();
        assert!(allows.iter().all(|l| l.starts_with("allow ")));
        assert!(text.lines().last() == rules.last().copied());
    }

    #[test]
    fn rendering_refuses_values_that_could_add_a_line() {
        let mut config = enabled_config();
        config.friendly_name = "x\nallow 0-65535 0.0.0.0/0 0-65535".to_string();
        assert!(
            render_miniupnpd_conf(
                &config,
                &["192.168.1.0/24".to_string()],
                "01234567-89ab-cdef-0123-456789abcdef"
            )
            .is_err()
        );
        let mut config = enabled_config();
        config.wan_interface = "eth0\nx".to_string();
        assert!(
            render_miniupnpd_conf(&config, &[], "01234567-89ab-cdef-0123-456789abcdef").is_err()
        );
    }
}
