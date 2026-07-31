//! Opinionated basic SOHO router profile generation.
//!
//! This module turns the setup wizard's WAN/LAN assignments into a complete,
//! internally consistent router configuration rather than a collection of
//! unrelated interface labels.

use std::collections::HashSet;
use std::net::Ipv4Addr;

use anyhow::{Context, Result, bail};
use ipnet::Ipv4Net;
use keystone_core::{
    AddressScope, DhcpMode, DhcpPrefixDelegationConfig, Dhcpv4ClientConfig, Dhcpv6ClientConfig,
    DnsmasqDhcpRange, FirewallAction, FirewallPolicy, FirewallZone, InterfaceConfig, InterfaceRole,
    IpForwardMode, IpMasqueradeMode, StaticAddress, WizardInterfaceAssignment, ZoneForwardPolicy,
};
use tracing::info;

use crate::{db::Database, dnsmasq};

const SOHO_WAN_DESCRIPTION: &str = "SOHO WAN uplink";
const SOHO_LAN_DESCRIPTION: &str = "SOHO LAN";
const SOHO_RANGE_PREFIX: &str = "SOHO LAN (";

/// Result of staging a basic SOHO router profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SohoProfileSummary {
    pub wan_interface: String,
    pub lan_interfaces: Vec<String>,
}

/// Stage a complete basic dual-stack SOHO router profile in the database.
pub async fn configure_soho_profile(
    db: &Database,
    assignments: &[WizardInterfaceAssignment],
) -> Result<SohoProfileSummary> {
    validate_assignments(assignments)?;

    let wan = assignments
        .iter()
        .find(|assignment| assignment.role == InterfaceRole::WAN)
        .expect("validated exactly one WAN");
    let lan_assignments: Vec<_> = assignments
        .iter()
        .filter(|assignment| assignment.role == InterfaceRole::LAN)
        .collect();

    let mut lan_networks = HashSet::new();
    let existing_configs = db.get_interface_configs().await?;
    let existing_ranges = dnsmasq::load_dhcp_ranges(db.pool()).await?;
    let selected_names = assignments
        .iter()
        .map(|assignment| assignment.name.clone())
        .collect::<HashSet<_>>();
    let mut lan_plans = Vec::with_capacity(lan_assignments.len());

    // Validate and construct the complete plan before making any database changes.
    for (index, assignment) in lan_assignments.iter().enumerate() {
        let address = assignment
            .static_ip
            .clone()
            .unwrap_or_else(|| default_lan_address(index));
        let network = parse_lan_network(&address)?;
        if !lan_networks.insert(network.trunc()) {
            bail!(
                "LAN interfaces must use distinct IPv4 subnets; {} is duplicated",
                network
            );
        }

        lan_plans.push((
            assignment.name.clone(),
            create_lan_config(assignment, &address, &wan.name, index as u64),
            create_dhcp_range(assignment, network, &existing_ranges)?,
        ));
    }

    db.save_interface_config(&create_wan_config(wan)).await?;
    for (_, interface_config, range) in &lan_plans {
        db.save_interface_config(interface_config).await?;
        dnsmasq::save_dhcp_range(db.pool(), range).await?;
    }
    let lan_interfaces = lan_plans
        .into_iter()
        .map(|(name, _, _)| name)
        .collect::<Vec<_>>();

    for config in existing_configs {
        let generated_by_soho = matches!(
            config.description.as_deref(),
            Some(SOHO_WAN_DESCRIPTION | SOHO_LAN_DESCRIPTION)
        );
        if generated_by_soho && !selected_names.contains(&config.name) {
            db.delete_interface_config(&config.name).await?;
        }
    }
    for range in existing_ranges {
        if range.name.starts_with(SOHO_RANGE_PREFIX)
            && !selected_names.contains(&range.interface)
            && let Some(id) = range.id
        {
            dnsmasq::delete_dhcp_range(db.pool(), id).await?;
        }
    }

    configure_zones(db, &wan.name, &lan_interfaces).await?;
    configure_dnsmasq(db, &wan.name, &lan_interfaces).await?;

    info!(
        wan = %wan.name,
        lan = ?lan_interfaces,
        "Staged basic SOHO router profile"
    );

    Ok(SohoProfileSummary {
        wan_interface: wan.name.clone(),
        lan_interfaces,
    })
}

fn validate_assignments(assignments: &[WizardInterfaceAssignment]) -> Result<()> {
    if assignments.is_empty() {
        bail!("No interfaces provided");
    }

    let mut names = HashSet::new();
    for assignment in assignments {
        if assignment.name.is_empty() {
            bail!("Interface name cannot be empty");
        }
        if !names.insert(assignment.name.as_str()) {
            bail!(
                "Interface '{}' was assigned more than once",
                assignment.name
            );
        }
    }

    let wan_count = assignments
        .iter()
        .filter(|assignment| assignment.role == InterfaceRole::WAN)
        .count();
    let lan_count = assignments
        .iter()
        .filter(|assignment| assignment.role == InterfaceRole::LAN)
        .count();

    if wan_count != 1 {
        bail!("The basic SOHO profile requires exactly one WAN interface");
    }
    let wan = assignments
        .iter()
        .find(|assignment| assignment.role == InterfaceRole::WAN)
        .expect("validated exactly one WAN");
    if !wan.use_dhcp {
        bail!("The basic SOHO profile requires IPv4 DHCP on the WAN interface");
    }
    if lan_count == 0 {
        bail!("At least one LAN interface is required");
    }

    Ok(())
}

fn create_wan_config(assignment: &WizardInterfaceAssignment) -> InterfaceConfig {
    InterfaceConfig {
        name: assignment.name.clone(),
        role: InterfaceRole::WAN,
        description: Some(SOHO_WAN_DESCRIPTION.to_string()),
        dhcp_mode: DhcpMode::Yes,
        dhcpv4_client: Some(Dhcpv4ClientConfig::default()),
        dhcpv6_client: Some(Dhcpv6ClientConfig {
            use_delegated_prefix: true,
            ..Default::default()
        }),
        ipv6_accept_ra: true,
        ip_forward: IpForwardMode::Yes,
        // nftables is the single owner of source NAT.
        ip_masquerade: IpMasqueradeMode::No,
        ..Default::default()
    }
}

fn create_lan_config(
    assignment: &WizardInterfaceAssignment,
    address: &str,
    wan_interface: &str,
    subnet_id: u64,
) -> InterfaceConfig {
    InterfaceConfig {
        name: assignment.name.clone(),
        role: InterfaceRole::LAN,
        description: Some(SOHO_LAN_DESCRIPTION.to_string()),
        dhcp_mode: DhcpMode::No,
        addresses: vec![StaticAddress {
            address: address.to_string(),
            label: None,
            scope: AddressScope::Global,
        }],
        ipv6_accept_ra: false,
        ipv6_send_ra: true,
        dhcp_prefix_delegation: Some(DhcpPrefixDelegationConfig {
            uplink_interface: Some(wan_interface.to_string()),
            subnet_id: Some(subnet_id),
            announce: true,
        }),
        ip_forward: IpForwardMode::Yes,
        ip_masquerade: IpMasqueradeMode::No,
        ..Default::default()
    }
}

async fn configure_zones(db: &Database, wan: &str, lans: &[String]) -> Result<()> {
    let wan_id = db
        .get_firewall_zone_by_name("wan")
        .await?
        .and_then(|zone| zone.id);
    db.save_firewall_zone(&FirewallZone {
        id: wan_id,
        name: "wan".to_string(),
        description: Some("Internet-facing interfaces".to_string()),
        interfaces: vec![wan.to_string()],
        is_wan: true,
        masquerade_ipv4: true,
        default_input_policy: FirewallPolicy::Drop,
        default_forward_policy: FirewallPolicy::Drop,
    })
    .await?;

    let lan_id = db
        .get_firewall_zone_by_name("lan")
        .await?
        .and_then(|zone| zone.id);
    db.save_firewall_zone(&FirewallZone {
        id: lan_id,
        name: "lan".to_string(),
        description: Some("Trusted local interfaces".to_string()),
        interfaces: lans.to_vec(),
        is_wan: false,
        masquerade_ipv4: false,
        default_input_policy: FirewallPolicy::Accept,
        default_forward_policy: FirewallPolicy::Accept,
    })
    .await?;

    let existing = db
        .get_zone_forwards()
        .await?
        .into_iter()
        .find(|forward| forward.source_zone == "lan" && forward.dest_zone == "wan");
    db.save_zone_forward(&ZoneForwardPolicy {
        id: existing.and_then(|forward| forward.id),
        source_zone: "lan".to_string(),
        dest_zone: "wan".to_string(),
        policy: FirewallAction::Accept,
        enabled: true,
    })
    .await?;

    Ok(())
}

async fn configure_dnsmasq(db: &Database, wan: &str, lans: &[String]) -> Result<()> {
    let mut config = dnsmasq::load_dnsmasq_config(db.pool()).await?;
    config.enabled = true;
    config.listen_interfaces = lans.to_vec();
    config.except_interfaces = vec![wan.to_string()];
    config.no_dhcp_interfaces.clear();
    dnsmasq::save_dnsmasq_config(db.pool(), &config).await?;
    Ok(())
}

fn default_lan_address(index: usize) -> String {
    format!("192.168.{}.1/24", index + 1)
}

fn parse_lan_network(address: &str) -> Result<Ipv4Net> {
    let network: Ipv4Net = address.parse().with_context(|| {
        format!(
            "Invalid LAN IPv4 address '{}'; expected CIDR notation",
            address
        )
    })?;
    if network.prefix_len() >= 31 {
        bail!(
            "LAN subnet {} is too small to provide DHCP service",
            network
        );
    }
    Ok(network)
}

fn create_dhcp_range(
    assignment: &WizardInterfaceAssignment,
    network: Ipv4Net,
    existing_ranges: &[DnsmasqDhcpRange],
) -> Result<DnsmasqDhcpRange> {
    let router = network.addr();
    let (start, end) = select_dhcp_pool(network, router)?;
    if existing_ranges.iter().any(|range| {
        range.interface == assignment.name && !range.name.starts_with(SOHO_RANGE_PREFIX)
    }) {
        bail!(
            "Interface '{}' already has a custom DHCP range; remove it before applying the basic SOHO profile",
            assignment.name
        );
    }
    let existing_id = existing_ranges
        .iter()
        .find(|range| {
            range.interface == assignment.name && range.name.starts_with(SOHO_RANGE_PREFIX)
        })
        .and_then(|range| range.id);

    Ok(DnsmasqDhcpRange {
        id: existing_id,
        name: format!("{}{})", SOHO_RANGE_PREFIX, assignment.name),
        interface: assignment.name.clone(),
        start_address: start.to_string(),
        end_address: end.to_string(),
        netmask: Some(network.netmask().to_string()),
        lease_time: "12h".to_string(),
        enabled: true,
        // systemd-networkd owns delegated-prefix assignment and RAs.
        ipv6_mode: None,
        ipv6_prefix: None,
    })
}

fn select_dhcp_pool(network: Ipv4Net, router: Ipv4Addr) -> Result<(Ipv4Addr, Ipv4Addr)> {
    let network_address = u32::from(network.network());
    let broadcast = u32::from(network.broadcast());
    let router = u32::from(router);
    let first = network_address + 1;
    let last = broadcast - 1;

    if router < first || router > last {
        bail!("Router address is not a usable host in {}", network);
    }

    let left = router.saturating_sub(first);
    let right = last.saturating_sub(router);
    let (segment_start, segment_end) = if right >= left && router < last {
        (router + 1, last)
    } else if router > first {
        (first, router - 1)
    } else {
        bail!("LAN subnet {} has no addresses available for DHCP", network);
    };

    let preferred = network_address.saturating_add(100);
    let start = if preferred >= segment_start && preferred <= segment_end {
        preferred
    } else {
        segment_start
    };
    let end = start.saturating_add(99).min(segment_end);

    if end.saturating_sub(start) < 3 {
        bail!(
            "LAN subnet {} has fewer than four DHCP addresses available",
            network
        );
    }

    Ok((Ipv4Addr::from(start), Ipv4Addr::from(end)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pool_is_conventional_for_slash_24() {
        let network: Ipv4Net = "192.168.1.1/24".parse().unwrap();
        let (start, end) = select_dhcp_pool(network, network.addr()).unwrap();
        assert_eq!(start, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(end, Ipv4Addr::new(192, 168, 1, 199));
    }

    #[test]
    fn pool_avoids_router_in_middle_of_subnet() {
        let network: Ipv4Net = "10.0.0.128/24".parse().unwrap();
        let (start, end) = select_dhcp_pool(network, network.addr()).unwrap();
        assert!(start > network.addr() || end < network.addr());
    }

    #[test]
    fn profile_requires_exactly_one_wan() {
        let assignments = vec![WizardInterfaceAssignment {
            name: "lan0".to_string(),
            role: InterfaceRole::LAN,
            use_dhcp: false,
            static_ip: None,
        }];
        assert!(validate_assignments(&assignments).is_err());
    }

    #[test]
    fn lan_config_consumes_delegated_prefix() {
        let assignment = WizardInterfaceAssignment {
            name: "lan0".to_string(),
            role: InterfaceRole::LAN,
            use_dhcp: false,
            static_ip: None,
        };
        let config = create_lan_config(&assignment, "192.168.1.1/24", "wan0", 2);
        assert!(config.ipv6_send_ra);
        let pd = config.dhcp_prefix_delegation.unwrap();
        assert_eq!(pd.uplink_interface.as_deref(), Some("wan0"));
        assert_eq!(pd.subnet_id, Some(2));
    }

    #[tokio::test]
    async fn complete_profile_is_persisted_from_fresh_migrations() {
        let db = Database::new_in_memory().await.unwrap();
        let assignments = vec![
            WizardInterfaceAssignment {
                name: "wan0".to_string(),
                role: InterfaceRole::WAN,
                use_dhcp: true,
                static_ip: None,
            },
            WizardInterfaceAssignment {
                name: "lan0".to_string(),
                role: InterfaceRole::LAN,
                use_dhcp: false,
                static_ip: None,
            },
        ];

        configure_soho_profile(&db, &assignments).await.unwrap();

        let wan = db.get_interface_config("wan0").await.unwrap().unwrap();
        assert_eq!(wan.dhcp_mode, DhcpMode::Yes);
        assert!(wan.dhcpv6_client.unwrap().use_delegated_prefix);

        let lan = db.get_interface_config("lan0").await.unwrap().unwrap();
        assert_eq!(lan.addresses[0].address, "192.168.1.1/24");
        assert!(lan.ipv6_send_ra);
        assert_eq!(
            lan.dhcp_prefix_delegation
                .as_ref()
                .and_then(|config| config.uplink_interface.as_deref()),
            Some("wan0")
        );
        let network_file = crate::networkd::generate_network_file(&lan);
        assert!(network_file.contains("IPv6SendRA=yes"));
        assert!(network_file.contains("DHCPPrefixDelegation=yes"));
        assert!(network_file.contains("UplinkInterface=wan0"));

        let zones = db.get_firewall_zones().await.unwrap();
        let wan_zone = zones.iter().find(|zone| zone.name == "wan").unwrap();
        assert!(wan_zone.is_wan);
        assert!(wan_zone.masquerade_ipv4);
        assert_eq!(wan_zone.interfaces, vec!["wan0"]);
        let lan_zone = zones.iter().find(|zone| zone.name == "lan").unwrap();
        assert_eq!(lan_zone.interfaces, vec!["lan0"]);

        let ranges = dnsmasq::load_dhcp_ranges(db.pool()).await.unwrap();
        let range = ranges
            .iter()
            .find(|range| range.interface == "lan0")
            .unwrap();
        assert_eq!(range.start_address, "192.168.1.100");
        assert_eq!(range.end_address, "192.168.1.199");

        let dnsmasq_config = dnsmasq::load_dnsmasq_config(db.pool()).await.unwrap();
        assert_eq!(dnsmasq_config.listen_interfaces, vec!["lan0"]);
        assert_eq!(dnsmasq_config.except_interfaces, vec!["wan0"]);
    }

    #[tokio::test]
    async fn firewall_snapshots_distinguish_confirmed_and_absent_rulesets() {
        let db = Database::new_in_memory().await.unwrap();
        let config = db.get_firewall_config().await.unwrap();

        assert!(db.get_active_firewall_config().await.unwrap().is_none());
        db.save_active_firewall_config(&config).await.unwrap();
        assert_eq!(
            db.get_active_firewall_config().await.unwrap(),
            Some(config.clone())
        );

        db.save_rollback_state(None, 42).await.unwrap();
        assert_eq!(db.get_rollback_state().await.unwrap(), Some((None, 42)));

        db.save_rollback_state(Some(&config), 43).await.unwrap();
        assert_eq!(
            db.get_rollback_state().await.unwrap(),
            Some((Some(config), 43))
        );
    }

    #[tokio::test]
    async fn rerunning_profile_replaces_only_prior_soho_entries() {
        let db = Database::new_in_memory().await.unwrap();
        db.save_interface_config(&InterfaceConfig {
            name: "manual0".to_string(),
            description: Some("Manual configuration".to_string()),
            ..Default::default()
        })
        .await
        .unwrap();

        let first = vec![
            WizardInterfaceAssignment {
                name: "wan0".to_string(),
                role: InterfaceRole::WAN,
                use_dhcp: true,
                static_ip: None,
            },
            WizardInterfaceAssignment {
                name: "lan0".to_string(),
                role: InterfaceRole::LAN,
                use_dhcp: false,
                static_ip: None,
            },
        ];
        configure_soho_profile(&db, &first).await.unwrap();

        let second = vec![
            WizardInterfaceAssignment {
                name: "wan1".to_string(),
                role: InterfaceRole::WAN,
                use_dhcp: true,
                static_ip: None,
            },
            WizardInterfaceAssignment {
                name: "lan1".to_string(),
                role: InterfaceRole::LAN,
                use_dhcp: false,
                static_ip: None,
            },
        ];
        configure_soho_profile(&db, &second).await.unwrap();

        assert!(db.get_interface_config("wan0").await.unwrap().is_none());
        assert!(db.get_interface_config("lan0").await.unwrap().is_none());
        assert!(db.get_interface_config("wan1").await.unwrap().is_some());
        assert!(db.get_interface_config("lan1").await.unwrap().is_some());
        assert!(db.get_interface_config("manual0").await.unwrap().is_some());

        let ranges = dnsmasq::load_dhcp_ranges(db.pool()).await.unwrap();
        assert!(ranges.iter().all(|range| range.interface != "lan0"));
        assert!(ranges.iter().any(|range| range.interface == "lan1"));
    }

    #[tokio::test]
    async fn invalid_profile_does_not_partially_write_interfaces() {
        let db = Database::new_in_memory().await.unwrap();
        let assignments = vec![
            WizardInterfaceAssignment {
                name: "wan0".to_string(),
                role: InterfaceRole::WAN,
                use_dhcp: true,
                static_ip: None,
            },
            WizardInterfaceAssignment {
                name: "lan0".to_string(),
                role: InterfaceRole::LAN,
                use_dhcp: false,
                static_ip: Some("192.168.1.1/24".to_string()),
            },
            WizardInterfaceAssignment {
                name: "lan1".to_string(),
                role: InterfaceRole::LAN,
                use_dhcp: false,
                static_ip: Some("192.168.1.2/24".to_string()),
            },
        ];

        assert!(configure_soho_profile(&db, &assignments).await.is_err());
        assert!(db.get_interface_configs().await.unwrap().is_empty());
    }
}
