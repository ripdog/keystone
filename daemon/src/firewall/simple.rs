//! Convenience WAN exposures. The source of truth remains the regular forward-rule
//! and DNAT tables: there is deliberately no separate "simple forwards" table.
use super::routes::FirewallState;
use crate::AppError;
use axum::{
    Json,
    extract::{Path, State},
};
use keystone_core::{
    CreateSimplePortForwardRequest, DeleteResponse, FirewallAction, FirewallConfig, InterfaceRole,
    LanDevice, LanDevicesResponse, RuleProtocol, SimplePortForward, SimplePortForwardsResponse,
};
use std::{
    collections::{BTreeMap, HashSet},
    net::{IpAddr, Ipv4Addr},
};
use tokio::process::Command;

fn protocols_match(a: RuleProtocol, b: RuleProtocol) -> bool {
    a == b
        || (a == RuleProtocol::TcpUdp && matches!(b, RuleProtocol::Tcp | RuleProtocol::Udp))
        || (b == RuleProtocol::TcpUdp && matches!(a, RuleProtocol::Tcp | RuleProtocol::Udp))
}

fn effective_protocol(a: RuleProtocol, b: RuleProtocol) -> RuleProtocol {
    if a == RuleProtocol::TcpUdp { b } else { a }
}

/// Derive the displayed list from WAN-initiated ACCEPT rules, not NAT entries.
/// For IPv4 a matching DNAT entry must exist. IPv6 is routed, without NAT.
pub fn derive_forwards(config: &FirewallConfig) -> Vec<SimplePortForward> {
    let wan: HashSet<&str> = config
        .zones
        .iter()
        .filter(|z| z.is_wan)
        .map(|z| z.name.as_str())
        .collect();
    let mut result = Vec::new();
    for rule in &config.forward_rules {
        if rule.action != FirewallAction::Accept
            || wan.is_empty()
            || !rule.source_zone.as_deref().is_none_or(|z| wan.contains(z))
            || !rule.dest_zone.as_deref().is_none_or(|z| !wan.contains(z))
            || rule.dest_port_end.is_some()
        {
            continue;
        }
        let (Some(rule_id), Some(addr), Some(dest_port), Some(proto)) = (
            rule.id,
            rule.dest_ip.as_ref(),
            rule.dest_port_start,
            rule.protocol,
        ) else {
            continue;
        };
        if !matches!(
            proto,
            RuleProtocol::Tcp | RuleProtocol::Udp | RuleProtocol::TcpUdp
        ) {
            continue;
        }
        let Ok(ip) = addr.parse::<IpAddr>() else {
            continue;
        };
        match ip {
            IpAddr::V6(_) => result.push(SimplePortForward {
                rule_id,
                nat_id: None,
                name: rule.name.clone(),
                protocol: proto,
                external_port: dest_port,
                destination: addr.clone(),
                destination_port: dest_port,
                source_ip: rule.source_ip.clone(),
                enabled: rule.enabled,
            }),
            IpAddr::V4(_) => {
                for nat in &config.port_forwards {
                    if nat.dest_ip != *addr
                        || nat.dest_port.unwrap_or(nat.external_port_start) != dest_port
                        || !protocols_match(proto, nat.protocol)
                        || !nat.source_zone.as_deref().is_none_or(|z| wan.contains(z))
                        || !match (rule.source_zone.as_deref(), nat.source_zone.as_deref()) {
                            (Some(a), Some(b)) => a == b,
                            _ => true,
                        }
                        || !match (rule.source_ip.as_deref(), nat.source_ip.as_deref()) {
                            (Some(a), Some(b)) => a == b,
                            _ => true,
                        }
                        || nat.external_port_end.is_some()
                    {
                        continue;
                    }
                    result.push(SimplePortForward {
                        rule_id,
                        nat_id: nat.id,
                        name: rule.name.clone(),
                        protocol: effective_protocol(proto, nat.protocol),
                        external_port: nat.external_port_start,
                        destination: addr.clone(),
                        destination_port: dest_port,
                        source_ip: rule.source_ip.clone().or_else(|| nat.source_ip.clone()),
                        enabled: rule.enabled && nat.enabled,
                    });
                }
            }
        }
    }
    result.sort_by(|a, b| {
        (a.destination.as_str(), a.external_port, a.rule_id).cmp(&(
            b.destination.as_str(),
            b.external_port,
            b.rule_id,
        ))
    });
    result
}

fn valid_destination(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            !a.is_unspecified()
                && !a.is_loopback()
                && !a.is_multicast()
                && a != Ipv4Addr::BROADCAST
                && !a.is_link_local()
        }
        IpAddr::V6(a) => {
            !a.is_unspecified()
                && !a.is_loopback()
                && !a.is_multicast()
                && !a.is_unicast_link_local()
        }
    }
}

fn validate(request: &CreateSimplePortForwardRequest) -> Result<Vec<IpAddr>, String> {
    if !request.tcp && !request.udp {
        return Err("Select TCP and/or UDP".into());
    }
    if request.port == 0 || request.destination_port == Some(0) {
        return Err("Ports must be between 1 and 65535".into());
    }
    let mut addresses = Vec::new();
    for (value, is_v4) in [(&request.ipv4, true), (&request.ipv6, false)] {
        if let Some(value) = value.as_ref().filter(|s| !s.trim().is_empty()) {
            let ip: IpAddr = value
                .trim()
                .parse()
                .map_err(|_| format!("Invalid destination address: {value}"))?;
            if ip.is_ipv4() != is_v4 || !valid_destination(ip) {
                return Err(format!("Invalid destination address: {value}"));
            }
            addresses.push(ip);
        }
    }
    if addresses.is_empty() {
        return Err("Select a destination address".into());
    }
    if addresses.iter().any(IpAddr::is_ipv6)
        && request.destination_port.is_some_and(|p| p != request.port)
    {
        return Err("IPv6 is routed, not translated. Destination port must equal the WAN port when selecting IPv6".into());
    }
    Ok(addresses)
}

pub async fn list(
    State(state): State<FirewallState>,
) -> Result<Json<SimplePortForwardsResponse>, AppError> {
    Ok(Json(SimplePortForwardsResponse {
        forwards: derive_forwards(&state.db.get_firewall_config().await?),
    }))
}

pub async fn create(
    State(state): State<FirewallState>,
    Json(req): Json<CreateSimplePortForwardRequest>,
) -> Result<Json<SimplePortForwardsResponse>, AppError> {
    let addresses = validate(&req).map_err(anyhow::Error::msg)?;
    let zones = state.db.get_firewall_zones().await?;
    let wan: Vec<_> = zones
        .iter()
        .filter(|z| z.is_wan && !z.interfaces.is_empty())
        .collect();
    if wan.is_empty() {
        return Err(
            anyhow::anyhow!("Configure a WAN firewall zone with an interface first").into(),
        );
    }

    let protocol = match (req.tcp, req.udp) {
        (true, true) => RuleProtocol::TcpUdp,
        (true, false) => RuleProtocol::Tcp,
        (false, true) => RuleProtocol::Udp,
        _ => unreachable!(),
    };
    // Changes to the NAT and firewall rule tables must commit together.
    let mut tx = state.db.pool().begin().await?;
    for zone in &wan {
        let zone_id = zone.id.expect("persisted firewall zone");
        for ip in &addresses {
            let dest_port = req.destination_port.unwrap_or(req.port);
            let name = format!(
                "{} {}:{} -> {}:{}",
                zone.name, protocol, req.port, ip, dest_port
            );
            // This is the WAN -> host accept rule, evaluated before broad zone policies.
            sqlx::query("INSERT INTO firewall_forward_rules (name, enabled, position, source_zone_id, protocol, dest_port_start, dest_ip, action, log_enabled, created_at, updated_at) VALUES (?, 1, 0, ?, ?, ?, ?, 'accept', 0, strftime('%s','now'), strftime('%s','now'))")
                .bind(&name).bind(zone_id).bind(protocol.to_string()).bind(dest_port as i64)
                .bind(ip.to_string()).execute(&mut *tx).await?;
            if ip.is_ipv4() {
                // nftables sees the translated destination address/port in forward.
                sqlx::query("INSERT INTO firewall_port_forwards (name, enabled, protocol, source_zone_id, external_port_start, dest_ip, dest_port, created_at, updated_at) VALUES (?, 1, ?, ?, ?, ?, ?, strftime('%s','now'), strftime('%s','now'))")
                    .bind(&name).bind(protocol.to_string()).bind(zone_id).bind(req.port as i64)
                    .bind(ip.to_string()).bind(dest_port as i64).execute(&mut *tx).await?;
            }
        }
    }
    tx.commit().await?;
    list(State(state)).await
}

pub async fn remove(
    State(state): State<FirewallState>,
    Path(rule_id): Path<i64>,
) -> Result<Json<DeleteResponse>, AppError> {
    let config = state.db.get_firewall_config().await?;
    let matched: Vec<_> = derive_forwards(&config)
        .into_iter()
        .filter(|f| f.rule_id == rule_id)
        .collect();
    if matched.is_empty() {
        return Ok(Json(DeleteResponse {
            success: false,
            message: "Forward not found".into(),
        }));
    }
    let mut tx = state.db.pool().begin().await?;
    sqlx::query("DELETE FROM firewall_forward_rules WHERE id = ?")
        .bind(rule_id)
        .execute(&mut *tx)
        .await?;
    // A NAT may be shared by several WAN allow rules. Don't remove it if still used.
    let remaining = derive_forwards(&FirewallConfig {
        forward_rules: config
            .forward_rules
            .into_iter()
            .filter(|r| r.id != Some(rule_id))
            .collect(),
        ..config
    });
    for nat_id in matched
        .into_iter()
        .filter_map(|f| f.nat_id)
        .collect::<HashSet<_>>()
    {
        if !remaining.iter().any(|f| f.nat_id == Some(nat_id)) {
            sqlx::query("DELETE FROM firewall_port_forwards WHERE id = ?")
                .bind(nat_id)
                .execute(&mut *tx)
                .await?;
        }
    }
    tx.commit().await?;
    Ok(Json(DeleteResponse {
        success: true,
        message: "Forward deleted".into(),
    }))
}

/// Use the kernel's IPv4/IPv6 neighbour cache, enriched with local DHCP leases.
/// Group by MAC to show both address families for the same LAN host.
pub async fn devices(
    State(state): State<FirewallState>,
) -> Result<Json<LanDevicesResponse>, AppError> {
    let zones = state.db.get_firewall_zones().await?;
    let wan_interfaces: HashSet<_> = zones.iter().filter(|z| z.is_wan)
        .flat_map(|z| z.interfaces.iter().cloned()).collect();
    let mut interfaces: HashSet<_> = zones
        .iter()
        .filter(|z| !z.is_wan)
        .flat_map(|z| z.interfaces.iter().cloned())
        .collect();
    // Also recognise interfaces classified as LAN in the network configuration,
    // including systems without explicit firewall-zone interface assignments.
    for iface in state.db.get_interface_configs().await? {
        if iface.enabled && iface.role == InterfaceRole::LAN {
            interfaces.insert(iface.name);
        }
    }
    interfaces.retain(|name| !wan_interfaces.contains(name));
    let output = Command::new("ip")
        .args(["-j", "neigh", "show"])
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("Cannot inspect neighbour table: {e}"))?;
    if !output.status.success() {
        return Err(anyhow::anyhow!("Failed to inspect LAN neighbours").into());
    }
    let neighbours: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)
        .map_err(|e| anyhow::anyhow!("Cannot parse neighbour table: {e}"))?;
    let mut devices: BTreeMap<String, LanDevice> = BTreeMap::new();
    for neighbour in neighbours {
        let (Some(mac), Some(iface), Some(addr)) = (
            neighbour.get("lladdr").and_then(|s| s.as_str()),
            neighbour.get("dev").and_then(|s| s.as_str()),
            neighbour.get("dst").and_then(|s| s.as_str()),
        ) else {
            continue;
        };
        if !interfaces.contains(iface) || mac == "00:00:00:00:00:00"
            || neighbour.get("state").and_then(|s| s.as_array())
                .is_some_and(|states| states.iter().any(|s| matches!(s.as_str(), Some("FAILED" | "INCOMPLETE"))))
        {
            continue;
        }
        let Ok(ip) = addr.parse::<IpAddr>() else {
            continue;
        };
        let entry = devices
            .entry(mac.to_ascii_lowercase())
            .or_insert_with(|| LanDevice {
                mac: mac.to_ascii_lowercase(),
                hostname: None,
                ipv4: vec![],
                ipv6: vec![],
            });
        match ip {
            IpAddr::V4(_) => {
                if !entry.ipv4.contains(&addr.to_string()) {
                    entry.ipv4.push(addr.into());
                }
            }
            IpAddr::V6(v6) => {
                if !v6.is_unicast_link_local() && !entry.ipv6.contains(&addr.to_string()) {
                    entry.ipv6.push(addr.into());
                }
            }
        }
    }
    if let Ok(leases) = crate::dnsmasq::get_active_leases() {
        for lease in leases {
            let mac = lease.mac_address.to_ascii_lowercase();
            let entry = devices.entry(mac.clone()).or_insert_with(|| LanDevice {
                mac,
                hostname: None,
                ipv4: vec![],
                ipv6: vec![],
            });
            if entry.hostname.is_none() {
                entry.hostname = lease.hostname;
            }
            if let Ok(ip) = lease.ip_address.parse::<IpAddr>() {
                let addresses = if ip.is_ipv4() {
                    &mut entry.ipv4
                } else {
                    &mut entry.ipv6
                };
                if !addresses.contains(&lease.ip_address) {
                    addresses.push(lease.ip_address);
                }
            }
        }
    }
    let mut devices: Vec<_> = devices.into_values().collect();
    for device in &mut devices {
        device.ipv4.sort();
        device.ipv6.sort();
    }
    devices.sort_by(|a, b| {
        a.hostname
            .as_ref()
            .unwrap_or(&a.mac)
            .cmp(b.hostname.as_ref().unwrap_or(&b.mac))
    });
    Ok(Json(LanDevicesResponse { devices }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use keystone_core::{FirewallZone, ForwardRule, PortForward};
    fn config() -> FirewallConfig {
        FirewallConfig {
            zones: vec![FirewallZone {
                name: "internet".into(),
                is_wan: true,
                ..Default::default()
            }],
            ..Default::default()
        }
    }
    #[test]
    fn validates_protocols_and_families() {
        let mut r = CreateSimplePortForwardRequest {
            tcp: true,
            udp: false,
            ipv4: Some("192.168.1.3".into()),
            ipv6: Some("2001:db8::3".into()),
            port: 443,
            destination_port: None,
        };
        assert_eq!(validate(&r).unwrap().len(), 2);
        r.destination_port = Some(8443);
        assert!(validate(&r).is_err());
        r.destination_port = None;
        r.ipv6 = Some("fe80::1".into());
        assert!(validate(&r).is_err());
        r.ipv6 = None;
        r.tcp = false;
        assert!(validate(&r).is_err());
    }
    #[test]
    fn derives_only_reachable_wan_rules() {
        let mut c = config();
        let rule = ForwardRule {
            id: Some(3),
            name: "web".into(),
            source_zone: Some("internet".into()),
            dest_ip: Some("192.168.1.3".into()),
            dest_port_start: Some(80),
            protocol: Some(RuleProtocol::Tcp),
            ..Default::default()
        };
        c.forward_rules.push(rule.clone());
        assert!(derive_forwards(&c).is_empty());
        c.port_forwards.push(PortForward {
            id: Some(8),
            source_zone: Some("internet".into()),
            dest_ip: "192.168.1.3".into(),
            external_port_start: 8080,
            dest_port: Some(80),
            ..Default::default()
        });
        let forwards = derive_forwards(&c);
        assert_eq!(forwards.len(), 1);
        assert_eq!(forwards[0].external_port, 8080);
        assert_eq!(forwards[0].nat_id, Some(8));
        c.forward_rules[0].dest_ip = Some("2001:db8::1".into());
        let forwards = derive_forwards(&c);
        assert_eq!(forwards.len(), 1);
        assert_eq!(forwards[0].nat_id, None);
        c.forward_rules[0].source_zone = Some("lan".into());
        assert!(derive_forwards(&c).is_empty());
    }

    #[tokio::test]
    async fn creates_and_deletes_both_families_atomically() {
        let db = crate::db::Database::new_in_memory().await.unwrap();
        let wan = db.get_firewall_zone_by_name("wan").await.unwrap().unwrap();
        assert!(wan.is_wan);
        sqlx::query("INSERT INTO firewall_zone_interfaces (zone_id, interface_name) VALUES (?, ?)")
            .bind(wan.id.unwrap())
            .bind("eth-wan")
            .execute(db.pool())
            .await
            .unwrap();
        let state = FirewallState {
            db: db.clone(),
            apply_manager: std::sync::Arc::new(super::super::FirewallApplyManager::new(
                std::sync::Arc::new(db.clone()),
            )),
        };
        let request = CreateSimplePortForwardRequest {
            tcp: true,
            udp: true,
            ipv4: Some("192.168.1.40".into()),
            ipv6: Some("2001:db8::40".into()),
            port: 8080,
            destination_port: None,
        };
        let Json(created) = create(State(state.clone()), Json(request))
            .await
            .unwrap_or_else(|e| panic!("{}", e.0));
        assert_eq!(created.forwards.len(), 2);
        assert!(
            created
                .forwards
                .iter()
                .any(|f| f.nat_id.is_some() && f.protocol == RuleProtocol::TcpUdp)
        );
        assert!(
            created
                .forwards
                .iter()
                .any(|f| f.nat_id.is_none() && f.protocol == RuleProtocol::TcpUdp)
        );

        let config = db.get_firewall_config().await.unwrap();
        let json =
            serde_json::to_string(&super::super::generate::generate_ruleset(&config).nftables)
                .unwrap();
        assert!(
            json.contains("ip6"),
            "IPv6 address must generate an ip6 payload match"
        );
        assert!(json.contains("2001:db8::40"));
        assert!(json.contains("192.168.1.40"));

        for f in created.forwards {
            let Json(deleted) = remove(State(state.clone()), Path(f.rule_id))
                .await
                .unwrap_or_else(|e| panic!("{}", e.0));
            assert!(deleted.success);
        }
        assert!(derive_forwards(&db.get_firewall_config().await.unwrap()).is_empty());
        assert!(db.get_port_forwards().await.unwrap().is_empty());
    }
}
