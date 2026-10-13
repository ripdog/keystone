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
    LanDevice, LanDevicesResponse, PortForward, RuleProtocol, SimplePortForward,
    SimplePortForwardsResponse,
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
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

#[derive(Debug, Clone)]
struct EffectiveForward {
    rule_id: i64,
    nat_id: Option<i64>,
    name: String,
    description: Option<String>,
    source_zone: Option<String>,
    protocol: RuleProtocol,
    external_port: u16,
    destination: String,
    destination_port: u16,
    source_ip: Option<String>,
    enabled: bool,
}

/// Discover effective WAN exposures from firewall rules, never from DNAT alone.
/// IPv4 must have a matching DNAT, while IPv6 needs just a forward allow rule.
fn derive_entries(config: &FirewallConfig) -> Vec<EffectiveForward> {
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
        let make_entry =
            |nat_id: Option<i64>, external_port, protocol, source_ip, enabled| EffectiveForward {
                rule_id,
                nat_id,
                name: rule.name.clone(),
                description: rule.description.clone(),
                source_zone: rule.source_zone.clone(),
                protocol,
                external_port,
                destination: addr.clone(),
                destination_port: dest_port,
                source_ip,
                enabled,
            };
        match ip {
            IpAddr::V6(_) => result.push(make_entry(
                None,
                dest_port,
                proto,
                rule.source_ip.clone(),
                rule.enabled,
            )),
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
                    result.push(make_entry(
                        nat.id,
                        nat.external_port_start,
                        effective_protocol(proto, nat.protocol),
                        rule.source_ip.clone().or_else(|| nat.source_ip.clone()),
                        rule.enabled && nat.enabled,
                    ));
                }
            }
        }
    }
    result.sort_by_key(|e| (e.external_port, e.rule_id));
    result
}

/// Original automatically-generated rules encode the same WAN/protocol/port
/// prefix and their respective destination suffixes. Only use that hint when
/// both ends are uniquely compatible; never pair arbitrary same-port rules.
fn legacy_pair_name(entry: &EffectiveForward) -> Option<&str> {
    let (prefix, suffix) = entry.name.split_once(" -> ")?;
    let zone = entry.source_zone.as_deref()?;
    if prefix != format!("{} {}:{}", zone, entry.protocol, entry.external_port)
        || suffix != format!("{}:{}", entry.destination, entry.destination_port)
    {
        return None;
    }
    Some(prefix)
}

fn compatible_pair(
    a: &EffectiveForward,
    b: &EffectiveForward,
    keys: &HashMap<i64, String>,
) -> bool {
    if a.destination
        .parse::<IpAddr>()
        .ok()
        .is_some_and(|ip| ip.is_ipv4())
        == b.destination
            .parse::<IpAddr>()
            .ok()
            .is_some_and(|ip| ip.is_ipv4())
        || a.protocol != b.protocol
        || a.external_port != b.external_port
        || a.destination_port != b.destination_port
        || a.source_zone != b.source_zone
        || a.source_ip != b.source_ip
        || a.enabled != b.enabled
    {
        return false;
    }
    match (keys.get(&a.rule_id), keys.get(&b.rule_id)) {
        (Some(a), Some(b)) => a == b,
        (None, None) => legacy_pair_name(a).is_some() && legacy_pair_name(a) == legacy_pair_name(b),
        _ => false,
    }
}

/// Group only unambiguous one-to-one IPv4/IPv6 counterparts.
fn group_forwards(
    entries: &[EffectiveForward],
    keys: &HashMap<i64, String>,
) -> Vec<SimplePortForward> {
    let mut result = Vec::new();
    let mut used = HashSet::new();
    for (i, entry) in entries.iter().enumerate() {
        if used.contains(&i) {
            continue;
        }
        let candidates: Vec<_> = entries
            .iter()
            .enumerate()
            .filter(|(j, e)| *j != i && !used.contains(j) && compatible_pair(entry, e, keys))
            .map(|(j, _)| j)
            .collect();
        let pair = if candidates.len() == 1 {
            let j = candidates[0];
            (entries
                .iter()
                .enumerate()
                .filter(|(k, e)| {
                    *k != j && !used.contains(k) && compatible_pair(&entries[j], e, keys)
                })
                .count()
                == 1)
                .then_some(j)
        } else {
            None
        };
        used.insert(i);
        if let Some(j) = pair {
            used.insert(j);
        }
        let first_is_v4 = entry
            .destination
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_ipv4());
        let v4 = if first_is_v4 {
            Some(entry)
        } else {
            pair.map(|j| &entries[j])
        };
        let v6 = if first_is_v4 {
            pair.map(|j| &entries[j])
        } else {
            Some(entry)
        };
        result.push(SimplePortForward {
            rule_id: entry.rule_id,
            ipv4_rule_id: v4.map(|e| e.rule_id),
            ipv6_rule_id: v6.map(|e| e.rule_id),
            name: entry.name.clone(),
            description: entry.description.clone(),
            protocol: entry.protocol,
            external_port: entry.external_port,
            destination_port: entry.destination_port,
            ipv4: v4.map(|e| e.destination.clone()),
            ipv6: v6.map(|e| e.destination.clone()),
            source_zone: entry.source_zone.clone(),
            source_ip: entry.source_ip.clone(),
            enabled: entry.enabled,
        });
    }
    result
}

/// Port forward rows that no simple forward is built from. They are still live
/// DNAT, so the UI lists them separately.
fn other_port_forwards(config: &FirewallConfig) -> Vec<PortForward> {
    let linked: HashSet<i64> = derive_entries(config)
        .iter()
        .filter_map(|e| e.nat_id)
        .collect();
    config
        .port_forwards
        .iter()
        .filter(|pf| pf.id.is_none_or(|id| !linked.contains(&id)))
        .cloned()
        .collect()
}

#[cfg(test)]
fn derive_forwards(config: &FirewallConfig) -> Vec<SimplePortForward> {
    group_forwards(&derive_entries(config), &HashMap::new())
}

async fn load_forwards(
    state: &FirewallState,
) -> Result<(FirewallConfig, Vec<SimplePortForward>), AppError> {
    let config = state.db.get_firewall_config().await?;
    let keys: Vec<(i64, String)> = sqlx::query_as(
        "SELECT id, simple_forward_group FROM firewall_forward_rules WHERE simple_forward_group IS NOT NULL"
    ).fetch_all(state.db.pool()).await?;
    let list = group_forwards(&derive_entries(&config), &keys.into_iter().collect());
    Ok((config, list))
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
    let (config, forwards) = load_forwards(&state).await?;
    let other_port_forwards = other_port_forwards(&config);
    Ok(Json(SimplePortForwardsResponse {
        forwards,
        other_port_forwards,
    }))
}

fn protocol_for(req: &CreateSimplePortForwardRequest) -> RuleProtocol {
    match (req.tcp, req.udp) {
        (true, true) => RuleProtocol::TcpUdp,
        (true, false) => RuleProtocol::Tcp,
        (false, true) => RuleProtocol::Udp,
        _ => unreachable!("validated protocol"),
    }
}

fn rule_name(zone: &str, protocol: RuleProtocol, port: u16, ip: IpAddr, dest_port: u16) -> String {
    format!("{zone} {protocol}:{port} -> {ip}:{dest_port}")
}

fn normalize_comment(req: &CreateSimplePortForwardRequest) -> Option<String> {
    req.description
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
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
    let protocol = protocol_for(&req);
    let description = normalize_comment(&req);
    let mut tx = state.db.pool().begin().await?;
    for zone in wan {
        let zone_id = zone.id.expect("persisted firewall zone");
        let pair_key = uuid::Uuid::new_v4().to_string();
        for ip in &addresses {
            let dest_port = req.destination_port.unwrap_or(req.port);
            let name = rule_name(&zone.name, protocol, req.port, *ip, dest_port);
            sqlx::query("INSERT INTO firewall_forward_rules (name, description, simple_forward_group, enabled, position, source_zone_id, protocol, dest_port_start, dest_ip, action, log_enabled, created_at, updated_at) VALUES (?, ?, ?, 1, 0, ?, ?, ?, ?, 'accept', 0, strftime('%s','now'), strftime('%s','now'))")
                .bind(&name).bind(&description).bind(&pair_key).bind(zone_id)
                .bind(protocol.to_string()).bind(dest_port as i64).bind(ip.to_string())
                .execute(&mut *tx).await?;
            if ip.is_ipv4() {
                sqlx::query("INSERT INTO firewall_port_forwards (name, description, enabled, protocol, source_zone_id, external_port_start, dest_ip, dest_port, created_at, updated_at) VALUES (?, ?, 1, ?, ?, ?, ?, ?, strftime('%s','now'), strftime('%s','now'))")
                    .bind(&name).bind(&description).bind(protocol.to_string()).bind(zone_id)
                    .bind(req.port as i64).bind(ip.to_string()).bind(dest_port as i64)
                    .execute(&mut *tx).await?;
            }
        }
    }
    tx.commit().await?;
    list(State(state)).await
}

/// Edit an existing logical forward atomically. The IDs represent ordinary
/// firewall rules; no parallel convenience-rule table exists. Unchanged
/// advanced settings (zone, source restriction, position, logging) survive.
pub async fn update(
    State(state): State<FirewallState>,
    Path(rule_id): Path<i64>,
    Json(req): Json<CreateSimplePortForwardRequest>,
) -> Result<Json<SimplePortForwardsResponse>, AppError> {
    let addresses = validate(&req).map_err(anyhow::Error::msg)?;
    let (config, groups) = load_forwards(&state).await?;
    let current = groups
        .into_iter()
        .find(|f| f.rule_id == rule_id)
        .ok_or_else(|| anyhow::anyhow!("Forward not found"))?;
    let old_ids: HashSet<i64> = [current.ipv4_rule_id, current.ipv6_rule_id]
        .into_iter()
        .flatten()
        .collect();
    let old_nats: HashSet<i64> = derive_entries(&config)
        .into_iter()
        .filter(|e| old_ids.contains(&e.rule_id))
        .filter_map(|e| e.nat_id)
        .collect();
    let old_nat_ids_used_elsewhere: HashSet<i64> = derive_entries(&config)
        .into_iter()
        .filter(|e| !old_ids.contains(&e.rule_id))
        .filter_map(|e| e.nat_id)
        .collect();
    let key: Option<(Option<String>,)> =
        sqlx::query_as("SELECT simple_forward_group FROM firewall_forward_rules WHERE id = ?")
            .bind(rule_id)
            .fetch_optional(state.db.pool())
            .await?;
    let key = key
        .and_then(|(k,)| k)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let protocol = protocol_for(&req);
    let description = normalize_comment(&req);
    let dest_port = req.destination_port.unwrap_or(req.port);
    let mut tx = state.db.pool().begin().await?;

    // Insert a newly selected family while the template rule still exists.
    for ip in &addresses {
        let existing = if ip.is_ipv4() {
            current.ipv4_rule_id
        } else {
            current.ipv6_rule_id
        };
        if existing.is_none() {
            let name = rule_name(
                current.source_zone.as_deref().unwrap_or("WAN"),
                protocol,
                req.port,
                *ip,
                dest_port,
            );
            sqlx::query("INSERT INTO firewall_forward_rules (name, description, simple_forward_group, enabled, position, source_zone_id, dest_zone_id, protocol, dest_port_start, source_ip, dest_ip, action, log_enabled, log_prefix, rate_limit, created_at, updated_at) SELECT ?, ?, ?, enabled, position, source_zone_id, dest_zone_id, ?, ?, source_ip, ?, action, log_enabled, log_prefix, rate_limit, strftime('%s','now'), strftime('%s','now') FROM firewall_forward_rules WHERE id = ?")
                .bind(name).bind(&description).bind(&key).bind(protocol.to_string())
                .bind(dest_port as i64).bind(ip.to_string()).bind(rule_id)
                .execute(&mut *tx).await?;
        }
    }
    // Update or remove original family rules; preserve all other rule options.
    for (old, ip) in [
        (
            current.ipv4_rule_id,
            addresses.iter().find(|ip| ip.is_ipv4()),
        ),
        (
            current.ipv6_rule_id,
            addresses.iter().find(|ip| ip.is_ipv6()),
        ),
    ] {
        let Some(old) = old else { continue };
        if let Some(ip) = ip {
            let name = rule_name(
                current.source_zone.as_deref().unwrap_or("WAN"),
                protocol,
                req.port,
                *ip,
                dest_port,
            );
            sqlx::query("UPDATE firewall_forward_rules SET name = ?, description = ?, simple_forward_group = ?, protocol = ?, dest_port_start = ?, dest_ip = ?, updated_at = strftime('%s','now') WHERE id = ?")
                .bind(name).bind(&description).bind(&key).bind(protocol.to_string())
                .bind(dest_port as i64).bind(ip.to_string()).bind(old)
                .execute(&mut *tx).await?;
        } else {
            sqlx::query("DELETE FROM firewall_forward_rules WHERE id = ?")
                .bind(old)
                .execute(&mut *tx)
                .await?;
        }
    }
    // Preserve the NAT ID when it is exclusively owned by this forward.
    // Shared DNATs must be cloned so editing cannot change someone else's rule.
    let mut retained_nat = None;
    if let Some(ip) = addresses.iter().find(|ip| ip.is_ipv4()) {
        let name = rule_name(
            current.source_zone.as_deref().unwrap_or("WAN"),
            protocol,
            req.port,
            *ip,
            dest_port,
        );
        let nat_template_id = old_nats.iter().next().copied();
        if let Some(nat_id) = nat_template_id
            .filter(|_| old_nats.len() == 1)
            .filter(|id| !old_nat_ids_used_elsewhere.contains(id))
        {
            sqlx::query("UPDATE firewall_port_forwards SET name = ?, description = ?, protocol = ?, external_port_start = ?, dest_ip = ?, dest_port = ?, updated_at = strftime('%s','now') WHERE id = ?")
                .bind(&name).bind(&description).bind(protocol.to_string())
                .bind(req.port as i64).bind(ip.to_string()).bind(dest_port as i64).bind(nat_id)
                .execute(&mut *tx).await?;
            retained_nat = Some(nat_id);
        } else if let Some(nat_id) = nat_template_id {
            sqlx::query("INSERT INTO firewall_port_forwards (name, description, enabled, protocol, source_zone_id, external_port_start, source_ip, dest_ip, dest_port, created_at, updated_at) SELECT ?, ?, enabled, ?, source_zone_id, ?, source_ip, ?, ?, strftime('%s','now'), strftime('%s','now') FROM firewall_port_forwards WHERE id = ?")
                .bind(&name).bind(&description).bind(protocol.to_string())
                .bind(req.port as i64).bind(ip.to_string()).bind(dest_port as i64).bind(nat_id)
                .execute(&mut *tx).await?;
        } else {
            sqlx::query("INSERT INTO firewall_port_forwards (name, description, enabled, protocol, source_zone_id, external_port_start, source_ip, dest_ip, dest_port, created_at, updated_at) SELECT ?, ?, enabled, ?, source_zone_id, ?, source_ip, ?, ?, strftime('%s','now'), strftime('%s','now') FROM firewall_forward_rules WHERE simple_forward_group = ? LIMIT 1")
                .bind(&name).bind(&description).bind(protocol.to_string())
                .bind(req.port as i64).bind(ip.to_string()).bind(dest_port as i64).bind(&key)
                .execute(&mut *tx).await?;
        }
    }
    for nat_id in old_nats.difference(&old_nat_ids_used_elsewhere) {
        if Some(*nat_id) == retained_nat {
            continue;
        }
        sqlx::query("DELETE FROM firewall_port_forwards WHERE id = ?")
            .bind(nat_id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    list(State(state)).await
}

pub async fn remove(
    State(state): State<FirewallState>,
    Path(rule_id): Path<i64>,
) -> Result<Json<DeleteResponse>, AppError> {
    let (config, groups) = load_forwards(&state).await?;
    let Some(group) = groups.into_iter().find(|f| f.rule_id == rule_id) else {
        return Ok(Json(DeleteResponse {
            success: false,
            message: "Forward not found".into(),
        }));
    };
    let ids: HashSet<i64> = [group.ipv4_rule_id, group.ipv6_rule_id]
        .into_iter()
        .flatten()
        .collect();
    let entries = derive_entries(&config);
    let old_nats: HashSet<i64> = entries
        .iter()
        .filter(|e| ids.contains(&e.rule_id))
        .filter_map(|e| e.nat_id)
        .collect();
    let shared: HashSet<i64> = entries
        .iter()
        .filter(|e| !ids.contains(&e.rule_id))
        .filter_map(|e| e.nat_id)
        .collect();
    let mut tx = state.db.pool().begin().await?;
    for id in ids {
        sqlx::query("DELETE FROM firewall_forward_rules WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    for nat_id in old_nats.difference(&shared) {
        sqlx::query("DELETE FROM firewall_port_forwards WHERE id = ?")
            .bind(nat_id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(Json(DeleteResponse {
        success: true,
        message: "Forward deleted".into(),
    }))
}

pub async fn devices(
    State(state): State<FirewallState>,
) -> Result<Json<LanDevicesResponse>, AppError> {
    let zones = state.db.get_firewall_zones().await?;
    let wan_interfaces: HashSet<_> = zones
        .iter()
        .filter(|z| z.is_wan)
        .flat_map(|z| z.interfaces.iter().cloned())
        .collect();
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
        if !interfaces.contains(iface)
            || mac == "00:00:00:00:00:00"
            || neighbour
                .get("state")
                .and_then(|s| s.as_array())
                .is_some_and(|states| {
                    states
                        .iter()
                        .any(|s| matches!(s.as_str(), Some("FAILED" | "INCOMPLETE")))
                })
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
    use keystone_core::{FirewallZone, ForwardRule};
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
            description: None,
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
        assert_eq!(forwards[0].ipv4.as_deref(), Some("192.168.1.3"));
        c.forward_rules[0].dest_ip = Some("2001:db8::1".into());
        let forwards = derive_forwards(&c);
        assert_eq!(forwards.len(), 1);
        assert_eq!(forwards[0].ipv6.as_deref(), Some("2001:db8::1"));
        c.forward_rules[0].source_zone = Some("lan".into());
        assert!(derive_forwards(&c).is_empty());
    }

    #[test]
    fn port_forwards_without_a_simple_group_are_listed_as_other() {
        let mut c = config();
        c.forward_rules.push(ForwardRule {
            id: Some(3),
            name: "web".into(),
            source_zone: Some("internet".into()),
            dest_ip: Some("192.168.1.3".into()),
            dest_port_start: Some(80),
            protocol: Some(RuleProtocol::Tcp),
            ..Default::default()
        });
        // Linked to the forward rule above.
        c.port_forwards.push(PortForward {
            id: Some(8),
            source_zone: Some("internet".into()),
            dest_ip: "192.168.1.3".into(),
            external_port_start: 80,
            dest_port: Some(80),
            ..Default::default()
        });
        // CLI-created: no matching forward accept rule.
        c.port_forwards.push(PortForward {
            id: Some(9),
            name: "cli".into(),
            dest_ip: "192.168.1.9".into(),
            external_port_start: 2222,
            dest_port: Some(22),
            ..Default::default()
        });
        // Range forwards are never part of a simple forward.
        c.port_forwards.push(PortForward {
            id: Some(10),
            name: "range".into(),
            dest_ip: "192.168.1.3".into(),
            external_port_start: 5000,
            external_port_end: Some(5010),
            ..Default::default()
        });
        let other: Vec<_> = other_port_forwards(&c).into_iter().map(|p| p.id).collect();
        assert_eq!(other, vec![Some(9), Some(10)]);
    }

    #[test]
    fn legacy_pairs_are_conservative_and_unambiguous() {
        let mut c = config();
        c.forward_rules.push(ForwardRule {
            id: Some(1),
            name: "internet tcp:80 -> 192.168.1.3:80".into(),
            description: Some("Web".into()),
            source_zone: Some("internet".into()),
            dest_ip: Some("192.168.1.3".into()),
            dest_port_start: Some(80),
            protocol: Some(RuleProtocol::Tcp),
            ..Default::default()
        });
        c.forward_rules.push(ForwardRule {
            id: Some(2),
            name: "internet tcp:80 -> 2001:db8::3:80".into(),
            description: Some("Web".into()),
            source_zone: Some("internet".into()),
            dest_ip: Some("2001:db8::3".into()),
            dest_port_start: Some(80),
            protocol: Some(RuleProtocol::Tcp),
            ..Default::default()
        });
        c.port_forwards.push(PortForward {
            id: Some(3),
            source_zone: Some("internet".into()),
            dest_ip: "192.168.1.3".into(),
            external_port_start: 80,
            dest_port: Some(80),
            ..Default::default()
        });
        let grouped = derive_forwards(&c);
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped[0].ipv4_rule_id, Some(1));
        assert_eq!(grouped[0].ipv6_rule_id, Some(2));
        // A second IPv6 candidate makes the legacy inference ambiguous.
        c.forward_rules.push(ForwardRule {
            id: Some(4),
            name: "internet tcp:80 -> 2001:db8::4:80".into(),
            description: Some("Web".into()),
            source_zone: Some("internet".into()),
            dest_ip: Some("2001:db8::4".into()),
            dest_port_start: Some(80),
            protocol: Some(RuleProtocol::Tcp),
            ..Default::default()
        });
        assert_eq!(derive_forwards(&c).len(), 3);
        // Existing explicit pair metadata takes precedence over naming conventions.
        let keys = HashMap::from([(1, "a".into()), (2, "a".into())]);
        let grouped = group_forwards(&derive_entries(&c), &keys);
        assert_eq!(grouped.len(), 2);
        assert!(grouped.iter().any(|f| f.ipv4.is_some() && f.ipv6.is_some()));
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
            description: Some("Media server".into()),
        };
        let Json(created) = create(State(state.clone()), Json(request))
            .await
            .unwrap_or_else(|e| panic!("{}", e.0));
        assert_eq!(created.forwards.len(), 1);
        let pair = &created.forwards[0];
        assert!(pair.ipv4_rule_id.is_some());
        assert!(pair.ipv6_rule_id.is_some());
        assert_eq!(pair.description.as_deref(), Some("Media server"));
        let rows: Vec<(Option<String>,)> =
            sqlx::query_as("SELECT description FROM firewall_port_forwards")
                .fetch_all(db.pool())
                .await
                .unwrap();
        assert_eq!(rows, vec![(Some("Media server".into()),)]);
        assert!(
            created
                .forwards
                .iter()
                .any(|f| f.ipv4.is_some() && f.protocol == RuleProtocol::TcpUdp)
        );
        assert!(
            created
                .forwards
                .iter()
                .any(|f| f.ipv6.is_some() && f.protocol == RuleProtocol::TcpUdp)
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

        let mut edit = CreateSimplePortForwardRequest {
            tcp: true,
            udp: false,
            ipv4: Some("192.168.1.41".into()),
            ipv6: None,
            port: 8888,
            destination_port: Some(9999),
            description: Some("Updated comment".into()),
        };
        let Json(updated) = update(State(state.clone()), Path(pair.rule_id), Json(edit.clone()))
            .await
            .unwrap_or_else(|e| panic!("{}", e.0));
        assert_eq!(updated.forwards.len(), 1);
        let single = &updated.forwards[0];
        assert_eq!(single.ipv4.as_deref(), Some("192.168.1.41"));
        assert!(single.ipv6.is_none());
        assert_eq!(single.destination_port, 9999);
        assert_eq!(single.description.as_deref(), Some("Updated comment"));
        let nat = db.get_port_forwards().await.unwrap();
        assert_eq!(nat.len(), 1);
        assert_eq!(nat[0].description.as_deref(), Some("Updated comment"));
        assert_eq!(db.get_forward_rules().await.unwrap().len(), 1);
        edit.ipv6 = Some("2001:db8::41".into());
        edit.destination_port = None;
        let Json(updated) = update(State(state.clone()), Path(single.rule_id), Json(edit))
            .await
            .unwrap_or_else(|e| panic!("{}", e.0));
        assert_eq!(updated.forwards.len(), 1);
        assert!(updated.forwards[0].ipv6.is_some());
        assert!(updated.forwards[0].ipv4.is_some());
        assert_eq!(db.get_forward_rules().await.unwrap().len(), 2);
        for f in updated.forwards {
            let Json(deleted) = remove(State(state.clone()), Path(f.rule_id))
                .await
                .unwrap_or_else(|e| panic!("{}", e.0));
            assert!(deleted.success);
        }
        assert!(derive_forwards(&db.get_firewall_config().await.unwrap()).is_empty());
        assert!(db.get_port_forwards().await.unwrap().is_empty());
    }
}
