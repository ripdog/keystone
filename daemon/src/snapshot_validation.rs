//! Semantic validation of a complete configuration.
//!
//! Configuration normally reaches the database through save endpoints that
//! validate each setting as it is written. Snapshots bypass those endpoints: an
//! uploaded or hand-edited file can hold any row at all. [`validate_configuration`]
//! therefore re-runs the checks that the save and apply paths rely on, over the
//! typed configuration a snapshot would put back, and scans every configuration
//! table for control characters.
//!
//! It is semantic only. It never runs `dnsmasq --test` or `caddy validate`,
//! which need system state; those still run when a configuration is applied.

use std::collections::BTreeSet;

use anyhow::{Result, ensure};
use keystone_core::changes::Component;
use keystone_core::validation::interface_name;
use sqlx::{Row, SqlitePool};

use crate::blocky;
use crate::caddy;
use crate::config_validation;
use crate::db::Database;
use crate::dnsmasq;
use crate::firewall::validate::validate_firewall_definitions;
use crate::networkd::{validate_bridge_fields, validate_topology, validate_vlan_fields};
use crate::snapshots::{CONFIG_TABLES, component_of};
use crate::upnp;
use crate::wireless;

/// Every semantic error in the configuration the database holds, each prefixed
/// with the component it belongs to. An empty result means the configuration
/// is one the save endpoints would accept.
pub async fn validate_configuration(db: &Database) -> Vec<String> {
    let mut errors = Vec::new();
    match control_character_errors(db.pool()).await {
        Ok(found) => errors.extend(found),
        Err(error) => errors.push(format!(
            "configuration: could not scan for control characters: {error:#}"
        )),
    }
    errors.extend(networkd_errors(db).await);
    errors.extend(firewall_errors(db).await);
    errors.extend(upnp_errors(db).await);
    errors.extend(blocky_errors(db).await);
    errors.extend(wireless_errors(db).await);
    errors.extend(dnsmasq_errors(db).await);
    errors.extend(caddy_errors(db).await);
    errors
}

fn prefixed(component: Component, errors: Vec<String>) -> Vec<String> {
    errors
        .into_iter()
        .map(|error| format!("{component}: {error}"))
        .collect()
}

fn load_failure(component: Component, what: &str, error: anyhow::Error) -> Vec<String> {
    vec![format!("{component}: could not load {what}: {error:#}")]
}

fn name_error(name: &str) -> Option<String> {
    interface_name(name).err()
}

async fn networkd_errors(db: &Database) -> Vec<String> {
    const C: Component = Component::Networkd;
    let managed = match db.get_managed_interfaces().await {
        Ok(rows) => rows,
        Err(error) => return load_failure(C, "managed interfaces", error),
    };
    let configs = match db.get_interface_configs().await {
        Ok(rows) => rows,
        Err(error) => return load_failure(C, "interface configuration", error),
    };
    let vlans = match db.get_all_vlans().await {
        Ok(rows) => rows,
        Err(error) => return load_failure(C, "VLANs", error),
    };
    let bridges = match db.get_all_bridges().await {
        Ok(rows) => rows,
        Err(error) => return load_failure(C, "bridges", error),
    };

    let mut errors = Vec::new();
    errors.extend(managed.iter().filter_map(|i| name_error(&i.name)));
    for config in &configs {
        errors.extend(config_validation::validate_interface_config(config));
        errors.extend(name_error(&config.name));
        errors.extend(config.vlans.iter().filter_map(|name| name_error(name)));
    }
    errors.extend(validate_topology(&configs, &vlans, &bridges));
    for vlan in &vlans {
        errors.extend(validate_vlan_fields(vlan));
        errors.extend(name_error(&vlan.name));
        errors.extend(name_error(&vlan.parent_interface));
    }
    for bridge in &bridges {
        errors.extend(validate_bridge_fields(bridge));
        errors.extend(name_error(&bridge.name));
        errors.extend(bridge.members.iter().filter_map(|m| name_error(m)));
    }
    prefixed(C, errors)
}

async fn firewall_errors(db: &Database) -> Vec<String> {
    match db.get_firewall_config().await {
        Ok(config) => prefixed(Component::Firewall, validate_firewall_definitions(&config)),
        Err(error) => load_failure(Component::Firewall, "firewall configuration", error),
    }
}

async fn upnp_errors(db: &Database) -> Vec<String> {
    const C: Component = Component::Upnp;
    let config = match upnp::load_upnp_config(db.pool()).await {
        Ok(config) => config,
        Err(error) => return load_failure(C, "UPnP configuration", error),
    };
    let (lan, wan) = match upnp::interface_candidates(db).await {
        Ok(candidates) => candidates,
        Err(error) => return load_failure(C, "interface configuration", error),
    };
    match upnp::config::validate_config(&config, &lan, &wan) {
        Ok(()) => Vec::new(),
        Err(error) => prefixed(C, vec![error]),
    }
}

async fn wireless_errors(db: &Database) -> Vec<String> {
    const C: Component = Component::Wireless;
    let config = match wireless::load_wireless_config(db.pool()).await {
        Ok(config) => config,
        Err(error) => return load_failure(C, "wireless configuration", error),
    };
    let bridges = match wireless::bridge_candidates(db).await {
        Ok(bridges) => bridges,
        Err(error) => return load_failure(C, "bridge configuration", error),
    };
    match config.validate(&bridges) {
        Ok(()) => Vec::new(),
        Err(error) => prefixed(C, vec![error]),
    }
}

async fn blocky_errors(db: &Database) -> Vec<String> {
    const C: Component = Component::Blocky;
    let config = match blocky::load_blocky_config(db.pool()).await {
        Ok(config) => config,
        Err(error) => return load_failure(C, "DNS filtering configuration", error),
    };
    let mut errors = match blocky::config::validate_config(&config) {
        Ok(()) => Vec::new(),
        Err(error) => prefixed(C, vec![error]),
    };
    // A restored snapshot must not leave dnsmasq pointing at a disabled Blocky.
    let dnsmasq = match dnsmasq::load_dnsmasq_state(db.pool()).await {
        Ok(state) => state,
        Err(error) => return load_failure(C, "DNS and DHCP configuration", error),
    };
    errors.extend(prefixed(
        C,
        blocky::config::dnsmasq_link_errors(&dnsmasq.config, config.enabled),
    ));
    errors
}

async fn dnsmasq_errors(db: &Database) -> Vec<String> {
    const C: Component = Component::Dnsmasq;
    let state = match dnsmasq::load_dnsmasq_state(db.pool()).await {
        Ok(state) => state,
        Err(error) => return load_failure(C, "DNS and DHCP configuration", error),
    };
    let configs = match db.get_interface_configs().await {
        Ok(rows) => rows,
        Err(error) => return load_failure(C, "interface configuration", error),
    };

    let mut errors = config_validation::validate_dnsmasq_config(&state.config);
    let lists = [
        &state.config.listen_interfaces,
        &state.config.except_interfaces,
        &state.config.no_dhcp_interfaces,
    ];
    for name in lists.into_iter().flatten() {
        errors.extend(name_error(name));
    }
    for range in &state.dhcp_ranges {
        errors.extend(name_error(&range.interface));
    }
    errors.extend(config_validation::validate_dhcp_state(
        &state.dhcp_ranges,
        &state.static_leases,
        &configs,
    ));

    for option in &state.dhcp_options {
        errors.extend(config_validation::validate_dhcp_option(option));
    }
    for record in &state.host_records {
        errors.extend(config_validation::validate_host_record(record));
    }
    for record in &state.cname_records {
        errors.extend(config_validation::validate_cname_record(record));
    }
    for entry in &state.address_overrides {
        errors.extend(config_validation::validate_address_override(entry));
    }
    prefixed(C, errors)
}

async fn caddy_errors(db: &Database) -> Vec<String> {
    let config = match caddy::load_caddy_config(db.pool()).await {
        Ok(config) => config,
        Err(error) => return load_failure(Component::Caddy, "Caddy configuration", error),
    };
    // Disabled configuration is never written to the Caddyfile. The SSH port
    // is not passed in: it is system state, not part of the configuration.
    if !config.enabled {
        return Vec::new();
    }
    match caddy::validate_settings(&config, None) {
        Ok(()) => Vec::new(),
        Err(error) => prefixed(Component::Caddy, vec![format!("{error:#}")]),
    }
}

/// Columns whose text may span several lines. The Caddy custom TLS block is
/// the only one: it is validated against an allowlist before it is written.
fn may_span_lines(table: &str, column: &str) -> bool {
    table == "caddy_config" && column == "custom_tls_config"
}

fn has_control_character(text: &str, multi_line: bool) -> bool {
    text.chars().any(|c| {
        let control = c.is_control() || c == '\u{2028}' || c == '\u{2029}';
        control && !(multi_line && matches!(c, '\n' | '\r' | '\t'))
    })
}

/// Every text value in every configuration table, checked for control
/// characters. This is the shared check behind every generated file: a value
/// that would break a line of dnsmasq, networkd, nftables or Caddy config is
/// rejected here wherever it is stored.
async fn control_character_errors(pool: &SqlitePool) -> Result<Vec<String>> {
    let mut errors = Vec::new();
    for table in CONFIG_TABLES {
        let component = component_of(table).map_or_else(
            || "configuration".to_owned(),
            |component| component.to_string(),
        );
        let columns: Vec<String> = sqlx::query_scalar("SELECT name FROM pragma_table_info(?)")
            .bind(*table)
            .fetch_all(pool)
            .await?;
        if columns.is_empty() {
            continue;
        }
        ensure!(
            columns.iter().all(|column| !column.contains('"')),
            "unsupported column name in {table}"
        );
        // Casting to BLOB reads the exact stored bytes, and never fails on text
        // that is not valid UTF-8.
        let select = columns
            .iter()
            .map(|column| format!("CAST(\"{column}\" AS BLOB)"))
            .collect::<Vec<_>>()
            .join(", ");
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!("SELECT {select} FROM {table}")))
            .fetch_all(pool)
            .await?;

        let mut bad_columns = BTreeSet::new();
        for row in &rows {
            for (index, column) in columns.iter().enumerate() {
                let value: Option<Vec<u8>> = row.try_get(index)?;
                let Some(bytes) = value else { continue };
                let text = String::from_utf8_lossy(&bytes);
                if has_control_character(&text, may_span_lines(table, column)) {
                    bad_columns.insert(column.as_str());
                }
            }
        }
        for column in bad_columns {
            errors.push(format!(
                "{component}: {table}.{column} contains control characters"
            ));
        }
    }
    Ok(errors)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use keystone_core::{
        CaddyConfig, DhcpMode, DnsmasqAddressAction, DnsmasqAddressOverride, DnsmasqCnameRecord,
        DnsmasqDhcpRange, DnsmasqHostRecord, DnsmasqStaticLease, FirewallZone, InputRule,
        InterfaceConfig, InterfaceRole, RuleProtocol, StaticAddress,
    };

    /// Save a configuration spanning every component through the same
    /// functions the save endpoints use. Every row is valid.
    pub(crate) async fn populate_valid_configuration(db: &Database) {
        db.save_interface_config(&InterfaceConfig {
            name: "wan0".into(),
            role: InterfaceRole::WAN,
            enabled: true,
            dhcp_mode: DhcpMode::Ipv4,
            ..Default::default()
        })
        .await
        .unwrap();
        db.save_interface_config(&InterfaceConfig {
            name: "lan0".into(),
            role: InterfaceRole::LAN,
            enabled: true,
            addresses: vec![StaticAddress {
                address: "192.168.50.1/24".into(),
                label: None,
                scope: Default::default(),
            }],
            ..Default::default()
        })
        .await
        .unwrap();
        db.save_firewall_zone(&FirewallZone {
            name: "office".into(),
            interfaces: vec!["lan0".into()],
            ..Default::default()
        })
        .await
        .unwrap();
        db.save_input_rule(&InputRule {
            name: "allow ssh".into(),
            enabled: true,
            zone: Some("office".into()),
            protocol: Some(RuleProtocol::Tcp),
            port_start: Some(22),
            ..Default::default()
        })
        .await
        .unwrap();

        let pool = db.pool();
        dnsmasq::save_dhcp_range(
            pool,
            &DnsmasqDhcpRange {
                name: "lan-pool".into(),
                interface: "lan0".into(),
                start_address: "192.168.50.100".into(),
                end_address: "192.168.50.200".into(),
                lease_time: "12h".into(),
                enabled: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        dnsmasq::save_static_lease(
            pool,
            &DnsmasqStaticLease {
                mac_address: "00:11:22:33:44:55".into(),
                ip_address: "192.168.50.30".into(),
                enabled: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        dnsmasq::save_host_record(
            pool,
            &DnsmasqHostRecord {
                hostnames: vec!["nas.lan.example".into()],
                ipv4_address: Some("192.168.50.20".into()),
                enabled: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        dnsmasq::save_cname_record(
            pool,
            &DnsmasqCnameRecord {
                alias: "files.lan.example".into(),
                target: "nas.lan.example".into(),
                enabled: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        dnsmasq::save_address_override(
            pool,
            &DnsmasqAddressOverride {
                domain: "*.ads.example".into(),
                action: DnsmasqAddressAction::Block,
                enabled: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        // Disabled, so the populated configuration does not depend on the
        // system's SSH port.
        crate::caddy::save_caddy_config(
            pool,
            &CaddyConfig {
                enabled: false,
                server_address: "router.lan.example".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }

    async fn tamper(db: &Database, sql: &str) {
        sqlx::query(sqlx::AssertSqlSafe(sql.to_owned()))
            .execute(db.pool())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn empty_configuration_is_valid() {
        let db = Database::new_in_memory().await.unwrap();
        assert!(validate_configuration(&db).await.is_empty());
    }

    #[tokio::test]
    async fn valid_configuration_across_components_has_no_errors() {
        let db = Database::new_in_memory().await.unwrap();
        populate_valid_configuration(&db).await;
        let errors = validate_configuration(&db).await;
        assert!(errors.is_empty(), "{errors:#?}");
    }

    #[tokio::test]
    async fn tampered_rows_are_reported_under_their_component() {
        // (tampering SQL, component prefix, text that must appear)
        let cases = [
            (
                "UPDATE dnsmasq_host_record_names SET hostname = 'nas.example' || char(10) || 'dhcp-script=/bin/sh'",
                "dnsmasq: ",
                "control characters",
            ),
            (
                "UPDATE dnsmasq_host_records SET ipv4_address = '192.168.50.256'",
                "dnsmasq: ",
                "not a valid IPv4 address",
            ),
            (
                "UPDATE dnsmasq_static_leases SET mac_address = '00:11:22:33:44,55'",
                "dnsmasq: ",
                "not a valid MAC address",
            ),
            (
                "UPDATE interface_config SET description = 'uplink' || char(10) || 'Table=1'",
                "networkd: ",
                "control characters",
            ),
            (
                "UPDATE interface_config SET mtu = 40 WHERE interface_name = 'lan0'",
                "networkd: ",
                "MTU 40",
            ),
            (
                "UPDATE firewall_input_rules SET name = 'ssh' || char(10) || 'accept'",
                "firewall: ",
                "control characters",
            ),
            (
                "UPDATE caddy_config SET enabled = 1, server_address = 'router.example' || char(10) || 'other.example'",
                "caddy: ",
                "control characters",
            ),
        ];
        for (sql, component, needle) in cases {
            let db = Database::new_in_memory().await.unwrap();
            populate_valid_configuration(&db).await;
            tamper(&db, sql).await;
            let errors = validate_configuration(&db).await;
            assert!(
                errors
                    .iter()
                    .any(|e| e.starts_with(component) && e.contains(needle)),
                "{sql}: expected a {component}{needle:?} error, got {errors:#?}"
            );
        }
    }

    #[tokio::test]
    async fn caddy_custom_tls_block_may_span_lines() {
        let db = Database::new_in_memory().await.unwrap();
        populate_valid_configuration(&db).await;
        tamper(
            &db,
            "UPDATE caddy_config SET custom_tls_config = \
             'tls {' || char(10) || '    dns cloudflare {env.CF_API_TOKEN}' || char(10) || '}'",
        )
        .await;
        let errors = validate_configuration(&db).await;
        assert!(errors.is_empty(), "{errors:#?}");

        // The same newline anywhere else is still refused.
        tamper(
            &db,
            "UPDATE caddy_config SET custom_tls_config = 'tls' || char(7) || 'x'",
        )
        .await;
        let errors = validate_configuration(&db).await;
        assert!(
            errors
                .iter()
                .any(|e| e.contains("caddy_config.custom_tls_config contains control")),
            "{errors:#?}"
        );
    }

    #[tokio::test]
    async fn save_paths_refuse_control_characters() {
        let db = Database::new_in_memory().await.unwrap();

        // dnsmasq: the host record name would become a second directive.
        let record = DnsmasqHostRecord {
            hostnames: vec!["nas.example\ndhcp-script=/bin/sh".into()],
            ipv4_address: Some("192.168.50.20".into()),
            enabled: true,
            ..Default::default()
        };
        assert!(
            !config_validation::validate_host_record(&record).is_empty(),
            "the API check must refuse the record"
        );
        assert!(
            dnsmasq::save_host_record(db.pool(), &record).await.is_err(),
            "the storage layer must refuse the record"
        );

        // networkd: a newline in a description ends up as a generated line.
        let interface = InterfaceConfig {
            name: "lan0".into(),
            role: InterfaceRole::LAN,
            enabled: true,
            description: Some("office\nAddress=10.0.0.1/8".into()),
            ..Default::default()
        };
        assert!(db.save_interface_config(&interface).await.is_err());

        // firewall: a rule name is written into generated rules and logs.
        let rule = InputRule {
            name: "ssh\naccept".into(),
            enabled: true,
            protocol: Some(RuleProtocol::Tcp),
            port_start: Some(22),
            ..Default::default()
        };
        assert!(
            !validate_firewall_definitions(&keystone_core::FirewallConfig {
                input_rules: vec![rule],
                ..Default::default()
            })
            .is_empty()
        );
    }
}
