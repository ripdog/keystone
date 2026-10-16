//! Database operations for dnsmasq configuration

use anyhow::Result;
use keystone_core::{
    DnsmasqAddressAction, DnsmasqAddressOverride, DnsmasqCnameRecord, DnsmasqConfig,
    DnsmasqDhcpOption, DnsmasqDhcpRange, DnsmasqHostRecord, DnsmasqIpv6Mode, DnsmasqStateResponse,
    DnsmasqStaticLease, DnsmasqUpstreamMode, DnsmasqUpstreamServer,
};
use sqlx::{Row, SqlitePool};

/// Load the global dnsmasq configuration from the database
pub async fn load_dnsmasq_config(pool: &SqlitePool) -> Result<DnsmasqConfig> {
    // Load main config
    let row = sqlx::query(
        r#"
        SELECT enabled, dns_port, cache_size, dnssec_enabled, domain_needed, bogus_priv,
               local_domain, expand_hosts, upstream_mode, bind_dynamic, log_queries, log_dhcp
        FROM dnsmasq_config WHERE id = 1
        "#,
    )
    .fetch_optional(pool)
    .await?;

    let config = if let Some(row) = row {
        let upstream_mode_str: String = row.get("upstream_mode");
        let upstream_mode = upstream_mode_str
            .parse()
            .unwrap_or(DnsmasqUpstreamMode::System);

        DnsmasqConfig {
            enabled: row.get::<i32, _>("enabled") != 0,
            dns_port: row.get::<i32, _>("dns_port") as u16,
            cache_size: row.get::<i32, _>("cache_size") as u32,
            dnssec_enabled: row.get::<i32, _>("dnssec_enabled") != 0,
            domain_needed: row.get::<i32, _>("domain_needed") != 0,
            bogus_priv: row.get::<i32, _>("bogus_priv") != 0,
            local_domain: row.get("local_domain"),
            expand_hosts: row.get::<i32, _>("expand_hosts") != 0,
            upstream_mode,
            upstream_servers: Vec::new(),   // Loaded separately
            listen_interfaces: Vec::new(),  // Loaded separately
            except_interfaces: Vec::new(),  // Loaded separately
            no_dhcp_interfaces: Vec::new(), // Loaded separately
            bind_dynamic: row.get::<i32, _>("bind_dynamic") != 0,
            log_queries: row.get::<i32, _>("log_queries") != 0,
            log_dhcp: row.get::<i32, _>("log_dhcp") != 0,
        }
    } else {
        DnsmasqConfig::default()
    };

    // Load upstream servers
    let upstream_servers = load_upstream_servers(pool).await?;

    // Load interface lists
    let listen_interfaces = load_interface_list(pool, InterfaceListTable::Listen).await?;
    let except_interfaces = load_interface_list(pool, InterfaceListTable::Except).await?;
    let no_dhcp_interfaces = load_interface_list(pool, InterfaceListTable::NoDhcp).await?;

    Ok(DnsmasqConfig {
        upstream_servers,
        listen_interfaces,
        except_interfaces,
        no_dhcp_interfaces,
        ..config
    })
}

/// Save the global dnsmasq configuration to the database
pub async fn save_dnsmasq_config(pool: &SqlitePool, config: &DnsmasqConfig) -> Result<()> {
    keystone_core::validation::single_line_fields(config).map_err(anyhow::Error::msg)?;
    // Upsert main config
    sqlx::query(
        r#"
        INSERT OR REPLACE INTO dnsmasq_config 
            (id, enabled, dns_port, cache_size, dnssec_enabled, domain_needed, bogus_priv,
             local_domain, expand_hosts, upstream_mode, bind_dynamic, log_queries, log_dhcp)
        VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(config.enabled as i32)
    .bind(config.dns_port as i32)
    .bind(config.cache_size as i32)
    .bind(config.dnssec_enabled as i32)
    .bind(config.domain_needed as i32)
    .bind(config.bogus_priv as i32)
    .bind(&config.local_domain)
    .bind(config.expand_hosts as i32)
    .bind(config.upstream_mode.to_string())
    .bind(config.bind_dynamic as i32)
    .bind(config.log_queries as i32)
    .bind(config.log_dhcp as i32)
    .execute(pool)
    .await?;

    // Save upstream servers
    save_upstream_servers(pool, &config.upstream_servers).await?;

    // Save interface lists
    save_interface_list(pool, InterfaceListTable::Listen, &config.listen_interfaces).await?;
    save_interface_list(pool, InterfaceListTable::Except, &config.except_interfaces).await?;
    save_interface_list(pool, InterfaceListTable::NoDhcp, &config.no_dhcp_interfaces).await?;

    Ok(())
}

/// Load upstream DNS servers
async fn load_upstream_servers(pool: &SqlitePool) -> Result<Vec<DnsmasqUpstreamServer>> {
    let rows = sqlx::query(
        "SELECT address, port, domain FROM dnsmasq_upstream_servers ORDER BY priority, id",
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| DnsmasqUpstreamServer {
            address: row.get("address"),
            port: row.get::<Option<i32>, _>("port").map(|p| p as u16),
            domain: row.get("domain"),
        })
        .collect())
}

/// Save upstream DNS servers
async fn save_upstream_servers(pool: &SqlitePool, servers: &[DnsmasqUpstreamServer]) -> Result<()> {
    // Clear existing
    sqlx::query("DELETE FROM dnsmasq_upstream_servers")
        .execute(pool)
        .await?;

    // Insert new
    for (priority, server) in servers.iter().enumerate() {
        sqlx::query(
            "INSERT INTO dnsmasq_upstream_servers (address, port, domain, priority) VALUES (?, ?, ?, ?)",
        )
        .bind(&server.address)
        .bind(server.port.map(|p| p as i32))
        .bind(&server.domain)
        .bind(priority as i32)
        .execute(pool)
        .await?;
    }

    Ok(())
}

/// Only these three fixed tables can be used for interface lists.
#[derive(Clone, Copy)]
enum InterfaceListTable {
    Listen,
    Except,
    NoDhcp,
}

impl InterfaceListTable {
    fn select_sql(self) -> &'static str {
        match self {
            Self::Listen => "SELECT interface FROM dnsmasq_listen_interfaces ORDER BY id",
            Self::Except => "SELECT interface FROM dnsmasq_except_interfaces ORDER BY id",
            Self::NoDhcp => "SELECT interface FROM dnsmasq_no_dhcp_interfaces ORDER BY id",
        }
    }

    fn delete_sql(self) -> &'static str {
        match self {
            Self::Listen => "DELETE FROM dnsmasq_listen_interfaces",
            Self::Except => "DELETE FROM dnsmasq_except_interfaces",
            Self::NoDhcp => "DELETE FROM dnsmasq_no_dhcp_interfaces",
        }
    }

    fn insert_sql(self) -> &'static str {
        match self {
            Self::Listen => "INSERT INTO dnsmasq_listen_interfaces (interface) VALUES (?)",
            Self::Except => "INSERT INTO dnsmasq_except_interfaces (interface) VALUES (?)",
            Self::NoDhcp => "INSERT INTO dnsmasq_no_dhcp_interfaces (interface) VALUES (?)",
        }
    }
}

/// Load interface list from one of the supported tables.
async fn load_interface_list(pool: &SqlitePool, table: InterfaceListTable) -> Result<Vec<String>> {
    let rows = sqlx::query(table.select_sql()).fetch_all(pool).await?;
    Ok(rows.into_iter().map(|row| row.get("interface")).collect())
}

/// Save interface list to one of the supported tables.
async fn save_interface_list(
    pool: &SqlitePool,
    table: InterfaceListTable,
    interfaces: &[String],
) -> Result<()> {
    sqlx::query(table.delete_sql()).execute(pool).await?;
    for iface in interfaces {
        sqlx::query(table.insert_sql())
            .bind(iface)
            .execute(pool)
            .await?;
    }
    Ok(())
}

// ============================================================================
// DHCP Ranges
// ============================================================================

/// Load all DHCP ranges from the database
pub async fn load_dhcp_ranges(pool: &SqlitePool) -> Result<Vec<DnsmasqDhcpRange>> {
    let rows = sqlx::query(
        r#"
        SELECT id, name, interface, start_address, end_address, netmask, 
               lease_time, enabled, ipv6_mode, ipv6_prefix
        FROM dnsmasq_dhcp_ranges ORDER BY interface, id
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| {
            let ipv6_mode_str: Option<String> = row.get("ipv6_mode");
            let ipv6_mode = ipv6_mode_str.and_then(|s| s.parse::<DnsmasqIpv6Mode>().ok());

            DnsmasqDhcpRange {
                id: Some(row.get("id")),
                name: row.get("name"),
                interface: row.get("interface"),
                start_address: row.get("start_address"),
                end_address: row.get("end_address"),
                netmask: row.get("netmask"),
                lease_time: row.get("lease_time"),
                enabled: row.get::<i32, _>("enabled") != 0,
                ipv6_mode,
                ipv6_prefix: row.get("ipv6_prefix"),
            }
        })
        .collect())
}

/// Save a DHCP range (insert or update)
pub async fn save_dhcp_range(pool: &SqlitePool, range: &DnsmasqDhcpRange) -> Result<i64> {
    keystone_core::validation::single_line_fields(range).map_err(anyhow::Error::msg)?;
    keystone_core::validation::interface_name(&range.interface).map_err(anyhow::Error::msg)?;
    let ipv6_mode_str = range.ipv6_mode.map(|m| m.to_string());

    if let Some(id) = range.id {
        // Update existing
        sqlx::query(
            r#"
            UPDATE dnsmasq_dhcp_ranges SET
                name = ?, interface = ?, start_address = ?, end_address = ?,
                netmask = ?, lease_time = ?, enabled = ?, ipv6_mode = ?, ipv6_prefix = ?
            WHERE id = ?
            "#,
        )
        .bind(&range.name)
        .bind(&range.interface)
        .bind(&range.start_address)
        .bind(&range.end_address)
        .bind(&range.netmask)
        .bind(&range.lease_time)
        .bind(range.enabled as i32)
        .bind(&ipv6_mode_str)
        .bind(&range.ipv6_prefix)
        .bind(id)
        .execute(pool)
        .await?;
        Ok(id)
    } else {
        // Insert new
        let result = sqlx::query(
            r#"
            INSERT INTO dnsmasq_dhcp_ranges 
                (name, interface, start_address, end_address, netmask, lease_time, enabled, ipv6_mode, ipv6_prefix)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&range.name)
        .bind(&range.interface)
        .bind(&range.start_address)
        .bind(&range.end_address)
        .bind(&range.netmask)
        .bind(&range.lease_time)
        .bind(range.enabled as i32)
        .bind(&ipv6_mode_str)
        .bind(&range.ipv6_prefix)
        .execute(pool)
        .await?;
        Ok(result.last_insert_rowid())
    }
}

/// Delete a DHCP range
pub async fn delete_dhcp_range(pool: &SqlitePool, id: i64) -> Result<bool> {
    let result = sqlx::query("DELETE FROM dnsmasq_dhcp_ranges WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

// ============================================================================
// Static Leases
// ============================================================================

/// Load all static leases from the database
pub async fn load_static_leases(pool: &SqlitePool) -> Result<Vec<DnsmasqStaticLease>> {
    let rows = sqlx::query(
        r#"
        SELECT id, mac_address, ip_address, hostname, lease_time, client_id, enabled
        FROM dnsmasq_static_leases ORDER BY ip_address
        "#,
    )
    .fetch_all(pool)
    .await?;

    let mut leases = Vec::new();
    for row in rows {
        let id: i64 = row.get("id");

        // Load tags for this lease
        let tag_rows = sqlx::query("SELECT tag FROM dnsmasq_static_lease_tags WHERE lease_id = ?")
            .bind(id)
            .fetch_all(pool)
            .await?;
        let set_tags: Vec<String> = tag_rows.into_iter().map(|r| r.get("tag")).collect();

        leases.push(DnsmasqStaticLease {
            id: Some(id),
            mac_address: row.get("mac_address"),
            ip_address: row.get("ip_address"),
            hostname: row.get("hostname"),
            lease_time: row.get("lease_time"),
            client_id: row.get("client_id"),
            set_tags,
            enabled: row.get::<i32, _>("enabled") != 0,
        });
    }

    Ok(leases)
}

/// Save a static lease (insert or update)
pub async fn save_static_lease(pool: &SqlitePool, lease: &DnsmasqStaticLease) -> Result<i64> {
    keystone_core::validation::single_line_fields(lease).map_err(anyhow::Error::msg)?;
    let id = if let Some(id) = lease.id {
        // Update existing
        sqlx::query(
            r#"
            UPDATE dnsmasq_static_leases SET
                mac_address = ?, ip_address = ?, hostname = ?, lease_time = ?, client_id = ?, enabled = ?
            WHERE id = ?
            "#,
        )
        .bind(&lease.mac_address)
        .bind(&lease.ip_address)
        .bind(&lease.hostname)
        .bind(&lease.lease_time)
        .bind(&lease.client_id)
        .bind(lease.enabled as i32)
        .bind(id)
        .execute(pool)
        .await?;
        id
    } else {
        // Insert new
        let result = sqlx::query(
            r#"
            INSERT INTO dnsmasq_static_leases (mac_address, ip_address, hostname, lease_time, client_id, enabled)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&lease.mac_address)
        .bind(&lease.ip_address)
        .bind(&lease.hostname)
        .bind(&lease.lease_time)
        .bind(&lease.client_id)
        .bind(lease.enabled as i32)
        .execute(pool)
        .await?;
        result.last_insert_rowid()
    };

    // Update tags
    sqlx::query("DELETE FROM dnsmasq_static_lease_tags WHERE lease_id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    for tag in &lease.set_tags {
        sqlx::query("INSERT INTO dnsmasq_static_lease_tags (lease_id, tag) VALUES (?, ?)")
            .bind(id)
            .bind(tag)
            .execute(pool)
            .await?;
    }

    Ok(id)
}

/// Delete a static lease
pub async fn delete_static_lease(pool: &SqlitePool, id: i64) -> Result<bool> {
    let result = sqlx::query("DELETE FROM dnsmasq_static_leases WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

// ============================================================================
// DHCP Options
// ============================================================================

/// Load all DHCP options from the database
pub async fn load_dhcp_options(pool: &SqlitePool) -> Result<Vec<DnsmasqDhcpOption>> {
    let rows = sqlx::query(
        r#"
        SELECT id, description, option, value, enabled, ipv6, force_send
        FROM dnsmasq_dhcp_options ORDER BY id
        "#,
    )
    .fetch_all(pool)
    .await?;

    let mut options = Vec::new();
    for row in rows {
        let id: i64 = row.get("id");

        // Load tags for this option
        let tag_rows = sqlx::query("SELECT tag FROM dnsmasq_dhcp_option_tags WHERE option_id = ?")
            .bind(id)
            .fetch_all(pool)
            .await?;
        let match_tags: Vec<String> = tag_rows.into_iter().map(|r| r.get("tag")).collect();

        options.push(DnsmasqDhcpOption {
            id: Some(id),
            description: row.get("description"),
            option: row.get("option"),
            value: row.get("value"),
            match_tags,
            enabled: row.get::<i32, _>("enabled") != 0,
            ipv6: row.get::<i32, _>("ipv6") != 0,
            force: row.get::<i32, _>("force_send") != 0,
        });
    }

    Ok(options)
}

/// Save a DHCP option (insert or update)
pub async fn save_dhcp_option(pool: &SqlitePool, option: &DnsmasqDhcpOption) -> Result<i64> {
    keystone_core::validation::single_line_fields(option).map_err(anyhow::Error::msg)?;
    let id = if let Some(id) = option.id {
        // Update existing
        sqlx::query(
            r#"
            UPDATE dnsmasq_dhcp_options SET
                description = ?, option = ?, value = ?, enabled = ?, ipv6 = ?, force_send = ?
            WHERE id = ?
            "#,
        )
        .bind(&option.description)
        .bind(&option.option)
        .bind(&option.value)
        .bind(option.enabled as i32)
        .bind(option.ipv6 as i32)
        .bind(option.force as i32)
        .bind(id)
        .execute(pool)
        .await?;
        id
    } else {
        // Insert new
        let result = sqlx::query(
            r#"
            INSERT INTO dnsmasq_dhcp_options (description, option, value, enabled, ipv6, force_send)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&option.description)
        .bind(&option.option)
        .bind(&option.value)
        .bind(option.enabled as i32)
        .bind(option.ipv6 as i32)
        .bind(option.force as i32)
        .execute(pool)
        .await?;
        result.last_insert_rowid()
    };

    // Update tags
    sqlx::query("DELETE FROM dnsmasq_dhcp_option_tags WHERE option_id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    for tag in &option.match_tags {
        sqlx::query("INSERT INTO dnsmasq_dhcp_option_tags (option_id, tag) VALUES (?, ?)")
            .bind(id)
            .bind(tag)
            .execute(pool)
            .await?;
    }

    Ok(id)
}

/// Delete a DHCP option
pub async fn delete_dhcp_option(pool: &SqlitePool, id: i64) -> Result<bool> {
    let result = sqlx::query("DELETE FROM dnsmasq_dhcp_options WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

// ============================================================================
// Host Records
// ============================================================================

/// Load all host records from the database
pub async fn load_host_records(pool: &SqlitePool) -> Result<Vec<DnsmasqHostRecord>> {
    let rows = sqlx::query(
        "SELECT id, ipv4_address, ipv6_address, ttl, enabled FROM dnsmasq_host_records ORDER BY id",
    )
    .fetch_all(pool)
    .await?;

    let mut records = Vec::new();
    for row in rows {
        let id: i64 = row.get("id");

        // Load hostnames for this record
        let name_rows = sqlx::query(
            "SELECT hostname FROM dnsmasq_host_record_names WHERE record_id = ? ORDER BY id",
        )
        .bind(id)
        .fetch_all(pool)
        .await?;
        let hostnames: Vec<String> = name_rows.into_iter().map(|r| r.get("hostname")).collect();

        records.push(DnsmasqHostRecord {
            id: Some(id),
            hostnames,
            ipv4_address: row.get("ipv4_address"),
            ipv6_address: row.get("ipv6_address"),
            ttl: row.get::<Option<i32>, _>("ttl").map(|t| t as u32),
            enabled: row.get::<i32, _>("enabled") != 0,
        });
    }

    Ok(records)
}

/// Save a host record (insert or update)
pub async fn save_host_record(pool: &SqlitePool, record: &DnsmasqHostRecord) -> Result<i64> {
    keystone_core::validation::single_line_fields(record).map_err(anyhow::Error::msg)?;
    let id = if let Some(id) = record.id {
        // Update existing
        sqlx::query(
            r#"
            UPDATE dnsmasq_host_records SET
                ipv4_address = ?, ipv6_address = ?, ttl = ?, enabled = ?
            WHERE id = ?
            "#,
        )
        .bind(&record.ipv4_address)
        .bind(&record.ipv6_address)
        .bind(record.ttl.map(|t| t as i32))
        .bind(record.enabled as i32)
        .bind(id)
        .execute(pool)
        .await?;
        id
    } else {
        // Insert new
        let result = sqlx::query(
            r#"
            INSERT INTO dnsmasq_host_records (ipv4_address, ipv6_address, ttl, enabled)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(&record.ipv4_address)
        .bind(&record.ipv6_address)
        .bind(record.ttl.map(|t| t as i32))
        .bind(record.enabled as i32)
        .execute(pool)
        .await?;
        result.last_insert_rowid()
    };

    // Update hostnames
    sqlx::query("DELETE FROM dnsmasq_host_record_names WHERE record_id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    for hostname in &record.hostnames {
        sqlx::query("INSERT INTO dnsmasq_host_record_names (record_id, hostname) VALUES (?, ?)")
            .bind(id)
            .bind(hostname)
            .execute(pool)
            .await?;
    }

    Ok(id)
}

/// Delete a host record
pub async fn delete_host_record(pool: &SqlitePool, id: i64) -> Result<bool> {
    let result = sqlx::query("DELETE FROM dnsmasq_host_records WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

// ============================================================================
// CNAME Records
// ============================================================================

/// Load all CNAME records from the database
pub async fn load_cname_records(pool: &SqlitePool) -> Result<Vec<DnsmasqCnameRecord>> {
    let rows = sqlx::query(
        "SELECT id, alias, target, ttl, enabled FROM dnsmasq_cname_records ORDER BY alias",
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| DnsmasqCnameRecord {
            id: Some(row.get("id")),
            alias: row.get("alias"),
            target: row.get("target"),
            ttl: row.get::<Option<i32>, _>("ttl").map(|t| t as u32),
            enabled: row.get::<i32, _>("enabled") != 0,
        })
        .collect())
}

/// Save a CNAME record (insert or update)
pub async fn save_cname_record(pool: &SqlitePool, record: &DnsmasqCnameRecord) -> Result<i64> {
    keystone_core::validation::single_line_fields(record).map_err(anyhow::Error::msg)?;
    if let Some(id) = record.id {
        // Update existing
        sqlx::query(
            "UPDATE dnsmasq_cname_records SET alias = ?, target = ?, ttl = ?, enabled = ? WHERE id = ?",
        )
        .bind(&record.alias)
        .bind(&record.target)
        .bind(record.ttl.map(|t| t as i32))
        .bind(record.enabled as i32)
        .bind(id)
        .execute(pool)
        .await?;
        Ok(id)
    } else {
        // Insert new
        let result = sqlx::query(
            "INSERT INTO dnsmasq_cname_records (alias, target, ttl, enabled) VALUES (?, ?, ?, ?)",
        )
        .bind(&record.alias)
        .bind(&record.target)
        .bind(record.ttl.map(|t| t as i32))
        .bind(record.enabled as i32)
        .execute(pool)
        .await?;
        Ok(result.last_insert_rowid())
    }
}

/// Delete a CNAME record
pub async fn delete_cname_record(pool: &SqlitePool, id: i64) -> Result<bool> {
    let result = sqlx::query("DELETE FROM dnsmasq_cname_records WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

// ============================================================================
// Address Overrides
// ============================================================================

/// Load all address overrides from the database
pub async fn load_address_overrides(pool: &SqlitePool) -> Result<Vec<DnsmasqAddressOverride>> {
    let rows = sqlx::query(
        "SELECT id, domain, action, redirect_address, enabled FROM dnsmasq_address_overrides ORDER BY domain",
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| {
            let action_str: String = row.get("action");
            let action = action_str.parse().unwrap_or(DnsmasqAddressAction::Block);

            DnsmasqAddressOverride {
                id: Some(row.get("id")),
                domain: row.get("domain"),
                action,
                redirect_address: row.get("redirect_address"),
                enabled: row.get::<i32, _>("enabled") != 0,
            }
        })
        .collect())
}

/// Save an address override (insert or update)
pub async fn save_address_override(
    pool: &SqlitePool,
    override_entry: &DnsmasqAddressOverride,
) -> Result<i64> {
    keystone_core::validation::single_line_fields(override_entry).map_err(anyhow::Error::msg)?;
    if let Some(id) = override_entry.id {
        // Update existing
        sqlx::query(
            "UPDATE dnsmasq_address_overrides SET domain = ?, action = ?, redirect_address = ?, enabled = ? WHERE id = ?",
        )
        .bind(&override_entry.domain)
        .bind(override_entry.action.to_string())
        .bind(&override_entry.redirect_address)
        .bind(override_entry.enabled as i32)
        .bind(id)
        .execute(pool)
        .await?;
        Ok(id)
    } else {
        // Insert new
        let result = sqlx::query(
            "INSERT INTO dnsmasq_address_overrides (domain, action, redirect_address, enabled) VALUES (?, ?, ?, ?)",
        )
        .bind(&override_entry.domain)
        .bind(override_entry.action.to_string())
        .bind(&override_entry.redirect_address)
        .bind(override_entry.enabled as i32)
        .execute(pool)
        .await?;
        Ok(result.last_insert_rowid())
    }
}

/// Delete an address override
pub async fn delete_address_override(pool: &SqlitePool, id: i64) -> Result<bool> {
    let result = sqlx::query("DELETE FROM dnsmasq_address_overrides WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

// ============================================================================
// Complete State
// ============================================================================

/// Load the complete dnsmasq state (config + all entities)
pub async fn load_dnsmasq_state(pool: &SqlitePool) -> Result<DnsmasqStateResponse> {
    let config = load_dnsmasq_config(pool).await?;
    let dhcp_ranges = load_dhcp_ranges(pool).await?;
    let static_leases = load_static_leases(pool).await?;
    let dhcp_options = load_dhcp_options(pool).await?;
    let host_records = load_host_records(pool).await?;
    let cname_records = load_cname_records(pool).await?;
    let address_overrides = load_address_overrides(pool).await?;

    Ok(DnsmasqStateResponse {
        config,
        dhcp_ranges,
        static_leases,
        dhcp_options,
        host_records,
        cname_records,
        address_overrides,
    })
}

#[cfg(test)]
mod interface_list_tests {
    use super::*;

    #[tokio::test]
    async fn interface_lists_use_separate_fixed_tables() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        sqlx::query("CREATE TABLE dnsmasq_listen_interfaces (id INTEGER PRIMARY KEY, interface TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE dnsmasq_except_interfaces (id INTEGER PRIMARY KEY, interface TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE dnsmasq_no_dhcp_interfaces (id INTEGER PRIMARY KEY, interface TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();

        for (table, iface) in [
            (InterfaceListTable::Listen, "lan0"),
            (InterfaceListTable::Except, "wan0"),
            (InterfaceListTable::NoDhcp, "dmz0"),
        ] {
            save_interface_list(&pool, table, &[iface.to_owned()])
                .await
                .unwrap();
            assert_eq!(load_interface_list(&pool, table).await.unwrap(), [iface]);
        }

        save_interface_list(&pool, InterfaceListTable::Listen, &["br0".to_owned()])
            .await
            .unwrap();
        assert_eq!(
            load_interface_list(&pool, InterfaceListTable::Listen)
                .await
                .unwrap(),
            ["br0"]
        );
        assert_eq!(
            load_interface_list(&pool, InterfaceListTable::Except)
                .await
                .unwrap(),
            ["wan0"]
        );
    }
}

#[cfg(test)]
mod local_adguard_migration_tests {
    use super::*;
    use crate::db::Database;

    const MIGRATION: &str =
        include_str!("../../migrations/20261017000100_drop_local_adguard_mode.sql");

    async fn run_migration(pool: &SqlitePool) {
        for statement in MIGRATION.split(';').filter(|s| !s.trim().is_empty()) {
            sqlx::query(statement).execute(pool).await.unwrap();
        }
    }

    #[tokio::test]
    async fn saved_local_adguard_mode_becomes_a_custom_server_on_the_same_port() {
        let db = Database::new_in_memory().await.unwrap();
        let pool = db.pool();
        sqlx::query("UPDATE dnsmasq_config SET upstream_mode = 'localadguard' WHERE id = 1")
            .execute(pool)
            .await
            .unwrap();
        // Listed while the old mode was active, so never used by it.
        sqlx::query("INSERT INTO dnsmasq_upstream_servers (address) VALUES ('9.9.9.9')")
            .execute(pool)
            .await
            .unwrap();

        run_migration(pool).await;

        let config = load_dnsmasq_config(pool).await.unwrap();
        assert_eq!(config.upstream_mode, DnsmasqUpstreamMode::Custom);
        assert_eq!(config.upstream_servers.len(), 1);
        assert_eq!(config.upstream_servers[0].address, "127.0.0.1");
        assert_eq!(config.upstream_servers[0].port, Some(5353));
    }

    #[tokio::test]
    async fn other_modes_and_their_servers_are_untouched() {
        let db = Database::new_in_memory().await.unwrap();
        let pool = db.pool();
        sqlx::query("UPDATE dnsmasq_config SET upstream_mode = 'custom' WHERE id = 1")
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO dnsmasq_upstream_servers (address) VALUES ('9.9.9.9')")
            .execute(pool)
            .await
            .unwrap();

        run_migration(pool).await;

        let config = load_dnsmasq_config(pool).await.unwrap();
        assert_eq!(config.upstream_mode, DnsmasqUpstreamMode::Custom);
        assert_eq!(config.upstream_servers.len(), 1);
        assert_eq!(config.upstream_servers[0].address, "9.9.9.9");
    }
}
