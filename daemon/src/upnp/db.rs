//! Database access for the UPnP configuration and the last applied state.

use anyhow::{Context, Result, anyhow};
use keystone_core::upnp::{PortRange, UpnpConfig};
use sqlx::{Row, SqlitePool, sqlite::SqliteRow};

/// Load the UPnP configuration. The migration always creates the row.
pub async fn load_upnp_config(pool: &SqlitePool) -> Result<UpnpConfig> {
    let row = sqlx::query(
        r#"
        SELECT enabled, wan_interface, enable_igd, enable_natpmp_pcp, secure_mode,
               external_port_min, external_port_max, internal_port_min, internal_port_max,
               max_lease_secs, friendly_name, notify_interval_secs, system_uptime
        FROM upnp_config WHERE id = 1
        "#,
    )
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else {
        return Ok(UpnpConfig::default());
    };

    let lan_interfaces: Vec<String> =
        sqlx::query_scalar("SELECT interface FROM upnp_lan_interfaces ORDER BY interface")
            .fetch_all(pool)
            .await?;
    let allowed_client_subnets: Vec<String> =
        sqlx::query_scalar("SELECT subnet FROM upnp_allowed_subnets ORDER BY subnet")
            .fetch_all(pool)
            .await?;

    Ok(UpnpConfig {
        enabled: row.get::<i64, _>("enabled") != 0,
        lan_interfaces,
        wan_interface: row.get("wan_interface"),
        enable_igd: row.get::<i64, _>("enable_igd") != 0,
        enable_natpmp_pcp: row.get::<i64, _>("enable_natpmp_pcp") != 0,
        secure_mode: row.get::<i64, _>("secure_mode") != 0,
        external_ports: PortRange {
            min: port(&row, "external_port_min")?,
            max: port(&row, "external_port_max")?,
        },
        internal_ports: PortRange {
            min: port(&row, "internal_port_min")?,
            max: port(&row, "internal_port_max")?,
        },
        allowed_client_subnets,
        max_lease_secs: u32::try_from(row.get::<i64, _>("max_lease_secs"))
            .context("max_lease_secs out of range")?,
        friendly_name: row.get("friendly_name"),
        notify_interval_secs: u32::try_from(row.get::<i64, _>("notify_interval_secs"))
            .context("notify_interval_secs out of range")?,
        system_uptime: row.get::<i64, _>("system_uptime") != 0,
    })
}

fn port(row: &SqliteRow, column: &str) -> Result<u16> {
    u16::try_from(row.get::<i64, _>(column)).with_context(|| format!("{column} out of range"))
}

/// Replace the UPnP configuration. Callers validate the values first.
pub async fn save_upnp_config(pool: &SqlitePool, config: &UpnpConfig) -> Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        r#"
        INSERT INTO upnp_config
            (id, enabled, wan_interface, enable_igd, enable_natpmp_pcp, secure_mode,
             external_port_min, external_port_max, internal_port_min, internal_port_max,
             max_lease_secs, friendly_name, notify_interval_secs, system_uptime, updated_at)
        VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%s', 'now'))
        ON CONFLICT(id) DO UPDATE SET
            enabled = excluded.enabled,
            wan_interface = excluded.wan_interface,
            enable_igd = excluded.enable_igd,
            enable_natpmp_pcp = excluded.enable_natpmp_pcp,
            secure_mode = excluded.secure_mode,
            external_port_min = excluded.external_port_min,
            external_port_max = excluded.external_port_max,
            internal_port_min = excluded.internal_port_min,
            internal_port_max = excluded.internal_port_max,
            max_lease_secs = excluded.max_lease_secs,
            friendly_name = excluded.friendly_name,
            notify_interval_secs = excluded.notify_interval_secs,
            system_uptime = excluded.system_uptime,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(config.enabled as i64)
    .bind(&config.wan_interface)
    .bind(config.enable_igd as i64)
    .bind(config.enable_natpmp_pcp as i64)
    .bind(config.secure_mode as i64)
    .bind(i64::from(config.external_ports.min))
    .bind(i64::from(config.external_ports.max))
    .bind(i64::from(config.internal_ports.min))
    .bind(i64::from(config.internal_ports.max))
    .bind(i64::from(config.max_lease_secs))
    .bind(&config.friendly_name)
    .bind(i64::from(config.notify_interval_secs))
    .bind(config.system_uptime as i64)
    .execute(&mut *tx)
    .await?;

    sqlx::query("DELETE FROM upnp_lan_interfaces")
        .execute(&mut *tx)
        .await?;
    for interface in &config.lan_interfaces {
        sqlx::query("INSERT INTO upnp_lan_interfaces (interface) VALUES (?)")
            .bind(interface)
            .execute(&mut *tx)
            .await?;
    }

    sqlx::query("DELETE FROM upnp_allowed_subnets")
        .execute(&mut *tx)
        .await?;
    for subnet in &config.allowed_client_subnets {
        sqlx::query("INSERT INTO upnp_allowed_subnets (subnet) VALUES (?)")
            .bind(subnet)
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await?;
    Ok(())
}

/// The configuration last applied to the system, if any apply has succeeded.
pub async fn load_applied(pool: &SqlitePool) -> Result<Option<UpnpConfig>> {
    let json: Option<String> =
        sqlx::query_scalar("SELECT config_json FROM upnp_applied WHERE id = 1")
            .fetch_optional(pool)
            .await?;
    json.map(|json| serde_json::from_str(&json).context("stored UPnP applied state is invalid"))
        .transpose()
}

/// Record `config` as the configuration now in effect on the system.
pub async fn save_applied(pool: &SqlitePool, config: &UpnpConfig) -> Result<()> {
    let json = serde_json::to_string(config).map_err(|error| anyhow!(error))?;
    sqlx::query(
        r#"
        INSERT INTO upnp_applied (id, config_json, applied_at)
        VALUES (1, ?, strftime('%s', 'now'))
        ON CONFLICT(id) DO UPDATE SET
            config_json = excluded.config_json,
            applied_at = excluded.applied_at
        "#,
    )
    .bind(json)
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;

    #[tokio::test]
    async fn a_fresh_database_holds_the_disabled_defaults() {
        let db = Database::new_in_memory().await.unwrap();
        assert_eq!(
            load_upnp_config(db.pool()).await.unwrap(),
            UpnpConfig::default()
        );
        assert_eq!(load_applied(db.pool()).await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_saved_configuration_round_trips_and_replaces_its_lists() {
        let db = Database::new_in_memory().await.unwrap();
        let mut config = UpnpConfig {
            enabled: true,
            lan_interfaces: vec!["eth1".to_string(), "eth2".to_string()],
            wan_interface: "eth0".to_string(),
            enable_natpmp_pcp: false,
            secure_mode: false,
            external_ports: PortRange {
                min: 2000,
                max: 3000,
            },
            allowed_client_subnets: vec!["10.0.0.0/8".to_string(), "192.168.1.0/24".to_string()],
            max_lease_secs: 3600,
            friendly_name: "Lab".to_string(),
            notify_interval_secs: 600,
            system_uptime: false,
            ..UpnpConfig::default()
        };
        save_upnp_config(db.pool(), &config).await.unwrap();
        assert_eq!(load_upnp_config(db.pool()).await.unwrap(), config);

        config.lan_interfaces = vec!["eth2".to_string()];
        config.allowed_client_subnets.clear();
        save_upnp_config(db.pool(), &config).await.unwrap();
        let loaded = load_upnp_config(db.pool()).await.unwrap();
        assert_eq!(loaded.lan_interfaces, vec!["eth2".to_string()]);
        assert!(loaded.allowed_client_subnets.is_empty());
    }

    #[tokio::test]
    async fn the_applied_state_is_stored_separately_from_the_configuration() {
        let db = Database::new_in_memory().await.unwrap();
        let config = UpnpConfig {
            enabled: true,
            ..UpnpConfig::default()
        };
        save_applied(db.pool(), &config).await.unwrap();
        assert_eq!(load_applied(db.pool()).await.unwrap(), Some(config));
        assert!(!load_upnp_config(db.pool()).await.unwrap().enabled);
    }
}
