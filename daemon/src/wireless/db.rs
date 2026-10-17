//! Database access for the access point configuration and the last applied state.

use anyhow::{Context, Result, anyhow};
use keystone_core::wireless::WirelessConfig;
use sqlx::{Row, SqlitePool};

/// Load the access point configuration. The migration always creates the row.
pub async fn load_wireless_config(pool: &SqlitePool) -> Result<WirelessConfig> {
    let row = sqlx::query(
        r#"
        SELECT enabled, interface, bridge, ssid, hidden_ssid, country_code, channel,
               passphrase, client_isolation
        FROM wireless_config WHERE id = 1
        "#,
    )
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else {
        return Ok(WirelessConfig::default());
    };

    Ok(WirelessConfig {
        enabled: row.get::<i64, _>("enabled") != 0,
        interface: row.get("interface"),
        bridge: row.get("bridge"),
        ssid: row.get("ssid"),
        hidden_ssid: row.get::<i64, _>("hidden_ssid") != 0,
        country_code: row.get("country_code"),
        channel: u8::try_from(row.get::<i64, _>("channel")).context("channel out of range")?,
        passphrase: row.get("passphrase"),
        client_isolation: row.get::<i64, _>("client_isolation") != 0,
    })
}

/// Replace the access point configuration. Callers validate the values first.
pub async fn save_wireless_config(pool: &SqlitePool, config: &WirelessConfig) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO wireless_config
            (id, enabled, interface, bridge, ssid, hidden_ssid, country_code, channel,
             passphrase, client_isolation, updated_at)
        VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%s', 'now'))
        ON CONFLICT(id) DO UPDATE SET
            enabled = excluded.enabled,
            interface = excluded.interface,
            bridge = excluded.bridge,
            ssid = excluded.ssid,
            hidden_ssid = excluded.hidden_ssid,
            country_code = excluded.country_code,
            channel = excluded.channel,
            passphrase = excluded.passphrase,
            client_isolation = excluded.client_isolation,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(config.enabled as i64)
    .bind(&config.interface)
    .bind(&config.bridge)
    .bind(&config.ssid)
    .bind(config.hidden_ssid as i64)
    .bind(&config.country_code)
    .bind(i64::from(config.channel))
    .bind(&config.passphrase)
    .bind(config.client_isolation as i64)
    .execute(pool)
    .await?;
    Ok(())
}

/// The configuration last applied to the system, if any apply has succeeded.
pub async fn load_applied(pool: &SqlitePool) -> Result<Option<WirelessConfig>> {
    let json: Option<String> =
        sqlx::query_scalar("SELECT config_json FROM wireless_applied WHERE id = 1")
            .fetch_optional(pool)
            .await?;
    json.map(|json| serde_json::from_str(&json).context("stored wireless applied state is invalid"))
        .transpose()
}

/// Record `config` as the configuration now in effect on the system.
pub async fn save_applied(pool: &SqlitePool, config: &WirelessConfig) -> Result<()> {
    let json = serde_json::to_string(config).map_err(|error| anyhow!(error))?;
    sqlx::query(
        r#"
        INSERT INTO wireless_applied (id, config_json, applied_at)
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
            load_wireless_config(db.pool()).await.unwrap(),
            WirelessConfig::default()
        );
        assert_eq!(load_applied(db.pool()).await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_saved_configuration_round_trips() {
        let db = Database::new_in_memory().await.unwrap();
        let config = WirelessConfig {
            enabled: true,
            interface: "wlan0".to_string(),
            bridge: "br-lan".to_string(),
            ssid: "Lab".to_string(),
            hidden_ssid: true,
            country_code: "NZ".to_string(),
            channel: 11,
            passphrase: "hunter2hunter2".to_string(),
            client_isolation: true,
        };
        save_wireless_config(db.pool(), &config).await.unwrap();
        assert_eq!(load_wireless_config(db.pool()).await.unwrap(), config);
    }

    #[tokio::test]
    async fn the_applied_state_is_stored_separately_from_the_configuration() {
        let db = Database::new_in_memory().await.unwrap();
        let config = WirelessConfig {
            enabled: true,
            interface: "wlan0".to_string(),
            ..WirelessConfig::default()
        };
        save_applied(db.pool(), &config).await.unwrap();
        assert_eq!(load_applied(db.pool()).await.unwrap(), Some(config));
        assert!(!load_wireless_config(db.pool()).await.unwrap().enabled);
    }
}
