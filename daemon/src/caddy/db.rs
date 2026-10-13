//! Database operations for Caddy configuration

use anyhow::Result;
use keystone_core::{CaddyConfig, CaddyHttpsMode};
use sqlx::{Row, SqlitePool};

/// Load the Caddy configuration from the database
pub async fn load_caddy_config(pool: &SqlitePool) -> Result<CaddyConfig> {
    let row = sqlx::query(
        r#"
        SELECT enabled, server_address, bind_interface, https_mode, custom_tls_config,
               https_port, http_port, last_validation_status, last_validation_time
        FROM caddy_config WHERE id = 1
        "#,
    )
    .fetch_optional(pool)
    .await?;

    let config = if let Some(row) = row {
        let https_mode_str: String = row.get("https_mode");
        let https_mode = https_mode_str.parse().unwrap_or(CaddyHttpsMode::Disabled);

        CaddyConfig {
            enabled: row.get::<i32, _>("enabled") != 0,
            server_address: row.get("server_address"),
            bind_interface: row.get("bind_interface"),
            https_mode,
            custom_tls_config: row.get("custom_tls_config"),
            https_port: row.get::<i32, _>("https_port") as u16,
            http_port: row.get::<i32, _>("http_port") as u16,
            last_validation_status: row.get("last_validation_status"),
            last_validation_time: row.get("last_validation_time"),
        }
    } else {
        CaddyConfig::default()
    };

    Ok(config)
}

/// Save the Caddy configuration to the database
pub async fn save_caddy_config(pool: &SqlitePool, config: &CaddyConfig) -> Result<()> {
    // Checked even while disabled: the stored values are what a later enable
    // or a restored snapshot will write into the Caddyfile.
    anyhow::ensure!(
        keystone_core::validation::is_single_line(&config.server_address)
            && keystone_core::validation::is_single_line(&config.bind_interface),
        "Caddy server address and bind interface must be single-line values"
    );
    if config.enabled {
        super::apply::validate_config(config)?;
    }
    sqlx::query(
        r#"
        INSERT OR REPLACE INTO caddy_config 
            (id, enabled, server_address, bind_interface, https_mode, custom_tls_config,
             https_port, http_port, updated_at)
        VALUES (1, ?, ?, ?, ?, ?, ?, ?, strftime('%s', 'now'))
        "#,
    )
    .bind(config.enabled as i32)
    .bind(&config.server_address)
    .bind(&config.bind_interface)
    .bind(config.https_mode.to_string())
    .bind(&config.custom_tls_config)
    .bind(config.https_port as i32)
    .bind(config.http_port as i32)
    .execute(pool)
    .await?;

    Ok(())
}

/// Update the last validation status in the database
pub async fn update_validation_status(pool: &SqlitePool, status: &str) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE caddy_config 
        SET last_validation_status = ?, last_validation_time = strftime('%s', 'now')
        WHERE id = 1
        "#,
    )
    .bind(status)
    .execute(pool)
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;

    #[tokio::test]
    async fn newline_in_server_address_is_refused_even_when_disabled() {
        let db = Database::new_in_memory().await.unwrap();
        for enabled in [false, true] {
            let config = CaddyConfig {
                enabled,
                server_address: "router.example\nsite.example {".into(),
                ..Default::default()
            };
            let error = save_caddy_config(db.pool(), &config).await.unwrap_err();
            assert!(error.to_string().contains("single-line"), "{error:#}");
        }
        let stored = load_caddy_config(db.pool()).await.unwrap();
        assert!(
            stored.server_address.is_empty(),
            "rejected value was stored"
        );
    }

    #[tokio::test]
    async fn newline_in_bind_interface_is_refused() {
        let db = Database::new_in_memory().await.unwrap();
        let config = CaddyConfig {
            bind_interface: "eth1\n".into(),
            ..Default::default()
        };
        assert!(save_caddy_config(db.pool(), &config).await.is_err());
    }
}
