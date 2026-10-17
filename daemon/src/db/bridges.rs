//! Bridge configuration database operations

use anyhow::{Context, Result};
use keystone_core::BridgeConfig;
use sqlx::SqlitePool;

/// Bridge-related database operations
pub struct BridgesDb<'a> {
    pool: &'a SqlitePool,
}

impl<'a> BridgesDb<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    /// Get all bridge configurations
    pub async fn get_all_bridges(&self) -> Result<Vec<BridgeConfig>> {
        let rows = sqlx::query_as::<_, (i64, String, String, i64, i64, Option<String>, Option<i64>, Option<String>)>(
            "SELECT id, name, members, stp, stp_forward_delay, description, interface_config_id, mac_address 
             FROM bridge_config 
             ORDER BY name"
        )
        .fetch_all(self.pool)
        .await
        .context("Failed to fetch bridges")?;

        let bridges = rows
            .into_iter()
            .map(
                |(
                    id,
                    name,
                    members_json,
                    stp,
                    stp_forward_delay,
                    description,
                    interface_config_id,
                    mac_address,
                )| {
                    let members: Vec<String> =
                        serde_json::from_str(&members_json).unwrap_or_default();
                    BridgeConfig {
                        id: Some(id),
                        name,
                        members,
                        stp: stp != 0,
                        stp_forward_delay: stp_forward_delay as u32,
                        description,
                        interface_config_id,
                        mac_address,
                    }
                },
            )
            .collect();

        Ok(bridges)
    }

    /// Get a single bridge by ID
    pub async fn get_bridge(&self, id: i64) -> Result<Option<BridgeConfig>> {
        let row = sqlx::query_as::<_, (i64, String, String, i64, i64, Option<String>, Option<i64>, Option<String>)>(
            "SELECT id, name, members, stp, stp_forward_delay, description, interface_config_id, mac_address 
             FROM bridge_config 
             WHERE id = ?"
        )
        .bind(id)
        .fetch_optional(self.pool)
        .await
        .context("Failed to fetch bridge")?;

        Ok(row.map(
            |(
                id,
                name,
                members_json,
                stp,
                stp_forward_delay,
                description,
                interface_config_id,
                mac_address,
            )| {
                let members: Vec<String> = serde_json::from_str(&members_json).unwrap_or_default();
                BridgeConfig {
                    id: Some(id),
                    name,
                    members,
                    stp: stp != 0,
                    stp_forward_delay: stp_forward_delay as u32,
                    description,
                    interface_config_id,
                    mac_address,
                }
            },
        ))
    }

    /// Save (insert or update) a bridge configuration
    pub async fn save_bridge(&self, config: &BridgeConfig) -> Result<i64> {
        keystone_core::validation::single_line_fields(config).map_err(anyhow::Error::msg)?;
        keystone_core::validation::interface_name(&config.name).map_err(anyhow::Error::msg)?;
        for name in &config.members {
            keystone_core::validation::interface_name(name).map_err(anyhow::Error::msg)?;
        }
        if let Some(mac) = &config.mac_address
            && !crate::networkd::link::is_mac_address(mac)
        {
            anyhow::bail!("Invalid bridge MAC address: {mac:?}");
        }
        let members_json =
            serde_json::to_string(&config.members).context("Failed to serialize bridge members")?;

        let stp_int = if config.stp { 1 } else { 0 };

        if let Some(id) = config.id {
            // Update existing bridge
            sqlx::query(
                "UPDATE bridge_config 
                 SET name = ?, members = ?, stp = ?, stp_forward_delay = ?, 
                     description = ?, interface_config_id = ?, mac_address = ?,
                     updated_at = strftime('%s', 'now')
                 WHERE id = ?",
            )
            .bind(&config.name)
            .bind(&members_json)
            .bind(stp_int)
            .bind(config.stp_forward_delay as i64)
            .bind(&config.description)
            .bind(config.interface_config_id)
            .bind(&config.mac_address)
            .bind(id)
            .execute(self.pool)
            .await
            .context("Failed to update bridge")?;

            Ok(id)
        } else {
            // Insert new bridge
            let result = sqlx::query(
                "INSERT INTO bridge_config 
                 (name, members, stp, stp_forward_delay, description, interface_config_id, mac_address) 
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&config.name)
            .bind(&members_json)
            .bind(stp_int)
            .bind(config.stp_forward_delay as i64)
            .bind(&config.description)
            .bind(config.interface_config_id)
            .bind(&config.mac_address)
            .execute(self.pool)
            .await
            .context("Failed to insert bridge")?;

            Ok(result.last_insert_rowid())
        }
    }

    /// Delete a bridge configuration
    pub async fn delete_bridge(&self, id: i64) -> Result<bool> {
        let result = sqlx::query("DELETE FROM bridge_config WHERE id = ?")
            .bind(id)
            .execute(self.pool)
            .await
            .context("Failed to delete bridge")?;

        Ok(result.rows_affected() > 0)
    }
}
