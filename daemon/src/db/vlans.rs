//! VLAN configuration database operations

use anyhow::{Context, Result};
use keystone_core::VlanConfig;
use sqlx::SqlitePool;

/// VLAN-related database operations
pub struct VlansDb<'a> {
    pool: &'a SqlitePool,
}

impl<'a> VlansDb<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    /// Get all VLAN configurations
    pub async fn get_all_vlans(&self) -> Result<Vec<VlanConfig>> {
        let rows = sqlx::query_as::<_, (i64, String, String, i64, String, Option<String>, Option<i64>)>(
            r#"SELECT id, name, parent_interface, vlan_id, protocol, description, interface_config_id
               FROM vlan_config ORDER BY parent_interface, vlan_id"#
        )
        .fetch_all(self.pool)
        .await
        .context("Failed to fetch VLANs")?;

        let vlans = rows
            .into_iter()
            .map(
                |(
                    id,
                    name,
                    parent_interface,
                    vlan_id,
                    protocol,
                    description,
                    interface_config_id,
                )| {
                    VlanConfig {
                        id: Some(id),
                        name,
                        parent_interface,
                        vlan_id: vlan_id as u16,
                        protocol: protocol.parse().unwrap_or_default(),
                        description,
                        interface_config_id,
                    }
                },
            )
            .collect();

        Ok(vlans)
    }

    /// Get a single VLAN by ID
    pub async fn get_vlan(&self, id: i64) -> Result<Option<VlanConfig>> {
        let row = sqlx::query_as::<_, (i64, String, String, i64, String, Option<String>, Option<i64>)>(
            r#"SELECT id, name, parent_interface, vlan_id, protocol, description, interface_config_id
               FROM vlan_config WHERE id = ?"#
        )
        .bind(id)
        .fetch_optional(self.pool)
        .await
        .context("Failed to fetch VLAN")?;

        Ok(row.map(
            |(id, name, parent_interface, vlan_id, protocol, description, interface_config_id)| {
                VlanConfig {
                    id: Some(id),
                    name,
                    parent_interface,
                    vlan_id: vlan_id as u16,
                    protocol: protocol.parse().unwrap_or_default(),
                    description,
                    interface_config_id,
                }
            },
        ))
    }

    /// Save (insert or update) a VLAN configuration
    pub async fn save_vlan(&self, config: &VlanConfig) -> Result<i64> {
        keystone_core::validation::single_line_fields(config).map_err(anyhow::Error::msg)?;
        keystone_core::validation::interface_name(&config.name).map_err(anyhow::Error::msg)?;
        keystone_core::validation::interface_name(&config.parent_interface)
            .map_err(anyhow::Error::msg)?;
        // Validate VLAN ID
        if config.vlan_id < 1 || config.vlan_id > 4094 {
            anyhow::bail!("VLAN ID must be between 1 and 4094");
        }

        if config.name.is_empty() {
            anyhow::bail!("VLAN name is required");
        }

        if config.parent_interface.is_empty() {
            anyhow::bail!("Parent interface is required");
        }

        let mut tx = self.pool.begin().await?;

        let id = if let Some(id) = config.id {
            // Update existing
            sqlx::query(
                r#"UPDATE vlan_config SET 
                   name = ?, parent_interface = ?, vlan_id = ?, protocol = ?, 
                   description = ?, interface_config_id = ?, updated_at = strftime('%s', 'now')
                   WHERE id = ?"#,
            )
            .bind(&config.name)
            .bind(&config.parent_interface)
            .bind(config.vlan_id as i64)
            .bind(config.protocol.to_string())
            .bind(&config.description)
            .bind(config.interface_config_id)
            .bind(id)
            .execute(&mut *tx)
            .await
            .context("Failed to update VLAN")?;
            id
        } else {
            // Insert new
            let result = sqlx::query(
                r#"INSERT INTO vlan_config (name, parent_interface, vlan_id, protocol, description, interface_config_id)
                   VALUES (?, ?, ?, ?, ?, ?)"#
            )
            .bind(&config.name)
            .bind(&config.parent_interface)
            .bind(config.vlan_id as i64)
            .bind(config.protocol.to_string())
            .bind(&config.description)
            .bind(config.interface_config_id)
            .execute(&mut *tx)
            .await
            .context("Failed to insert VLAN")?;
            result.last_insert_rowid()
        };

        tx.commit().await?;
        Ok(id)
    }

    /// Delete a VLAN by ID
    pub async fn delete_vlan(&self, id: i64) -> Result<bool> {
        let result = sqlx::query("DELETE FROM vlan_config WHERE id = ?")
            .bind(id)
            .execute(self.pool)
            .await
            .context("Failed to delete VLAN")?;

        Ok(result.rows_affected() > 0)
    }
}
