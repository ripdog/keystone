//! Firewall configuration database operations

use anyhow::{Context, Result};
use keystone_core::{
    FirewallAction, FirewallConfig, FirewallGlobalSettings, FirewallPolicy, FirewallZone,
    ForwardRule, InputRule, PortForward, RuleProtocol, ZoneForwardPolicy,
};
use sqlx::SqlitePool;
use std::collections::HashMap;
use tracing::info;

/// Firewall-related database operations
pub struct FirewallDb<'a> {
    pool: &'a SqlitePool,
}

impl<'a> FirewallDb<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    // ========================================================================
    // Firewall Zone CRUD Operations
    // ========================================================================

    /// Get all firewall zones
    pub async fn get_firewall_zones(&self) -> Result<Vec<FirewallZone>> {
        // First get all zones
        let zone_rows =
            sqlx::query_as::<_, (i64, String, Option<String>, bool, bool, String, String)>(
                r#"SELECT id, name, description, is_wan, masquerade_ipv4,
                      default_input_policy, default_forward_policy
               FROM firewall_zones ORDER BY name"#,
            )
            .fetch_all(self.pool)
            .await
            .context("Failed to fetch firewall zones")?;

        let mut zones = Vec::with_capacity(zone_rows.len());
        for (id, name, description, is_wan, masquerade_ipv4, input_policy, forward_policy) in
            zone_rows
        {
            // Get interfaces for this zone
            let interface_rows = sqlx::query_as::<_, (String,)>(
                "SELECT interface_name FROM firewall_zone_interfaces WHERE zone_id = ?",
            )
            .bind(id)
            .fetch_all(self.pool)
            .await
            .context("Failed to fetch zone interfaces")?;

            let interfaces: Vec<String> = interface_rows.into_iter().map(|(name,)| name).collect();

            zones.push(FirewallZone {
                id: Some(id),
                name,
                description,
                interfaces,
                is_wan,
                masquerade_ipv4,
                default_input_policy: input_policy.parse().unwrap_or(FirewallPolicy::Drop),
                default_forward_policy: forward_policy.parse().unwrap_or(FirewallPolicy::Drop),
            });
        }

        Ok(zones)
    }

    /// Get a single firewall zone by ID
    pub async fn get_firewall_zone(&self, id: i64) -> Result<Option<FirewallZone>> {
        let row = sqlx::query_as::<_, (i64, String, Option<String>, bool, bool, String, String)>(
            r#"SELECT id, name, description, is_wan, masquerade_ipv4,
                      default_input_policy, default_forward_policy
               FROM firewall_zones WHERE id = ?"#,
        )
        .bind(id)
        .fetch_optional(self.pool)
        .await
        .context("Failed to fetch firewall zone")?;

        match row {
            Some((
                id,
                name,
                description,
                is_wan,
                masquerade_ipv4,
                input_policy,
                forward_policy,
            )) => {
                let interface_rows = sqlx::query_as::<_, (String,)>(
                    "SELECT interface_name FROM firewall_zone_interfaces WHERE zone_id = ?",
                )
                .bind(id)
                .fetch_all(self.pool)
                .await
                .context("Failed to fetch zone interfaces")?;

                let interfaces: Vec<String> =
                    interface_rows.into_iter().map(|(name,)| name).collect();

                Ok(Some(FirewallZone {
                    id: Some(id),
                    name,
                    description,
                    interfaces,
                    is_wan,
                    masquerade_ipv4,
                    default_input_policy: input_policy.parse().unwrap_or(FirewallPolicy::Drop),
                    default_forward_policy: forward_policy.parse().unwrap_or(FirewallPolicy::Drop),
                }))
            }
            None => Ok(None),
        }
    }

    /// Get a firewall zone by name
    pub async fn get_firewall_zone_by_name(&self, name: &str) -> Result<Option<FirewallZone>> {
        let row = sqlx::query_as::<_, (i64, String, Option<String>, bool, bool, String, String)>(
            r#"SELECT id, name, description, is_wan, masquerade_ipv4,
                      default_input_policy, default_forward_policy
               FROM firewall_zones WHERE name = ?"#,
        )
        .bind(name)
        .fetch_optional(self.pool)
        .await
        .context("Failed to fetch firewall zone by name")?;

        match row {
            Some((
                id,
                name,
                description,
                is_wan,
                masquerade_ipv4,
                input_policy,
                forward_policy,
            )) => {
                let interface_rows = sqlx::query_as::<_, (String,)>(
                    "SELECT interface_name FROM firewall_zone_interfaces WHERE zone_id = ?",
                )
                .bind(id)
                .fetch_all(self.pool)
                .await
                .context("Failed to fetch zone interfaces")?;

                let interfaces: Vec<String> =
                    interface_rows.into_iter().map(|(name,)| name).collect();

                Ok(Some(FirewallZone {
                    id: Some(id),
                    name,
                    description,
                    interfaces,
                    is_wan,
                    masquerade_ipv4,
                    default_input_policy: input_policy.parse().unwrap_or(FirewallPolicy::Drop),
                    default_forward_policy: forward_policy.parse().unwrap_or(FirewallPolicy::Drop),
                }))
            }
            None => Ok(None),
        }
    }

    /// Save (insert or update) a firewall zone
    pub async fn save_firewall_zone(&self, zone: &FirewallZone) -> Result<i64> {
        if zone.name.is_empty() {
            anyhow::bail!("Zone name is required");
        }

        let mut tx = self.pool.begin().await?;

        let id = if let Some(id) = zone.id {
            // Update existing zone
            sqlx::query(
                r#"UPDATE firewall_zones SET
                   name = ?, description = ?, is_wan = ?, masquerade_ipv4 = ?,
                   default_input_policy = ?, default_forward_policy = ?,
                   updated_at = strftime('%s', 'now')
                   WHERE id = ?"#,
            )
            .bind(&zone.name)
            .bind(&zone.description)
            .bind(zone.is_wan)
            .bind(zone.masquerade_ipv4)
            .bind(zone.default_input_policy.to_string())
            .bind(zone.default_forward_policy.to_string())
            .bind(id)
            .execute(&mut *tx)
            .await
            .context("Failed to update firewall zone")?;

            // Clear existing interfaces
            sqlx::query("DELETE FROM firewall_zone_interfaces WHERE zone_id = ?")
                .bind(id)
                .execute(&mut *tx)
                .await
                .context("Failed to clear zone interfaces")?;

            id
        } else {
            // Insert new zone
            let result = sqlx::query(
                r#"INSERT INTO firewall_zones
                   (name, description, is_wan, masquerade_ipv4, default_input_policy,
                    default_forward_policy, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, strftime('%s', 'now'), strftime('%s', 'now'))"#,
            )
            .bind(&zone.name)
            .bind(&zone.description)
            .bind(zone.is_wan)
            .bind(zone.masquerade_ipv4)
            .bind(zone.default_input_policy.to_string())
            .bind(zone.default_forward_policy.to_string())
            .execute(&mut *tx)
            .await
            .context("Failed to insert firewall zone")?;

            result.last_insert_rowid()
        };

        // Insert interfaces
        for iface_name in &zone.interfaces {
            sqlx::query(
                "INSERT INTO firewall_zone_interfaces (zone_id, interface_name) VALUES (?, ?)",
            )
            .bind(id)
            .bind(iface_name)
            .execute(&mut *tx)
            .await
            .context("Failed to insert zone interface")?;
        }

        tx.commit().await?;
        info!("Saved firewall zone '{}' with id {}", zone.name, id);
        Ok(id)
    }

    /// Delete a firewall zone by ID
    /// Returns error if zone is in use by forwarding policies or rules
    pub async fn delete_firewall_zone(&self, id: i64) -> Result<bool> {
        // Check if zone is used in zone forwards
        let forward_count = sqlx::query_as::<_, (i64,)>(
            "SELECT COUNT(*) FROM firewall_zone_forwards WHERE source_zone_id = ? OR dest_zone_id = ?",
        )
        .bind(id)
        .bind(id)
        .fetch_one(self.pool)
        .await?
        .0;

        if forward_count > 0 {
            anyhow::bail!(
                "Cannot delete zone: it is used in {} zone forwarding policies",
                forward_count
            );
        }

        // Rule zone FKs are ON DELETE SET NULL and NULL means "any zone", so
        // deleting a referenced zone would silently widen those rules.
        let mut referencing: Vec<String> = Vec::new();
        let input_rules: Vec<(String,)> =
            sqlx::query_as("SELECT name FROM firewall_input_rules WHERE zone_id = ? ORDER BY id")
                .bind(id)
                .fetch_all(self.pool)
                .await?;
        referencing.extend(
            input_rules
                .into_iter()
                .map(|r| format!("input rule '{}'", r.0)),
        );
        let forward_rules: Vec<(String,)> = sqlx::query_as(
            "SELECT name FROM firewall_forward_rules WHERE source_zone_id = ? OR dest_zone_id = ? ORDER BY id",
        )
        .bind(id)
        .bind(id)
        .fetch_all(self.pool)
        .await?;
        referencing.extend(
            forward_rules
                .into_iter()
                .map(|r| format!("forward rule '{}'", r.0)),
        );
        let port_forwards: Vec<(String,)> = sqlx::query_as(
            "SELECT name FROM firewall_port_forwards WHERE source_zone_id = ? ORDER BY id",
        )
        .bind(id)
        .fetch_all(self.pool)
        .await?;
        referencing.extend(
            port_forwards
                .into_iter()
                .map(|r| format!("port forward '{}'", r.0)),
        );
        if !referencing.is_empty() {
            anyhow::bail!(
                "Cannot delete zone: it is referenced by {}. Delete or change these first",
                referencing.join(", ")
            );
        }

        let result = sqlx::query("DELETE FROM firewall_zones WHERE id = ?")
            .bind(id)
            .execute(self.pool)
            .await
            .context("Failed to delete firewall zone")?;

        Ok(result.rows_affected() > 0)
    }

    // ========================================================================
    // Zone Forward Policy CRUD Operations
    // ========================================================================

    /// Get all zone forward policies
    pub async fn get_zone_forwards(&self) -> Result<Vec<ZoneForwardPolicy>> {
        let rows = sqlx::query_as::<_, (i64, i64, i64, String, bool)>(
            r#"SELECT zf.id, zf.source_zone_id, zf.dest_zone_id, zf.policy, zf.enabled
               FROM firewall_zone_forwards zf
               ORDER BY zf.id"#,
        )
        .fetch_all(self.pool)
        .await
        .context("Failed to fetch zone forwards")?;

        // Get zone name lookup
        let zones = self.get_firewall_zones().await?;
        let zone_names: HashMap<i64, String> = zones
            .into_iter()
            .filter_map(|z| z.id.map(|id| (id, z.name)))
            .collect();

        let forwards = rows
            .into_iter()
            .filter_map(|(id, source_id, dest_id, policy, enabled)| {
                Some(ZoneForwardPolicy {
                    id: Some(id),
                    source_zone: zone_names.get(&source_id)?.clone(),
                    dest_zone: zone_names.get(&dest_id)?.clone(),
                    policy: policy.parse().unwrap_or(FirewallAction::Drop),
                    enabled,
                })
            })
            .collect();

        Ok(forwards)
    }

    /// Save (insert or update) a zone forward policy
    pub async fn save_zone_forward(&self, forward: &ZoneForwardPolicy) -> Result<i64> {
        // Look up zone IDs by name
        let source_zone = self
            .get_firewall_zone_by_name(&forward.source_zone)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Source zone '{}' not found", forward.source_zone))?;
        let dest_zone = self
            .get_firewall_zone_by_name(&forward.dest_zone)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Destination zone '{}' not found", forward.dest_zone))?;

        let source_id = source_zone.id.unwrap();
        let dest_id = dest_zone.id.unwrap();

        let id = if let Some(id) = forward.id {
            // Update existing
            sqlx::query(
                r#"UPDATE firewall_zone_forwards SET 
                   source_zone_id = ?, dest_zone_id = ?, policy = ?, enabled = ?,
                   updated_at = strftime('%s', 'now')
                   WHERE id = ?"#,
            )
            .bind(source_id)
            .bind(dest_id)
            .bind(forward.policy.to_string())
            .bind(forward.enabled)
            .bind(id)
            .execute(self.pool)
            .await
            .context("Failed to update zone forward")?;
            id
        } else {
            // Insert new - use INSERT OR REPLACE to handle unique constraint
            let result = sqlx::query(
                r#"INSERT INTO firewall_zone_forwards 
                   (source_zone_id, dest_zone_id, policy, enabled, created_at, updated_at)
                   VALUES (?, ?, ?, ?, strftime('%s', 'now'), strftime('%s', 'now'))
                   ON CONFLICT(source_zone_id, dest_zone_id) DO UPDATE SET
                   policy = excluded.policy, enabled = excluded.enabled,
                   updated_at = strftime('%s', 'now')"#,
            )
            .bind(source_id)
            .bind(dest_id)
            .bind(forward.policy.to_string())
            .bind(forward.enabled)
            .execute(self.pool)
            .await
            .context("Failed to insert zone forward")?;
            result.last_insert_rowid()
        };

        info!(
            "Saved zone forward {} -> {} ({})",
            forward.source_zone, forward.dest_zone, forward.policy
        );
        Ok(id)
    }

    /// Delete a zone forward policy by ID
    pub async fn delete_zone_forward(&self, id: i64) -> Result<bool> {
        let result = sqlx::query("DELETE FROM firewall_zone_forwards WHERE id = ?")
            .bind(id)
            .execute(self.pool)
            .await
            .context("Failed to delete zone forward")?;

        Ok(result.rows_affected() > 0)
    }

    // ========================================================================
    // Port Forward CRUD Operations
    // ========================================================================

    /// Get all port forwards
    pub async fn get_port_forwards(&self) -> Result<Vec<PortForward>> {
        let rows = sqlx::query_as::<
            _,
            (
                i64,
                String,
                Option<String>,
                bool,
                String,
                Option<i64>,
                i64,
                Option<i64>,
                Option<String>,
                String,
                Option<i64>,
            ),
        >(
            r#"SELECT pf.id, pf.name, pf.description, pf.enabled, pf.protocol,
                      pf.source_zone_id, pf.external_port_start, pf.external_port_end,
                      pf.source_ip, pf.dest_ip, pf.dest_port
               FROM firewall_port_forwards pf
               ORDER BY pf.name"#,
        )
        .fetch_all(self.pool)
        .await
        .context("Failed to fetch port forwards")?;

        // Get zone name lookup
        let zones = self.get_firewall_zones().await?;
        let zone_names: HashMap<i64, String> = zones
            .into_iter()
            .filter_map(|z| z.id.map(|id| (id, z.name)))
            .collect();

        let forwards = rows
            .into_iter()
            .map(
                |(
                    id,
                    name,
                    description,
                    enabled,
                    protocol,
                    source_zone_id,
                    ext_port_start,
                    ext_port_end,
                    source_ip,
                    dest_ip,
                    dest_port,
                )| {
                    PortForward {
                        id: Some(id),
                        name,
                        description,
                        enabled,
                        protocol: protocol.parse().unwrap_or(RuleProtocol::Tcp),
                        source_zone: source_zone_id.and_then(|id| zone_names.get(&id).cloned()),
                        external_port_start: ext_port_start as u16,
                        external_port_end: ext_port_end.map(|p| p as u16),
                        source_ip,
                        dest_ip,
                        dest_port: dest_port.map(|p| p as u16),
                    }
                },
            )
            .collect();

        Ok(forwards)
    }

    /// Save (insert or update) a port forward
    pub async fn save_port_forward(&self, pf: &PortForward) -> Result<i64> {
        if pf.name.is_empty() {
            anyhow::bail!("Port forward name is required");
        }
        if pf.dest_ip.is_empty() {
            anyhow::bail!("Destination IP is required");
        }
        if pf.external_port_start == 0 {
            anyhow::bail!("External port is required");
        }

        // Look up source zone ID if specified
        let source_zone_id = if let Some(ref zone_name) = pf.source_zone {
            let zone = self
                .get_firewall_zone_by_name(zone_name)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Zone '{}' not found", zone_name))?;
            zone.id
        } else {
            None
        };

        let id = if let Some(id) = pf.id {
            // Update existing
            sqlx::query(
                r#"UPDATE firewall_port_forwards SET 
                   name = ?, description = ?, enabled = ?, protocol = ?,
                   source_zone_id = ?, external_port_start = ?, external_port_end = ?,
                   source_ip = ?, dest_ip = ?, dest_port = ?,
                   updated_at = strftime('%s', 'now')
                   WHERE id = ?"#,
            )
            .bind(&pf.name)
            .bind(&pf.description)
            .bind(pf.enabled)
            .bind(pf.protocol.to_string())
            .bind(source_zone_id)
            .bind(pf.external_port_start as i64)
            .bind(pf.external_port_end.map(|p| p as i64))
            .bind(&pf.source_ip)
            .bind(&pf.dest_ip)
            .bind(pf.dest_port.map(|p| p as i64))
            .bind(id)
            .execute(self.pool)
            .await
            .context("Failed to update port forward")?;
            id
        } else {
            // Insert new
            let result = sqlx::query(
                r#"INSERT INTO firewall_port_forwards 
                   (name, description, enabled, protocol, source_zone_id, 
                    external_port_start, external_port_end, source_ip, dest_ip, dest_port,
                    created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%s', 'now'), strftime('%s', 'now'))"#,
            )
            .bind(&pf.name)
            .bind(&pf.description)
            .bind(pf.enabled)
            .bind(pf.protocol.to_string())
            .bind(source_zone_id)
            .bind(pf.external_port_start as i64)
            .bind(pf.external_port_end.map(|p| p as i64))
            .bind(&pf.source_ip)
            .bind(&pf.dest_ip)
            .bind(pf.dest_port.map(|p| p as i64))
            .execute(self.pool)
            .await
            .context("Failed to insert port forward")?;
            result.last_insert_rowid()
        };

        info!("Saved port forward '{}' with id {}", pf.name, id);
        Ok(id)
    }

    /// Delete a port forward by ID
    pub async fn delete_port_forward(&self, id: i64) -> Result<bool> {
        let result = sqlx::query("DELETE FROM firewall_port_forwards WHERE id = ?")
            .bind(id)
            .execute(self.pool)
            .await
            .context("Failed to delete port forward")?;

        Ok(result.rows_affected() > 0)
    }

    // ========================================================================
    // Input Rule CRUD Operations
    // ========================================================================

    /// Get all input rules
    pub async fn get_input_rules(&self) -> Result<Vec<InputRule>> {
        let rows = sqlx::query_as::<
            _,
            (
                i64,
                String,
                Option<String>,
                bool,
                i64,
                Option<i64>,
                Option<String>,
                Option<i64>,
                Option<i64>,
                Option<String>,
                String,
                bool,
                Option<String>,
                Option<String>,
            ),
        >(
            r#"SELECT id, name, description, enabled, position, zone_id, protocol,
                      port_start, port_end, source_ip, action, log_enabled, log_prefix, rate_limit
               FROM firewall_input_rules
               ORDER BY position, id"#,
        )
        .fetch_all(self.pool)
        .await
        .context("Failed to fetch input rules")?;

        // Get zone name lookup
        let zones = self.get_firewall_zones().await?;
        let zone_names: HashMap<i64, String> = zones
            .into_iter()
            .filter_map(|z| z.id.map(|id| (id, z.name)))
            .collect();

        let rules = rows
            .into_iter()
            .map(
                |(
                    id,
                    name,
                    description,
                    enabled,
                    position,
                    zone_id,
                    protocol,
                    port_start,
                    port_end,
                    source_ip,
                    action,
                    log_enabled,
                    log_prefix,
                    rate_limit,
                )| {
                    InputRule {
                        id: Some(id),
                        name,
                        description,
                        enabled,
                        position: position as i32,
                        zone: zone_id.and_then(|id| zone_names.get(&id).cloned()),
                        protocol: protocol.and_then(|p| p.parse::<RuleProtocol>().ok()),
                        port_start: port_start.map(|p| p as u16),
                        port_end: port_end.map(|p| p as u16),
                        source_ip,
                        action: action.parse().unwrap_or(FirewallAction::Accept),
                        log_enabled,
                        log_prefix,
                        rate_limit,
                    }
                },
            )
            .collect();

        Ok(rules)
    }

    /// Get a single input rule by ID
    pub async fn get_input_rule(&self, id: i64) -> Result<Option<InputRule>> {
        let row = sqlx::query_as::<
            _,
            (
                i64,
                String,
                Option<String>,
                bool,
                i64,
                Option<i64>,
                Option<String>,
                Option<i64>,
                Option<i64>,
                Option<String>,
                String,
                bool,
                Option<String>,
                Option<String>,
            ),
        >(
            r#"SELECT id, name, description, enabled, position, zone_id, protocol,
                      port_start, port_end, source_ip, action, log_enabled, log_prefix, rate_limit
               FROM firewall_input_rules WHERE id = ?"#,
        )
        .bind(id)
        .fetch_optional(self.pool)
        .await
        .context("Failed to fetch input rule")?;

        match row {
            Some((
                id,
                name,
                description,
                enabled,
                position,
                zone_id,
                protocol,
                port_start,
                port_end,
                source_ip,
                action,
                log_enabled,
                log_prefix,
                rate_limit,
            )) => {
                // Get zone name if zone_id is set
                let zone = if let Some(zid) = zone_id {
                    self.get_firewall_zone(zid).await?.map(|z| z.name)
                } else {
                    None
                };

                Ok(Some(InputRule {
                    id: Some(id),
                    name,
                    description,
                    enabled,
                    position: position as i32,
                    zone,
                    protocol: protocol.and_then(|p| p.parse::<RuleProtocol>().ok()),
                    port_start: port_start.map(|p| p as u16),
                    port_end: port_end.map(|p| p as u16),
                    source_ip,
                    action: action.parse().unwrap_or(FirewallAction::Accept),
                    log_enabled,
                    log_prefix,
                    rate_limit,
                }))
            }
            None => Ok(None),
        }
    }

    /// Save (insert or update) an input rule
    pub async fn save_input_rule(&self, rule: &InputRule) -> Result<i64> {
        if rule.name.is_empty() {
            anyhow::bail!("Input rule name is required");
        }

        // Look up zone ID if specified
        let zone_id = if let Some(ref zone_name) = rule.zone {
            let zone = self
                .get_firewall_zone_by_name(zone_name)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Zone '{}' not found", zone_name))?;
            zone.id
        } else {
            None
        };

        let id = if let Some(id) = rule.id {
            // Update existing
            sqlx::query(
                r#"UPDATE firewall_input_rules SET 
                   name = ?, description = ?, enabled = ?, position = ?, zone_id = ?,
                   protocol = ?, port_start = ?, port_end = ?, source_ip = ?,
                   action = ?, log_enabled = ?, log_prefix = ?, rate_limit = ?,
                   updated_at = strftime('%s', 'now')
                   WHERE id = ?"#,
            )
            .bind(&rule.name)
            .bind(&rule.description)
            .bind(rule.enabled)
            .bind(rule.position as i64)
            .bind(zone_id)
            .bind(rule.protocol.map(|p| p.to_string()))
            .bind(rule.port_start.map(|p| p as i64))
            .bind(rule.port_end.map(|p| p as i64))
            .bind(&rule.source_ip)
            .bind(rule.action.to_string())
            .bind(rule.log_enabled)
            .bind(&rule.log_prefix)
            .bind(&rule.rate_limit)
            .bind(id)
            .execute(self.pool)
            .await
            .context("Failed to update input rule")?;
            id
        } else {
            // Insert new
            let result = sqlx::query(
                r#"INSERT INTO firewall_input_rules 
                   (name, description, enabled, position, zone_id, protocol,
                    port_start, port_end, source_ip, action, log_enabled, log_prefix, rate_limit,
                    created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%s', 'now'), strftime('%s', 'now'))"#,
            )
            .bind(&rule.name)
            .bind(&rule.description)
            .bind(rule.enabled)
            .bind(rule.position as i64)
            .bind(zone_id)
            .bind(rule.protocol.map(|p| p.to_string()))
            .bind(rule.port_start.map(|p| p as i64))
            .bind(rule.port_end.map(|p| p as i64))
            .bind(&rule.source_ip)
            .bind(rule.action.to_string())
            .bind(rule.log_enabled)
            .bind(&rule.log_prefix)
            .bind(&rule.rate_limit)
            .execute(self.pool)
            .await
            .context("Failed to insert input rule")?;
            result.last_insert_rowid()
        };

        info!("Saved input rule '{}' with id {}", rule.name, id);
        Ok(id)
    }

    /// Delete an input rule by ID
    pub async fn delete_input_rule(&self, id: i64) -> Result<bool> {
        let result = sqlx::query("DELETE FROM firewall_input_rules WHERE id = ?")
            .bind(id)
            .execute(self.pool)
            .await
            .context("Failed to delete input rule")?;

        Ok(result.rows_affected() > 0)
    }

    // ========================================================================
    // Forward Rule CRUD Operations
    // ========================================================================

    /// Get all forward rules
    pub async fn get_forward_rules(&self) -> Result<Vec<ForwardRule>> {
        let rows = sqlx::query_as::<
            _,
            (
                i64,
                String,
                Option<String>,
                bool,
                i64,
                Option<i64>,
                Option<i64>,
                Option<String>,
                Option<i64>,
                Option<i64>,
                Option<String>,
                Option<String>,
                String,
                bool,
                Option<String>,
                Option<String>,
            ),
        >(
            r#"SELECT id, name, description, enabled, position, source_zone_id, dest_zone_id,
                      protocol, dest_port_start, dest_port_end, source_ip, dest_ip,
                      action, log_enabled, log_prefix, rate_limit
               FROM firewall_forward_rules
               ORDER BY position, id"#,
        )
        .fetch_all(self.pool)
        .await
        .context("Failed to fetch forward rules")?;

        // Get zone name lookup
        let zones = self.get_firewall_zones().await?;
        let zone_names: HashMap<i64, String> = zones
            .into_iter()
            .filter_map(|z| z.id.map(|id| (id, z.name)))
            .collect();

        let rules = rows
            .into_iter()
            .map(
                |(
                    id,
                    name,
                    description,
                    enabled,
                    position,
                    source_zone_id,
                    dest_zone_id,
                    protocol,
                    dest_port_start,
                    dest_port_end,
                    source_ip,
                    dest_ip,
                    action,
                    log_enabled,
                    log_prefix,
                    rate_limit,
                )| {
                    ForwardRule {
                        id: Some(id),
                        name,
                        description,
                        enabled,
                        position: position as i32,
                        source_zone: source_zone_id.and_then(|id| zone_names.get(&id).cloned()),
                        dest_zone: dest_zone_id.and_then(|id| zone_names.get(&id).cloned()),
                        protocol: protocol.and_then(|p| p.parse::<RuleProtocol>().ok()),
                        dest_port_start: dest_port_start.map(|p| p as u16),
                        dest_port_end: dest_port_end.map(|p| p as u16),
                        source_ip,
                        dest_ip,
                        action: action.parse().unwrap_or(FirewallAction::Accept),
                        log_enabled,
                        log_prefix,
                        rate_limit,
                    }
                },
            )
            .collect();

        Ok(rules)
    }

    /// Get a single forward rule by ID
    pub async fn get_forward_rule(&self, id: i64) -> Result<Option<ForwardRule>> {
        let row = sqlx::query_as::<
            _,
            (
                i64,
                String,
                Option<String>,
                bool,
                i64,
                Option<i64>,
                Option<i64>,
                Option<String>,
                Option<i64>,
                Option<i64>,
                Option<String>,
                Option<String>,
                String,
                bool,
                Option<String>,
                Option<String>,
            ),
        >(
            r#"SELECT id, name, description, enabled, position, source_zone_id, dest_zone_id,
                      protocol, dest_port_start, dest_port_end, source_ip, dest_ip,
                      action, log_enabled, log_prefix, rate_limit
               FROM firewall_forward_rules WHERE id = ?"#,
        )
        .bind(id)
        .fetch_optional(self.pool)
        .await
        .context("Failed to fetch forward rule")?;

        match row {
            Some((
                id,
                name,
                description,
                enabled,
                position,
                source_zone_id,
                dest_zone_id,
                protocol,
                dest_port_start,
                dest_port_end,
                source_ip,
                dest_ip,
                action,
                log_enabled,
                log_prefix,
                rate_limit,
            )) => {
                // Get zone names
                let source_zone = if let Some(zid) = source_zone_id {
                    self.get_firewall_zone(zid).await?.map(|z| z.name)
                } else {
                    None
                };
                let dest_zone = if let Some(zid) = dest_zone_id {
                    self.get_firewall_zone(zid).await?.map(|z| z.name)
                } else {
                    None
                };

                Ok(Some(ForwardRule {
                    id: Some(id),
                    name,
                    description,
                    enabled,
                    position: position as i32,
                    source_zone,
                    dest_zone,
                    protocol: protocol.and_then(|p| p.parse::<RuleProtocol>().ok()),
                    dest_port_start: dest_port_start.map(|p| p as u16),
                    dest_port_end: dest_port_end.map(|p| p as u16),
                    source_ip,
                    dest_ip,
                    action: action.parse().unwrap_or(FirewallAction::Accept),
                    log_enabled,
                    log_prefix,
                    rate_limit,
                }))
            }
            None => Ok(None),
        }
    }

    /// Save (insert or update) a forward rule
    pub async fn save_forward_rule(&self, rule: &ForwardRule) -> Result<i64> {
        if rule.name.is_empty() {
            anyhow::bail!("Forward rule name is required");
        }

        // Look up zone IDs if specified
        let source_zone_id = if let Some(ref zone_name) = rule.source_zone {
            let zone = self
                .get_firewall_zone_by_name(zone_name)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Source zone '{}' not found", zone_name))?;
            zone.id
        } else {
            None
        };

        let dest_zone_id = if let Some(ref zone_name) = rule.dest_zone {
            let zone = self
                .get_firewall_zone_by_name(zone_name)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Destination zone '{}' not found", zone_name))?;
            zone.id
        } else {
            None
        };

        let id = if let Some(id) = rule.id {
            // Update existing
            sqlx::query(
                r#"UPDATE firewall_forward_rules SET 
                   name = ?, description = ?, enabled = ?, position = ?,
                   source_zone_id = ?, dest_zone_id = ?, protocol = ?,
                   dest_port_start = ?, dest_port_end = ?, source_ip = ?, dest_ip = ?,
                   action = ?, log_enabled = ?, log_prefix = ?, rate_limit = ?,
                   updated_at = strftime('%s', 'now')
                   WHERE id = ?"#,
            )
            .bind(&rule.name)
            .bind(&rule.description)
            .bind(rule.enabled)
            .bind(rule.position as i64)
            .bind(source_zone_id)
            .bind(dest_zone_id)
            .bind(rule.protocol.map(|p| p.to_string()))
            .bind(rule.dest_port_start.map(|p| p as i64))
            .bind(rule.dest_port_end.map(|p| p as i64))
            .bind(&rule.source_ip)
            .bind(&rule.dest_ip)
            .bind(rule.action.to_string())
            .bind(rule.log_enabled)
            .bind(&rule.log_prefix)
            .bind(&rule.rate_limit)
            .bind(id)
            .execute(self.pool)
            .await
            .context("Failed to update forward rule")?;
            id
        } else {
            // Insert new
            let result = sqlx::query(
                r#"INSERT INTO firewall_forward_rules 
                   (name, description, enabled, position, source_zone_id, dest_zone_id,
                    protocol, dest_port_start, dest_port_end, source_ip, dest_ip,
                    action, log_enabled, log_prefix, rate_limit, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%s', 'now'), strftime('%s', 'now'))"#,
            )
            .bind(&rule.name)
            .bind(&rule.description)
            .bind(rule.enabled)
            .bind(rule.position as i64)
            .bind(source_zone_id)
            .bind(dest_zone_id)
            .bind(rule.protocol.map(|p| p.to_string()))
            .bind(rule.dest_port_start.map(|p| p as i64))
            .bind(rule.dest_port_end.map(|p| p as i64))
            .bind(&rule.source_ip)
            .bind(&rule.dest_ip)
            .bind(rule.action.to_string())
            .bind(rule.log_enabled)
            .bind(&rule.log_prefix)
            .bind(&rule.rate_limit)
            .execute(self.pool)
            .await
            .context("Failed to insert forward rule")?;
            result.last_insert_rowid()
        };

        info!("Saved forward rule '{}' with id {}", rule.name, id);
        Ok(id)
    }

    /// Delete a forward rule by ID
    pub async fn delete_forward_rule(&self, id: i64) -> Result<bool> {
        let result = sqlx::query("DELETE FROM firewall_forward_rules WHERE id = ?")
            .bind(id)
            .execute(self.pool)
            .await
            .context("Failed to delete forward rule")?;

        Ok(result.rows_affected() > 0)
    }

    // ========================================================================
    // Firewall Config Aggregate Operations
    // ========================================================================

    /// Get complete firewall configuration
    pub async fn get_firewall_config(&self) -> Result<FirewallConfig> {
        Ok(FirewallConfig {
            zones: self.get_firewall_zones().await?,
            zone_forwards: self.get_zone_forwards().await?,
            port_forwards: self.get_port_forwards().await?,
            input_rules: self.get_input_rules().await?,
            forward_rules: self.get_forward_rules().await?,
            global_settings: self.get_firewall_global_settings().await?,
        })
    }

    // ========================================================================
    // Firewall Global Settings Operations
    // ========================================================================

    /// Get global firewall settings
    pub async fn get_firewall_global_settings(&self) -> Result<FirewallGlobalSettings> {
        let row = sqlx::query_as::<_, (bool, bool, bool)>(
            "SELECT ping_wan_enabled, ping_lan_enabled, hairpin_nat_enabled 
             FROM firewall_global_settings WHERE id = 1",
        )
        .fetch_optional(self.pool)
        .await
        .context("Failed to fetch firewall global settings")?;

        match row {
            Some((ping_wan, ping_lan, hairpin)) => Ok(FirewallGlobalSettings {
                ping_wan_enabled: ping_wan,
                ping_lan_enabled: ping_lan,
                hairpin_nat_enabled: hairpin,
            }),
            None => {
                // Return defaults if no row exists (shouldn't happen after migration)
                Ok(FirewallGlobalSettings::default())
            }
        }
    }

    /// Save global firewall settings
    pub async fn save_firewall_global_settings(
        &self,
        settings: &FirewallGlobalSettings,
    ) -> Result<()> {
        sqlx::query(
            r#"INSERT OR REPLACE INTO firewall_global_settings 
               (id, ping_wan_enabled, ping_lan_enabled, hairpin_nat_enabled, updated_at)
               VALUES (1, ?, ?, ?, strftime('%s', 'now'))"#,
        )
        .bind(settings.ping_wan_enabled)
        .bind(settings.ping_lan_enabled)
        .bind(settings.hairpin_nat_enabled)
        .execute(self.pool)
        .await
        .context("Failed to save firewall global settings")?;

        info!(
            "Saved firewall global settings: ping_wan={}, ping_lan={}, hairpin={}",
            settings.ping_wan_enabled, settings.ping_lan_enabled, settings.hairpin_nat_enabled
        );
        Ok(())
    }

    // ========================================================================
    // Active and Rollback State Operations
    // ========================================================================

    /// Save the last successfully confirmed firewall configuration.
    pub async fn save_active_firewall_config(&self, config: &FirewallConfig) -> Result<()> {
        let config_json =
            serde_json::to_string(config).context("Failed to serialize active firewall config")?;

        sqlx::query(
            r#"INSERT OR REPLACE INTO firewall_active_config (id, config_json, updated_at)
               VALUES (1, ?, strftime('%s', 'now'))"#,
        )
        .bind(config_json)
        .execute(self.pool)
        .await
        .context("Failed to save active firewall config")?;

        info!("Saved confirmed firewall configuration snapshot");
        Ok(())
    }

    /// Get the last successfully confirmed firewall configuration.
    pub async fn get_active_firewall_config(&self) -> Result<Option<FirewallConfig>> {
        let row = sqlx::query_as::<_, (String,)>(
            "SELECT config_json FROM firewall_active_config WHERE id = 1",
        )
        .fetch_optional(self.pool)
        .await
        .context("Failed to fetch active firewall config")?;

        row.map(|(config_json,)| {
            serde_json::from_str(&config_json)
                .context("Failed to deserialize active firewall config")
        })
        .transpose()
    }

    /// Clear the active snapshot when rollback restores a system with no
    /// Keystone-owned nftables tables.
    pub async fn clear_active_firewall_config(&self) -> Result<()> {
        sqlx::query("DELETE FROM firewall_active_config WHERE id = 1")
            .execute(self.pool)
            .await
            .context("Failed to clear active firewall config")?;
        info!("Cleared confirmed firewall configuration snapshot");
        Ok(())
    }

    /// Save rollback state for safe apply. `None` means Keystone previously
    /// owned no nftables tables and rollback should remove them.
    pub async fn save_rollback_state(
        &self,
        config: Option<&FirewallConfig>,
        rollback_at: i64,
    ) -> Result<()> {
        let previous_present = config.is_some();
        let config_json = serde_json::to_string(config.unwrap_or(&FirewallConfig::default()))
            .context("Failed to serialize firewall rollback config")?;

        sqlx::query(
            r#"INSERT OR REPLACE INTO firewall_rollback_state
               (id, previous_config, rollback_at, created_at, previous_present)
               VALUES (1, ?, ?, strftime('%s', 'now'), ?)"#,
        )
        .bind(config_json)
        .bind(rollback_at)
        .bind(previous_present)
        .execute(self.pool)
        .await
        .context("Failed to save rollback state")?;

        info!("Saved rollback state, will rollback at {}", rollback_at);
        Ok(())
    }

    /// Get pending rollback state.
    pub async fn get_rollback_state(&self) -> Result<Option<(Option<FirewallConfig>, i64)>> {
        let row = sqlx::query_as::<_, (String, i64, bool)>(
            r#"SELECT previous_config, rollback_at, previous_present
               FROM firewall_rollback_state WHERE id = 1"#,
        )
        .fetch_optional(self.pool)
        .await
        .context("Failed to fetch rollback state")?;

        match row {
            Some((config_json, rollback_at, previous_present)) => {
                let config = if previous_present {
                    Some(
                        serde_json::from_str(&config_json)
                            .context("Failed to deserialize rollback config")?,
                    )
                } else {
                    None
                };
                Ok(Some((config, rollback_at)))
            }
            None => Ok(None),
        }
    }

    /// Clear rollback state (called on confirm)
    pub async fn clear_rollback_state(&self) -> Result<()> {
        sqlx::query("DELETE FROM firewall_rollback_state WHERE id = 1")
            .execute(self.pool)
            .await
            .context("Failed to clear rollback state")?;

        info!("Cleared rollback state");
        Ok(())
    }
}

#[cfg(test)]
mod zone_delete_tests {
    use keystone_core::{FirewallZone, ForwardRule, InputRule, PortForward};

    async fn db_with_zone() -> (crate::db::Database, i64) {
        let db = crate::db::Database::new_in_memory().await.unwrap();
        let id = db
            .save_firewall_zone(&FirewallZone {
                name: "testzone".into(),
                interfaces: vec!["eth1".into()],
                ..Default::default()
            })
            .await
            .unwrap();
        (db, id)
    }

    #[tokio::test]
    async fn unreferenced_zone_can_be_deleted() {
        let (db, id) = db_with_zone().await;
        assert!(db.delete_firewall_zone(id).await.unwrap());
    }

    #[tokio::test]
    async fn zone_referenced_by_input_rule_cannot_be_deleted() {
        let (db, id) = db_with_zone().await;
        db.save_input_rule(&InputRule {
            name: "ssh".into(),
            zone: Some("testzone".into()),
            ..Default::default()
        })
        .await
        .unwrap();
        let err = db.delete_firewall_zone(id).await.unwrap_err().to_string();
        assert!(err.contains("input rule 'ssh'"), "{err}");
    }

    #[tokio::test]
    async fn zone_referenced_by_forward_rule_or_port_forward_cannot_be_deleted() {
        let (db, id) = db_with_zone().await;
        db.save_forward_rule(&ForwardRule {
            name: "fwd".into(),
            dest_zone: Some("testzone".into()),
            ..Default::default()
        })
        .await
        .unwrap();
        let err = db.delete_firewall_zone(id).await.unwrap_err().to_string();
        assert!(err.contains("forward rule 'fwd'"), "{err}");

        let (db, id) = db_with_zone().await;
        db.save_port_forward(&PortForward {
            name: "web".into(),
            source_zone: Some("testzone".into()),
            external_port_start: 80,
            dest_ip: "10.0.0.2".into(),
            ..Default::default()
        })
        .await
        .unwrap();
        let err = db.delete_firewall_zone(id).await.unwrap_err().to_string();
        assert!(err.contains("port forward 'web'"), "{err}");
    }
}
