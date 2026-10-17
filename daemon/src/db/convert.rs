//! Moving a LAN interface's configuration onto a bridge.

use anyhow::{Context, Result, bail};
use sqlx::{Sqlite, Transaction};
use tracing::info;

use super::Database;

/// References that follow the LAN configuration from the member to the bridge:
/// the addressing, the firewall zone, DHCP/DNS service binding, and anything
/// else that listens on the LAN. What stays on the member: its link settings
/// (`managed_interfaces`, the `.link` file), shaping and anything WAN-facing.
const MOVE_STATEMENTS: &[&str] = &[
    "UPDATE firewall_zone_interfaces SET interface_name = ? WHERE interface_name = ?",
    "UPDATE dnsmasq_listen_interfaces SET interface = ? WHERE interface = ?",
    "UPDATE dnsmasq_except_interfaces SET interface = ? WHERE interface = ?",
    "UPDATE dnsmasq_no_dhcp_interfaces SET interface = ? WHERE interface = ?",
    "UPDATE dnsmasq_dhcp_ranges SET interface = ? WHERE interface = ?",
    "UPDATE caddy_config SET bind_interface = ? WHERE bind_interface = ?",
    "UPDATE upnp_lan_interfaces SET interface = ? WHERE interface = ?",
];

impl Database {
    /// Create bridge `bridge` with `member` as its only member and move
    /// `member`'s interface configuration and LAN references onto it, in one
    /// transaction. Returns the bridge's id.
    ///
    /// Callers have checked that `member` has an interface configuration and
    /// that `bridge` is free.
    pub async fn convert_interface_to_bridge(&self, member: &str, bridge: &str) -> Result<i64> {
        let mut tx = self
            .pool
            .begin()
            .await
            .context("Failed to start the conversion transaction")?;

        let config_id: i64 = sqlx::query_scalar(
            "UPDATE interface_config SET interface_name = ?, updated_at = strftime('%s', 'now') \
             WHERE interface_name = ? RETURNING id",
        )
        .bind(bridge)
        .bind(member)
        .fetch_optional(&mut *tx)
        .await
        .context("Failed to move the interface configuration")?
        .with_context(|| format!("{member} has no interface configuration"))?;

        for &sql in MOVE_STATEMENTS {
            sqlx::query(sql)
                .bind(bridge)
                .bind(member)
                .execute(&mut *tx)
                .await
                .with_context(|| format!("Failed to move {member} to {bridge}: {sql}"))?;
        }

        let bridge_id = insert_bridge(&mut tx, member, bridge, config_id).await?;
        tx.commit()
            .await
            .context("Failed to commit the bridge conversion")?;
        info!("Moved the configuration of {member} onto new bridge {bridge}");
        Ok(bridge_id)
    }
}

async fn insert_bridge(
    tx: &mut Transaction<'_, Sqlite>,
    member: &str,
    bridge: &str,
    config_id: i64,
) -> Result<i64> {
    let members = serde_json::to_string(&[member])?;
    let description = format!("LAN bridge (was {member})");
    let result = sqlx::query(
        "INSERT INTO bridge_config (name, members, stp, description, interface_config_id) \
         VALUES (?, ?, 0, ?, ?)",
    )
    .bind(bridge)
    .bind(members)
    .bind(description)
    .bind(config_id)
    .execute(&mut **tx)
    .await;
    match result {
        Ok(result) => Ok(result.last_insert_rowid()),
        Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
            bail!("A bridge named {bridge} already exists")
        }
        Err(error) => Err(error).context("Failed to create the bridge"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn exec(db: &Database, sql: &'static str) {
        sqlx::query(sql)
            .execute(db.pool())
            .await
            .unwrap_or_else(|e| panic!("{sql}: {e}"));
    }

    async fn count(db: &Database, sql: &'static str, bind: &str) -> i64 {
        sqlx::query_scalar(sql)
            .bind(bind)
            .fetch_one(db.pool())
            .await
            .unwrap()
    }

    async fn lan_database() -> Database {
        let db = Database::new_in_memory().await.unwrap();
        for sql in [
            "INSERT INTO interface_config (interface_name, role, enabled, dhcp_mode, created_at, updated_at) VALUES ('lan0', 'lan', 1, 'none', 0, 0)",
            "INSERT INTO interface_config (interface_name, role, enabled, dhcp_mode, created_at, updated_at) VALUES ('wan0', 'wan', 1, 'ipv4', 0, 0)",
            "INSERT INTO firewall_zone_interfaces (zone_id, interface_name) SELECT id, 'lan0' FROM firewall_zones WHERE name = 'lan'",
            "INSERT INTO firewall_zone_interfaces (zone_id, interface_name) SELECT id, 'wan0' FROM firewall_zones WHERE name = 'wan'",
            "INSERT INTO dnsmasq_listen_interfaces (interface) VALUES ('lan0')",
            "INSERT INTO dnsmasq_except_interfaces (interface) VALUES ('wan0')",
            "INSERT INTO dnsmasq_dhcp_ranges (name, interface, start_address, end_address) VALUES ('r', 'lan0', '192.168.1.100', '192.168.1.200')",
            "UPDATE caddy_config SET bind_interface = 'lan0'",
            "INSERT INTO upnp_lan_interfaces (interface) VALUES ('lan0')",
            "UPDATE sqm_config SET interface = 'wan0' WHERE id = 1",
        ] {
            exec(&db, sql).await;
        }
        db
    }

    #[tokio::test]
    async fn the_lan_configuration_and_its_references_move_to_the_bridge() {
        let db = lan_database().await;
        let id = db
            .convert_interface_to_bridge("lan0", "br-lan")
            .await
            .unwrap();

        for sql in [
            "SELECT COUNT(*) FROM interface_config WHERE interface_name = ? AND role = 'lan'",
            "SELECT COUNT(*) FROM firewall_zone_interfaces WHERE interface_name = ?",
            "SELECT COUNT(*) FROM dnsmasq_listen_interfaces WHERE interface = ?",
            "SELECT COUNT(*) FROM dnsmasq_dhcp_ranges WHERE interface = ?",
            "SELECT COUNT(*) FROM caddy_config WHERE bind_interface = ?",
            "SELECT COUNT(*) FROM upnp_lan_interfaces WHERE interface = ?",
        ] {
            assert_eq!(count(&db, sql, "br-lan").await, 1, "{sql}");
            assert_eq!(count(&db, sql, "lan0").await, 0, "{sql}");
        }

        // The bridge has the old port as its only member and points at the
        // configuration that moved.
        let bridge = db.get_bridge(id).await.unwrap().expect("bridge exists");
        assert_eq!(bridge.name, "br-lan");
        assert_eq!(bridge.members, vec!["lan0".to_string()]);
        let config_id: i64 =
            sqlx::query_scalar("SELECT id FROM interface_config WHERE interface_name = 'br-lan'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(bridge.interface_config_id, Some(config_id));
    }

    #[tokio::test]
    async fn wan_side_references_stay_where_they_were() {
        let db = lan_database().await;
        db.convert_interface_to_bridge("lan0", "br-lan")
            .await
            .unwrap();
        assert_eq!(
            count(
                &db,
                "SELECT COUNT(*) FROM interface_config WHERE interface_name = ?",
                "wan0"
            )
            .await,
            1
        );
        assert_eq!(
            count(
                &db,
                "SELECT COUNT(*) FROM dnsmasq_except_interfaces WHERE interface = ?",
                "wan0"
            )
            .await,
            1
        );
        assert_eq!(
            count(
                &db,
                "SELECT COUNT(*) FROM firewall_zone_interfaces WHERE interface_name = ?",
                "wan0"
            )
            .await,
            1
        );
        assert_eq!(
            count(
                &db,
                "SELECT COUNT(*) FROM sqm_config WHERE interface = ?",
                "wan0"
            )
            .await,
            1
        );
    }

    #[tokio::test]
    async fn a_failed_conversion_changes_nothing() {
        let db = lan_database().await;
        db.convert_interface_to_bridge("lan0", "br-lan")
            .await
            .unwrap();
        // lan0 no longer has a configuration, so a second conversion fails
        // before it can touch the bridge or the references.
        assert!(
            db.convert_interface_to_bridge("lan0", "br-other")
                .await
                .is_err()
        );
        assert_eq!(db.get_all_bridges().await.unwrap().len(), 1);

        // A duplicate bridge name rolls the configuration move back.
        exec(&db, "INSERT INTO interface_config (interface_name, role, enabled, dhcp_mode, created_at, updated_at) VALUES ('lan1', 'lan', 1, 'none', 0, 0)").await;
        assert!(
            db.convert_interface_to_bridge("lan1", "br-lan")
                .await
                .is_err()
        );
        assert_eq!(
            count(
                &db,
                "SELECT COUNT(*) FROM interface_config WHERE interface_name = ?",
                "lan1"
            )
            .await,
            1,
            "the configuration move must be rolled back with the failed bridge insert"
        );
    }
}
