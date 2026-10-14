//! Renaming an interface everywhere the configuration refers to it.

use anyhow::{Context, Result, bail};
use sqlx::{Sqlite, Transaction};
use tracing::info;

use super::Database;

/// One statement per plain interface-name column.
const RENAME_STATEMENTS: &[&str] = &[
    "UPDATE managed_interfaces SET name = ? WHERE name = ?",
    "UPDATE interface_config SET interface_name = ? WHERE interface_name = ?",
    "UPDATE interface_config SET dhcp_prefix_delegation_uplink = ? WHERE dhcp_prefix_delegation_uplink = ?",
    "UPDATE firewall_zone_interfaces SET interface_name = ? WHERE interface_name = ?",
    "UPDATE dnsmasq_listen_interfaces SET interface = ? WHERE interface = ?",
    "UPDATE dnsmasq_except_interfaces SET interface = ? WHERE interface = ?",
    "UPDATE dnsmasq_no_dhcp_interfaces SET interface = ? WHERE interface = ?",
    "UPDATE dnsmasq_dhcp_ranges SET interface = ? WHERE interface = ?",
    "UPDATE caddy_config SET bind_interface = ? WHERE bind_interface = ?",
    "UPDATE sqm_config SET interface = ? WHERE interface = ?",
    "UPDATE upnp_config SET wan_interface = ? WHERE wan_interface = ?",
    "UPDATE upnp_lan_interfaces SET interface = ? WHERE interface = ?",
];

impl Database {
    /// Point every reference to interface `old` at `new`, in one transaction.
    ///
    /// Callers check that `new` is free first. Bridge membership is a JSON
    /// array, so it is rewritten in Rust. The SQM *applied* state keeps the old
    /// name on purpose: the next SQM apply uses it to tear the old shaper down.
    pub async fn rename_interface_references(&self, old: &str, new: &str) -> Result<()> {
        if old == new {
            bail!("The new interface name is the same as the current one");
        }
        let mut tx = self
            .pool
            .begin()
            .await
            .context("Failed to start the rename transaction")?;

        for &sql in RENAME_STATEMENTS {
            sqlx::query(sql)
                .bind(new)
                .bind(old)
                .execute(&mut *tx)
                .await
                .with_context(|| format!("Failed to rename {old}: {sql}"))?;
        }
        rename_bridge_members(&mut tx, old, new).await?;

        tx.commit()
            .await
            .context("Failed to commit the interface rename")?;
        info!("Renamed interface {old} to {new} in the configuration");
        Ok(())
    }
}

async fn rename_bridge_members(
    tx: &mut Transaction<'_, Sqlite>,
    old: &str,
    new: &str,
) -> Result<()> {
    let rows: Vec<(i64, String)> = sqlx::query_as("SELECT id, members FROM bridge_config")
        .fetch_all(&mut **tx)
        .await
        .context("Failed to read bridge members")?;
    for (id, members) in rows {
        let mut members: Vec<String> =
            serde_json::from_str(&members).context("Stored bridge members are invalid")?;
        if !members.iter().any(|member| member == old) {
            continue;
        }
        for member in &mut members {
            if member == old {
                *member = new.to_string();
            }
        }
        sqlx::query("UPDATE bridge_config SET members = ? WHERE id = ?")
            .bind(serde_json::to_string(&members)?)
            .bind(id)
            .execute(&mut **tx)
            .await
            .context("Failed to rename a bridge member")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn count(db: &Database, sql: &'static str, bind: &str) -> i64 {
        sqlx::query_scalar(sql)
            .bind(bind)
            .fetch_one(db.pool())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn rename_updates_every_reference() {
        let db = Database::new_in_memory().await.unwrap();
        let pool = db.pool();
        for sql in [
            "INSERT INTO interface_config (interface_name, role, enabled, dhcp_mode, created_at, updated_at) VALUES ('enp1s0', 'wan', 1, 'none', 0, 0)",
            "INSERT INTO interface_config (interface_name, role, enabled, dhcp_mode, dhcp_prefix_delegation_uplink, created_at, updated_at) VALUES ('enp2s0', 'lan', 1, 'none', 'enp1s0', 0, 0)",
            "INSERT INTO firewall_zones (name, description, default_input_policy, created_at, updated_at) VALUES ('wanz', '', 'drop', 0, 0)",
            "INSERT INTO firewall_zone_interfaces (zone_id, interface_name) SELECT id, 'enp1s0' FROM firewall_zones WHERE name = 'wanz'",
            "INSERT INTO dnsmasq_listen_interfaces (interface) VALUES ('enp1s0')",
            "INSERT INTO dnsmasq_dhcp_ranges (name, interface, start_address, end_address) VALUES ('r', 'enp1s0', '10.0.0.2', '10.0.0.9')",
            "UPDATE caddy_config SET bind_interface = 'enp1s0'",
            "UPDATE sqm_config SET interface = 'enp1s0' WHERE id = 1",
            "UPDATE upnp_config SET wan_interface = 'enp1s0' WHERE id = 1",
            "INSERT INTO upnp_lan_interfaces (interface) VALUES ('enp1s0')",
            "INSERT INTO bridge_config (name, members) VALUES ('br0', '[\"enp3s0\",\"enp1s0\"]')",
            "INSERT INTO bridge_config (name, members) VALUES ('br1', '[\"enp3s0\"]')",
            "INSERT INTO sqm_applied (id, config_json) VALUES (1, '{\"interface\":\"enp1s0\"}')",
        ] {
            sqlx::query(sql)
                .execute(pool)
                .await
                .unwrap_or_else(|e| panic!("{sql}: {e}"));
        }

        db.rename_interface_references("enp1s0", "wan0")
            .await
            .unwrap();

        for sql in [
            "SELECT COUNT(*) FROM interface_config WHERE interface_name = ?",
            "SELECT COUNT(*) FROM interface_config WHERE dhcp_prefix_delegation_uplink = ?",
            "SELECT COUNT(*) FROM firewall_zone_interfaces WHERE interface_name = ?",
            "SELECT COUNT(*) FROM dnsmasq_listen_interfaces WHERE interface = ?",
            "SELECT COUNT(*) FROM dnsmasq_dhcp_ranges WHERE interface = ?",
            "SELECT COUNT(*) FROM caddy_config WHERE bind_interface = ?",
            "SELECT COUNT(*) FROM sqm_config WHERE interface = ?",
            "SELECT COUNT(*) FROM upnp_config WHERE wan_interface = ?",
            "SELECT COUNT(*) FROM upnp_lan_interfaces WHERE interface = ?",
            "SELECT COUNT(*) FROM bridge_config WHERE members LIKE '%' || ? || '%'",
        ] {
            assert_eq!(count(&db, sql, "wan0").await, 1, "{sql}");
            assert_eq!(count(&db, sql, "enp1s0").await, 0, "{sql}");
        }
        let untouched: String =
            sqlx::query_scalar("SELECT members FROM bridge_config WHERE name = 'br1'")
                .fetch_one(pool)
                .await
                .unwrap();
        assert_eq!(untouched, "[\"enp3s0\"]");
        let applied: String =
            sqlx::query_scalar("SELECT config_json FROM sqm_applied WHERE id = 1")
                .fetch_one(pool)
                .await
                .unwrap();
        assert!(
            applied.contains("enp1s0"),
            "applied SQM state keeps the old name"
        );
    }

    #[tokio::test]
    async fn rename_is_all_or_nothing() {
        let db = Database::new_in_memory().await.unwrap();
        let pool = db.pool();
        sqlx::query("INSERT INTO dnsmasq_listen_interfaces (interface) VALUES ('enp1s0')")
            .execute(pool)
            .await
            .unwrap();
        // The target name is already taken in a UNIQUE column.
        sqlx::query("INSERT INTO dnsmasq_listen_interfaces (interface) VALUES ('wan0')")
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("UPDATE sqm_config SET interface = 'enp1s0' WHERE id = 1")
            .execute(pool)
            .await
            .unwrap();

        assert!(
            db.rename_interface_references("enp1s0", "wan0")
                .await
                .is_err()
        );
        assert_eq!(
            count(
                &db,
                "SELECT COUNT(*) FROM sqm_config WHERE interface = ?",
                "enp1s0"
            )
            .await,
            1,
            "an earlier table must be rolled back with the failed one"
        );
        assert!(
            db.rename_interface_references("enp1s0", "enp1s0")
                .await
                .is_err()
        );
    }
}
