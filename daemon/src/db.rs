//! Database module for Keystone configuration storage
//!
//! Uses SQLite via sqlx for persistent configuration storage.

use anyhow::{Context, Result};
use keystone_core::{InterfaceRole, ManagedInterface};
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
use tracing::info;

const DB_PATH: &str = "/var/lib/keystone/keystone.db";

/// Database connection pool wrapper
#[derive(Clone)]
pub struct Database {
    pool: SqlitePool,
}

impl Database {
    /// Initialize the database, creating tables if needed
    pub async fn new() -> Result<Self> {
        // Ensure directory exists
        let db_dir = std::path::Path::new(DB_PATH).parent().unwrap();
        std::fs::create_dir_all(db_dir)
            .context("Failed to create database directory")?;

        let db_url = format!("sqlite:{}?mode=rwc", DB_PATH);
        
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await
            .context("Failed to connect to database")?;

        info!("Connected to database at {}", DB_PATH);

        let db = Self { pool };
        db.run_migrations().await?;

        Ok(db)
    }

    /// Run database migrations
    async fn run_migrations(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS managed_interfaces (
                name TEXT PRIMARY KEY,
                role TEXT NOT NULL,
                static_ip TEXT,
                enabled INTEGER NOT NULL DEFAULT 1
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .context("Failed to create managed_interfaces table")?;

        info!("Database migrations complete");
        Ok(())
    }

    /// Get all managed interfaces
    pub async fn get_managed_interfaces(&self) -> Result<Vec<ManagedInterface>> {
        let rows = sqlx::query_as::<_, (String, String, Option<String>, bool)>(
            "SELECT name, role, static_ip, enabled FROM managed_interfaces ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch managed interfaces")?;

        let interfaces = rows
            .into_iter()
            .filter_map(|(name, role, static_ip, enabled)| {
                let role: InterfaceRole = role.parse().ok()?;
                Some(ManagedInterface {
                    name,
                    role,
                    static_ip,
                    enabled,
                })
            })
            .collect();

        Ok(interfaces)
    }

    /// Save managed interfaces (replaces all existing)
    pub async fn save_managed_interfaces(&self, interfaces: &[ManagedInterface]) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        // Clear existing
        sqlx::query("DELETE FROM managed_interfaces")
            .execute(&mut *tx)
            .await
            .context("Failed to clear managed interfaces")?;

        // Insert new
        for iface in interfaces {
            sqlx::query(
                "INSERT INTO managed_interfaces (name, role, static_ip, enabled) VALUES (?, ?, ?, ?)",
            )
            .bind(&iface.name)
            .bind(iface.role.to_string())
            .bind(&iface.static_ip)
            .bind(iface.enabled)
            .execute(&mut *tx)
            .await
            .context("Failed to insert managed interface")?;
        }

        tx.commit().await.context("Failed to commit transaction")?;

        info!("Saved {} managed interfaces", interfaces.len());
        Ok(())
    }
}
