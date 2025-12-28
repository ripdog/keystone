//! Database module for Keystone configuration storage
//!
//! Uses SQLite via sqlx for persistent configuration storage.

use anyhow::{Context, Result};
use keystone_core::{InterfaceRole, ManagedInterface, User, UserInfo};
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
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .context("Failed to run database migrations")?;

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

    /// Get or create JWT signing key
    pub async fn get_or_create_jwt_key(&self) -> Result<Vec<u8>> {
        // Try to get existing key
        if let Some(row) = sqlx::query_as::<_, (Vec<u8>,)>(
            "SELECT key_bytes FROM jwt_key WHERE id = 1"
        )
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch JWT key")? {
            info!("Loaded existing JWT key from database");
            return Ok(row.0);
        }

        // Generate new key
        use rand::random;
        let key_bytes: [u8; 32] = random();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        sqlx::query(
            "INSERT INTO jwt_key (id, key_bytes, created_at) VALUES (1, ?, ?)"
        )
        .bind(&key_bytes[..])
        .bind(now)
        .execute(&self.pool)
        .await
        .context("Failed to create JWT key")?;

        info!("Generated new JWT key and stored in database");
        Ok(key_bytes.to_vec())
    }

    /// Get all users (without password hashes)
    pub async fn get_users(&self) -> Result<Vec<UserInfo>> {
        let rows = sqlx::query_as::<_, (i64, String, Option<String>, i64)>(
            "SELECT id, username, email, created_at FROM users ORDER BY username",
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch users")?;

        let users = rows
            .into_iter()
            .map(|(id, username, email, created_at)| UserInfo {
                id,
                username,
                email,
                created_at,
            })
            .collect();

        Ok(users)
    }

    /// Get a user by username (with password hash)
    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let row = sqlx::query_as::<_, (i64, String, Option<String>, String, i64)>(
            "SELECT id, username, email, password_hash, created_at FROM users WHERE username = ?",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch user")?;

        Ok(row.map(|(id, username, email, password_hash, created_at)| User {
            id,
            username,
            email,
            password_hash,
            created_at,
        }))
    }

    /// Create a new user
    pub async fn create_user(&self, username: &str, email: Option<&str>, password_hash: &str) -> Result<i64> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let result = sqlx::query(
            "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
        )
        .bind(username)
        .bind(email)
        .bind(password_hash)
        .bind(now)
        .execute(&self.pool)
        .await
        .context("Failed to create user")?;

        Ok(result.last_insert_rowid())
    }

    /// Update user information
    pub async fn update_user(&self, id: i64, username: &str, email: Option<&str>, password_hash: Option<&str>) -> Result<()> {
        if let Some(hash) = password_hash {
            sqlx::query(
                "UPDATE users SET username = ?, email = ?, password_hash = ? WHERE id = ?",
            )
            .bind(username)
            .bind(email)
            .bind(hash)
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to update user")?;
        } else {
            sqlx::query(
                "UPDATE users SET username = ?, email = ? WHERE id = ?",
            )
            .bind(username)
            .bind(email)
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to update user")?;
        }

        info!("Updated user {} (id: {})", username, id);
        Ok(())
    }

    /// Delete a user
    pub async fn delete_user(&self, id: i64) -> Result<()> {
        sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to delete user")?;

        info!("Deleted user id: {}", id);
        Ok(())
    }
}
