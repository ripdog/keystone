//! User and authentication database operations

use anyhow::{Context, Result};
use keystone_core::{User, UserInfo};
use sqlx::SqlitePool;
use tracing::info;

/// User-related database operations
pub struct UsersDb<'a> {
    pool: &'a SqlitePool,
}

impl<'a> UsersDb<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    /// Get all users (without password hashes)
    pub async fn get_users(&self) -> Result<Vec<UserInfo>> {
        let rows = sqlx::query_as::<_, (i64, String, Option<String>, i64)>(
            "SELECT id, username, email, created_at FROM users ORDER BY username",
        )
        .fetch_all(self.pool)
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
        .fetch_optional(self.pool)
        .await
        .context("Failed to fetch user")?;

        Ok(
            row.map(|(id, username, email, password_hash, created_at)| User {
                id,
                username,
                email,
                password_hash,
                created_at,
            }),
        )
    }

    /// Create a new user
    pub async fn create_user(
        &self,
        username: &str,
        email: Option<&str>,
        password_hash: &str,
    ) -> Result<i64> {
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
        .execute(self.pool)
        .await
        .context("Failed to create user")?;

        Ok(result.last_insert_rowid())
    }

    /// Update user information
    pub async fn update_user(
        &self,
        id: i64,
        username: &str,
        email: Option<&str>,
        password_hash: Option<&str>,
    ) -> Result<()> {
        if let Some(hash) = password_hash {
            sqlx::query("UPDATE users SET username = ?, email = ?, password_hash = ? WHERE id = ?")
                .bind(username)
                .bind(email)
                .bind(hash)
                .bind(id)
                .execute(self.pool)
                .await
                .context("Failed to update user")?;
        } else {
            sqlx::query("UPDATE users SET username = ?, email = ? WHERE id = ?")
                .bind(username)
                .bind(email)
                .bind(id)
                .execute(self.pool)
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
            .execute(self.pool)
            .await
            .context("Failed to delete user")?;

        info!("Deleted user id: {}", id);
        Ok(())
    }

    /// Get or create JWT signing key
    pub async fn get_or_create_jwt_key(&self) -> Result<Vec<u8>> {
        // Try to get existing key
        if let Some(row) =
            sqlx::query_as::<_, (Vec<u8>,)>("SELECT key_bytes FROM jwt_key WHERE id = 1")
                .fetch_optional(self.pool)
                .await
                .context("Failed to fetch JWT key")?
        {
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

        sqlx::query("INSERT INTO jwt_key (id, key_bytes, created_at) VALUES (1, ?, ?)")
            .bind(&key_bytes[..])
            .bind(now)
            .execute(self.pool)
            .await
            .context("Failed to create JWT key")?;

        info!("Generated new JWT key and stored in database");
        Ok(key_bytes.to_vec())
    }
}
