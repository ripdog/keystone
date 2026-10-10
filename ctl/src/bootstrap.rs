//! Root-only, one-time administrator provisioning. This cannot be reached over HTTP.

use anyhow::{Context, Result, bail};
use argon2::{
    Argon2, PasswordHasher,
    password_hash::{SaltString, rand_core::OsRng},
};
use nix::unistd::Uid;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::{fs, os::unix::fs::PermissionsExt, str::FromStr};

const DATA_DIR: &str = "/var/lib/keystone";
const DB_PATH: &str = "/var/lib/keystone/keystone.db";

pub async fn run(username: &str) -> Result<()> {
    if !Uid::effective().is_root() {
        bail!("Bootstrap must run locally as root (sudo keystonectl bootstrap-admin)");
    }
    if username.is_empty() || username.len() > 50 || username.chars().any(char::is_control) {
        bail!("Username must contain 1-50 printable characters");
    }

    let password = rpassword::prompt_password("New administrator password (12+ characters): ")?;
    if password.chars().count() < 12 {
        bail!("Password must be at least 12 characters");
    }
    let confirmation = rpassword::prompt_password("Confirm password: ")?;
    if password != confirmation {
        bail!("Passwords do not match");
    }

    fs::create_dir_all(DATA_DIR).context("Cannot create Keystone state directory")?;
    // The JWT signing key and password hashes reside here. The directory must
    // be inaccessible even to the unprivileged web UI and keystone group.
    fs::set_permissions(DATA_DIR, fs::Permissions::from_mode(0o700))?;

    let options =
        SqliteConnectOptions::from_str(&format!("sqlite:{DB_PATH}"))?.create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await?;
    fs::set_permissions(DB_PATH, fs::Permissions::from_mode(0o600))?;
    sqlx::migrate!("../daemon/migrations").run(&pool).await?;

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Password hashing failed: {e}"))?
        .to_string();

    if !insert_first_user(&pool, username, &hash).await? {
        bail!("Keystone already has an administrator; log in to manage accounts");
    }

    // Account creation satisfies the wizard's initial password step.
    sqlx::query(
        "UPDATE global_settings SET wizard_step = 1, updated_at = strftime('%s', 'now') \
         WHERE id = 1 AND wizard_step = 0",
    )
    .execute(&pool)
    .await?;
    pool.close().await;

    println!(
        "Administrator '{username}' created. Run 'keystonectl setup' or log in to the web UI."
    );
    Ok(())
}

/// The conditional INSERT is atomic: even concurrent requests cannot both
/// claim the first administrator. The SQL constraint is the ultimate gate.
async fn insert_first_user(pool: &sqlx::SqlitePool, username: &str, hash: &str) -> Result<bool> {
    let affected = sqlx::query(
        "INSERT INTO users (username, email, password_hash, created_at) \
         SELECT ?, NULL, ?, strftime('%s', 'now') \
         WHERE NOT EXISTS (SELECT 1 FROM users)",
    )
    .bind(username)
    .bind(hash)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(affected == 1)
}

#[cfg(test)]
mod tests {
    #[test]
    fn database_path_is_not_under_the_web_root() {
        assert!(std::path::Path::new(super::DB_PATH).is_absolute());
    }

    #[tokio::test]
    async fn cannot_bootstrap_twice() {
        let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, password_hash TEXT, created_at INTEGER)")
            .execute(&pool).await.unwrap();
        assert!(
            super::insert_first_user(&pool, "admin", "hash")
                .await
                .unwrap()
        );
        assert!(
            !super::insert_first_user(&pool, "intruder", "hash")
                .await
                .unwrap()
        );
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count.0, 1);
    }
}
