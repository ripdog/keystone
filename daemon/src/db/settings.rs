//! Global settings database operations

use anyhow::{Context, Result};
use keystone_core::GlobalSettings;
use sqlx::SqlitePool;
use tracing::info;

/// Global settings database operations
pub struct SettingsDb<'a> {
    pool: &'a SqlitePool,
}

impl<'a> SettingsDb<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    /// Get global application settings
    pub async fn get_global_settings(&self) -> Result<GlobalSettings> {
        let row = sqlx::query_as::<_, (bool, bool)>(
            "SELECT config_changes_disabled, setup_complete FROM global_settings WHERE id = 1",
        )
        .fetch_optional(self.pool)
        .await
        .context("Failed to fetch global settings")?;

        match row {
            Some((config_changes_disabled, setup_complete)) => Ok(GlobalSettings {
                config_changes_disabled,
                setup_complete,
            }),
            None => {
                // Return defaults if no row exists (shouldn't happen after migration)
                Ok(GlobalSettings::default())
            }
        }
    }

    /// Save global application settings
    pub async fn save_global_settings(&self, settings: &GlobalSettings) -> Result<()> {
        sqlx::query(
            r#"INSERT OR REPLACE INTO global_settings 
               (id, config_changes_disabled, setup_complete, updated_at)
               VALUES (1, ?, ?, strftime('%s', 'now'))"#,
        )
        .bind(settings.config_changes_disabled)
        .bind(settings.setup_complete)
        .execute(self.pool)
        .await
        .context("Failed to save global settings")?;

        info!(
            "Saved global settings: config_changes_disabled={}, setup_complete={}",
            settings.config_changes_disabled, settings.setup_complete
        );
        Ok(())
    }

    /// Mark setup as complete
    pub async fn mark_setup_complete(&self) -> Result<()> {
        sqlx::query(
            r#"UPDATE global_settings SET setup_complete = 1, updated_at = strftime('%s', 'now') WHERE id = 1"#,
        )
        .execute(self.pool)
        .await
        .context("Failed to mark setup as complete")?;

        info!("Setup marked as complete");
        Ok(())
    }
}
