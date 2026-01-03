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
        let row = sqlx::query_as::<_, (bool,)>(
            "SELECT config_changes_disabled FROM global_settings WHERE id = 1",
        )
        .fetch_optional(self.pool)
        .await
        .context("Failed to fetch global settings")?;

        match row {
            Some((config_changes_disabled,)) => Ok(GlobalSettings {
                config_changes_disabled,
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
               (id, config_changes_disabled, updated_at)
               VALUES (1, ?, strftime('%s', 'now'))"#,
        )
        .bind(settings.config_changes_disabled)
        .execute(self.pool)
        .await
        .context("Failed to save global settings")?;

        info!(
            "Saved global settings: config_changes_disabled={}",
            settings.config_changes_disabled
        );
        Ok(())
    }
}
