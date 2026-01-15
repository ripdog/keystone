//! Global settings database operations

use anyhow::{Context, Result};
use keystone_core::{GlobalSettings, WizardStep};
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
        let row = sqlx::query_as::<_, (bool, bool, i64)>(
            "SELECT config_changes_disabled, setup_complete, wizard_step FROM global_settings WHERE id = 1",
        )
        .fetch_optional(self.pool)
        .await
        .context("Failed to fetch global settings")?;

        match row {
            Some((config_changes_disabled, setup_complete, wizard_step)) => Ok(GlobalSettings {
                config_changes_disabled,
                setup_complete,
                wizard_step: wizard_step as u8,
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
               (id, config_changes_disabled, setup_complete, wizard_step, updated_at)
               VALUES (1, ?, ?, ?, strftime('%s', 'now'))"#,
        )
        .bind(settings.config_changes_disabled)
        .bind(settings.setup_complete)
        .bind(settings.wizard_step as i64)
        .execute(self.pool)
        .await
        .context("Failed to save global settings")?;

        info!(
            "Saved global settings: config_changes_disabled={}, setup_complete={}, wizard_step={}",
            settings.config_changes_disabled, settings.setup_complete, settings.wizard_step
        );
        Ok(())
    }

    /// Mark setup as complete
    pub async fn mark_setup_complete(&self) -> Result<()> {
        sqlx::query(
            r#"UPDATE global_settings SET setup_complete = 1, wizard_step = ?, updated_at = strftime('%s', 'now') WHERE id = 1"#,
        )
        .bind(WizardStep::Complete.as_u8() as i64)
        .execute(self.pool)
        .await
        .context("Failed to mark setup as complete")?;

        info!("Setup marked as complete");
        Ok(())
    }

    /// Update wizard step
    pub async fn set_wizard_step(&self, step: WizardStep) -> Result<()> {
        let is_complete = step.is_complete();

        sqlx::query(
            r#"UPDATE global_settings 
               SET wizard_step = ?, setup_complete = ?, updated_at = strftime('%s', 'now') 
               WHERE id = 1"#,
        )
        .bind(step.as_u8() as i64)
        .bind(is_complete)
        .execute(self.pool)
        .await
        .context("Failed to update wizard step")?;

        info!("Wizard step updated to: {} ({})", step.as_u8(), step.name());
        Ok(())
    }
}
