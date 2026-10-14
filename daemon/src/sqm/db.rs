//! Database access for the SQM configuration and the last applied state.

use anyhow::{Context, Result, anyhow};
use keystone_core::sqm::{SqmConfig, SqmDiffserv, SqmIsolation, SqmLinkPreset};
use sqlx::{Row, SqlitePool};

/// Load the SQM configuration row. The migration always creates it.
pub async fn load_sqm_config(pool: &SqlitePool) -> Result<SqmConfig> {
    let row = sqlx::query(
        r#"
        SELECT enabled, interface, download_kbit, upload_kbit, link_preset, overhead, mpu,
               diffserv, isolation, nat, ack_filter, wash
        FROM sqm_config WHERE id = 1
        "#,
    )
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else {
        return Ok(SqmConfig::default());
    };

    let link_preset: String = row.get("link_preset");
    let diffserv: String = row.get("diffserv");
    let isolation: String = row.get("isolation");
    let mpu: Option<i64> = row.get("mpu");
    Ok(SqmConfig {
        enabled: row.get::<i64, _>("enabled") != 0,
        interface: row.get("interface"),
        download_kbit: u32::try_from(row.get::<i64, _>("download_kbit"))
            .context("download_kbit out of range")?,
        upload_kbit: u32::try_from(row.get::<i64, _>("upload_kbit"))
            .context("upload_kbit out of range")?,
        link_preset: SqmLinkPreset::parse(&link_preset)
            .ok_or_else(|| anyhow!("stored link preset {link_preset:?} is unknown"))?,
        overhead: row
            .get::<Option<i64>, _>("overhead")
            .map(|value| i32::try_from(value).context("overhead out of range"))
            .transpose()?,
        mpu: mpu
            .map(|value| u32::try_from(value).context("mpu out of range"))
            .transpose()?,
        diffserv: SqmDiffserv::parse(&diffserv)
            .ok_or_else(|| anyhow!("stored diffserv mode {diffserv:?} is unknown"))?,
        isolation: SqmIsolation::parse(&isolation)
            .ok_or_else(|| anyhow!("stored isolation mode {isolation:?} is unknown"))?,
        nat: row.get::<i64, _>("nat") != 0,
        ack_filter: row.get::<i64, _>("ack_filter") != 0,
        wash: row.get::<i64, _>("wash") != 0,
    })
}

/// Replace the SQM configuration row. Callers validate the values first.
pub async fn save_sqm_config(pool: &SqlitePool, config: &SqmConfig) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO sqm_config
            (id, enabled, interface, download_kbit, upload_kbit, link_preset, overhead, mpu,
             diffserv, isolation, nat, ack_filter, wash, updated_at)
        VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%s', 'now'))
        ON CONFLICT(id) DO UPDATE SET
            enabled = excluded.enabled,
            interface = excluded.interface,
            download_kbit = excluded.download_kbit,
            upload_kbit = excluded.upload_kbit,
            link_preset = excluded.link_preset,
            overhead = excluded.overhead,
            mpu = excluded.mpu,
            diffserv = excluded.diffserv,
            isolation = excluded.isolation,
            nat = excluded.nat,
            ack_filter = excluded.ack_filter,
            wash = excluded.wash,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(config.enabled as i64)
    .bind(&config.interface)
    .bind(i64::from(config.download_kbit))
    .bind(i64::from(config.upload_kbit))
    .bind(config.link_preset.as_str())
    .bind(config.overhead.map(i64::from))
    .bind(config.mpu.map(i64::from))
    .bind(config.diffserv.as_str())
    .bind(config.isolation.as_str())
    .bind(config.nat as i64)
    .bind(config.ack_filter as i64)
    .bind(config.wash as i64)
    .execute(pool)
    .await?;
    Ok(())
}

/// The configuration last applied to the system, if any apply has succeeded.
pub async fn load_applied(pool: &SqlitePool) -> Result<Option<SqmConfig>> {
    let json: Option<String> =
        sqlx::query_scalar("SELECT config_json FROM sqm_applied WHERE id = 1")
            .fetch_optional(pool)
            .await?;
    json.map(|json| serde_json::from_str(&json).context("stored SQM applied state is invalid"))
        .transpose()
}

/// Record `config` as the configuration now in effect on the system.
pub async fn save_applied(pool: &SqlitePool, config: &SqmConfig) -> Result<()> {
    let json = serde_json::to_string(config)?;
    sqlx::query(
        r#"
        INSERT INTO sqm_applied (id, config_json, applied_at)
        VALUES (1, ?, strftime('%s', 'now'))
        ON CONFLICT(id) DO UPDATE SET
            config_json = excluded.config_json,
            applied_at = excluded.applied_at
        "#,
    )
    .bind(json)
    .execute(pool)
    .await?;
    Ok(())
}

/// Forget the applied state, so the reconciler has nothing to restore.
pub async fn clear_applied(pool: &SqlitePool) -> Result<()> {
    sqlx::query("DELETE FROM sqm_applied WHERE id = 1")
        .execute(pool)
        .await?;
    Ok(())
}
