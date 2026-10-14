//! Database access for the Blocky configuration.

use std::collections::BTreeMap;
use std::net::IpAddr;

use anyhow::{Context, Result};
use keystone_core::blocky::{
    BlockyBlockType, BlockyClientGroups, BlockyConfig, BlockyGroup, BlockyUpstreamStrategy,
};
use sqlx::{Row, SqlitePool};

/// `kind` value of a denylist source in `blocky_group_sources`.
const DENY: &str = "deny";
/// `kind` value of an allowlist source in `blocky_group_sources`.
const ALLOW: &str = "allow";

/// Load the Blocky configuration. The migration always creates the row.
pub async fn load_blocky_config(pool: &SqlitePool) -> Result<BlockyConfig> {
    let row = sqlx::query(
        r#"
        SELECT enabled, upstream_strategy, block_type, refresh_hours, prefetching,
               min_cache_minutes, query_log_enabled, query_log_retention_days
        FROM blocky_config WHERE id = 1
        "#,
    )
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else {
        return Ok(BlockyConfig::default());
    };

    let upstreams: Vec<String> =
        sqlx::query_scalar("SELECT upstream FROM blocky_upstreams ORDER BY position")
            .fetch_all(pool)
            .await?;
    let bootstrap =
        sqlx::query_scalar::<_, String>("SELECT address FROM blocky_bootstrap ORDER BY position")
            .fetch_all(pool)
            .await?
            .into_iter()
            .map(|address| {
                address
                    .parse::<IpAddr>()
                    .with_context(|| format!("stored bootstrap address {address:?} is invalid"))
            })
            .collect::<Result<Vec<_>>>()?;

    let names: Vec<String> = sqlx::query_scalar("SELECT name FROM blocky_groups ORDER BY position")
        .fetch_all(pool)
        .await?;
    let mut sources = load_group_sources(pool).await?;
    let groups = names
        .into_iter()
        .map(|name| {
            let mut group_sources = sources.remove(&name).unwrap_or_default();
            BlockyGroup {
                denylists: group_sources.take(DENY, false),
                allowlists: group_sources.take(ALLOW, false),
                custom_deny: group_sources.take(DENY, true),
                custom_allow: group_sources.take(ALLOW, true),
                name,
            }
        })
        .collect();

    let client_groups = load_client_groups(pool).await?;

    Ok(BlockyConfig {
        enabled: row.get::<i64, _>("enabled") != 0,
        upstreams,
        bootstrap,
        upstream_strategy: parse_strategy(&row.get::<String, _>("upstream_strategy"))?,
        block_type: parse_block_type(&row.get::<String, _>("block_type"))?,
        refresh_hours: u32::try_from(row.get::<i64, _>("refresh_hours"))
            .context("refresh_hours out of range")?,
        prefetching: row.get::<i64, _>("prefetching") != 0,
        min_cache_minutes: u32::try_from(row.get::<i64, _>("min_cache_minutes"))
            .context("min_cache_minutes out of range")?,
        query_log_enabled: row.get::<i64, _>("query_log_enabled") != 0,
        query_log_retention_days: u32::try_from(row.get::<i64, _>("query_log_retention_days"))
            .context("query_log_retention_days out of range")?,
        groups,
        client_groups,
    })
}

fn parse_strategy(value: &str) -> Result<BlockyUpstreamStrategy> {
    match value {
        "parallel_best" => Ok(BlockyUpstreamStrategy::ParallelBest),
        "strict" => Ok(BlockyUpstreamStrategy::Strict),
        "random" => Ok(BlockyUpstreamStrategy::Random),
        other => anyhow::bail!("stored upstream strategy {other:?} is invalid"),
    }
}

fn parse_block_type(value: &str) -> Result<BlockyBlockType> {
    match value {
        "zero_ip" => Ok(BlockyBlockType::ZeroIp),
        "nx_domain" => Ok(BlockyBlockType::NxDomain),
        other => anyhow::bail!("stored block type {other:?} is invalid"),
    }
}

/// The sources of every group, keyed by group name, in stored order.
async fn load_group_sources(pool: &SqlitePool) -> Result<BTreeMap<String, GroupSources>> {
    let rows = sqlx::query(
        r#"
        SELECT group_name, kind, custom, value
        FROM blocky_group_sources
        ORDER BY group_name, kind, custom, position
        "#,
    )
    .fetch_all(pool)
    .await?;

    let mut by_group: BTreeMap<String, GroupSources> = BTreeMap::new();
    for row in rows {
        let name: String = row.get("group_name");
        let kind: String = row.get("kind");
        let custom = row.get::<i64, _>("custom") != 0;
        let value: String = row.get("value");
        by_group.entry(name).or_default().push(&kind, custom, value);
    }
    Ok(by_group)
}

/// Sources of one group, split by kind (deny or allow) and by origin (URL or
/// hand-written entry).
#[derive(Default)]
struct GroupSources {
    deny_urls: Vec<String>,
    deny_custom: Vec<String>,
    allow_urls: Vec<String>,
    allow_custom: Vec<String>,
}

impl GroupSources {
    fn push(&mut self, kind: &str, custom: bool, value: String) {
        match (kind == DENY, custom) {
            (true, false) => self.deny_urls.push(value),
            (true, true) => self.deny_custom.push(value),
            (false, false) => self.allow_urls.push(value),
            (false, true) => self.allow_custom.push(value),
        }
    }

    fn take(&mut self, kind: &str, custom: bool) -> Vec<String> {
        let list = match (kind == DENY, custom) {
            (true, false) => &mut self.deny_urls,
            (true, true) => &mut self.deny_custom,
            (false, false) => &mut self.allow_urls,
            (false, true) => &mut self.allow_custom,
        };
        std::mem::take(list)
    }
}

async fn load_client_groups(pool: &SqlitePool) -> Result<Vec<BlockyClientGroups>> {
    let rows = sqlx::query(
        r#"
        SELECT selector_position, selector, group_name
        FROM blocky_client_groups
        ORDER BY selector_position, group_position
        "#,
    )
    .fetch_all(pool)
    .await?;

    let mut client_groups: Vec<(i64, BlockyClientGroups)> = Vec::new();
    for row in rows {
        let position: i64 = row.get("selector_position");
        let group: String = row.get("group_name");
        match client_groups.last_mut() {
            Some((last, entry)) if *last == position => entry.groups.push(group),
            _ => client_groups.push((
                position,
                BlockyClientGroups {
                    selector: row.get("selector"),
                    groups: vec![group],
                },
            )),
        }
    }
    Ok(client_groups.into_iter().map(|(_, entry)| entry).collect())
}

/// Replace the Blocky configuration. Callers validate the values first.
pub async fn save_blocky_config(pool: &SqlitePool, config: &BlockyConfig) -> Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        r#"
        INSERT INTO blocky_config
            (id, enabled, upstream_strategy, block_type, refresh_hours, prefetching,
             min_cache_minutes, query_log_enabled, query_log_retention_days, updated_at)
        VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%s', 'now'))
        ON CONFLICT(id) DO UPDATE SET
            enabled = excluded.enabled,
            upstream_strategy = excluded.upstream_strategy,
            block_type = excluded.block_type,
            refresh_hours = excluded.refresh_hours,
            prefetching = excluded.prefetching,
            min_cache_minutes = excluded.min_cache_minutes,
            query_log_enabled = excluded.query_log_enabled,
            query_log_retention_days = excluded.query_log_retention_days,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(config.enabled as i64)
    .bind(config.upstream_strategy.blocky_value())
    .bind(block_type_value(config.block_type))
    .bind(i64::from(config.refresh_hours))
    .bind(config.prefetching as i64)
    .bind(i64::from(config.min_cache_minutes))
    .bind(config.query_log_enabled as i64)
    .bind(i64::from(config.query_log_retention_days))
    .execute(&mut *tx)
    .await?;

    sqlx::query("DELETE FROM blocky_upstreams")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM blocky_bootstrap")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM blocky_groups")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM blocky_group_sources")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM blocky_client_groups")
        .execute(&mut *tx)
        .await?;

    for (position, upstream) in config.upstreams.iter().enumerate() {
        sqlx::query("INSERT INTO blocky_upstreams (position, upstream) VALUES (?, ?)")
            .bind(position as i64)
            .bind(upstream)
            .execute(&mut *tx)
            .await?;
    }

    for (position, address) in config.bootstrap.iter().enumerate() {
        sqlx::query("INSERT INTO blocky_bootstrap (position, address) VALUES (?, ?)")
            .bind(position as i64)
            .bind(address.to_string())
            .execute(&mut *tx)
            .await?;
    }

    for (position, group) in config.groups.iter().enumerate() {
        sqlx::query("INSERT INTO blocky_groups (position, name) VALUES (?, ?)")
            .bind(position as i64)
            .bind(&group.name)
            .execute(&mut *tx)
            .await?;
        let sources = [
            (DENY, false, &group.denylists),
            (ALLOW, false, &group.allowlists),
            (DENY, true, &group.custom_deny),
            (ALLOW, true, &group.custom_allow),
        ];
        for (kind, custom, values) in sources {
            for (index, value) in values.iter().enumerate() {
                sqlx::query(
                    r#"
                    INSERT INTO blocky_group_sources
                        (group_name, kind, custom, position, value)
                    VALUES (?, ?, ?, ?, ?)
                    "#,
                )
                .bind(&group.name)
                .bind(kind)
                .bind(custom as i64)
                .bind(index as i64)
                .bind(value)
                .execute(&mut *tx)
                .await?;
            }
        }
    }

    for (selector_position, assignment) in config.client_groups.iter().enumerate() {
        for (group_position, group) in assignment.groups.iter().enumerate() {
            sqlx::query(
                r#"
                INSERT INTO blocky_client_groups
                    (selector_position, selector, group_position, group_name)
                VALUES (?, ?, ?, ?)
                "#,
            )
            .bind(selector_position as i64)
            .bind(&assignment.selector)
            .bind(group_position as i64)
            .bind(group)
            .execute(&mut *tx)
            .await?;
        }
    }

    tx.commit().await?;
    Ok(())
}

fn block_type_value(block_type: BlockyBlockType) -> &'static str {
    match block_type {
        BlockyBlockType::ZeroIp => "zero_ip",
        BlockyBlockType::NxDomain => "nx_domain",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;

    #[tokio::test]
    async fn a_fresh_database_holds_the_defaults() {
        let db = Database::new_in_memory().await.unwrap();
        assert_eq!(
            load_blocky_config(db.pool()).await.unwrap(),
            BlockyConfig::default()
        );
    }

    #[tokio::test]
    async fn a_saved_configuration_round_trips_and_replaces_its_lists() {
        let db = Database::new_in_memory().await.unwrap();
        let mut config = BlockyConfig {
            enabled: true,
            upstreams: vec!["9.9.9.9".to_string(), "tcp-tls:dns.example.com".to_string()],
            bootstrap: vec![IpAddr::from([192, 0, 2, 1])],
            upstream_strategy: BlockyUpstreamStrategy::Strict,
            block_type: BlockyBlockType::NxDomain,
            refresh_hours: 12,
            prefetching: false,
            min_cache_minutes: 0,
            query_log_enabled: false,
            query_log_retention_days: 30,
            groups: vec![
                BlockyGroup {
                    name: "ads".to_string(),
                    denylists: vec![
                        "https://lists.example.com/b.txt".to_string(),
                        "https://lists.example.com/a.txt".to_string(),
                    ],
                    custom_deny: vec!["tracker.example.com".to_string()],
                    ..BlockyGroup::default()
                },
                BlockyGroup {
                    name: "kids".to_string(),
                    denylists: vec!["https://lists.example.com/adult.txt".to_string()],
                    allowlists: vec!["https://lists.example.com/allow.txt".to_string()],
                    custom_allow: vec!["school.example.com".to_string()],
                    ..BlockyGroup::default()
                },
            ],
            client_groups: vec![
                BlockyClientGroups {
                    selector: "default".to_string(),
                    groups: vec!["ads".to_string()],
                },
                BlockyClientGroups {
                    selector: "192.168.10.0/24".to_string(),
                    groups: vec!["kids".to_string(), "ads".to_string()],
                },
            ],
        };
        save_blocky_config(db.pool(), &config).await.unwrap();
        assert_eq!(load_blocky_config(db.pool()).await.unwrap(), config);

        config.groups.truncate(1);
        config.client_groups.truncate(1);
        config.upstreams.clear();
        config
            .upstreams
            .push("https://dns.example.com/dns-query".to_string());
        save_blocky_config(db.pool(), &config).await.unwrap();
        let loaded = load_blocky_config(db.pool()).await.unwrap();
        assert_eq!(loaded, config);
    }

    #[tokio::test]
    async fn the_stored_selector_order_is_kept() {
        let db = Database::new_in_memory().await.unwrap();
        let config = BlockyConfig {
            client_groups: vec![
                BlockyClientGroups {
                    selector: "10.0.0.0/8".to_string(),
                    groups: vec!["ads".to_string()],
                },
                BlockyClientGroups {
                    selector: "default".to_string(),
                    groups: vec!["ads".to_string()],
                },
            ],
            ..BlockyConfig::default()
        };
        save_blocky_config(db.pool(), &config).await.unwrap();
        assert_eq!(
            load_blocky_config(db.pool()).await.unwrap().client_groups,
            config.client_groups
        );
    }
}
