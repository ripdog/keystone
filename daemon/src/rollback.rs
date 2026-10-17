//! Undoing the configuration of an apply that was rolled back.
//!
//! A network rollback restores the generated files, but the saved
//! configuration stays as it was edited. That leaves the system and the
//! database disagreeing: the files describe the old setup while the
//! configuration (and everything that reads it, such as the LAN monitoring and
//! the address the web service binds) describes the new one. A rolled back
//! apply is therefore undone completely: the components it covered return to
//! their last applied configuration, and the services that apply without a
//! rollback timer are applied again from it.
//!
//! The configuration that is replaced is kept as a `pre_restore` snapshot, so
//! the rejected edits can still be brought back from the history page.

use anyhow::{Result, bail};
use keystone_core::changes::Component;
use keystone_core::wireless::WirelessConfig;
use tracing::{error, info, warn};

use crate::db::Database;
use crate::snapshots::{self, NewSnapshot, SnapshotKind, SnapshotStatus};
use crate::{blocky, caddy, dnsmasq, sqm, upnp, wireless};

/// Whether a component that was never applied can be reset to "no
/// configuration". True for a component added after the router's first
/// baseline snapshot was taken, whose defaults mean "off".
pub fn can_reset_unapplied(component: Component) -> bool {
    matches!(component, Component::Wireless)
}

/// Reset a component that has no applied configuration to its defaults.
pub async fn reset_unapplied(db: &Database, component: Component) -> Result<()> {
    match component {
        Component::Wireless => {
            wireless::db::save_wireless_config(db.pool(), &WirelessConfig::default()).await
        }
        other => bail!("{other} has no applied configuration to discard back to"),
    }
}

/// Settle the snapshot of a rolled back apply session and undo its
/// configuration. Failures are logged: the rollback itself already happened.
pub async fn settle_rolled_back(db: &Database, session_id: &str) {
    let components = match snapshots::session_components(db, session_id).await {
        Ok(components) => components,
        Err(error) => {
            warn!("Could not read the components of rolled back session {session_id}: {error:#}");
            Vec::new()
        }
    };
    snapshots::settle_session(db, session_id, SnapshotStatus::RolledBack).await;
    if components.is_empty() {
        return;
    }
    match revert_configuration(db, &components).await {
        Ok(()) => reapply_services(db, &components).await,
        Err(error) => error!("Reverting the configuration after a rollback failed: {error:#}"),
    }
}

/// Return `components` to their last applied configuration in the database.
async fn revert_configuration(db: &Database, components: &[Component]) -> Result<()> {
    let mut plan: std::collections::BTreeMap<i64, Vec<Component>> = Default::default();
    let mut unapplied = Vec::new();
    for &component in components {
        match snapshots::baseline_for(db, component, &[]).await? {
            Some(baseline) => plan.entry(baseline.id).or_default().push(component),
            None if can_reset_unapplied(component) => unapplied.push(component),
            None => warn!("{component} has no applied configuration to return to after a rollback"),
        }
    }

    let plan: Vec<_> = plan.into_iter().collect();
    if !plan.is_empty() {
        snapshots::restore_components(db, &plan, None).await?;
    } else if !unapplied.is_empty() {
        save_replaced_configuration(db).await?;
    }
    for component in &unapplied {
        reset_unapplied(db, *component).await?;
    }
    info!("Returned {components:?} to the last applied configuration after a rollback");
    Ok(())
}

async fn save_replaced_configuration(db: &Database) -> Result<()> {
    snapshots::create_snapshot(
        db,
        NewSnapshot {
            kind: SnapshotKind::PreRestore,
            status: SnapshotStatus::Active,
            session_id: None,
            components: &[],
            actor: None,
            note: Some("Automatic backup before undoing a rolled back apply"),
        },
    )
    .await?;
    Ok(())
}

/// Apply again the services whose files a network rollback does not restore:
/// they were written by the rolled back apply and still describe it.
async fn reapply_services(db: &Database, components: &[Component]) {
    let wanted = |component| components.contains(&component);
    macro_rules! reapply {
        ($component:expr, $name:literal, $call:expr) => {
            if wanted($component) {
                match $call.await {
                    Ok(()) => info!("{}: applied again after a rollback", $name),
                    Err(error) => warn!("{} could not be applied again: {error:#}", $name),
                }
            }
        };
    }
    reapply!(Component::Sqm, "SQM", sqm::apply_saved(db));
    reapply!(Component::Upnp, "UPnP", upnp::apply_saved(db));
    reapply!(Component::Blocky, "Blocky", blocky::apply_saved(db));
    reapply!(Component::Wireless, "Wireless", wireless::apply_saved(db));
    reapply!(
        Component::Dnsmasq,
        "dnsmasq",
        dnsmasq::apply_dnsmasq_config(db.pool())
    );
    reapply!(
        Component::Caddy,
        "Caddy",
        caddy::apply_caddy_config(db.pool())
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshots::tests::{Scratch, open};

    #[test]
    fn only_components_whose_defaults_mean_off_can_be_reset() {
        assert!(can_reset_unapplied(Component::Wireless));
        for component in [
            Component::Networkd,
            Component::Firewall,
            Component::Dnsmasq,
            Component::Caddy,
        ] {
            assert!(!can_reset_unapplied(component), "{component}");
        }
    }

    async fn dnsmasq_cache_size(db: &Database) -> i64 {
        sqlx::query_scalar("SELECT cache_size FROM dnsmasq_config WHERE id = 1")
            .fetch_one(db.pool())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_rolled_back_apply_returns_its_components_to_the_applied_configuration() {
        let scratch = Scratch::new();
        let db = open(&scratch).await;

        // Applied: wireless is not part of the first baseline, as on a router
        // that was upgraded to a version with Wi-Fi support.
        let applied: Vec<Component> = Component::ALL
            .into_iter()
            .filter(|c| *c != Component::Wireless)
            .collect();
        snapshots::record_applied(&db, None, None, &applied, "baseline").await;
        let before = dnsmasq_cache_size(&db).await;

        // The rejected apply: edits to dnsmasq and a new access point.
        sqlx::query("UPDATE dnsmasq_config SET cache_size = ? WHERE id = 1")
            .bind(before + 7)
            .execute(db.pool())
            .await
            .unwrap();
        wireless::db::save_wireless_config(
            db.pool(),
            &WirelessConfig {
                enabled: false,
                interface: "wlan0".to_string(),
                ..WirelessConfig::default()
            },
        )
        .await
        .unwrap();
        snapshots::record_applied(
            &db,
            None,
            Some("s1"),
            &[Component::Dnsmasq, Component::Wireless],
            "rejected",
        )
        .await;

        let components = snapshots::session_components(&db, "s1").await.unwrap();
        assert_eq!(components, vec![Component::Wireless, Component::Dnsmasq]);
        snapshots::settle_session(&db, "s1", SnapshotStatus::RolledBack).await;
        revert_configuration(&db, &components).await.unwrap();

        assert_eq!(dnsmasq_cache_size(&db).await, before);
        assert_eq!(
            wireless::load_wireless_config(db.pool()).await.unwrap(),
            WirelessConfig::default()
        );
        // The rejected configuration is kept in history.
        let kept = snapshots::list_snapshots(&db).await.unwrap();
        assert!(kept.iter().any(|s| s.kind == SnapshotKind::PreRestore));
    }

    #[tokio::test]
    async fn resetting_wireless_restores_the_disabled_defaults() {
        let db = Database::new_in_memory().await.unwrap();
        wireless::db::save_wireless_config(
            db.pool(),
            &WirelessConfig {
                enabled: true,
                interface: "wlan0".to_string(),
                ssid: "x".to_string(),
                ..WirelessConfig::default()
            },
        )
        .await
        .unwrap();
        reset_unapplied(&db, Component::Wireless).await.unwrap();
        assert_eq!(
            wireless::load_wireless_config(db.pool()).await.unwrap(),
            WirelessConfig::default()
        );
        assert!(reset_unapplied(&db, Component::Networkd).await.is_err());
    }
}
