//! Configuration components, snapshots and pending-change models.
//!
//! The router configuration is split into five components. Each one is
//! generated into system files (or traffic-control state) by its own apply
//! step, so a snapshot records which components it was taken as applied for,
//! and pending changes are computed per component.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// A part of the router configuration that is generated into system files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Component {
    Networkd,
    Firewall,
    /// Traffic shaping (SQM / CAKE) applied with `tc`.
    Sqm,
    /// UPnP IGD and NAT-PMP / PCP port mapping served by miniupnpd.
    Upnp,
    Dnsmasq,
    Caddy,
}

impl Component {
    /// Every component, in apply order.
    pub const ALL: [Component; 6] = [
        Component::Networkd,
        Component::Firewall,
        Component::Sqm,
        Component::Upnp,
        Component::Dnsmasq,
        Component::Caddy,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Component::Networkd => "networkd",
            Component::Firewall => "firewall",
            Component::Sqm => "sqm",
            Component::Upnp => "upnp",
            Component::Dnsmasq => "dnsmasq",
            Component::Caddy => "caddy",
        }
    }

    /// Parse a component name as written by [`Component::as_str`].
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|component| component.as_str() == value)
    }
}

impl fmt::Display for Component {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Component {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value).ok_or_else(|| {
            format!(
                "unknown component {value:?}; expected one of networkd, firewall, sqm, upnp, dnsmasq, caddy"
            )
        })
    }
}

/// Why a snapshot was taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotKind {
    /// Taken by a successful apply.
    Applied,
    /// The configuration replaced by a restore.
    PreRestore,
    /// Uploaded with the import endpoint.
    Imported,
    /// Taken on request of an administrator.
    Manual,
}

impl SnapshotKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            SnapshotKind::Applied => "applied",
            SnapshotKind::PreRestore => "pre_restore",
            SnapshotKind::Imported => "imported",
            SnapshotKind::Manual => "manual",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "applied" => SnapshotKind::Applied,
            "pre_restore" => SnapshotKind::PreRestore,
            "imported" => SnapshotKind::Imported,
            "manual" => SnapshotKind::Manual,
            _ => return None,
        })
    }
}

/// Whether a snapshot's apply is live, awaiting confirmation or was undone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotStatus {
    Active,
    PendingConfirmation,
    RolledBack,
}

impl SnapshotStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            SnapshotStatus::Active => "active",
            SnapshotStatus::PendingConfirmation => "pending_confirmation",
            SnapshotStatus::RolledBack => "rolled_back",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "active" => SnapshotStatus::Active,
            "pending_confirmation" => SnapshotStatus::PendingConfirmation,
            "rolled_back" => SnapshotStatus::RolledBack,
            _ => return None,
        })
    }
}

/// Largest snapshot file accepted by the import endpoint. Configuration
/// snapshots are small, so this only bounds the work done on an uploaded file.
pub const MAX_SNAPSHOT_UPLOAD_BYTES: usize = 32 * 1024 * 1024;

/// Civil `(year, month, day)` in UTC for a Unix timestamp in seconds.
fn utc_civil(unix_secs: i64) -> (i64, i64, i64) {
    // Civil-from-days (Howard Hinnant's algorithm), days counted from 1970-01-01.
    let days = unix_secs.div_euclid(86_400) + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// `YYYY-MM-DD` in UTC.
pub fn format_utc_date(unix_secs: i64) -> String {
    let (year, month, day) = utc_civil(unix_secs);
    format!("{year:04}-{month:02}-{day:02}")
}

/// `YYYY-MM-DD HH:MM` in UTC.
pub fn format_utc_datetime(unix_secs: i64) -> String {
    let minutes = unix_secs.rem_euclid(86_400) / 60;
    format!(
        "{} {:02}:{:02}",
        format_utc_date(unix_secs),
        minutes / 60,
        minutes % 60
    )
}

/// Snapshot metadata as presented by the API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotSummary {
    pub id: i64,
    /// Unix seconds.
    pub created_at: i64,
    pub kind: SnapshotKind,
    pub status: SnapshotStatus,
    pub actor: Option<String>,
    pub note: Option<String>,
    /// Components this snapshot was taken as applied for. Empty for snapshots
    /// that never count as an applied baseline.
    pub components: Vec<Component>,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotListResponse {
    pub snapshots: Vec<SnapshotSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSnapshotRequest {
    #[serde(default)]
    pub note: Option<String>,
}

/// Result of creating or importing a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotResponse {
    pub success: bool,
    pub message: String,
    pub snapshot: SnapshotSummary,
}

/// Optional component selection for discard and restore. Omitting it selects
/// every component: all changed components for a discard, and the whole
/// configuration for a restore.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComponentSelectionRequest {
    #[serde(default)]
    pub components: Option<Vec<Component>>,
}

/// One generated file that differs between the baseline and the live
/// configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDiff {
    pub path: String,
    pub status: FileChangeStatus,
    pub unified_diff: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileChangeStatus {
    Added,
    Removed,
    Modified,
}

/// Differences for one component. `error` is set when either side of the
/// comparison could not be generated; such a component counts as changed so
/// that a configuration the generator rejects is never hidden.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentDiff {
    pub component: Component,
    pub changed: bool,
    pub files: Vec<FileDiff>,
    pub error: Option<String>,
}

/// Snapshot id each component was compared against, if any.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentBaselines {
    pub networkd: Option<i64>,
    pub firewall: Option<i64>,
    #[serde(default)]
    pub sqm: Option<i64>,
    #[serde(default)]
    pub upnp: Option<i64>,
    pub dnsmasq: Option<i64>,
    pub caddy: Option<i64>,
}

impl ComponentBaselines {
    pub fn get(&self, component: Component) -> Option<i64> {
        match component {
            Component::Networkd => self.networkd,
            Component::Firewall => self.firewall,
            Component::Sqm => self.sqm,
            Component::Upnp => self.upnp,
            Component::Dnsmasq => self.dnsmasq,
            Component::Caddy => self.caddy,
        }
    }

    pub fn set(&mut self, component: Component, id: Option<i64>) {
        match component {
            Component::Networkd => self.networkd = id,
            Component::Firewall => self.firewall = id,
            Component::Sqm => self.sqm = id,
            Component::Upnp => self.upnp = id,
            Component::Dnsmasq => self.dnsmasq = id,
            Component::Caddy => self.caddy = id,
        }
    }
}

/// Generated configuration that differs from a baseline.
///
/// For `GET /changes/pending`, the baseline is the last applied state and the
/// live database is the new side. For `GET /snapshots/{id}/diff`, the live
/// database is the old side and the snapshot is the new side, so the diff shows
/// what restoring the snapshot would change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingChangesResponse {
    pub components: Vec<ComponentDiff>,
    pub baseline_ids: ComponentBaselines,
    /// An apply that is live but not yet confirmed. The system already runs
    /// its configuration, so it is not a pending change; it must be confirmed
    /// or it rolls back. `None` when nothing awaits confirmation.
    #[serde(default)]
    pub awaiting_confirmation: Option<AwaitingConfirmation>,
}

/// An applied configuration that awaits confirmation before its rollback timer
/// fires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AwaitingConfirmation {
    /// Session to pass to the confirm endpoint.
    pub session_id: String,
    /// Unix seconds at which the change rolls back unless confirmed.
    pub deadline: u64,
    /// Components the pending apply covers. Empty when the apply has no
    /// snapshot to name them.
    pub components: Vec<Component>,
}

/// Result of discarding pending changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscardChangesResponse {
    pub success: bool,
    pub message: String,
    /// Automatic backup of the replaced configuration. `None` when there was
    /// nothing to discard.
    pub pre_restore_snapshot_id: Option<i64>,
    pub components: Vec<Component>,
}

/// Result of restoring a snapshot into the live database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreSnapshotResponse {
    pub success: bool,
    pub message: String,
    pub pre_restore_snapshot_id: Option<i64>,
    pub components: Vec<Component>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_names_round_trip() {
        for component in Component::ALL {
            assert_eq!(Component::parse(component.as_str()), Some(component));
            assert_eq!(component.as_str().parse::<Component>(), Ok(component));
            let json = serde_json::to_string(&component).unwrap();
            assert_eq!(json, format!("\"{}\"", component.as_str()));
        }
        assert_eq!(Component::parse("Dnsmasq"), None);
        assert!("bogus".parse::<Component>().is_err());
    }

    #[test]
    fn snapshot_enums_round_trip() {
        for kind in [
            SnapshotKind::Applied,
            SnapshotKind::PreRestore,
            SnapshotKind::Imported,
            SnapshotKind::Manual,
        ] {
            assert_eq!(SnapshotKind::parse(kind.as_str()), Some(kind));
        }
        for status in [
            SnapshotStatus::Active,
            SnapshotStatus::PendingConfirmation,
            SnapshotStatus::RolledBack,
        ] {
            assert_eq!(SnapshotStatus::parse(status.as_str()), Some(status));
        }
        assert_eq!(SnapshotKind::parse("nope"), None);
        assert_eq!(SnapshotStatus::parse("nope"), None);
    }

    #[test]
    fn utc_dates_are_calendar_dates() {
        assert_eq!(format_utc_date(0), "1970-01-01");
        assert_eq!(format_utc_date(1_700_000_000), "2023-11-14");
        // Leap day of a century year divisible by 400.
        assert_eq!(format_utc_date(951_782_400), "2000-02-29");
        assert_eq!(format_utc_date(1_709_251_199), "2024-02-29");
        assert_eq!(format_utc_datetime(1_700_000_000), "2023-11-14 22:13");
    }

    #[test]
    fn baselines_are_addressed_per_component() {
        let mut baselines = ComponentBaselines::default();
        baselines.set(Component::Dnsmasq, Some(7));
        assert_eq!(baselines.get(Component::Dnsmasq), Some(7));
        assert_eq!(baselines.get(Component::Firewall), None);
    }
}
