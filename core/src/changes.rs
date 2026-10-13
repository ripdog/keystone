//! Configuration components, snapshots and pending-change models.
//!
//! The router configuration is split into four components. Each one is
//! generated into system files by its own apply step, so a snapshot records
//! which components it was taken as applied for, and pending changes are
//! computed per component.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// A part of the router configuration that is generated into system files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Component {
    Networkd,
    Firewall,
    Dnsmasq,
    Caddy,
}

impl Component {
    /// Every component, in apply order.
    pub const ALL: [Component; 4] = [
        Component::Networkd,
        Component::Firewall,
        Component::Dnsmasq,
        Component::Caddy,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Component::Networkd => "networkd",
            Component::Firewall => "firewall",
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
                "unknown component {value:?}; expected one of networkd, firewall, dnsmasq, caddy"
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
    pub dnsmasq: Option<i64>,
    pub caddy: Option<i64>,
}

impl ComponentBaselines {
    pub fn get(&self, component: Component) -> Option<i64> {
        match component {
            Component::Networkd => self.networkd,
            Component::Firewall => self.firewall,
            Component::Dnsmasq => self.dnsmasq,
            Component::Caddy => self.caddy,
        }
    }

    pub fn set(&mut self, component: Component, id: Option<i64>) {
        match component {
            Component::Networkd => self.networkd = id,
            Component::Firewall => self.firewall = id,
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
    fn baselines_are_addressed_per_component() {
        let mut baselines = ComponentBaselines::default();
        baselines.set(Component::Dnsmasq, Some(7));
        assert_eq!(baselines.get(Component::Dnsmasq), Some(7));
        assert_eq!(baselines.get(Component::Firewall), None);
    }
}
