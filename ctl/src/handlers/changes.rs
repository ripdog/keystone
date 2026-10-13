use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::{Context, Result, bail};
use keystone_core::api::{DiscardChanges, Endpoint, RestoreSnapshot};
use keystone_core::changes::{
    Component, ComponentSelectionRequest, CreateSnapshotRequest, DiscardChangesResponse,
    MAX_SNAPSHOT_UPLOAD_BYTES, PendingChangesResponse, RestoreSnapshotResponse,
    SnapshotListResponse, SnapshotResponse,
};

use crate::client::DaemonClient;
use crate::commands::{ChangesAction, SnapshotsCommands};
use crate::io::output;
use crate::pretty;
use crate::token::get_token;

fn selection(components: Vec<Component>) -> Option<Vec<Component>> {
    (!components.is_empty()).then_some(components)
}

pub async fn handle_changes_command(
    client: &DaemonClient,
    cli_json: bool,
    token: Option<String>,
    action: Option<ChangesAction>,
) -> Result<()> {
    let authed = client.authed(get_token(token)?);
    match action {
        None => {
            let response: PendingChangesResponse = authed.get("/changes/pending").await?;
            output(cli_json, &response, pretty::pending_changes);
        }
        Some(ChangesAction::Discard { components }) => {
            let request = ComponentSelectionRequest {
                components: selection(components),
            };
            let response: DiscardChangesResponse = authed.call::<DiscardChanges>(&request).await?;
            output(cli_json, &response, pretty::discard_changes);
            if !response.success {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

pub async fn handle_snapshots_command(
    client: &DaemonClient,
    cli_json: bool,
    subcmd: SnapshotsCommands,
) -> Result<()> {
    match subcmd {
        SnapshotsCommands::List { token } => {
            let authed = client.authed(get_token(token)?);
            let response: SnapshotListResponse = authed.get("/snapshots").await?;
            output(cli_json, &response, pretty::snapshot_list);
        }

        SnapshotsCommands::Create { token, note } => {
            let authed = client.authed(get_token(token)?);
            let request = CreateSnapshotRequest { note };
            let response: SnapshotResponse = authed.post("/snapshots", &request).await?;
            output(cli_json, &response, pretty::snapshot_response);
        }

        SnapshotsCommands::ShowDiff { id, token } => {
            let authed = client.authed(get_token(token)?);
            let response: PendingChangesResponse =
                authed.get(&format!("/snapshots/{id}/diff")).await?;
            output(cli_json, &response, |response| {
                pretty::component_diffs(&format!("Restoring snapshot {id} would change"), response)
            });
        }

        SnapshotsCommands::Restore {
            id,
            components,
            token,
        } => {
            let authed = client.authed(get_token(token)?);
            let request = ComponentSelectionRequest {
                components: selection(components),
            };
            let path =
                keystone_core::api::render_path(RestoreSnapshot::PATH, &[("id", &id.to_string())]);
            let response: RestoreSnapshotResponse = authed.post(&path, &request).await?;
            output(cli_json, &response, pretty::restore_snapshot);
            if !response.success {
                std::process::exit(1);
            }
        }

        SnapshotsCommands::Export { id, file, token } => {
            let authed = client.authed(get_token(token)?);
            let bytes = authed.get_raw(&format!("/snapshots/{id}/export")).await?;
            write_new_private_file(&file, &bytes)?;
            if cli_json {
                println!(
                    "{}",
                    serde_json::json!({"snapshot": id, "file": file, "bytes": bytes.len()})
                );
            } else {
                println!(
                    "Saved snapshot {id} to {} ({} bytes)",
                    file.display(),
                    bytes.len()
                );
            }
        }

        SnapshotsCommands::Import { file, token } => {
            let metadata = std::fs::metadata(&file)
                .with_context(|| format!("Failed to read {}", file.display()))?;
            if metadata.len() > MAX_SNAPSHOT_UPLOAD_BYTES as u64 {
                bail!(
                    "{} is larger than the {MAX_SNAPSHOT_UPLOAD_BYTES}-byte snapshot limit",
                    file.display()
                );
            }
            let bytes = std::fs::read(&file)
                .with_context(|| format!("Failed to read {}", file.display()))?;
            let authed = client.authed(get_token(token)?);
            let response: SnapshotResponse = authed
                .post_raw("/snapshots/import", bytes, "application/vnd.sqlite3")
                .await?;
            output(cli_json, &response, pretty::snapshot_response);
            if !response.success {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

/// Write a file that must not already exist, readable by its owner only.
fn write_new_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("Refusing to overwrite or create {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("Failed to write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("Failed to flush {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::{Cli, Commands};
    use clap::Parser;

    #[test]
    fn restore_and_discard_take_repeatable_components() {
        let cli = Cli::try_parse_from([
            "keystonectl",
            "snapshots",
            "restore",
            "3",
            "--component",
            "dnsmasq",
            "--component",
            "caddy",
            "--token",
            "t",
        ])
        .unwrap();
        let Some(Commands::Snapshots(SnapshotsCommands::Restore { id, components, .. })) =
            cli.command
        else {
            panic!("expected snapshots restore");
        };
        assert_eq!(id, 3);
        assert_eq!(components, vec![Component::Dnsmasq, Component::Caddy]);

        let cli = Cli::try_parse_from(["keystonectl", "changes", "discard"]).unwrap();
        let Some(Commands::Changes {
            action: Some(ChangesAction::Discard { components }),
            ..
        }) = cli.command
        else {
            panic!("expected changes discard");
        };
        assert!(components.is_empty());
    }

    #[test]
    fn unknown_component_names_are_rejected_by_the_parser() {
        assert!(
            Cli::try_parse_from([
                "keystonectl",
                "snapshots",
                "restore",
                "1",
                "--component",
                "wifi"
            ])
            .is_err()
        );
    }

    #[test]
    fn export_never_overwrites_an_existing_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("keystonectl-export-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("snap.db");
        let _ = std::fs::remove_file(&path);

        write_new_private_file(&path, b"first").unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(write_new_private_file(&path, b"second").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
