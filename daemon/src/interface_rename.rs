//! Renaming a physical interface to a persistent custom name such as `wan0`.
//!
//! The configuration is the source of truth, so a rename first changes it and
//! the `.link` file that makes the name survive a reboot (both undoable), then
//! renames the live device, and finally runs the regular unified apply so every
//! service picks up the new name through its own, confirm-or-revert path. If
//! the daemon stops half way, the `.link` file and the database already agree,
//! and the device takes its new name at the next boot.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use keystone_core::{BridgeConfig, InterfaceConfig, RenameInterfaceResponse, VlanConfig};
use serde_json::Value;
use tracing::{info, warn};

use crate::apply;
use crate::db::Database;
use crate::firewall::FirewallApplyManager;
use crate::networkd::link;
use crate::sqm;
use crate::status;

const SYS_CLASS_NET: &str = "/sys/class/net";

/// Everything that decides whether a rename is allowed, gathered up front.
pub struct RenameContext<'a> {
    /// Physical interfaces present on the system.
    pub physical: &'a [String],
    /// Every device name present on the system, physical or not.
    pub system_names: &'a [String],
    pub configs: &'a [InterfaceConfig],
    pub vlans: &'a [VlanConfig],
    pub bridges: &'a [BridgeConfig],
}

/// Why `old` cannot be renamed to `new`, if it cannot.
pub fn check_rename(old: &str, new: &str, ctx: &RenameContext<'_>) -> Result<(), String> {
    keystone_core::validation::interface_name(old)?;
    keystone_core::validation::custom_interface_name(new)?;
    if old == new {
        return Err("The new name is the same as the current one".to_string());
    }
    if !ctx.physical.iter().any(|name| name == old) {
        return Err(format!(
            "{old} is not a physical network interface on this system"
        ));
    }
    if let Some(vlan) = ctx.vlans.iter().find(|v| v.parent_interface == old) {
        return Err(format!(
            "{old} is the parent of VLAN {}; remove the VLAN before renaming its parent",
            vlan.name
        ));
    }

    let mut taken: HashSet<&str> = ctx.system_names.iter().map(String::as_str).collect();
    taken.extend(ctx.configs.iter().map(|c| c.name.as_str()));
    taken.extend(ctx.vlans.iter().map(|v| v.name.as_str()));
    taken.extend(ctx.bridges.iter().map(|b| b.name.as_str()));
    taken.extend(
        ctx.bridges
            .iter()
            .flat_map(|b| b.members.iter().map(String::as_str)),
    );
    if taken.contains(new) {
        return Err(format!("The name {new} is already in use"));
    }
    Ok(())
}

/// The permanent hardware address in `ip -d -j link show` output. `ip` prints
/// `permaddr` only when it differs from the current address.
pub fn permanent_mac_from_ip_json(json: &str, name: &str) -> Result<String> {
    let links: Vec<Value> = serde_json::from_str(json).context("Unreadable `ip` output")?;
    let link = links
        .iter()
        .find(|link| link.get("ifname").and_then(Value::as_str) == Some(name))
        .ok_or_else(|| anyhow!("{name} was not reported by `ip link`"))?;
    let mac = ["permaddr", "address"]
        .iter()
        .find_map(|key| link.get(*key).and_then(Value::as_str))
        .ok_or_else(|| anyhow!("{name} has no hardware address"))?;
    if !link::is_mac_address(mac) || mac == "00:00:00:00:00:00" {
        bail!("{name} has no usable hardware address ({mac:?}), so its name cannot be pinned");
    }
    Ok(mac.to_string())
}

async fn run_ip(args: &[&str]) -> Result<String> {
    let output = tokio::process::Command::new("ip")
        .args(args)
        .output()
        .await
        .context("Failed to start `ip`")?;
    if !output.status.success() {
        bail!(
            "`ip {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

async fn permanent_mac(name: &str) -> Result<String> {
    let json = run_ip(&["-d", "-j", "link", "show", "dev", name]).await?;
    permanent_mac_from_ip_json(&json, name)
}

/// Whether the kernel reports the interface administratively up (IFF_UP).
fn is_admin_up(name: &str) -> bool {
    std::fs::read_to_string(Path::new(SYS_CLASS_NET).join(name).join("flags"))
        .ok()
        .and_then(|flags| u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16).ok())
        .is_some_and(|flags| flags & 0x1 != 0)
}

/// Rename the live device. A device must be down to change its name, so it is
/// taken down and, if it was up, brought back up under the new name.
async fn rename_live(old: &str, new: &str) -> Result<()> {
    let was_up = is_admin_up(old);
    run_ip(&["link", "set", "dev", old, "down"]).await?;
    if let Err(error) = run_ip(&["link", "set", "dev", old, "name", new]).await {
        if was_up && let Err(up) = run_ip(&["link", "set", "dev", old, "up"]).await {
            warn!("Could not bring {old} back up after a failed rename: {up:#}");
        }
        return Err(error);
    }
    if was_up {
        run_ip(&["link", "set", "dev", new, "up"]).await?;
    }
    Ok(())
}

fn system_interface_names() -> Vec<String> {
    std::fs::read_dir(SYS_CLASS_NET)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn refusal(message: impl Into<String>) -> RenameInterfaceResponse {
    RenameInterfaceResponse {
        success: false,
        message: message.into(),
        apply: None,
    }
}

/// Rename `old` to `new` and apply the configuration. Refusals and rolled-back
/// failures come back as an unsuccessful response; `Err` is for unexpected
/// failures after which nothing was left changed.
pub async fn rename_interface(
    db: &Database,
    firewall_manager: &Arc<FirewallApplyManager>,
    actor: Option<&str>,
    old: &str,
    new: &str,
) -> Result<RenameInterfaceResponse> {
    if db.get_global_settings().await?.config_changes_disabled {
        return Ok(refusal(
            "Configuration changes are disabled. Unlock in Settings to rename interfaces.",
        ));
    }
    if apply::pending_confirmation(firewall_manager)
        .await
        .is_some()
    {
        return Ok(refusal(apply::AWAITING_CONFIRMATION_MESSAGE));
    }

    let configs = db.get_interface_configs().await?;
    let vlans = db.get_all_vlans().await?;
    let bridges = db.get_all_bridges().await?;
    let physical = status::get_physical_interfaces();
    let system_names = system_interface_names();
    let context = RenameContext {
        physical: &physical,
        system_names: &system_names,
        configs: &configs,
        vlans: &vlans,
        bridges: &bridges,
    };
    if let Err(reason) = check_rename(old, new, &context) {
        return Ok(refusal(reason));
    }

    let mac = permanent_mac(old).await?;

    // Persistent name and configuration first: both can be undone, and the
    // pair is already consistent if the daemon stops before the live rename.
    let link_change = link::install(&mac, new).context("Failed to write the .link file")?;
    if let Err(error) = db.rename_interface_references(old, new).await {
        if let Err(revert) = link_change.revert() {
            warn!("Could not remove the .link file after a failed rename: {revert:#}");
        }
        return Err(error);
    }

    // Shaping on the old name cannot follow a rename; it is set up again by
    // the apply below.
    let shaped = sqm::load_sqm_config(db.pool()).await?.interface == new;
    let live = async {
        if shaped {
            sqm::release_interface(db, old).await?;
        }
        rename_live(old, new).await
    }
    .await;
    if let Err(error) = live {
        warn!("Renaming {old} to {new} failed, restoring the configuration: {error:#}");
        let restored = db.rename_interface_references(new, old).await;
        let unlinked = link_change.revert();
        return Ok(refusal(match (restored, unlinked) {
            (Ok(()), Ok(())) => format!("Could not rename {old}: {error:#}"),
            (restored, unlinked) => format!(
                "Could not rename {old}: {error:#}. Restoring the previous configuration also failed ({}); check the interface settings",
                [restored.err(), unlinked.err()]
                    .into_iter()
                    .flatten()
                    .map(|e| format!("{e:#}"))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        }));
    }
    info!("Renamed interface {old} to {new}");

    let applied = apply::apply_all(db, firewall_manager, None, actor).await?;
    let message = if applied.success {
        format!("Renamed {old} to {new}. {}", applied.message)
    } else {
        format!(
            "Renamed {old} to {new}, but applying the configuration failed. {}",
            applied.message
        )
    };
    Ok(RenameInterfaceResponse {
        success: applied.success,
        message,
        apply: Some(applied),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    fn check(
        old: &str,
        new: &str,
        configs: &[InterfaceConfig],
        vlans: &[VlanConfig],
        bridges: &[BridgeConfig],
    ) -> Result<(), String> {
        let physical = strings(&["enp1s0", "enp2s0"]);
        let system = strings(&["lo", "enp1s0", "enp2s0", "br0"]);
        check_rename(
            old,
            new,
            &RenameContext {
                physical: &physical,
                system_names: &system,
                configs,
                vlans,
                bridges,
            },
        )
    }

    #[test]
    fn a_free_name_on_a_physical_interface_is_accepted() {
        assert_eq!(check("enp1s0", "wan0", &[], &[], &[]), Ok(()));
    }

    #[test]
    fn refuses_bad_or_unchanged_names() {
        assert!(check("enp1s0", "eth0", &[], &[], &[]).is_err());
        assert!(check("enp1s0", "wan 0", &[], &[], &[]).is_err());
        assert!(check("enp1s0", "enp1s0", &[], &[], &[]).is_err());
    }

    #[test]
    fn refuses_interfaces_that_are_not_physical() {
        assert!(check("br0", "lan0", &[], &[], &[]).is_err());
        assert!(check("enp9s0", "lan0", &[], &[], &[]).is_err());
    }

    #[test]
    fn refuses_names_already_in_use() {
        let config = InterfaceConfig {
            name: "wan0".into(),
            ..Default::default()
        };
        assert!(check("enp1s0", "wan0", &[config], &[], &[]).is_err());
        let vlan = VlanConfig {
            name: "wan0".into(),
            parent_interface: "enp2s0".into(),
            ..Default::default()
        };
        assert!(check("enp1s0", "wan0", &[], &[vlan], &[]).is_err());
        let bridge = BridgeConfig {
            name: "lan0".into(),
            members: strings(&["wan0"]),
            ..Default::default()
        };
        assert!(check("enp1s0", "wan0", &[], &[], std::slice::from_ref(&bridge)).is_err());
        assert!(check("enp1s0", "lan0", &[], &[], &[bridge]).is_err());
    }

    #[test]
    fn refuses_the_parent_of_a_vlan() {
        let vlan = VlanConfig {
            name: "vlan10".into(),
            parent_interface: "enp1s0".into(),
            ..Default::default()
        };
        let error = check("enp1s0", "wan0", &[], &[vlan], &[]).unwrap_err();
        assert!(error.contains("vlan10"), "{error}");
    }

    #[test]
    fn a_bridge_member_can_be_renamed() {
        let bridge = BridgeConfig {
            name: "br0".into(),
            members: strings(&["enp1s0"]),
            ..Default::default()
        };
        assert_eq!(check("enp1s0", "lan0", &[], &[], &[bridge]), Ok(()));
    }

    #[test]
    fn permanent_address_prefers_permaddr() {
        let json = r#"[
            {"ifname":"enp1s0","address":"2c:f0:5d:3b:62:1a"},
            {"ifname":"wlo1","address":"76:76:6b:d8:1a:5d","permaddr":"e4:5e:37:cb:c5:e6"},
            {"ifname":"lo","address":"00:00:00:00:00:00"}
        ]"#;
        assert_eq!(
            permanent_mac_from_ip_json(json, "enp1s0").unwrap(),
            "2c:f0:5d:3b:62:1a"
        );
        assert_eq!(
            permanent_mac_from_ip_json(json, "wlo1").unwrap(),
            "e4:5e:37:cb:c5:e6"
        );
        assert!(permanent_mac_from_ip_json(json, "lo").is_err());
        assert!(permanent_mac_from_ip_json(json, "missing").is_err());
        assert!(permanent_mac_from_ip_json("not json", "enp1s0").is_err());
    }
}
