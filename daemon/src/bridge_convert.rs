//! Converting a LAN interface into a bridge in one staged step.
//!
//! A bridge that should carry the LAN (for example to add a Wi-Fi access point
//! to it) takes over everything the LAN port had: its addresses, DHCP range,
//! firewall zone and service bindings. Doing that by hand touches many places
//! and a slip locks the administrator out of the LAN. The conversion only edits
//! the saved configuration; applying it goes through the usual networkd
//! confirm-or-rollback path.

use std::collections::HashSet;

use keystone_core::{
    BridgeConfig, ConvertToBridgeResponse, InterfaceConfig, InterfaceRole, VlanConfig, validation,
};

use crate::db::Database;

/// Everything that decides whether a conversion is allowed, gathered up front.
pub struct ConvertContext<'a> {
    /// Every device name present on the system.
    pub system_names: &'a [String],
    pub configs: &'a [InterfaceConfig],
    pub vlans: &'a [VlanConfig],
    pub bridges: &'a [BridgeConfig],
}

/// Why `member` cannot be moved onto a new bridge called `bridge`, if it cannot.
pub fn check_conversion(
    member: &str,
    bridge: &str,
    ctx: &ConvertContext<'_>,
) -> Result<(), String> {
    validation::interface_name(member)?;
    validation::custom_interface_name(bridge)?;

    let config = ctx
        .configs
        .iter()
        .find(|config| config.name == member)
        .ok_or_else(|| format!("{member} has no interface configuration to move"))?;
    if config.role != InterfaceRole::LAN {
        return Err(format!(
            "{member} is not a LAN interface; only a LAN interface can be moved onto a bridge"
        ));
    }
    if !config.enabled {
        return Err(format!(
            "{member} is disabled; enable it before moving it onto a bridge"
        ));
    }
    if let Some(existing) = ctx
        .bridges
        .iter()
        .find(|b| b.members.iter().any(|m| m == member))
    {
        return Err(format!("{member} is already a member of {}", existing.name));
    }
    if ctx.bridges.iter().any(|b| b.name == member) || ctx.vlans.iter().any(|v| v.name == member) {
        return Err(format!(
            "{member} is a bridge or VLAN; only a physical port can be a bridge member"
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
    if taken.contains(bridge) {
        return Err(format!("The name {bridge} is already in use"));
    }
    Ok(())
}

fn refusal(message: impl Into<String>) -> ConvertToBridgeResponse {
    ConvertToBridgeResponse {
        success: false,
        message: message.into(),
        bridge_id: None,
    }
}

/// Check and stage the conversion of LAN interface `member` onto new bridge
/// `bridge`. Refusals come back as an unsuccessful response; `Err` is for
/// unexpected failures, after which nothing was changed.
pub async fn convert_to_bridge(
    db: &Database,
    member: &str,
    bridge: &str,
) -> anyhow::Result<ConvertToBridgeResponse> {
    let configs = db.get_interface_configs().await?;
    let vlans = db.get_all_vlans().await?;
    let bridges = db.get_all_bridges().await?;
    let system_names = crate::interface_rename::system_interface_names();
    let ctx = ConvertContext {
        system_names: &system_names,
        configs: &configs,
        vlans: &vlans,
        bridges: &bridges,
    };
    if let Err(message) = check_conversion(member, bridge, &ctx) {
        return Ok(refusal(message));
    }

    let bridge_id = db.convert_interface_to_bridge(member, bridge).await?;
    Ok(ConvertToBridgeResponse {
        success: true,
        message: format!(
            "{member} is now a member of the new bridge {bridge}, which carries its addresses, \
             DHCP range and firewall zone. Review the pending network changes, then apply."
        ),
        bridge_id: Some(bridge_id),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(name: &str, role: InterfaceRole, enabled: bool) -> InterfaceConfig {
        InterfaceConfig {
            name: name.to_string(),
            role,
            enabled,
            ..Default::default()
        }
    }

    fn bridge(name: &str, members: &[&str]) -> BridgeConfig {
        BridgeConfig {
            name: name.to_string(),
            members: members.iter().map(|m| m.to_string()).collect(),
            ..Default::default()
        }
    }

    fn check(
        configs: &[InterfaceConfig],
        bridges: &[BridgeConfig],
        system: &[&str],
        member: &str,
        name: &str,
    ) -> Result<(), String> {
        let system_names: Vec<String> = system.iter().map(|s| s.to_string()).collect();
        check_conversion(
            member,
            name,
            &ConvertContext {
                system_names: &system_names,
                configs,
                vlans: &[],
                bridges,
            },
        )
    }

    fn lan() -> Vec<InterfaceConfig> {
        vec![
            config("lan0", InterfaceRole::LAN, true),
            config("wan0", InterfaceRole::WAN, true),
        ]
    }

    #[test]
    fn an_enabled_lan_interface_can_be_converted() {
        assert_eq!(
            check(&lan(), &[], &["lan0", "wan0"], "lan0", "br-lan"),
            Ok(())
        );
    }

    #[test]
    fn only_an_enabled_lan_interface_with_a_configuration_qualifies() {
        let configs = lan();
        assert!(check(&configs, &[], &[], "wan0", "br-lan").is_err());
        assert!(check(&configs, &[], &[], "eth9", "br-lan").is_err());
        let disabled = vec![config("lan0", InterfaceRole::LAN, false)];
        assert!(check(&disabled, &[], &[], "lan0", "br-lan").is_err());
    }

    #[test]
    fn a_bridge_member_or_bridge_cannot_be_converted_again() {
        let bridges = [bridge("br-lan", &["lan0"])];
        let error = check(&lan(), &bridges, &[], "lan0", "br-other").unwrap_err();
        assert!(error.contains("br-lan"), "{error}");
        let configs = vec![config("br-lan", InterfaceRole::LAN, true)];
        assert!(check(&configs, &bridges, &[], "br-lan", "br-other").is_err());
    }

    #[test]
    fn the_new_name_must_be_free_and_acceptable() {
        let bridges = [bridge("br-x", &["lan1"])];
        for taken in ["br-x", "lan1", "lan0", "wan0", "enp3s0"] {
            assert!(
                check(&lan(), &bridges, &["enp3s0"], "lan0", taken).is_err(),
                "{taken}"
            );
        }
        for bad in ["", "br lan", "../x", "br.1", "eth5"] {
            assert!(check(&lan(), &[], &[], "lan0", bad).is_err(), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn the_converted_configuration_generates_a_consistent_networkd_setup() {
        let db = Database::new_in_memory().await.unwrap();
        db.save_interface_config(&InterfaceConfig {
            name: "lan0".to_string(),
            role: InterfaceRole::LAN,
            enabled: true,
            addresses: vec![keystone_core::StaticAddress {
                address: "192.168.1.1/24".to_string(),
                label: None,
                scope: Default::default(),
            }],
            ..Default::default()
        })
        .await
        .unwrap();

        let response = convert_to_bridge(&db, "lan0", "br-lan").await.unwrap();
        assert!(response.success, "{}", response.message);

        // The member and the bridge no longer conflict.
        let configs = db.get_interface_configs().await.unwrap();
        let bridges = db.get_all_bridges().await.unwrap();
        assert_eq!(
            crate::networkd::validate_topology(&configs, &[], &bridges),
            Vec::<String>::new()
        );

        // The address now belongs to the bridge, and the port is enslaved to it.
        let files = crate::networkd_preview_files(&db).await.unwrap();
        let file = |suffix: &str| {
            files
                .iter()
                .find(|file| file.filename.ends_with(suffix))
                .unwrap_or_else(|| panic!("no {suffix} among {:?}", files))
        };
        assert!(
            file("br-lan.network")
                .content
                .contains("Address=192.168.1.1/24")
        );
        let member = file("lan0.network");
        assert!(member.content.contains("Bridge=br-lan"));
        assert!(!member.content.contains("192.168.1.1"));
        assert!(file("br-lan.netdev").content.contains("Kind=bridge"));
    }

    #[tokio::test]
    async fn a_refused_conversion_leaves_the_configuration_alone() {
        let db = Database::new_in_memory().await.unwrap();
        let response = convert_to_bridge(&db, "lan0", "br-lan").await.unwrap();
        assert!(!response.success);
        assert!(db.get_all_bridges().await.unwrap().is_empty());
    }
}
