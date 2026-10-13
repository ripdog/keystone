//! The nftables table that miniupnpd writes its port-mapping rules into.
//!
//! miniupnpd does not create its tables; its own setup script does, and that
//! script assumes the default `filter` names. Keystone creates this table
//! instead, with the chains and jumps miniupnpd expects.
//!
//! The table is separate from Keystone's `keystone` and `keystone_nat` tables,
//! which a firewall apply deletes and recreates. Mapping rules here therefore
//! survive firewall applies. The table is ip-family because miniupnpd's
//! `upnp_nftables_family_split=yes` option is the IPv4-only mode, which avoids
//! matching IPv4 payload offsets against IPv6 packets.

use std::borrow::Cow;
use std::process::Stdio;

use anyhow::{Context, Result, bail};
use nftables::{
    batch::Batch,
    schema::{Chain, NfListObject, Rule},
    stmt::{JumpTarget, Statement},
    types::{NfChainPolicy, NfChainType, NfFamily, NfHook},
};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// Name of the table. miniupnpd's `upnp_table_name` and `upnp_nat_table_name`.
pub const UPNP_TABLE: &str = "keystone_upnp";
/// miniupnpd's `upnp_forward_chain`: filter rules, jumped to from `forward`.
pub const FORWARD_CHAIN: &str = "miniupnpd";
/// miniupnpd's `upnp_nat_chain`: DNAT rules, jumped to from `prerouting`.
pub const PREROUTING_CHAIN: &str = "prerouting_miniupnpd";
/// miniupnpd's `upnp_nat_postrouting_chain`: SNAT rules for peers.
pub const POSTROUTING_CHAIN: &str = "postrouting_miniupnpd";

const FAMILY: NfFamily = NfFamily::IP;

/// The objects that make up the table, in the order they are loaded.
///
/// The base chains have an accept policy. Keystone's forward chain decides
/// what passes through the router; an accept here does not override a drop
/// there, and a drop policy here would make the firewall apply refuse to run
/// (see `firewall::apply::foreign_drop_chains`). miniupnpd's own rules only
/// add the DNAT and the forward matches that its clients need.
pub fn table_objects() -> Vec<NfListObject<'static>> {
    let mut objects = vec![NfListObject::Table(nftables::schema::Table {
        family: FAMILY,
        name: Cow::Borrowed(UPNP_TABLE),
        ..Default::default()
    })];

    objects.push(NfListObject::Chain(base_chain(
        "forward",
        NfChainType::Filter,
        NfHook::Forward,
        0,
    )));
    objects.push(NfListObject::Chain(regular_chain(FORWARD_CHAIN)));
    objects.push(NfListObject::Rule(jump_rule("forward", FORWARD_CHAIN)));

    objects.push(NfListObject::Chain(base_chain(
        "prerouting",
        NfChainType::NAT,
        NfHook::Prerouting,
        -100,
    )));
    objects.push(NfListObject::Chain(regular_chain(PREROUTING_CHAIN)));
    objects.push(NfListObject::Rule(jump_rule(
        "prerouting",
        PREROUTING_CHAIN,
    )));

    objects.push(NfListObject::Chain(base_chain(
        "postrouting",
        NfChainType::NAT,
        NfHook::Postrouting,
        100,
    )));
    objects.push(NfListObject::Chain(regular_chain(POSTROUTING_CHAIN)));
    objects.push(NfListObject::Rule(jump_rule(
        "postrouting",
        POSTROUTING_CHAIN,
    )));

    objects
}

fn base_chain(name: &'static str, kind: NfChainType, hook: NfHook, prio: i32) -> Chain<'static> {
    Chain {
        family: FAMILY,
        table: Cow::Borrowed(UPNP_TABLE),
        name: Cow::Borrowed(name),
        _type: Some(kind),
        hook: Some(hook),
        prio: Some(prio),
        policy: Some(NfChainPolicy::Accept),
        ..Default::default()
    }
}

fn regular_chain(name: &'static str) -> Chain<'static> {
    Chain {
        family: FAMILY,
        table: Cow::Borrowed(UPNP_TABLE),
        name: Cow::Borrowed(name),
        ..Default::default()
    }
}

fn jump_rule(chain: &'static str, target: &'static str) -> Rule<'static> {
    Rule {
        family: FAMILY,
        table: Cow::Borrowed(UPNP_TABLE),
        chain: Cow::Borrowed(chain),
        expr: vec![Statement::Jump(JumpTarget {
            target: Cow::Borrowed(target),
        })]
        .into(),
        ..Default::default()
    }
}

/// Whether the table exists.
pub async fn table_exists() -> bool {
    Command::new("nft")
        .args(["list", "table", "ip", UPNP_TABLE])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Create the table, failing if it already exists. Callers delete it first
/// when they need a fresh one.
pub async fn create_table() -> Result<()> {
    let mut batch = Batch::new();
    for object in table_objects() {
        batch.add(object);
    }
    let json = serde_json::to_string(&batch.to_nftables()).context("serialise UPnP table")?;

    let mut child = Command::new("nft")
        .args(["-j", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to start nft")?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(json.as_bytes())
            .await
            .context("failed to write the UPnP table to nft")?;
    }
    let output = child
        .wait_with_output()
        .await
        .context("failed to wait for nft")?;
    if !output.status.success() {
        bail!(
            "failed to create nftables table ip {UPNP_TABLE}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Delete the table with every rule miniupnpd added to it. Deleting a table
/// that does not exist is not an error.
pub async fn delete_table() -> Result<()> {
    let output = Command::new("nft")
        .args(["delete", "table", "ip", UPNP_TABLE])
        .output()
        .await
        .context("failed to run nft delete table")?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("No such file or directory") {
        return Ok(());
    }
    bail!(
        "failed to delete nftables table ip {UPNP_TABLE}: {}",
        stderr.trim()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_has_the_chains_and_jumps_miniupnpd_expects() {
        let mut batch = Batch::new();
        for object in table_objects() {
            batch.add(object);
        }
        let text = serde_json::to_value(batch.to_nftables())
            .unwrap()
            .to_string();
        for name in [FORWARD_CHAIN, PREROUTING_CHAIN, POSTROUTING_CHAIN] {
            assert!(
                text.contains(&format!("\"name\":\"{name}\"")),
                "missing {name}"
            );
        }
        assert!(text.contains("\"target\":\"miniupnpd\""));
        assert!(text.contains("\"target\":\"prerouting_miniupnpd\""));
        assert!(text.contains("\"target\":\"postrouting_miniupnpd\""));
    }

    #[test]
    fn base_chains_accept_so_they_cannot_veto_the_firewall() {
        for object in table_objects() {
            if let NfListObject::Chain(chain) = object
                && chain.hook.is_some()
            {
                assert_eq!(chain.policy, Some(NfChainPolicy::Accept), "{}", chain.name);
            }
        }
    }
}
