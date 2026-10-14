//! `.link` files that give a physical interface a persistent custom name.
//!
//! udev applies `.link` files when a device appears, so the name survives a
//! reboot. The files match the NIC by its permanent hardware address and are
//! named `10-keystone-<name>.link`, which sorts before the system's
//! `99-default.link`. They are deliberately outside the `50-keystone-` set that
//! a networkd apply rewrites and rolls back: a rename is not undone by an
//! unconfirmed-change rollback, because the device itself keeps its new name.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::{NETWORKD_DIR, atomic_write};

/// Prefix of the `.link` files Keystone owns.
const LINK_PREFIX: &str = "10-keystone-";

/// A hardware address as the kernel prints it: six lowercase hex pairs.
pub fn is_mac_address(value: &str) -> bool {
    value.len() == 17
        && value.split(':').count() == 6
        && value.split(':').all(|pair| {
            pair.len() == 2
                && pair
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

pub fn link_filename(name: &str) -> String {
    format!("{LINK_PREFIX}{name}.link")
}

/// The `.link` file that names the NIC with permanent address `mac` as `name`.
pub fn generate_link_file(mac: &str, name: &str) -> String {
    format!(
        "# Managed by Keystone: gives this NIC a persistent name.\n[Match]\nPermanentMACAddress={mac}\n\n[Link]\nName={name}\n"
    )
}

/// What installing a link file changed, so a failed rename can undo it.
#[derive(Debug)]
pub struct LinkFileChange {
    written: PathBuf,
    removed: Vec<(PathBuf, Vec<u8>)>,
}

impl LinkFileChange {
    /// Put the directory back as it was before the install.
    pub fn revert(self) -> Result<()> {
        std::fs::remove_file(&self.written)
            .or_else(|error| match error.kind() {
                std::io::ErrorKind::NotFound => Ok(()),
                _ => Err(error),
            })
            .with_context(|| format!("Failed to remove {:?}", self.written))?;
        for (path, content) in self.removed {
            atomic_write(&path, content)?;
        }
        Ok(())
    }
}

fn is_keystone_link_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_file())
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(LINK_PREFIX) && name.ends_with(".link"))
}

/// Install the link file for `mac` -> `name` in `dir`, replacing the Keystone
/// link file an earlier rename of the same NIC left behind.
pub fn install_in(dir: &Path, mac: &str, name: &str) -> Result<LinkFileChange> {
    anyhow::ensure!(is_mac_address(mac), "Invalid hardware address: {mac:?}");
    keystone_core::validation::custom_interface_name(name).map_err(anyhow::Error::msg)?;

    let written = dir.join(link_filename(name));
    let marker = format!("PermanentMACAddress={mac}\n");
    let mut removed = Vec::new();
    for entry in std::fs::read_dir(dir).with_context(|| format!("Failed to read {dir:?}"))? {
        let path = entry
            .context("Failed to inspect a networkd directory entry")?
            .path();
        if path == written || !is_keystone_link_file(&path) {
            continue;
        }
        let content = std::fs::read(&path).with_context(|| format!("Failed to read {path:?}"))?;
        if String::from_utf8_lossy(&content).contains(&marker) {
            removed.push((path, content));
        }
    }

    let previous = std::fs::read(&written).ok();
    atomic_write(&written, generate_link_file(mac, name))?;
    for (path, _) in &removed {
        std::fs::remove_file(path).with_context(|| format!("Failed to remove {path:?}"))?;
    }
    // Reverting must restore a same-named file this install overwrote, too.
    if let Some(previous) = previous {
        removed.push((written.clone(), previous));
    }
    Ok(LinkFileChange { written, removed })
}

/// Install the link file in the system's networkd directory.
pub fn install(mac: &str, name: &str) -> Result<LinkFileChange> {
    install_in(Path::new(NETWORKD_DIR), mac, name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("keystone-link-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn mac_addresses_are_checked() {
        assert!(is_mac_address("2c:f0:5d:3b:62:1a"));
        for bad in [
            "",
            "2C:F0:5D:3B:62:1A",
            "2c:f0:5d:3b:62",
            "2c:f0:5d:3b:62:1a\n[Link]",
            "zz:f0:5d:3b:62:1a",
        ] {
            assert!(!is_mac_address(bad), "{bad:?}");
        }
    }

    #[test]
    fn link_file_matches_the_permanent_address() {
        let content = generate_link_file("2c:f0:5d:3b:62:1a", "wan0");
        assert!(content.contains("[Match]\nPermanentMACAddress=2c:f0:5d:3b:62:1a\n"));
        assert!(content.contains("[Link]\nName=wan0\n"));
        assert_eq!(link_filename("wan0"), "10-keystone-wan0.link");
    }

    #[test]
    fn renaming_again_replaces_the_earlier_file_and_can_be_reverted() {
        let dir = temp_dir();
        let mac = "2c:f0:5d:3b:62:1a";
        let other = generate_link_file("00:11:22:33:44:55", "lan0");
        std::fs::write(dir.join(link_filename("lan0")), &other).unwrap();

        install_in(&dir, mac, "wan0").unwrap();
        let second = install_in(&dir, mac, "uplink").unwrap();
        assert!(!dir.join(link_filename("wan0")).exists());
        assert!(dir.join(link_filename("uplink")).exists());
        assert_eq!(
            std::fs::read_to_string(dir.join(link_filename("lan0"))).unwrap(),
            other
        );

        second.revert().unwrap();
        assert!(!dir.join(link_filename("uplink")).exists());
        assert_eq!(
            std::fs::read_to_string(dir.join(link_filename("wan0"))).unwrap(),
            generate_link_file(mac, "wan0")
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reverting_restores_a_file_of_the_same_name() {
        let dir = temp_dir();
        install_in(&dir, "2c:f0:5d:3b:62:1a", "wan0").unwrap();
        let change = install_in(&dir, "aa:bb:cc:dd:ee:ff", "wan0").unwrap();
        change.revert().unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join(link_filename("wan0"))).unwrap(),
            generate_link_file("2c:f0:5d:3b:62:1a", "wan0")
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_bad_input() {
        let dir = temp_dir();
        assert!(install_in(&dir, "nonsense", "wan0").is_err());
        assert!(install_in(&dir, "2c:f0:5d:3b:62:1a", "eth0").is_err());
        assert!(install_in(&dir, "2c:f0:5d:3b:62:1a", "wan0\nName=x").is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
