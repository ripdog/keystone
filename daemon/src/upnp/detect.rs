//! Detection of the installed miniupnpd's firewall backend.
//!
//! The binary is read as bytes and searched for the names of the libraries it
//! links against. It is never executed and never passed to `ldd`, so a
//! malicious or broken binary cannot run as root here.

use std::fs::{self, File};
use std::io::{ErrorKind, Read};
use std::sync::Mutex;
use std::time::SystemTime;

use keystone_core::upnp::UpnpBinaryStatus;

/// Where the package manager installs miniupnpd, in preference order.
pub const MINIUPNPD_CANDIDATES: [&str; 2] = ["/usr/bin/miniupnpd", "/usr/sbin/miniupnpd"];

/// A miniupnpd binary is a few hundred kilobytes. Anything larger is not read.
const MAX_BINARY_BYTES: u64 = 64 * 1024 * 1024;

/// Libraries that only an nftables build links against.
const NFT_MARKERS: [&[u8]; 2] = [b"libnftnl.so", b"libmnl.so"];
/// Libraries (or the backend name) that only an iptables build carries.
const IPTABLES_MARKERS: [&[u8]; 3] = [b"libiptc", b"libip4tc", b"iptables"];

/// Classify a miniupnpd binary from its bytes. nftables wins when both sets
/// of markers are present, since the iptables name can appear in help text.
pub fn classify_binary(bytes: &[u8]) -> UpnpBinaryStatus {
    if NFT_MARKERS.iter().all(|marker| contains(bytes, marker)) {
        UpnpBinaryStatus::NftablesBuild
    } else if IPTABLES_MARKERS
        .iter()
        .any(|marker| contains(bytes, marker))
    {
        UpnpBinaryStatus::IptablesBuild
    } else {
        UpnpBinaryStatus::Unknown
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Last result, keyed by path, size and modification time, so that the status
/// endpoint, which polls, does not re-read the binary every time.
#[derive(Clone)]
struct CacheEntry {
    path: &'static str,
    len: u64,
    modified: Option<SystemTime>,
    status: UpnpBinaryStatus,
}

static CACHE: Mutex<Option<CacheEntry>> = Mutex::new(None);

/// Detect the installed miniupnpd. Blocking file access: call from
/// `spawn_blocking` when used from async code.
pub fn detect_binary() -> UpnpBinaryStatus {
    detect_in(&MINIUPNPD_CANDIDATES)
}

fn detect_in(candidates: &[&'static str]) -> UpnpBinaryStatus {
    for &path in candidates {
        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(_) => return UpnpBinaryStatus::Unknown,
        };
        if !metadata.is_file() {
            return UpnpBinaryStatus::Unknown;
        }
        let len = metadata.len();
        let modified = metadata.modified().ok();
        if let Ok(guard) = CACHE.lock()
            && let Some(entry) = guard.as_ref()
            && entry.path == path
            && entry.len == len
            && entry.modified == modified
        {
            return entry.status;
        }
        let status = read_capped(path)
            .map(|bytes| classify_binary(&bytes))
            .unwrap_or(UpnpBinaryStatus::Unknown);
        if let Ok(mut guard) = CACHE.lock() {
            *guard = Some(CacheEntry {
                path,
                len,
                modified,
                status,
            });
        }
        return status;
    }
    UpnpBinaryStatus::NotInstalled
}

fn read_capped(path: &str) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_BINARY_BYTES)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixture shaped like the dynamic section of an nftables build.
    fn nft_fixture() -> Vec<u8> {
        let mut bytes = b"\x7fELF\x00\x00".to_vec();
        bytes.extend_from_slice(b"\x00libc.so.6\x00libnftnl.so.11\x00libmnl.so.0\x00");
        bytes.extend_from_slice(b"usage: miniupnpd -f config\x00");
        bytes
    }

    fn iptables_fixture() -> Vec<u8> {
        let mut bytes = b"\x7fELF\x00\x00".to_vec();
        bytes.extend_from_slice(b"\x00libc.so.6\x00libiptc.so.0\x00");
        bytes
    }

    #[test]
    fn an_nftables_build_is_recognised_from_its_libraries() {
        assert_eq!(
            classify_binary(&nft_fixture()),
            UpnpBinaryStatus::NftablesBuild
        );
    }

    #[test]
    fn an_iptables_build_is_recognised_from_its_libraries() {
        assert_eq!(
            classify_binary(&iptables_fixture()),
            UpnpBinaryStatus::IptablesBuild
        );
        let text = b"\x7fELF libip4tc.so.2 and iptables_init.sh";
        assert_eq!(classify_binary(text), UpnpBinaryStatus::IptablesBuild);
    }

    #[test]
    fn nftables_wins_when_the_iptables_name_only_appears_as_text() {
        let mut bytes = nft_fixture();
        bytes.extend_from_slice(b"see iptables_init.sh for the other backend\x00");
        assert_eq!(classify_binary(&bytes), UpnpBinaryStatus::NftablesBuild);
    }

    #[test]
    fn a_single_nft_marker_is_not_enough() {
        assert_eq!(
            classify_binary(b"libnftnl.so.11 only"),
            UpnpBinaryStatus::Unknown
        );
    }

    #[test]
    fn an_unrecognised_binary_is_unknown_not_guessed() {
        assert_eq!(
            classify_binary(b"\x7fELF static binary"),
            UpnpBinaryStatus::Unknown
        );
        assert_eq!(classify_binary(&[]), UpnpBinaryStatus::Unknown);
    }

    #[test]
    fn a_missing_binary_is_not_installed() {
        assert_eq!(
            detect_in(&["/nonexistent/keystone-test/miniupnpd"]),
            UpnpBinaryStatus::NotInstalled
        );
    }

    #[test]
    fn a_fixture_file_is_classified_by_its_contents() {
        let dir = std::env::temp_dir().join(format!("keystone-upnp-detect-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("miniupnpd");
        fs::write(&path, nft_fixture()).unwrap();
        let leaked: &'static str = Box::leak(path.to_string_lossy().into_owned().into_boxed_str());
        assert_eq!(detect_in(&[leaked]), UpnpBinaryStatus::NftablesBuild);
        fs::write(&path, iptables_fixture()).unwrap();
        // A changed file (new contents, new modification time) is read again.
        let status = detect_in(&[leaked]);
        assert_eq!(status, UpnpBinaryStatus::IptablesBuild);
        fs::remove_dir_all(&dir).ok();
    }
}
