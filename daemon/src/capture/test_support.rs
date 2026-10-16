//! Stand-in `tcpdump` and `setpriv` programs and a scratch directory, so the
//! capture pipeline can be tested end to end without privilege.

use super::*;
use keystone_core::capture::{CaptureClause, CaptureFilter, DEFAULT_SNAPLEN};
use std::sync::atomic::AtomicU32;

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A scratch directory with stand-in `tcpdump` and `setpriv` programs.
pub(crate) struct Fixture {
    pub(crate) root: PathBuf,
    pub(crate) env: CaptureEnv,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A little-endian pcap holding `count` 60-byte packets.
pub(crate) fn sample_pcap(count: usize) -> Vec<u8> {
    let mut out = vec![0xd4, 0xc3, 0xb2, 0xa1];
    out.extend_from_slice(&[0; 20]);
    for _ in 0..count {
        out.extend_from_slice(&[0; 8]);
        out.extend_from_slice(&60u32.to_le_bytes());
        out.extend_from_slice(&60u32.to_le_bytes());
        out.extend_from_slice(&[0xcd; 60]);
    }
    out
}

fn write_script(path: &Path, body: &str) {
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// `capture_body` is what the stand-in does when asked to capture; as a
/// viewer it prints three lines, whatever it reads.
pub(crate) fn fixture(capture_body: impl FnOnce(&Path) -> String) -> Fixture {
    let root = std::env::temp_dir().join(format!(
        "keystone-capture-test-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(root.join("net/eth1")).unwrap();
    std::fs::write(root.join("sample.pcap"), sample_pcap(3)).unwrap();
    let tcpdump = root.join("tcpdump");
    write_script(
        &tcpdump,
        &format!(
            "mode=viewer\nfor a in \"$@\"; do [ \"$a\" = -w ] && mode=capture; done\n\
                 if [ $mode = capture ]; then\n{}\nelse\n\
                 cat >/dev/null; echo 'line one'; echo 'line two'; echo 'line three'\nfi",
            capture_body(&root)
        ),
    );
    // Skips setpriv's own options, then runs the program it was given.
    let setpriv = root.join("setpriv");
    write_script(
        &setpriv,
        "while [ \"${1#/}\" = \"$1\" ]; do shift; done\nexec \"$@\"",
    );
    let env = CaptureEnv {
        dir: root.join("out"),
        tcpdump,
        setpriv,
        net_dir: root.join("net"),
    };
    Fixture { root, env }
}

/// Writes the sample capture and tcpdump's usual notes.
pub(crate) fn sample_command(root: &Path) -> String {
    format!(
        "cat {}; echo 'tcpdump: listening on eth1' >&2; \\
             echo '3 packets captured' >&2; echo '1 packets dropped by kernel' >&2",
        root.join("sample.pcap").display()
    )
}

pub(crate) fn request(filter: Vec<CaptureClause>) -> CaptureRequest {
    CaptureRequest {
        interface: "eth1".into(),
        filter: CaptureFilter { clauses: filter },
        snaplen: DEFAULT_SNAPLEN,
        max_packets: 10,
        max_seconds: 30,
    }
}
