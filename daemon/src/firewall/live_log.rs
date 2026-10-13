//! Live view of the kernel lines logged by firewall rules.
//!
//! A logging rule's nftables prefix starts with `ks:<kind>:<id> ` (see
//! `rules::log_prefix`). The kernel writes each logged packet to the kernel
//! log, which journald stores with `_TRANSPORT=kernel`. This module reads those
//! lines with `journalctl -k -o json`, keeps the ones that carry the prefix, and
//! parses the netfilter fields after it. The journal is read with an argument
//! vector, and the cursor is validated before it is passed on.

use anyhow::{Context, Result};
use keystone_core::{FirewallLogEntry, FirewallLogResponse};
use serde_json::Value;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

/// Lines returned when the request gives no limit.
pub const DEFAULT_LIMIT: usize = 200;
/// Largest number of lines one request may return.
pub const MAX_LIMIT: usize = 500;

/// Longest journal cursor accepted. Real cursors are under 120 bytes.
const MAX_CURSOR_BYTES: usize = 256;

/// Check that `cursor` has the form journald writes:
/// `s=<32 hex>;i=<hex>;b=<32 hex>;m=<hex>;t=<hex>;x=<hex>`. Anything else is
/// refused before it reaches `journalctl`.
pub fn validate_cursor(cursor: &str) -> Result<(), String> {
    fn is_hex(value: &str) -> bool {
        !value.is_empty()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }
    let invalid = || "cursor is not a journal cursor".to_string();
    if cursor.len() > MAX_CURSOR_BYTES {
        return Err(invalid());
    }
    let parts: Vec<&str> = cursor.split(';').collect();
    let [seqnum_id, seqnum, boot_id, monotonic, realtime, xor] = parts.as_slice() else {
        return Err(invalid());
    };
    let fields = [
        (*seqnum_id, "s", Some(32)),
        (*seqnum, "i", None),
        (*boot_id, "b", Some(32)),
        (*monotonic, "m", None),
        (*realtime, "t", None),
        (*xor, "x", None),
    ];
    for (field, key, exact_len) in fields {
        let Some(value) = field
            .strip_prefix(key)
            .and_then(|rest| rest.strip_prefix('='))
        else {
            return Err(invalid());
        };
        if !is_hex(value) || exact_len.is_some_and(|len| value.len() != len) {
            return Err(invalid());
        }
    }
    Ok(())
}

/// The `ks:<kind>:<id> ` tag at the start of a message, and the rest of it.
fn split_tag(message: &str) -> Option<(&str, i64, &str)> {
    let body = message.strip_prefix("ks:")?;
    let (head, rest) = body.split_once(' ').unwrap_or((body, ""));
    let (kind, id) = head.rsplit_once(':')?;
    let valid_kind = !kind.is_empty()
        && kind
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'-');
    let id: i64 = id.parse().ok()?;
    (valid_kind && id >= 0).then_some((kind, id, rest))
}

/// Fields the kernel prints after the prefix, as far as the log needs them.
#[derive(Debug, Default, PartialEq, Eq)]
struct NetfilterFields {
    in_interface: Option<String>,
    out_interface: Option<String>,
    source: Option<String>,
    destination: Option<String>,
    protocol: Option<String>,
    source_port: Option<u16>,
    destination_port: Option<u16>,
}

/// Split the text after the tag into the human prefix and the netfilter
/// fields. The kernel always prints `IN=` first, so the fields start there.
/// Returns `None` when there is no `IN=` at all.
fn split_fields(text: &str) -> Option<(String, NetfilterFields)> {
    let start = if text.starts_with("IN=") {
        0
    } else {
        text.find(" IN=")? + 1
    };
    let prefix = text[..start]
        .trim()
        .trim_end_matches(':')
        .trim()
        .to_string();

    let mut fields = NetfilterFields::default();
    let non_empty = |value: &str| (!value.is_empty()).then(|| value.to_string());
    for token in text[start..].split(' ') {
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        match key {
            "IN" => fields.in_interface = non_empty(value),
            "OUT" => fields.out_interface = non_empty(value),
            "SRC" => fields.source = non_empty(value),
            "DST" => fields.destination = non_empty(value),
            "PROTO" => fields.protocol = non_empty(value),
            "SPT" => fields.source_port = value.parse().ok(),
            "DPT" => fields.destination_port = value.parse().ok(),
            _ => {}
        }
    }
    Some((prefix, fields))
}

/// Parse one journal JSON object (`journalctl -o json` output) into a log entry.
/// Lines that are not from a Keystone rule return `None`.
pub fn entry_from_journal(record: &Value) -> Option<FirewallLogEntry> {
    let message = match record.get("MESSAGE")? {
        Value::String(text) => text.clone(),
        // journald writes a byte array when the message is not valid UTF-8.
        Value::Array(bytes) => {
            let bytes: Vec<u8> = bytes
                .iter()
                .filter_map(|byte| byte.as_u64().and_then(|b| u8::try_from(b).ok()))
                .collect();
            String::from_utf8_lossy(&bytes).into_owned()
        }
        _ => return None,
    };
    if !message.starts_with("ks:") {
        return None;
    }
    let cursor = record.get("__CURSOR")?.as_str()?.to_string();
    let realtime_us = record
        .get("__REALTIME_TIMESTAMP")
        .and_then(Value::as_str)
        .and_then(|text| text.parse().ok())
        .unwrap_or_default();

    let base = FirewallLogEntry {
        cursor,
        realtime_us,
        rule_kind: None,
        rule_id: None,
        prefix: message.clone(),
        parsed: false,
        in_interface: None,
        out_interface: None,
        source: None,
        destination: None,
        protocol: None,
        source_port: None,
        destination_port: None,
        message: message.clone(),
    };
    let Some((kind, id, rest)) = split_tag(&message) else {
        return Some(base);
    };
    let Some((prefix, fields)) = split_fields(rest) else {
        // A tagged line whose layout is unknown keeps its raw message.
        return Some(FirewallLogEntry {
            rule_kind: Some(kind.to_string()),
            rule_id: Some(id),
            ..base
        });
    };
    Some(FirewallLogEntry {
        rule_kind: Some(kind.to_string()),
        rule_id: Some(id),
        prefix,
        parsed: true,
        in_interface: fields.in_interface,
        out_interface: fields.out_interface,
        source: fields.source,
        destination: fields.destination,
        protocol: fields.protocol,
        source_port: fields.source_port,
        destination_port: fields.destination_port,
        ..base
    })
}

/// Read up to `limit` Keystone log lines from the kernel journal. With a
/// cursor, the lines after it, oldest first. Without one, the most recent lines.
/// The journal output is streamed and the reader stops at `limit` lines, so a
/// busy log does not load into memory.
pub async fn read(cursor: Option<&str>, limit: usize) -> Result<FirewallLogResponse> {
    let limit = limit.clamp(1, MAX_LIMIT);
    let Some(cursor) = cursor else {
        let entries = journal_entries(None, limit).await?;
        return Ok(respond(None, entries, false));
    };
    match journal_entries(Some(cursor), limit).await {
        Ok(entries) => Ok(respond(Some(cursor), entries, false)),
        Err(error) => {
            // The cursor is no longer in the journal (rotation, or a reboot):
            // show the most recent lines and say so.
            tracing::warn!("firewall log cursor could not be used: {error:#}");
            let entries = journal_entries(None, limit).await?;
            Ok(respond(None, entries, true))
        }
    }
}

fn respond(
    given: Option<&str>,
    entries: Vec<FirewallLogEntry>,
    cursor_reset: bool,
) -> FirewallLogResponse {
    let next_cursor = entries
        .last()
        .map(|entry| entry.cursor.clone())
        .or_else(|| given.map(str::to_string));
    FirewallLogResponse {
        entries,
        next_cursor,
        cursor_reset,
    }
}

async fn journal_entries(after: Option<&str>, limit: usize) -> Result<Vec<FirewallLogEntry>> {
    let mut args: Vec<String> = [
        "-k",
        "-o",
        "json",
        "--no-pager",
        "--case-sensitive=true",
        "--grep=^ks:",
    ]
    .map(str::to_string)
    .to_vec();
    match after {
        Some(cursor) => {
            // Checked by the caller; the value is still passed as one argument.
            validate_cursor(cursor).map_err(|error| anyhow::anyhow!(error))?;
            args.push(format!("--after-cursor={cursor}"));
        }
        None => {
            args.push("-n".to_string());
            args.push(limit.to_string());
        }
    }

    let mut child = Command::new("journalctl")
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("failed to run journalctl")?;
    let stdout = child.stdout.take().context("journalctl has no output")?;
    let mut lines = BufReader::new(stdout).lines();

    let mut entries = Vec::new();
    while entries.len() < limit {
        let Some(line) = lines
            .next_line()
            .await
            .context("reading journalctl output")?
        else {
            break;
        };
        let Ok(record) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        if let Some(entry) = entry_from_journal(&record) {
            entries.push(entry);
        }
    }

    if entries.len() < limit {
        // Ran to the end. journalctl exits 1 without any message when nothing
        // matches, which is not an error. A message on stderr means the cursor
        // or the journal could not be used, and the lines are not trustworthy.
        let status = child.wait().await.context("waiting for journalctl")?;
        let mut stderr = String::new();
        if let Some(mut pipe) = child.stderr.take() {
            use tokio::io::AsyncReadExt;
            let _ = pipe.read_to_string(&mut stderr).await;
        }
        if !status.success() && !stderr.trim().is_empty() {
            anyhow::bail!("journalctl failed: {}", stderr.trim());
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const CURSOR: &str = "s=4d96364e985d4087ac821bf8ad76f2f9;i=8907da3;b=f55e2070856541daa6836c62e0e1600c;m=bef396834;t=65db8141ec574;x=146b0d51e193d1b9";

    fn record(message: &str) -> Value {
        json!({
            "MESSAGE": message,
            "__CURSOR": CURSOR,
            "__REALTIME_TIMESTAMP": "1791895053190516",
            "_TRANSPORT": "kernel",
            "SYSLOG_IDENTIFIER": "kernel",
        })
    }

    #[test]
    fn valid_cursors_are_accepted() {
        assert!(validate_cursor(CURSOR).is_ok());
    }

    #[test]
    fn malformed_cursors_are_refused() {
        let refused = [
            "",
            "garbage",
            "s=4d96364e985d4087ac821bf8ad76f2f9;i=8907da3;b=f55e2070856541daa6836c62e0e1600c;m=bef396834;t=65db8141ec574",
            "s=4d96364e985d4087ac821bf8ad76f2f9;i=8907da3;b=f55e2070856541daa6836c62e0e1600c;m=bef396834;t=65db8141ec574;x=146b0d51e193d1b9;extra=1",
            // Upper-case hex, a shell-looking suffix, and a short seqnum id.
            "s=4D96364E985D4087AC821BF8AD76F2F9;i=8907da3;b=f55e2070856541daa6836c62e0e1600c;m=bef396834;t=65db8141ec574;x=146b0d51e193d1b9",
            "s=4d96364e985d4087ac821bf8ad76f2f9;i=8907da3;b=f55e2070856541daa6836c62e0e1600c;m=bef396834;t=65db8141ec574;x=146b0d51e193d1b9 --all",
            "s=abcd;i=8907da3;b=f55e2070856541daa6836c62e0e1600c;m=bef396834;t=65db8141ec574;x=146b0d51e193d1b9",
            "--output=json;i=1;b=f55e2070856541daa6836c62e0e1600c;m=1;t=1;x=1",
        ];
        for cursor in refused {
            assert!(validate_cursor(cursor).is_err(), "accepted {cursor:?}");
        }
    }

    #[test]
    fn a_kernel_line_from_a_keystone_rule_is_parsed_into_fields() {
        let message = "ks:forward:7 iot-drop: IN=eth4 OUT=eth1 MAC=01:02:03:04:05:06:07:08:09:0a:0b:0c:08:00 SRC=192.168.50.10 DST=192.168.1.20 LEN=60 TOS=0x00 PREC=0x00 TTL=63 ID=1 DF PROTO=TCP SPT=51234 DPT=80 WINDOW=64240 RES=0x00 SYN URGP=0";
        let entry = entry_from_journal(&record(message)).expect("tagged line");
        assert!(entry.parsed);
        assert_eq!(entry.rule_kind.as_deref(), Some("forward"));
        assert_eq!(entry.rule_id, Some(7));
        assert_eq!(entry.prefix, "iot-drop");
        assert_eq!(entry.in_interface.as_deref(), Some("eth4"));
        assert_eq!(entry.out_interface.as_deref(), Some("eth1"));
        assert_eq!(entry.source.as_deref(), Some("192.168.50.10"));
        assert_eq!(entry.destination.as_deref(), Some("192.168.1.20"));
        assert_eq!(entry.protocol.as_deref(), Some("TCP"));
        assert_eq!(entry.source_port, Some(51234));
        assert_eq!(entry.destination_port, Some(80));
        assert_eq!(entry.cursor, CURSOR);
        assert_eq!(entry.realtime_us, 1791895053190516);
        assert_eq!(entry.message, message);
    }

    #[test]
    fn a_prefix_without_text_still_splits_at_in() {
        let entry = entry_from_journal(&record(
            "ks:input:3 IN=eth1 OUT= SRC=10.0.0.9 DST=10.0.0.1 PROTO=UDP SPT=5353 DPT=53",
        ))
        .unwrap();
        assert!(entry.parsed);
        assert_eq!(entry.prefix, "");
        assert_eq!(entry.out_interface, None);
        assert_eq!(entry.destination_port, Some(53));
    }

    #[test]
    fn an_unknown_layout_keeps_only_the_raw_message() {
        let entry = entry_from_journal(&record("ks:input:3 something the kernel printed")).unwrap();
        assert!(!entry.parsed);
        assert_eq!(entry.rule_id, Some(3));
        assert_eq!(entry.message, "ks:input:3 something the kernel printed");
    }

    #[test]
    fn kernel_lines_without_the_prefix_are_not_keystone_entries() {
        assert!(entry_from_journal(&record("veth75242b1: left promiscuous mode")).is_none());
        assert!(entry_from_journal(&record("ks:input:x IN=eth1")).is_some());
    }

    #[test]
    fn byte_array_messages_are_decoded() {
        let mut value = record("");
        value["MESSAGE"] = json!("ks:input:1 IN=eth1 PROTO=ICMP".as_bytes());
        let entry = entry_from_journal(&value).unwrap();
        assert!(entry.parsed);
        assert_eq!(entry.protocol.as_deref(), Some("ICMP"));
    }

    #[test]
    fn respond_keeps_the_cursor_when_nothing_new_was_logged() {
        let response = respond(Some(CURSOR), Vec::new(), false);
        assert_eq!(response.next_cursor.as_deref(), Some(CURSOR));
        let fresh = respond(None, Vec::new(), false);
        assert_eq!(fresh.next_cursor, None);
    }
}
