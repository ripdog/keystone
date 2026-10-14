//! Journal viewer for the managed services.
//!
//! One request reads a page of the journal for one or more managed units. A
//! page is the newest entries, the entries after a cursor (to follow the log),
//! the entries before a cursor (to scroll back), or the entries from a point in
//! time backwards (to jump to a date). `journalctl` is run with an argument
//! vector; the units come from the managed-unit list and the cursor is checked
//! against the form journald writes, so no request text reaches it unchecked.

use anyhow::{Context, Result};
use axum::{Json, Router, extract::Query, http::StatusCode, routing::get};
use keystone_core::{JOURNAL_MESSAGE_MAX_BYTES, JournalEntry, JournalResponse};
use serde::Deserialize;
use serde_json::{Value, json};
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::Command;

use crate::firewall::live_log::validate_cursor;
use crate::systemd::MANAGED_UNITS;

const DEFAULT_LIMIT: usize = 200;
const MAX_LIMIT: usize = 500;

/// Where a page starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Position {
    /// The newest entries.
    Newest,
    /// Entries after the cursor, oldest first.
    After(String),
    /// Entries before the cursor, the closest ones.
    Before(String),
    /// Entries at or before a time, the closest ones (microseconds since the epoch).
    Until(u64),
}

/// Units must be managed ones, and at least one is required. Duplicates are dropped.
pub fn validate_units(units: &[String]) -> Result<Vec<&'static str>, String> {
    if units.is_empty() {
        return Err("select at least one service".to_string());
    }
    let mut checked: Vec<&'static str> = Vec::new();
    for unit in units {
        let Some(known) = MANAGED_UNITS.iter().find(|known| **known == unit.as_str()) else {
            return Err(format!("service is not managed by Keystone: {unit}"));
        };
        if !checked.contains(known) {
            checked.push(known);
        }
    }
    Ok(checked)
}

/// `@<seconds>.<micros>`, the form `--until` takes for an absolute time.
fn until_argument(realtime_us: u64) -> String {
    format!(
        "--until=@{}.{:06}",
        realtime_us / 1_000_000,
        realtime_us % 1_000_000
    )
}

fn journal_args(units: &[&str], position: &Position, count: usize) -> Vec<String> {
    let mut args: Vec<String> = ["-o", "json", "--no-pager", "--all"]
        .map(str::to_string)
        .to_vec();
    for unit in units {
        args.push("-u".to_string());
        args.push((*unit).to_string());
    }
    match position {
        Position::Newest => {
            args.extend(["-r".to_string(), "-n".to_string(), count.to_string()]);
        }
        Position::After(cursor) => args.push(format!("--after-cursor={cursor}")),
        Position::Before(cursor) => {
            // `--cursor` starts at the cursor's own entry, which is skipped when reading.
            args.extend(["-r".to_string(), format!("--cursor={cursor}")]);
        }
        Position::Until(realtime_us) => {
            args.extend(["-r".to_string(), until_argument(*realtime_us)]);
        }
    }
    args
}

/// Text of a journal field. journald writes a byte array for text that is not
/// valid UTF-8, and a number string for some fields.
fn field_text(record: &Value, key: &str) -> Option<String> {
    match record.get(key)? {
        Value::String(text) => Some(text.clone()),
        Value::Array(bytes) => {
            let bytes: Vec<u8> = bytes
                .iter()
                .filter_map(|byte| byte.as_u64().and_then(|b| u8::try_from(b).ok()))
                .collect();
            Some(String::from_utf8_lossy(&bytes).into_owned())
        }
        _ => None,
    }
}

/// Cut `text` to at most `max` bytes at a character boundary, marking the cut.
fn truncate_message(mut text: String, max: usize) -> String {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    text.push('…');
    text
}

/// `text` without ANSI escape sequences. Programs such as tracing-based ones
/// colour their output, and the journal keeps the raw codes.
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        match chars.peek() {
            // CSI: parameters, then one final byte in 0x40..=0x7e.
            Some('[') => {
                chars.next();
                for next in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&next) {
                        break;
                    }
                }
            }
            // Two-character escape such as `ESC c`.
            Some(_) => {
                chars.next();
            }
            None => {}
        }
    }
    out
}

/// The unit a record belongs to. Messages systemd writes about a unit come from
/// PID 1 and name the unit in `UNIT`, so that wins over `init.scope`.
fn unit_of(record: &Value) -> String {
    let own = field_text(record, "_SYSTEMD_UNIT").filter(|unit| unit != "init.scope");
    own.or_else(|| field_text(record, "UNIT"))
        .or_else(|| field_text(record, "COREDUMP_UNIT"))
        .unwrap_or_default()
}

/// Parse one `journalctl -o json` object. Records without a cursor are skipped.
pub fn entry_from_journal(record: &Value) -> Option<JournalEntry> {
    let cursor = field_text(record, "__CURSOR")?;
    let realtime_us = field_text(record, "__REALTIME_TIMESTAMP")
        .and_then(|text| text.parse().ok())
        .unwrap_or_default();
    let priority = field_text(record, "PRIORITY")
        .and_then(|text| text.parse::<u8>().ok())
        .filter(|priority| *priority <= 7)
        .unwrap_or(6);
    Some(JournalEntry {
        cursor,
        realtime_us,
        unit: unit_of(record),
        identifier: field_text(record, "SYSLOG_IDENTIFIER").unwrap_or_default(),
        pid: field_text(record, "_PID").and_then(|text| text.parse().ok()),
        priority,
        message: truncate_message(
            strip_ansi(&field_text(record, "MESSAGE").unwrap_or_default()),
            JOURNAL_MESSAGE_MAX_BYTES,
        ),
    })
}

/// Read one page of up to `limit` entries, oldest first.
pub async fn read(units: &[&str], position: Position, limit: usize) -> Result<JournalResponse> {
    let limit = limit.clamp(1, MAX_LIMIT);
    if let Position::After(cursor) | Position::Before(cursor) = &position {
        validate_cursor(cursor).map_err(|error| anyhow::anyhow!(error))?;
    }
    match run(units, &position, limit).await {
        Ok(entries) => Ok(JournalResponse {
            entries,
            cursor_reset: false,
        }),
        Err(error) if matches!(position, Position::After(_)) => {
            // The cursor is no longer in the journal (rotation, or a reboot):
            // show the most recent entries and say so.
            tracing::warn!("journal cursor could not be used: {error:#}");
            let entries = run(units, &Position::Newest, limit).await?;
            Ok(JournalResponse {
                entries,
                cursor_reset: true,
            })
        }
        Err(error) => Err(error),
    }
}

/// Run `journalctl` and collect the page, oldest first. The output is streamed
/// and the reader stops at the limit, so a busy journal does not load into memory.
async fn run(units: &[&str], position: &Position, limit: usize) -> Result<Vec<JournalEntry>> {
    // Backward pages start with the entry the cursor names; read one extra.
    let skip_first = matches!(position, Position::Before(_));
    let wanted = limit + usize::from(skip_first);
    let args = journal_args(units, position, wanted);

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

    let mut entries: Vec<JournalEntry> = Vec::new();
    while entries.len() < wanted {
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

    if entries.len() < wanted {
        // Ran to the end. journalctl exits 1 without any message when nothing
        // matches, which is not an error. A message on stderr means the cursor
        // or the journal could not be used, and the entries are not trustworthy.
        let status = child.wait().await.context("waiting for journalctl")?;
        let mut stderr = String::new();
        if let Some(mut pipe) = child.stderr.take() {
            let _ = pipe.read_to_string(&mut stderr).await;
        }
        if !status.success() && !stderr.trim().is_empty() {
            anyhow::bail!("journalctl failed: {}", stderr.trim());
        }
    }

    if skip_first && !entries.is_empty() {
        entries.remove(0);
    }
    // Backward pages arrive newest first; the response is always oldest first.
    if matches!(
        position,
        Position::Newest | Position::Before(_) | Position::Until(_)
    ) {
        entries.reverse();
    }
    Ok(entries)
}

/// Query of `GET /logs`. At most one of `after`, `before` and `until_us`.
#[derive(Debug, Deserialize)]
struct LogsQuery {
    /// Comma-separated managed unit names.
    units: String,
    after: Option<String>,
    before: Option<String>,
    until_us: Option<u64>,
    limit: Option<usize>,
}

fn error_response(status: StatusCode, message: impl Into<String>) -> (StatusCode, Json<Value>) {
    (status, Json(json!({ "error": message.into() })))
}

fn position_of(query: &LogsQuery) -> Result<Position, String> {
    let position = match (&query.after, &query.before, query.until_us) {
        (None, None, None) => Position::Newest,
        (Some(cursor), None, None) => Position::After(cursor.clone()),
        (None, Some(cursor), None) => Position::Before(cursor.clone()),
        (None, None, Some(until)) => Position::Until(until),
        _ => return Err("give at most one of after, before and until_us".to_string()),
    };
    if let Position::After(cursor) | Position::Before(cursor) = &position {
        validate_cursor(cursor)?;
    }
    Ok(position)
}

/// GET /logs - A page of the journal for the selected managed services
async fn get_logs(
    Query(query): Query<LogsQuery>,
) -> Result<Json<JournalResponse>, (StatusCode, Json<Value>)> {
    let bad_request = |message: String| error_response(StatusCode::BAD_REQUEST, message);
    let requested: Vec<String> = query
        .units
        .split(',')
        .filter(|unit| !unit.is_empty())
        .map(str::to_string)
        .collect();
    let units = validate_units(&requested).map_err(bad_request)?;
    let position = position_of(&query).map_err(bad_request)?;
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT);
    let response = read(&units, position, limit)
        .await
        .map_err(|error| error_response(StatusCode::INTERNAL_SERVER_ERROR, format!("{error:#}")))?;
    Ok(Json(response))
}

pub fn logs_routes() -> Router<Arc<crate::AppState>> {
    Router::new().route("/logs", get(get_logs))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CURSOR: &str = "s=4d96364e985d4087ac821bf8ad76f2f9;i=8907da3;b=f55e2070856541daa6836c62e0e1600c;m=bef396834;t=65db8141ec574;x=146b0d51e193d1b9";

    fn query(after: Option<&str>, before: Option<&str>, until_us: Option<u64>) -> LogsQuery {
        LogsQuery {
            units: "dnsmasq.service".to_string(),
            after: after.map(str::to_string),
            before: before.map(str::to_string),
            until_us,
            limit: None,
        }
    }

    #[test]
    fn only_managed_units_are_accepted() {
        let managed = MANAGED_UNITS[0].to_string();
        assert_eq!(
            validate_units(&[managed.clone(), managed.clone()])
                .unwrap()
                .len(),
            1
        );
        assert!(validate_units(&[]).is_err());
        for unit in [
            "ssh.service",
            "--user",
            "-f",
            "dnsmasq.service --all",
            "../x",
        ] {
            assert!(validate_units(&[unit.to_string()]).is_err(), "{unit}");
        }
    }

    #[test]
    fn requests_with_two_positions_or_a_bad_cursor_are_refused() {
        assert!(position_of(&query(Some(CURSOR), Some(CURSOR), None)).is_err());
        assert!(position_of(&query(None, Some(CURSOR), Some(1))).is_err());
        assert!(position_of(&query(Some("--all"), None, None)).is_err());
        assert_eq!(position_of(&query(None, None, None)), Ok(Position::Newest));
        assert_eq!(
            position_of(&query(None, None, Some(7))),
            Ok(Position::Until(7))
        );
    }

    #[test]
    fn journal_arguments_pass_each_value_as_one_argument() {
        let units =
            validate_units(&["dnsmasq.service".to_string(), "caddy.service".to_string()]).unwrap();
        let args = journal_args(&units, &Position::Before(CURSOR.to_string()), 10);
        assert!(
            args.windows(2)
                .any(|pair| pair == ["-u", "dnsmasq.service"])
        );
        assert!(args.windows(2).any(|pair| pair == ["-u", "caddy.service"]));
        assert!(args.contains(&format!("--cursor={CURSOR}")));
        assert!(args.contains(&"-r".to_string()));

        let args = journal_args(&units, &Position::Until(1_791_895_053_190_516), 10);
        assert!(args.contains(&"--until=@1791895053.190516".to_string()));
        let args = journal_args(&units, &Position::After(CURSOR.to_string()), 10);
        assert!(!args.contains(&"-r".to_string()));
    }

    #[test]
    fn entries_are_parsed_with_the_unit_systemd_names() {
        let own = json!({
            "__CURSOR": CURSOR,
            "__REALTIME_TIMESTAMP": "1791895053190516",
            "_SYSTEMD_UNIT": "dnsmasq.service",
            "SYSLOG_IDENTIFIER": "dnsmasq",
            "_PID": "812",
            "PRIORITY": "4",
            "MESSAGE": "warning text",
        });
        let entry = entry_from_journal(&own).unwrap();
        assert_eq!(entry.unit, "dnsmasq.service");
        assert_eq!(entry.pid, Some(812));
        assert_eq!(entry.priority, 4);
        assert_eq!(entry.realtime_us, 1_791_895_053_190_516);

        let from_systemd = json!({
            "__CURSOR": CURSOR,
            "_SYSTEMD_UNIT": "init.scope",
            "UNIT": "dnsmasq.service",
            "MESSAGE": "Started dnsmasq.",
        });
        let entry = entry_from_journal(&from_systemd).unwrap();
        assert_eq!(entry.unit, "dnsmasq.service");
        assert_eq!(entry.priority, 6);

        assert!(entry_from_journal(&json!({ "MESSAGE": "no cursor" })).is_none());
    }

    #[test]
    fn colour_codes_are_removed_from_messages() {
        let coloured = "\u{1b}[2m2026-10-14T08:33:53Z\u{1b}[0m \u{1b}[34mDEBUG\u{1b}[0m \u{1b}[1mrequest\u{1b}[0m ok";
        assert_eq!(
            strip_ansi(coloured),
            "2026-10-14T08:33:53Z DEBUG request ok"
        );
        assert_eq!(strip_ansi("plain [text] é"), "plain [text] é");
        assert_eq!(strip_ansi("cut\u{1b}"), "cut");
    }

    #[test]
    fn non_utf8_messages_and_long_messages_are_handled() {
        let bytes = json!({ "__CURSOR": CURSOR, "MESSAGE": [104, 105, 255] });
        assert_eq!(entry_from_journal(&bytes).unwrap().message, "hi\u{fffd}");

        let cut = truncate_message("é".repeat(10), 5);
        assert!(cut.ends_with('…'));
        assert!(cut.len() <= 5 + '…'.len_utf8());
        assert_eq!(truncate_message("short".to_string(), 5), "short");
    }
}
