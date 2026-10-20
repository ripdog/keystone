//! Reading Blocky's CSV query log.
//!
//! Blocky writes one tab-separated file per day, `YYYY-MM-DD_ALL.log`, with
//! Go's `encoding/csv` quoting. The daemon only reads these files; Blocky owns
//! them. Newest files are read first, and each request reads at most a fixed
//! number of bytes and returns at most a fixed number of rows.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{ErrorKind, Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use keystone_core::DhcpLease;
use keystone_core::blocky::{BlockyQueryLogEntry, BlockyQueryLogResponse};

/// Most rows returned by one request.
pub const ROW_LIMIT: usize = 1000;
/// Most bytes read from the log by one request.
pub const BYTE_LIMIT: u64 = 32 * 1024 * 1024;

/// Number of columns Blocky writes per query, in the order it writes them:
/// time, client_ip, client_names, duration_ms, reason, question_name, answer,
/// response_code, response_type, question_type, instance_hostname.
const COLUMNS: usize = 11;

/// Filters applied to each entry. Empty fields match everything.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueryLogFilter {
    /// Exact client address.
    pub client: Option<String>,
    /// Case-insensitive part of the queried domain.
    pub domain: Option<String>,
    pub blocked_only: bool,
}

/// Bounds for one read. Production uses [`ROW_LIMIT`] and [`BYTE_LIMIT`].
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub rows: usize,
    pub bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            rows: ROW_LIMIT,
            bytes: BYTE_LIMIT,
        }
    }
}

/// Entries matching `filter`, newest first, read from the daily files in `dir`.
/// A missing directory means nothing has been logged yet.
pub fn read_query_log(
    dir: &Path,
    filter: &QueryLogFilter,
    leases: &[DhcpLease],
) -> BlockyQueryLogResponse {
    read_with_limits(dir, filter, leases, Limits::default())
}

pub fn read_with_limits(
    dir: &Path,
    filter: &QueryLogFilter,
    leases: &[DhcpLease],
    limits: Limits,
) -> BlockyQueryLogResponse {
    let mut response = BlockyQueryLogResponse {
        entries: Vec::new(),
        truncated: false,
        warnings: Vec::new(),
    };
    let files = match log_files(dir) {
        Ok(files) => files,
        Err(error) if error.kind() == ErrorKind::NotFound => return response,
        Err(error) => {
            response
                .warnings
                .push(format!("could not list the query log: {error}"));
            return response;
        }
    };

    let names = lease_hostnames(leases);
    let mut budget = limits.bytes;
    let mut malformed = 0usize;
    'files: for path in &files {
        if budget == 0 {
            response.truncated = true;
            break;
        }
        let (text, read, whole) = match read_tail(path, budget) {
            Ok(read) => read,
            Err(error) => {
                response.warnings.push(format!(
                    "could not read {}: {error}",
                    path.file_name().unwrap_or_default().to_string_lossy()
                ));
                continue;
            }
        };
        budget = budget.saturating_sub(read);
        if !whole {
            // Older rows exist beyond the byte limit and were not read.
            response.truncated = true;
        }

        for record in parse_records(&text).iter().rev() {
            let Some(entry) = entry_from_record(record, &names) else {
                malformed += 1;
                continue;
            };
            if !matches_filter(&entry, filter) {
                continue;
            }
            if response.entries.len() == limits.rows {
                response.truncated = true;
                break 'files;
            }
            response.entries.push(entry);
        }
    }

    if malformed > 0 {
        response
            .warnings
            .push(format!("{malformed} malformed log lines were skipped"));
    }
    response
}

/// Daily log files in `dir`, newest first. Names sort by date.
fn log_files(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(is_daily_log_name)
        {
            files.push(path);
        }
    }
    files.sort();
    files.reverse();
    Ok(files)
}

/// `YYYY-MM-DD_ALL.log`.
fn is_daily_log_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() == 18
        && bytes[..10]
            .iter()
            .enumerate()
            .all(|(index, byte)| match index {
                4 | 7 => *byte == b'-',
                _ => byte.is_ascii_digit(),
            })
        && &name[10..] == "_ALL.log"
}

/// The last `max_bytes` of the file, starting at a line boundary. Returns the
/// text, the number of bytes read from the file, and whether the whole file
/// was read.
fn read_tail(path: &Path, max_bytes: u64) -> std::io::Result<(String, u64, bool)> {
    let mut file = File::open(path)?;
    let length = file.metadata()?.len();
    let start = length.saturating_sub(max_bytes);
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;

    // Unless the read starts at the beginning, its first line may begin in the
    // middle of a record. Drop it.
    let usable = if start > 0 {
        match bytes.iter().position(|byte| *byte == b'\n') {
            Some(position) => &bytes[position + 1..],
            None => &[],
        }
    } else {
        &bytes[..]
    };
    let text = String::from_utf8_lossy(usable).into_owned();
    Ok((text, bytes.len() as u64, start == 0))
}

/// Split CSV text into records of fields. Fields are separated by tabs and
/// records by newlines. A field that starts with a quote runs to the closing
/// quote, where `""` stands for a quote; it may contain tabs and newlines.
pub fn parse_records(text: &str) -> Vec<Vec<String>> {
    let mut records = Vec::new();
    let mut record = Vec::new();
    let mut field = String::new();
    let mut at_field_start = true;
    let mut chars = text.chars().peekable();

    while let Some(c) = chars.next() {
        if at_field_start && c == '"' {
            at_field_start = false;
            while let Some(inner) = chars.next() {
                if inner == '"' {
                    if chars.peek() == Some(&'"') {
                        chars.next();
                        field.push('"');
                    } else {
                        break;
                    }
                } else {
                    field.push(inner);
                }
            }
            continue;
        }
        at_field_start = false;
        match c {
            '\t' => {
                record.push(std::mem::take(&mut field));
                at_field_start = true;
            }
            '\r' if chars.peek() == Some(&'\n') => {}
            '\n' => {
                record.push(std::mem::take(&mut field));
                records.push(std::mem::take(&mut record));
                at_field_start = true;
            }
            other => field.push(other),
        }
    }
    if !field.is_empty() || !record.is_empty() {
        record.push(field);
        records.push(record);
    }
    // A blank line is one empty field; it is not a query.
    records.retain(|record| !(record.len() == 1 && record[0].is_empty()));
    records
}

fn entry_from_record(
    record: &[String],
    lease_names: &HashMap<String, String>,
) -> Option<BlockyQueryLogEntry> {
    if record.len() < COLUMNS {
        return None;
    }
    let client_ip = record[1].clone();
    // Blocky has real client names only when client lookup is configured;
    // otherwise it writes nothing or just an address. Fall back to the DHCP
    // lease hostname, which dnsmasq knows.
    let client_name = if record[2].is_empty() || record[2].parse::<IpAddr>().is_ok() {
        lease_names.get(&client_ip).cloned()
    } else {
        Some(record[2].clone())
    };
    let response_type = record[8].clone();
    Some(BlockyQueryLogEntry {
        time: record[0].clone(),
        client_ip,
        client_name,
        duration_ms: record[3].parse().unwrap_or(0),
        reason: record[4].clone(),
        domain: record[5].clone(),
        answer: record[6].clone(),
        response_code: record[7].clone(),
        blocked: response_type.starts_with("BLOCKED"),
        response_type,
        question_type: record[9].clone(),
    })
}

fn matches_filter(entry: &BlockyQueryLogEntry, filter: &QueryLogFilter) -> bool {
    if let Some(client) = &filter.client
        && &entry.client_ip != client
    {
        return false;
    }
    if let Some(domain) = &filter.domain
        && !entry
            .domain
            .to_ascii_lowercase()
            .contains(&domain.to_ascii_lowercase())
    {
        return false;
    }
    !filter.blocked_only || entry.blocked
}

fn lease_hostnames(leases: &[DhcpLease]) -> HashMap<String, String> {
    leases
        .iter()
        .filter_map(|lease| {
            let name = lease.hostname.as_deref()?;
            (!name.is_empty() && name != "*").then(|| (lease.ip_address.clone(), name.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A line as Blocky writes it, with the instance hostname last.
    fn line(time: &str, client: &str, names: &str, domain: &str, response_type: &str) -> String {
        format!(
            "{time}\t{client}\t{names}\t12\tdefault\t{domain}\t0.0.0.0\tNOERROR\t{response_type}\tA\tblocky-1\n"
        )
    }

    fn lease(ip: &str, hostname: Option<&str>) -> DhcpLease {
        DhcpLease {
            mac_address: "aa:bb:cc:dd:ee:ff".to_string(),
            ip_address: ip.to_string(),
            hostname: hostname.map(str::to_string),
            expires_at: 0,
            client_id: None,
        }
    }

    /// A temporary directory removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("keystone-querylog-{}", uuid::Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Scratch(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn quoted_fields_keep_tabs_newlines_and_doubled_quotes() {
        let text = "a\t\"b\tc\"\t\"say \"\"hi\"\"\nthere\"\td\r\nlast\t\n";
        assert_eq!(
            parse_records(text),
            vec![
                vec!["a", "b\tc", "say \"hi\"\nthere", "d"],
                vec!["last", ""],
            ]
            .into_iter()
            .map(|record| record.into_iter().map(str::to_string).collect::<Vec<_>>())
            .collect::<Vec<_>>()
        );
    }

    #[test]
    fn blank_lines_are_not_records() {
        assert!(parse_records("\n\n").is_empty());
    }

    #[test]
    fn a_record_maps_columns_and_falls_back_to_the_lease_name() {
        let names = lease_hostnames(&[lease("192.168.1.20", Some("laptop"))]);
        let text = line(
            "2026-10-14 09:00:00",
            "192.168.1.20",
            "",
            "example.com",
            "RESOLVED",
        );
        let record = parse_records(&text).remove(0);
        let entry = entry_from_record(&record, &names).unwrap();
        assert_eq!(entry.time, "2026-10-14 09:00:00");
        assert_eq!(entry.client_ip, "192.168.1.20");
        assert_eq!(entry.client_name.as_deref(), Some("laptop"));
        assert_eq!(entry.duration_ms, 12);
        assert_eq!(entry.domain, "example.com");
        assert_eq!(entry.response_type, "RESOLVED");
        assert!(!entry.blocked);
    }

    #[test]
    fn blockys_own_client_name_wins_over_the_lease() {
        let names = lease_hostnames(&[lease("192.168.1.20", Some("laptop"))]);
        let text = line(
            "2026-10-14 09:00:00",
            "192.168.1.20",
            "tablet; kids",
            "x.test",
            "BLOCKED",
        );
        let record = parse_records(&text).remove(0);
        let entry = entry_from_record(&record, &names).unwrap();
        assert_eq!(entry.client_name.as_deref(), Some("tablet; kids"));
        assert!(entry.blocked);
    }

    #[test]
    fn a_bare_address_as_client_name_is_not_a_name() {
        let names = lease_hostnames(&[lease("192.168.1.20", Some("laptop"))]);
        let text = line(
            "2026-10-14 09:00:00",
            "192.168.1.20",
            "127.0.0.1",
            "x.test",
            "RESOLVED",
        );
        let record = parse_records(&text).remove(0);
        let entry = entry_from_record(&record, &names).unwrap();
        assert_eq!(entry.client_name.as_deref(), Some("laptop"));
        let entry = entry_from_record(&record, &HashMap::new()).unwrap();
        assert_eq!(entry.client_name, None);
    }

    #[test]
    fn short_records_are_not_entries() {
        let names = HashMap::new();
        let record = vec!["2026-10-14 09:00:00".to_string(), "10.0.0.2".to_string()];
        assert!(entry_from_record(&record, &names).is_none());
    }

    #[test]
    fn only_daily_log_names_are_read() {
        assert!(is_daily_log_name("2026-10-14_ALL.log"));
        assert!(!is_daily_log_name("2026-10-14_ALL.log.gz"));
        assert!(!is_daily_log_name("2026-10-14_client.log"));
        assert!(!is_daily_log_name("2026-1O-14_ALL.log"));
    }

    #[test]
    fn newest_files_come_first_and_filters_apply() {
        let scratch = Scratch::new();
        fs::write(
            scratch.0.join("2026-10-13_ALL.log"),
            line(
                "2026-10-13 23:59:59",
                "10.0.0.2",
                "",
                "old.example",
                "RESOLVED",
            ),
        )
        .unwrap();
        let today = [
            line(
                "2026-10-14 08:00:00",
                "10.0.0.2",
                "",
                "ads.example",
                "BLOCKED",
            ),
            line(
                "2026-10-14 08:01:00",
                "10.0.0.3",
                "",
                "news.example",
                "RESOLVED",
            ),
            line(
                "2026-10-14 08:02:00",
                "10.0.0.2",
                "",
                "Shop.Example",
                "CACHED",
            ),
        ]
        .concat();
        fs::write(scratch.0.join("2026-10-14_ALL.log"), today).unwrap();
        fs::write(scratch.0.join("notes.txt"), "not a log").unwrap();

        let everything = read_query_log(&scratch.0, &QueryLogFilter::default(), &[]);
        let times: Vec<_> = everything.entries.iter().map(|e| e.time.as_str()).collect();
        assert_eq!(
            times,
            vec![
                "2026-10-14 08:02:00",
                "2026-10-14 08:01:00",
                "2026-10-14 08:00:00",
                "2026-10-13 23:59:59",
            ]
        );
        assert!(!everything.truncated);

        let by_client = read_query_log(
            &scratch.0,
            &QueryLogFilter {
                client: Some("10.0.0.2".to_string()),
                ..QueryLogFilter::default()
            },
            &[],
        );
        assert_eq!(by_client.entries.len(), 3);

        let blocked = read_query_log(
            &scratch.0,
            &QueryLogFilter {
                blocked_only: true,
                ..QueryLogFilter::default()
            },
            &[],
        );
        assert_eq!(blocked.entries.len(), 1);
        assert_eq!(blocked.entries[0].domain, "ads.example");

        let domain = read_query_log(
            &scratch.0,
            &QueryLogFilter {
                domain: Some("SHOP.example".to_string()),
                ..QueryLogFilter::default()
            },
            &[],
        );
        assert_eq!(domain.entries.len(), 1);
    }

    #[test]
    fn a_missing_directory_is_an_empty_log_without_warnings() {
        let scratch = Scratch::new();
        let missing = scratch.0.join("absent");
        let response = read_query_log(&missing, &QueryLogFilter::default(), &[]);
        assert!(response.entries.is_empty());
        assert!(response.warnings.is_empty());
    }

    #[test]
    fn the_row_limit_truncates_the_newest_rows_kept() {
        let scratch = Scratch::new();
        let text: String = (0..5)
            .map(|i| {
                line(
                    &format!("2026-10-14 08:00:0{i}"),
                    "10.0.0.2",
                    "",
                    "a.example",
                    "RESOLVED",
                )
            })
            .collect();
        fs::write(scratch.0.join("2026-10-14_ALL.log"), text).unwrap();

        let response = read_with_limits(
            &scratch.0,
            &QueryLogFilter::default(),
            &[],
            Limits {
                rows: 2,
                bytes: BYTE_LIMIT,
            },
        );
        assert!(response.truncated);
        let times: Vec<_> = response.entries.iter().map(|e| e.time.as_str()).collect();
        assert_eq!(times, vec!["2026-10-14 08:00:04", "2026-10-14 08:00:03"]);
    }

    #[test]
    fn the_byte_limit_reads_the_end_of_the_file_and_drops_a_partial_line() {
        let scratch = Scratch::new();
        let text: String = (0..6)
            .map(|i| {
                line(
                    &format!("2026-10-14 08:00:0{i}"),
                    "10.0.0.2",
                    "",
                    "a.example",
                    "RESOLVED",
                )
            })
            .collect();
        let line_length = text.len() / 6;
        fs::write(scratch.0.join("2026-10-14_ALL.log"), &text).unwrap();

        // Room for about three and a half lines: the first partial line is dropped.
        let response = read_with_limits(
            &scratch.0,
            &QueryLogFilter::default(),
            &[],
            Limits {
                rows: ROW_LIMIT,
                bytes: (line_length * 7 / 2) as u64,
            },
        );
        assert!(response.truncated);
        assert!(!response.entries.is_empty());
        assert!(response.entries.len() < 6);
        assert_eq!(response.entries[0].time, "2026-10-14 08:00:05");
        assert!(response.entries.iter().all(|e| e.domain == "a.example"));
    }
}
