//! API client for the journal log viewer

use crate::api::client;
use keystone_core::JournalResponse;

/// Which part of the journal a request reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogPage {
    /// The newest entries.
    Newest,
    /// Entries after the cursor, to follow the log.
    After(String),
    /// Entries before the cursor, to scroll back.
    Before(String),
    /// Entries at or before a time (microseconds since the epoch).
    Until(u64),
}

/// The query string of a log request. `;` and `=` in a cursor are
/// percent-encoded so they cannot split the query; the daemon validates it.
fn query_for(units: &[String], page: &LogPage, limit: usize) -> String {
    let mut query = format!(
        "units={}&limit={limit}",
        urlencoding::encode(&units.join(","))
    );
    let cursor = |cursor: &str| cursor.replace(';', "%3B").replace('=', "%3D");
    match page {
        LogPage::Newest => {}
        LogPage::After(value) => query.push_str(&format!("&after={}", cursor(value))),
        LogPage::Before(value) => query.push_str(&format!("&before={}", cursor(value))),
        LogPage::Until(us) => query.push_str(&format!("&until_us={us}")),
    }
    query
}

/// One page of journal entries for the given managed units, oldest first.
pub async fn fetch_logs(
    token: &str,
    units: &[String],
    page: &LogPage,
    limit: usize,
) -> Result<JournalResponse, String> {
    let url = format!("/api/logs?{}", query_for(units, page, limit));
    client::get(&url, token).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const CURSOR: &str = "s=4d96364e985d4087ac821bf8ad76f2f9;i=8907da3;b=f55e2070856541daa6836c62e0e1600c;m=bef396834;t=65db8141ec574;x=146b0d51e193d1b9";

    #[test]
    fn cursors_cannot_split_the_query() {
        let units = ["dnsmasq.service".to_string()];
        let query = query_for(&units, &LogPage::After(CURSOR.to_string()), 50);
        let (_, after) = query.split_once("&after=").unwrap();
        assert!(!after.contains([';', '=', '&']));
        assert_eq!(query.matches('&').count(), 2);
    }

    #[test]
    fn units_are_joined_and_encoded_once() {
        let units = ["a.service".to_string(), "b.service".to_string()];
        let query = query_for(&units, &LogPage::Newest, 10);
        assert!(query.starts_with("units=a.service%2Cb.service&"));
        assert!(query_for(&units, &LogPage::Until(5), 10).ends_with("&until_us=5"));
    }
}
