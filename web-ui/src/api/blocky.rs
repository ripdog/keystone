//! DNS filtering (Blocky) API functions

use keystone_core::api::{PauseBlocky, SaveBlockyConfig};
use keystone_core::blocky::{
    BlockyActionResponse, BlockyConfig, BlockyPauseRequest, BlockyQueryLogResponse,
    BlockyStateResponse, BlockyStatusResponse, SaveBlockyConfigRequest,
};

use super::client::{call, get, post_empty};

/// Fetch the saved DNS filtering configuration and the binary check.
pub async fn fetch_blocky_state(token: &str) -> Result<BlockyStateResponse, String> {
    get("/api/blocky/config", token).await
}

/// Save the configuration. Nothing is applied until configuration is applied.
pub async fn save_blocky_config(token: &str, config: BlockyConfig) -> Result<(), String> {
    let response = call::<SaveBlockyConfig>(token, &SaveBlockyConfigRequest { config }).await?;
    if response.success {
        Ok(())
    } else {
        Err(response.message)
    }
}

/// Fetch the service state and Blocky's blocking state.
pub async fn fetch_blocky_status(token: &str) -> Result<BlockyStatusResponse, String> {
    get("/api/blocky/status", token).await
}

/// Pause blocking for `minutes`, or resume it when `minutes` is `None`.
pub async fn set_blocking_pause(
    token: &str,
    minutes: Option<u32>,
) -> Result<BlockyActionResponse, String> {
    call::<PauseBlocky>(token, &BlockyPauseRequest { minutes }).await
}

/// Download every filter list again.
pub async fn refresh_blocky_lists(token: &str) -> Result<BlockyActionResponse, String> {
    post_empty("/api/blocky/refresh-lists", token).await
}

/// Empty Blocky's answer cache.
pub async fn flush_blocky_cache(token: &str) -> Result<BlockyActionResponse, String> {
    post_empty("/api/blocky/flush-cache", token).await
}

/// Filters of the query log. Empty fields match everything.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueryLogQuery {
    pub client: String,
    pub domain: String,
    pub blocked_only: bool,
}

/// Fetch recent queries matching `query`, newest first.
pub async fn fetch_query_log(
    token: &str,
    query: &QueryLogQuery,
) -> Result<BlockyQueryLogResponse, String> {
    let mut params = Vec::new();
    if !query.client.trim().is_empty() {
        params.push(format!(
            "client={}",
            encode_query_value(query.client.trim())
        ));
    }
    if !query.domain.trim().is_empty() {
        params.push(format!("q={}", encode_query_value(query.domain.trim())));
    }
    if query.blocked_only {
        params.push("blocked=true".to_string());
    }
    let url = if params.is_empty() {
        "/api/blocky/querylog".to_string()
    } else {
        format!("/api/blocky/querylog?{}", params.join("&"))
    };
    get(&url, token).await
}

/// Percent-encode a query-string value. Everything except unreserved
/// characters is escaped, so that domain filters cannot change the query.
fn encode_query_value(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char)
            }
            other => encoded.push_str(&format!("%{other:02X}")),
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_values_escape_separators() {
        assert_eq!(encode_query_value("ads.example"), "ads.example");
        assert_eq!(encode_query_value("a&blocked=false"), "a%26blocked%3Dfalse");
        assert_eq!(encode_query_value("10.0.0.2"), "10.0.0.2");
        assert_eq!(encode_query_value("a b"), "a%20b");
    }
}
