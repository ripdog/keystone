//! DNS filtering (ad-blocking) and encrypted upstream DNS, served by Blocky.
//!
//! Keystone never runs Blocky from a shell. It generates
//! `/etc/keystone-blocky/config.yml`, controls `keystone-blocky.service`, and
//! talks to Blocky's HTTP API on loopback for runtime actions. dnsmasq keeps
//! port 53 and forwards every query to Blocky when its upstream mode is
//! `blocky`; see `DnsmasqUpstreamMode::Blocky`.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// Selector that matches every client not matched by a more specific selector.
pub const BLOCKY_DEFAULT_SELECTOR: &str = "default";
/// Name of the group every client falls back to when no other group matches.
pub const BLOCKY_DEFAULT_GROUP_NAME: &str = "ads";
/// Default denylist for the `ads` group: a curated wildcard list.
pub const BLOCKY_DEFAULT_DENYLIST: &str =
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.txt";

/// How Blocky chooses among its upstream resolvers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockyUpstreamStrategy {
    /// Ask every upstream and use the fastest answer.
    #[default]
    ParallelBest,
    /// Ask the upstreams in order, moving on only when one fails.
    Strict,
    /// Ask a random upstream for each query.
    Random,
}

impl BlockyUpstreamStrategy {
    /// The value Blocky's configuration uses for this strategy.
    pub const fn blocky_value(self) -> &'static str {
        match self {
            BlockyUpstreamStrategy::ParallelBest => "parallel_best",
            BlockyUpstreamStrategy::Strict => "strict",
            BlockyUpstreamStrategy::Random => "random",
        }
    }
}

/// The answer given to a blocked query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockyBlockType {
    /// Answer with 0.0.0.0 or :: so the client fails fast.
    #[default]
    ZeroIp,
    /// Answer with NXDOMAIN.
    NxDomain,
}

impl BlockyBlockType {
    /// The value Blocky's configuration uses for this block type.
    pub const fn blocky_value(self) -> &'static str {
        match self {
            BlockyBlockType::ZeroIp => "zeroIp",
            BlockyBlockType::NxDomain => "nxDomain",
        }
    }
}

/// DNS filtering settings. A single configuration row with child lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BlockyConfig {
    /// Run Blocky and send dnsmasq's upstream queries to it.
    pub enabled: bool,
    /// Encrypted or plain upstream resolvers: an IP, `tcp-tls:host[:port]`,
    /// or `https://host/path`.
    pub upstreams: Vec<String>,
    /// Plain resolvers used to look up upstream host names and list URLs.
    pub bootstrap: Vec<IpAddr>,
    pub upstream_strategy: BlockyUpstreamStrategy,
    pub block_type: BlockyBlockType,
    /// Hours between downloads of the denylists and allowlists.
    pub refresh_hours: u32,
    /// Resolve names that are about to expire before a client asks.
    pub prefetching: bool,
    /// Shortest time an answer is cached, in minutes.
    pub min_cache_minutes: u32,
    /// Keep a per-day CSV log of every query.
    pub query_log_enabled: bool,
    /// Days of query log kept before the oldest files are removed.
    pub query_log_retention_days: u32,
    /// Filtering groups. A group holds lists and custom domain entries.
    pub groups: Vec<BlockyGroup>,
    /// Which groups apply to which clients. The `default` selector applies to
    /// clients that no other selector matches.
    pub client_groups: Vec<BlockyClientGroups>,
}

impl Default for BlockyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            upstreams: vec![
                "https://dns.quad9.net/dns-query".to_string(),
                "tcp-tls:dns.quad9.net".to_string(),
            ],
            bootstrap: vec![
                IpAddr::from([9, 9, 9, 9]),
                IpAddr::from([149, 112, 112, 112]),
            ],
            upstream_strategy: BlockyUpstreamStrategy::ParallelBest,
            block_type: BlockyBlockType::ZeroIp,
            refresh_hours: 24,
            prefetching: true,
            min_cache_minutes: 5,
            query_log_enabled: true,
            query_log_retention_days: 7,
            groups: vec![BlockyGroup {
                name: BLOCKY_DEFAULT_GROUP_NAME.to_string(),
                denylists: vec![BLOCKY_DEFAULT_DENYLIST.to_string()],
                ..BlockyGroup::default()
            }],
            client_groups: vec![BlockyClientGroups {
                selector: BLOCKY_DEFAULT_SELECTOR.to_string(),
                groups: vec![BLOCKY_DEFAULT_GROUP_NAME.to_string()],
            }],
        }
    }
}

/// A named filtering group.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BlockyGroup {
    /// Lowercase identifier, referenced by client groups.
    pub name: String,
    /// `http` or `https` URLs of lists whose domains are blocked.
    pub denylists: Vec<String>,
    /// `http` or `https` URLs of lists whose domains are always allowed. A
    /// group with allowlists must also have a denylist.
    pub allowlists: Vec<String>,
    /// Domains blocked by hand: `example.com`, `*.example.com` or `/regex/`.
    pub custom_deny: Vec<String>,
    /// Domains allowed by hand, in the same forms as `custom_deny`.
    pub custom_allow: Vec<String>,
}

/// The groups that apply to one client selector.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BlockyClientGroups {
    /// `default`, an IP address, or a CIDR network.
    pub selector: String,
    /// Names of groups from [`BlockyConfig::groups`], in order.
    pub groups: Vec<String>,
}

/// Whether Blocky is installed and whether it is blocking, read live.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockyStatusResponse {
    /// `/usr/bin/blocky` exists.
    pub installed: bool,
    /// Actionable text about the installation, shown in the UI.
    pub binary_message: String,
    /// `keystone-blocky.service` is active.
    pub service_active: bool,
    /// The HTTP API answered. False when the service is not running.
    pub api_reachable: bool,
    /// Blocking state reported by Blocky, when the API answered.
    pub blocking: Option<BlockyBlockingStatus>,
    /// Why the status is incomplete, if it is.
    pub warnings: Vec<String>,
}

/// Blocking state reported by Blocky's `/api/blocking/status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockyBlockingStatus {
    /// Blocking is on.
    pub enabled: bool,
    /// Seconds until blocking resumes after a pause. Zero when not paused.
    pub auto_enable_in_secs: u64,
}

/// One line of Blocky's query log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockyQueryLogEntry {
    /// Local time, as Blocky wrote it (`YYYY-MM-DD HH:MM:SS`).
    pub time: String,
    pub client_ip: String,
    /// Name from Blocky's log or the DHCP leases. Untrusted: display as text.
    pub client_name: Option<String>,
    pub duration_ms: u64,
    pub reason: String,
    /// The queried domain. Untrusted: display as text.
    pub domain: String,
    pub answer: String,
    pub response_code: String,
    pub response_type: String,
    pub question_type: String,
    /// True when Blocky refused the query.
    pub blocked: bool,
}

/// Recent query log entries, newest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockyQueryLogResponse {
    pub entries: Vec<BlockyQueryLogEntry>,
    /// True when the result was cut short by the row or byte limit.
    pub truncated: bool,
    /// Why the log is incomplete, for example unreadable files.
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockyStateResponse {
    pub config: BlockyConfig,
    /// `/usr/bin/blocky` exists.
    pub installed: bool,
    /// Actionable text about the installation.
    pub binary_message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaveBlockyConfigRequest {
    pub config: BlockyConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaveBlockyConfigResponse {
    pub success: bool,
    pub message: String,
}

/// Result of a runtime action or an apply: pause, resume, refresh, flush.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockyActionResponse {
    pub success: bool,
    pub message: String,
}

/// Pause blocking for `minutes`, or resume it when `minutes` is `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockyPauseRequest {
    pub minutes: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_disabled_and_filters_ads_through_encrypted_upstreams() {
        let config = BlockyConfig::default();
        assert!(!config.enabled);
        assert!(config.upstreams.iter().any(|u| u.starts_with("https://")));
        assert!(config.upstreams.iter().any(|u| u.starts_with("tcp-tls:")));
        assert!(config.groups.iter().all(|group| group.allowlists.is_empty()));
        // Every client assignment refers to a group that exists, and unmatched
        // clients are covered by the default selector.
        assert!(config.client_groups.iter().any(|assignment| {
            assignment.selector == BLOCKY_DEFAULT_SELECTOR
        }));
        for assignment in &config.client_groups {
            for name in &assignment.groups {
                assert!(config.groups.iter().any(|group| &group.name == name));
            }
        }
    }

    #[test]
    fn config_fills_missing_fields_from_defaults() {
        let config: BlockyConfig = serde_json::from_str(r#"{"enabled": true}"#).unwrap();
        assert_eq!(
            config,
            BlockyConfig {
                enabled: true,
                ..BlockyConfig::default()
            }
        );
    }

    #[test]
    fn enums_serialise_snake_case_and_map_to_blocky_values() {
        assert_eq!(
            serde_json::to_string(&BlockyUpstreamStrategy::ParallelBest).unwrap(),
            "\"parallel_best\""
        );
        assert_eq!(
            serde_json::to_string(&BlockyBlockType::NxDomain).unwrap(),
            "\"nx_domain\""
        );
        assert_eq!(BlockyUpstreamStrategy::Strict.blocky_value(), "strict");
        assert_eq!(BlockyBlockType::ZeroIp.blocky_value(), "zeroIp");
        assert_eq!(BlockyBlockType::NxDomain.blocky_value(), "nxDomain");
    }
}
