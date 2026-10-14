//! Validation and generation of Blocky's `config.yml`.
//!
//! Everything here is a pure function of the typed configuration, so the same
//! text is shown in the pending-changes diff and written on apply. The file is
//! generated as JSON, which Blocky accepts because JSON is valid YAML. It is
//! never built by joining strings into YAML.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};

use ipnet::IpNet;
use keystone_core::DnsmasqConfig;
use keystone_core::DnsmasqUpstreamMode;
use keystone_core::blocky::{BLOCKY_DEFAULT_SELECTOR, BlockyConfig, BlockyGroup};
use keystone_core::validation::hostname_or_ip;
use serde::Serialize;

/// Where Keystone writes Blocky's configuration. Its directory is created by
/// `ConfigurationDirectory=` in the daemon unit.
pub const BLOCKY_CONFIG_PATH: &str = "/etc/keystone-blocky/config.yml";
/// The Blocky binary. Installed by the `blocky-bin` package from the AUR.
pub const BLOCKY_BINARY_PATH: &str = "/usr/bin/blocky";
/// Port Blocky answers DNS on. Loopback only: dnsmasq is the only client.
pub const BLOCKY_DNS_PORT: u16 = 5335;
/// Port of Blocky's HTTP API. Loopback only.
pub const BLOCKY_HTTP_PORT: u16 = 5336;
/// Directory of the daily CSV query log. Under the unit's `StateDirectory=`.
pub const BLOCKY_QUERY_LOG_DIR: &str = "/var/lib/keystone-blocky/querylog";

/// Most upstream resolvers accepted.
const UPSTREAMS_MAX: usize = 8;
/// Most bootstrap resolvers accepted.
const BOOTSTRAP_MAX: usize = 4;
/// Longest group name accepted.
const GROUP_NAME_MAX: usize = 32;
/// Most list URLs accepted per group and kind.
const LIST_URLS_MAX: usize = 32;
/// Most hand-written entries accepted per group and kind.
const CUSTOM_ENTRIES_MAX: usize = 2000;
/// Longest list URL accepted.
const LIST_URL_MAX: usize = 2048;
/// Longest hand-written domain entry accepted.
const CUSTOM_ENTRY_MAX: usize = 253;

/// Check a configuration. The result lists every problem, joined with `; `.
pub fn validate_config(config: &BlockyConfig) -> Result<(), String> {
    let mut errors = Vec::new();

    if !(1..=UPSTREAMS_MAX).contains(&config.upstreams.len()) {
        errors.push(format!(
            "choose between 1 and {UPSTREAMS_MAX} upstream resolvers"
        ));
    }
    for upstream in &config.upstreams {
        if let Err(error) = validate_upstream(upstream) {
            errors.push(error);
        }
    }

    if !(1..=BOOTSTRAP_MAX).contains(&config.bootstrap.len()) {
        errors.push(format!(
            "choose between 1 and {BOOTSTRAP_MAX} bootstrap resolvers"
        ));
    }
    let mut bootstrap = BTreeSet::new();
    for address in &config.bootstrap {
        if address.is_loopback() || address.is_unspecified() {
            // Loopback would send lookups back through dnsmasq and Blocky.
            errors.push(format!(
                "bootstrap resolver {address} must not be a loopback or unspecified address"
            ));
        }
        if !bootstrap.insert(*address) {
            errors.push(format!(
                "bootstrap resolver {address} is listed more than once"
            ));
        }
    }

    if !(1..=168).contains(&config.refresh_hours) {
        errors.push("list refresh must be between 1 and 168 hours".to_string());
    }
    if config.min_cache_minutes > 60 {
        errors.push("minimum cache time must be between 0 and 60 minutes".to_string());
    }
    if !(1..=90).contains(&config.query_log_retention_days) {
        errors.push("query log retention must be between 1 and 90 days".to_string());
    }

    let mut group_names = BTreeSet::new();
    for group in &config.groups {
        if let Err(error) = validate_group(group) {
            errors.push(error);
        }
        if !group_names.insert(group.name.as_str()) {
            errors.push(format!("group {:?} is defined more than once", group.name));
        }
    }

    let mut selectors = BTreeSet::new();
    for assignment in &config.client_groups {
        if let Err(error) = validate_selector(&assignment.selector) {
            errors.push(error);
        }
        if !selectors.insert(assignment.selector.as_str()) {
            errors.push(format!(
                "client {:?} is listed more than once",
                assignment.selector
            ));
        }
        if assignment.groups.is_empty() {
            errors.push(format!(
                "client {:?} needs at least one group",
                assignment.selector
            ));
        }
        for name in &assignment.groups {
            if !group_names.contains(name.as_str()) {
                errors.push(format!(
                    "client {:?} uses group {name:?}, which does not exist",
                    assignment.selector
                ));
            }
        }
    }
    if config.enabled && !selectors.contains(BLOCKY_DEFAULT_SELECTOR) {
        errors.push(format!(
            "choose the groups for {BLOCKY_DEFAULT_SELECTOR:?} clients, which apply to every client without a more specific selector"
        ));
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// An upstream resolver, in the forms Blocky reads: a plain IP address with an
/// optional port, `tcp-tls:host[:port]`, or `https://host[:port][/path]`.
pub fn validate_upstream(entry: &str) -> Result<(), String> {
    let invalid = || {
        format!(
            "upstream {entry:?} must be an IP address, tcp-tls:host[:port], or https://host[/path]"
        )
    };
    if !is_visible_ascii(entry) {
        return Err(invalid());
    }
    if let Some(rest) = entry.strip_prefix("https://") {
        let (authority, path) = match rest.split_once('/') {
            Some((authority, path)) => (authority, Some(path)),
            None => (rest, None),
        };
        validate_host_port(authority).map_err(|_| invalid())?;
        if let Some(path) = path
            && !path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~/%+".contains(&b))
        {
            return Err(invalid());
        }
        return Ok(());
    }
    if let Some(rest) = entry.strip_prefix("tcp-tls:") {
        return validate_host_port(rest).map_err(|_| invalid());
    }
    if entry.parse::<SocketAddr>().is_ok() || entry.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    Err(invalid())
}

/// `host`, `host:port`, `[v6]` or `[v6]:port`, where the host is an IP address
/// or a DNS name. A bare IPv6 address without brackets has no port. A missing
/// port is accepted; Blocky then uses the scheme's default.
fn validate_host_port(value: &str) -> Result<(), String> {
    if let Some(rest) = value.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| "bad address".to_string())?;
        host.parse::<IpAddr>().map_err(|e| e.to_string())?;
        return match tail {
            "" => Ok(()),
            tail => parse_port(
                tail.strip_prefix(':')
                    .ok_or_else(|| "bad address".to_string())?,
            ),
        };
    }
    if value.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    match value.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => {
            hostname_or_ip(host)?;
            parse_port(port)
        }
        Some(_) => Err("bad address".to_string()),
        None => hostname_or_ip(value),
    }
}

fn parse_port(value: &str) -> Result<(), String> {
    match value.parse::<u16>() {
        Ok(port) if port != 0 => Ok(()),
        _ => Err("bad port".to_string()),
    }
}

fn validate_group(group: &BlockyGroup) -> Result<(), String> {
    validate_group_name(&group.name)?;
    if group.name == BLOCKY_DEFAULT_SELECTOR {
        return Err(format!(
            "{BLOCKY_DEFAULT_SELECTOR:?} is reserved for the client selector and cannot be a group name"
        ));
    }
    for url in &group.denylists {
        validate_list_url(url)?;
    }
    for url in &group.allowlists {
        validate_list_url(url)?;
    }
    validate_list_count(&group.name, "denylists", group.denylists.len())?;
    validate_list_count(&group.name, "allowlists", group.allowlists.len())?;
    for entry in group.custom_deny.iter().chain(&group.custom_allow) {
        validate_custom_entry(entry)?;
    }
    if group.custom_deny.len() > CUSTOM_ENTRIES_MAX || group.custom_allow.len() > CUSTOM_ENTRIES_MAX
    {
        return Err(format!(
            "group {:?} has more than {CUSTOM_ENTRIES_MAX} hand-written entries of one kind",
            group.name
        ));
    }
    // Blocky lets an allowlist override a denylist. A group with allowlists and
    // no deny source would then block every domain that is not allowed, which
    // is almost never intended.
    let has_allow = !group.allowlists.is_empty() || !group.custom_allow.is_empty();
    let has_deny = !group.denylists.is_empty() || !group.custom_deny.is_empty();
    if has_allow && !has_deny {
        return Err(format!(
            "group {:?} has allowlists but no denylist; add a denylist, or the clients using it would be blocked from everything not allowed",
            group.name
        ));
    }
    Ok(())
}

fn validate_list_count(group: &str, kind: &str, count: usize) -> Result<(), String> {
    if count > LIST_URLS_MAX {
        Err(format!(
            "group {group:?} has more than {LIST_URLS_MAX} {kind}"
        ))
    } else {
        Ok(())
    }
}

/// Group names are lowercase and start with a letter or digit: `^[a-z0-9][a-z0-9_-]*$`.
pub fn validate_group_name(name: &str) -> Result<(), String> {
    let bytes = name.as_bytes();
    let starts_well = bytes
        .first()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    let valid = starts_well
        && bytes.len() <= GROUP_NAME_MAX
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-');
    if valid {
        Ok(())
    } else {
        Err(format!(
            "group name {name:?} must be 1 to {GROUP_NAME_MAX} lowercase letters, digits, _ or -, starting with a letter or digit"
        ))
    }
}

/// A list URL. Only `http` and `https` are fetched.
pub fn validate_list_url(url: &str) -> Result<(), String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"));
    let host_present = rest.is_some_and(|rest| !rest.split('/').next().unwrap_or("").is_empty());
    if url.len() <= LIST_URL_MAX && host_present && is_visible_ascii(url) {
        Ok(())
    } else {
        Err(format!(
            "list {url:?} must be an http or https URL with no spaces"
        ))
    }
}

/// A hand-written entry: a domain (`example.com`), a wildcard
/// (`*.example.com`) or a regular expression between slashes (`/.../`).
pub fn validate_custom_entry(entry: &str) -> Result<(), String> {
    let invalid = || {
        format!(
            "entry {entry:?} must be a domain, a wildcard such as *.example.com, or a regular expression between slashes"
        )
    };
    if entry.is_empty() || entry.len() > CUSTOM_ENTRY_MAX || !is_visible_ascii(entry) {
        return Err(invalid());
    }
    if entry.len() >= 3 && entry.starts_with('/') && entry.ends_with('/') {
        // Blocky compiles the expression when it loads the list; Keystone
        // checks only its framing.
        return Ok(());
    }
    let domain = entry.strip_prefix("*.").unwrap_or(entry);
    let labels_ok = domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    if labels_ok { Ok(()) } else { Err(invalid()) }
}

/// A client selector: `default`, an IP address, or a CIDR network.
pub fn validate_selector(selector: &str) -> Result<(), String> {
    if selector == BLOCKY_DEFAULT_SELECTOR
        || selector.parse::<IpAddr>().is_ok()
        || selector.parse::<IpNet>().is_ok()
    {
        Ok(())
    } else {
        Err(format!(
            "client {selector:?} must be {BLOCKY_DEFAULT_SELECTOR:?}, an IP address, or a CIDR network"
        ))
    }
}

/// Visible ASCII only: no spaces, control characters or non-ASCII. Every
/// value written into the configuration passes through this.
fn is_visible_ascii(value: &str) -> bool {
    value.bytes().all(|b| b.is_ascii_graphic())
}

/// Checks the dnsmasq settings that depend on Blocky. Blocky mode points
/// dnsmasq at Blocky, so Blocky must be enabled, and dnsmasq's cache is turned
/// off, which DNSSEC validation does not allow.
pub fn dnsmasq_link_errors(dnsmasq: &DnsmasqConfig, blocky_enabled: bool) -> Vec<String> {
    if dnsmasq.upstream_mode != DnsmasqUpstreamMode::Blocky {
        return Vec::new();
    }
    let mut errors = Vec::new();
    if !blocky_enabled {
        errors.push(
            "DNS upstream is set to Blocky, but DNS filtering is disabled; enable DNS filtering or choose another upstream"
                .to_string(),
        );
    }
    if dnsmasq.dnssec_enabled {
        errors.push(
            "DNSSEC needs dnsmasq's cache, which Blocky mode turns off; disable DNSSEC or choose another upstream"
                .to_string(),
        );
    }
    errors
}

// ============================================================================
// Rendering
// ============================================================================

#[derive(Serialize)]
struct RenderedConfig {
    upstreams: RenderedUpstreams,
    #[serde(rename = "bootstrapDns")]
    bootstrap_dns: Vec<String>,
    ports: RenderedPorts,
    blocking: RenderedBlocking,
    caching: RenderedCaching,
    ecs: RenderedEcs,
    #[serde(rename = "queryLog")]
    query_log: RenderedQueryLog,
}

#[derive(Serialize)]
struct RenderedUpstreams {
    strategy: &'static str,
    init: RenderedInit,
    groups: RenderedUpstreamGroups,
}

#[derive(Serialize)]
struct RenderedInit {
    strategy: &'static str,
}

#[derive(Serialize)]
struct RenderedUpstreamGroups {
    default: Vec<String>,
}

#[derive(Serialize)]
struct RenderedPorts {
    dns: Vec<String>,
    http: Vec<String>,
}

#[derive(Serialize)]
struct RenderedBlocking {
    denylists: BTreeMap<String, Vec<String>>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    allowlists: BTreeMap<String, Vec<String>>,
    #[serde(rename = "clientGroupsBlock")]
    client_groups_block: BTreeMap<String, Vec<String>>,
    #[serde(rename = "blockType")]
    block_type: &'static str,
    loading: RenderedLoading,
}

#[derive(Serialize)]
struct RenderedLoading {
    #[serde(rename = "refreshPeriod")]
    refresh_period: String,
    strategy: &'static str,
}

#[derive(Serialize)]
struct RenderedCaching {
    #[serde(rename = "minTime")]
    min_time: String,
    prefetching: bool,
}

#[derive(Serialize)]
struct RenderedEcs {
    /// Use the client address that dnsmasq passes with EDNS client subnet.
    #[serde(rename = "useAsClient")]
    use_as_client: bool,
    /// Never send client addresses to the upstream resolvers.
    forward: bool,
}

#[derive(Serialize)]
struct RenderedQueryLog {
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<&'static str>,
    #[serde(rename = "logRetentionDays", skip_serializing_if = "Option::is_none")]
    log_retention_days: Option<u32>,
}

/// The `config.yml` text for `config`, as pretty-printed JSON.
pub fn render_config(config: &BlockyConfig) -> Result<String, String> {
    let rendered = render_structure(config);
    let mut text = serde_json::to_string_pretty(&rendered).map_err(|error| error.to_string())?;
    text.push('\n');
    Ok(text)
}

fn render_structure(config: &BlockyConfig) -> RenderedConfig {
    // Every group gets a denylist key, even an empty one, so that every
    // client group refers to a group Blocky knows.
    let mut denylists = BTreeMap::new();
    let mut allowlists = BTreeMap::new();
    for group in &config.groups {
        denylists.insert(
            group.name.clone(),
            group_sources(&group.denylists, &group.custom_deny),
        );
        let allow = group_sources(&group.allowlists, &group.custom_allow);
        if !allow.is_empty() {
            allowlists.insert(group.name.clone(), allow);
        }
    }

    let client_groups_block = config
        .client_groups
        .iter()
        .map(|assignment| (assignment.selector.clone(), assignment.groups.clone()))
        .collect();

    let query_log = if config.query_log_enabled {
        RenderedQueryLog {
            kind: "csv",
            target: Some(BLOCKY_QUERY_LOG_DIR),
            log_retention_days: Some(config.query_log_retention_days),
        }
    } else {
        RenderedQueryLog {
            kind: "none",
            target: None,
            log_retention_days: None,
        }
    };

    RenderedConfig {
        upstreams: RenderedUpstreams {
            strategy: config.upstream_strategy.blocky_value(),
            init: RenderedInit { strategy: "fast" },
            groups: RenderedUpstreamGroups {
                default: config.upstreams.clone(),
            },
        },
        bootstrap_dns: config
            .bootstrap
            .iter()
            .map(|address| format!("tcp+udp:{address}"))
            .collect(),
        ports: RenderedPorts {
            dns: vec![format!("127.0.0.1:{BLOCKY_DNS_PORT}")],
            http: vec![format!("127.0.0.1:{BLOCKY_HTTP_PORT}")],
        },
        blocking: RenderedBlocking {
            denylists,
            allowlists,
            client_groups_block,
            block_type: config.block_type.blocky_value(),
            loading: RenderedLoading {
                refresh_period: format!("{}h", config.refresh_hours),
                strategy: "fast",
            },
        },
        caching: RenderedCaching {
            min_time: format!("{}m", config.min_cache_minutes),
            prefetching: config.prefetching,
        },
        ecs: RenderedEcs {
            use_as_client: true,
            forward: false,
        },
        query_log,
    }
}

/// List URLs, then one inline source holding the hand-written entries. Blocky
/// reads a source that is not a URL as inline list text.
fn group_sources(urls: &[String], custom: &[String]) -> Vec<String> {
    let mut sources = urls.to_vec();
    if !custom.is_empty() {
        sources.push(custom.join("\n"));
    }
    sources
}

#[cfg(test)]
mod tests {
    use super::*;
    use keystone_core::blocky::{BlockyClientGroups, BlockyGroup};

    fn valid_config() -> BlockyConfig {
        BlockyConfig {
            enabled: true,
            ..BlockyConfig::default()
        }
    }

    fn group(name: &str) -> BlockyGroup {
        BlockyGroup {
            name: name.to_string(),
            denylists: vec!["https://lists.example.com/ads.txt".to_string()],
            ..BlockyGroup::default()
        }
    }

    #[test]
    fn the_default_configuration_is_valid() {
        assert_eq!(validate_config(&valid_config()), Ok(()));
        assert_eq!(validate_config(&BlockyConfig::default()), Ok(()));
    }

    #[test]
    fn upstream_forms_are_parsed_not_guessed() {
        for valid in [
            "9.9.9.9",
            "9.9.9.9:53",
            "2620:fe::fe",
            "[2620:fe::fe]:853",
            "tcp-tls:dns.quad9.net",
            "tcp-tls:dns.quad9.net:853",
            "tcp-tls:192.0.2.1",
            "https://dns.quad9.net/dns-query",
            "https://dns.quad9.net",
            "https://192.0.2.1:443/dns-query",
        ] {
            assert_eq!(validate_upstream(valid), Ok(()), "{valid}");
        }
        for invalid in [
            "",
            "dns.quad9.net",
            "tls:dns.quad9.net",
            "udp://9.9.9.9",
            "http://dns.example.com/dns-query",
            "https://",
            "https://bad host/dns-query",
            "https://dns.example.com/dns query",
            "tcp-tls:",
            "tcp-tls:dns.example.com:0",
            "tcp-tls:dns.example.com:99999",
            "9.9.9.9\n",
            "9.9.9.9;evil",
        ] {
            assert!(
                validate_upstream(invalid).is_err(),
                "{invalid:?} should be refused"
            );
        }
    }

    #[test]
    fn upstreams_and_bootstrap_have_bounds() {
        let mut config = valid_config();
        config.upstreams.clear();
        assert!(validate_config(&config).is_err());

        let mut config = valid_config();
        config.upstreams = vec!["9.9.9.9".to_string(); UPSTREAMS_MAX + 1];
        assert!(validate_config(&config).is_err());

        let mut config = valid_config();
        config.bootstrap = vec![IpAddr::from([127, 0, 0, 1])];
        assert!(validate_config(&config).unwrap_err().contains("loopback"));

        let mut config = valid_config();
        config.bootstrap = vec![IpAddr::from([9, 9, 9, 9]), IpAddr::from([9, 9, 9, 9])];
        assert!(
            validate_config(&config)
                .unwrap_err()
                .contains("more than once")
        );
    }

    #[test]
    fn group_names_follow_the_pattern_and_are_unique() {
        assert!(validate_group_name("ads").is_ok());
        assert!(validate_group_name("kids-2_b").is_ok());
        for invalid in [
            "",
            "Ads",
            "-ads",
            "_ads",
            "ads.kids",
            "ads kids",
            &"a".repeat(33),
        ] {
            assert!(validate_group_name(invalid).is_err(), "{invalid:?}");
        }

        let mut config = valid_config();
        config.groups.push(group("ads"));
        assert!(
            validate_config(&config)
                .unwrap_err()
                .contains("more than once")
        );

        let mut config = valid_config();
        config.groups = vec![group("default")];
        assert!(validate_config(&config).unwrap_err().contains("reserved"));
    }

    #[test]
    fn list_urls_must_be_http_or_https_without_spaces() {
        assert!(validate_list_url("https://lists.example.com/ads.txt").is_ok());
        assert!(validate_list_url("http://lists.example.com/ads.txt").is_ok());
        for invalid in [
            "file:///etc/hosts",
            "ftp://lists.example.com/ads.txt",
            "https://",
            "https:///ads.txt",
            "https://lists.example.com/ads .txt",
            "https://lists.example.com/\nevil",
        ] {
            assert!(validate_list_url(invalid).is_err(), "{invalid:?}");
        }
        let long = format!("https://lists.example.com/{}", "a".repeat(LIST_URL_MAX));
        assert!(validate_list_url(&long).is_err());
    }

    #[test]
    fn custom_entries_are_domains_wildcards_or_regexes() {
        for valid in [
            "example.com",
            "*.example.com",
            "/^ads[0-9]+\\./",
            "my_host.lan",
        ] {
            assert!(validate_custom_entry(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "",
            "exa mple.com",
            "example.com\nevil.com",
            "a..b",
            "-.example.com",
            "//",
        ] {
            assert!(validate_custom_entry(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn selectors_are_default_ips_or_networks() {
        for valid in ["default", "192.168.1.10", "192.168.1.0/24", "fd00::/64"] {
            assert!(validate_selector(valid).is_ok(), "{valid}");
        }
        for invalid in ["", "lan", "192.168.1.0/33", "192.168.1.300"] {
            assert!(validate_selector(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn a_group_with_allowlists_and_no_denylist_is_refused() {
        let mut config = valid_config();
        config.groups = vec![BlockyGroup {
            name: "ads".to_string(),
            allowlists: vec!["https://lists.example.com/allow.txt".to_string()],
            ..BlockyGroup::default()
        }];
        let error = validate_config(&config).unwrap_err();
        assert!(error.contains("allowlists but no denylist"), "{error}");

        // A hand-written deny entry is a denylist source too.
        config.groups[0].custom_deny = vec!["ads.example.com".to_string()];
        config.groups[0].custom_allow = vec!["ok.example.com".to_string()];
        assert_eq!(validate_config(&config), Ok(()));
    }

    #[test]
    fn client_assignments_must_reference_existing_groups() {
        let mut config = valid_config();
        config.client_groups = vec![BlockyClientGroups {
            selector: BLOCKY_DEFAULT_SELECTOR.to_string(),
            groups: vec!["missing".to_string()],
        }];
        assert!(
            validate_config(&config)
                .unwrap_err()
                .contains("does not exist")
        );

        let mut config = valid_config();
        config.client_groups = vec![BlockyClientGroups {
            selector: "192.168.1.10".to_string(),
            groups: vec!["ads".to_string()],
        }];
        // Enabled without a default selector: unmatched clients would not be filtered.
        assert!(
            validate_config(&config)
                .unwrap_err()
                .contains("\"default\"")
        );

        let mut config = valid_config();
        config.client_groups.push(BlockyClientGroups {
            selector: "default".to_string(),
            groups: Vec::new(),
        });
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn numeric_settings_have_bounds() {
        let mut config = valid_config();
        config.refresh_hours = 0;
        config.min_cache_minutes = 61;
        config.query_log_retention_days = 91;
        let error = validate_config(&config).unwrap_err();
        assert!(error.contains("refresh"));
        assert!(error.contains("cache"));
        assert!(error.contains("retention"));
    }

    #[test]
    fn rendered_configuration_parses_and_keeps_the_security_settings() {
        let text = render_config(&valid_config()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();

        assert_eq!(value["ports"]["dns"][0], "127.0.0.1:5335");
        assert_eq!(value["ports"]["http"][0], "127.0.0.1:5336");
        assert_eq!(value["ecs"]["useAsClient"], true);
        assert_eq!(value["ecs"]["forward"], false);
        assert_eq!(value["bootstrapDns"][0], "tcp+udp:9.9.9.9");
        assert_eq!(
            value["upstreams"]["groups"]["default"][0],
            "https://dns.quad9.net/dns-query"
        );
        assert_eq!(value["queryLog"]["type"], "csv");
        assert_eq!(value["queryLog"]["target"], BLOCKY_QUERY_LOG_DIR);
    }

    #[test]
    fn client_groups_and_group_sources_round_trip_into_the_rendered_file() {
        let mut config = valid_config();
        config.groups = vec![
            BlockyGroup {
                name: "ads".to_string(),
                denylists: vec!["https://lists.example.com/ads.txt".to_string()],
                custom_deny: vec![
                    "tracker.example.com".to_string(),
                    "*.ads.example".to_string(),
                ],
                ..BlockyGroup::default()
            },
            BlockyGroup {
                name: "kids".to_string(),
                denylists: vec!["https://lists.example.com/adult.txt".to_string()],
                allowlists: vec!["https://lists.example.com/allow.txt".to_string()],
                custom_allow: vec!["school.example.com".to_string()],
                ..BlockyGroup::default()
            },
        ];
        config.client_groups = vec![
            BlockyClientGroups {
                selector: "default".to_string(),
                groups: vec!["ads".to_string()],
            },
            BlockyClientGroups {
                selector: "192.168.10.0/24".to_string(),
                groups: vec!["ads".to_string(), "kids".to_string()],
            },
        ];
        assert_eq!(validate_config(&config), Ok(()));

        let value: serde_json::Value =
            serde_json::from_str(&render_config(&config).unwrap()).unwrap();
        let blocking = &value["blocking"];
        assert_eq!(
            blocking["clientGroupsBlock"]["192.168.10.0/24"],
            serde_json::json!(["ads", "kids"])
        );
        assert_eq!(
            blocking["clientGroupsBlock"]["default"],
            serde_json::json!(["ads"])
        );
        assert_eq!(
            blocking["denylists"]["ads"],
            serde_json::json!([
                "https://lists.example.com/ads.txt",
                "tracker.example.com\n*.ads.example"
            ])
        );
        assert_eq!(
            blocking["allowlists"]["kids"],
            serde_json::json!(["https://lists.example.com/allow.txt", "school.example.com"])
        );
        assert!(blocking["allowlists"].get("ads").is_none());
    }

    #[test]
    fn disabling_the_query_log_writes_type_none() {
        let mut config = valid_config();
        config.query_log_enabled = false;
        let value: serde_json::Value =
            serde_json::from_str(&render_config(&config).unwrap()).unwrap();
        assert_eq!(value["queryLog"]["type"], "none");
        assert!(value["queryLog"].get("target").is_none());
    }

    #[test]
    fn blocky_mode_requires_blocky_and_refuses_dnssec() {
        let mut dnsmasq = DnsmasqConfig {
            upstream_mode: DnsmasqUpstreamMode::Blocky,
            ..DnsmasqConfig::default()
        };
        assert!(dnsmasq_link_errors(&dnsmasq, true).is_empty());
        assert_eq!(dnsmasq_link_errors(&dnsmasq, false).len(), 1);

        dnsmasq.dnssec_enabled = true;
        assert_eq!(dnsmasq_link_errors(&dnsmasq, true).len(), 1);

        dnsmasq.upstream_mode = DnsmasqUpstreamMode::System;
        assert!(dnsmasq_link_errors(&dnsmasq, false).is_empty());
    }
}
