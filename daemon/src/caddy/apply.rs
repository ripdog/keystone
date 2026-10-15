//! Caddy service management and configuration application

use anyhow::{Context, Result};
use keystone_core::{CaddyConfig, CaddyHttpsMode, CaddyInputAccept};
use sqlx::SqlitePool;
use std::fs;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use tracing::{info, warn};

use super::db::{load_caddy_config, update_validation_status};

/// Path to the Keystone Caddyfile
pub const CADDYFILE_PATH: &str = "/etc/caddy/Caddyfile.d/keystone.conf";

/// Path to the Caddy configuration directory
pub const CADDY_CONF_DIR: &str = "/etc/caddy/Caddyfile.d";

/// Main Caddyfile path that imports the conf.d files
pub const CADDY_MAIN_CONFIG: &str = "/etc/caddy/Caddyfile";

/// The port that keystone-web-ui listens on (internal)
const KEYSTONE_WEB_UI_PORT: u16 = 8080;

/// Ports used by other Keystone-managed services (DNS and DHCP).
const RESERVED_SERVICE_PORTS: [(u16, &str); 2] = [(53, "DNS"), (67, "DHCP")];

/// Last LAN IP Caddy was configured with; used to notice address changes.
const LAST_BIND_IP_PATH: &str = "/var/lib/keystone/caddy-bind-ip";

/// Serializes applies so the reconciler never races a user-triggered apply.
static APPLY_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Reject Caddy ports that are unusable or would collide with other listeners.
fn validate_ports(config: &CaddyConfig, ssh_port: Option<u16>) -> Result<()> {
    for (label, port) in [("HTTP", config.http_port), ("HTTPS", config.https_port)] {
        anyhow::ensure!(port != 0, "Caddy {label} port must be between 1 and 65535");
        anyhow::ensure!(
            port != KEYSTONE_WEB_UI_PORT,
            "Caddy {label} port {port} is used by the Keystone web UI"
        );
        if ssh_port == Some(port) {
            anyhow::bail!("Caddy {label} port {port} is used by the SSH server");
        }
        if let Some((_, service)) = RESERVED_SERVICE_PORTS.iter().find(|(p, _)| *p == port) {
            anyhow::bail!("Caddy {label} port {port} is reserved for {service}");
        }
    }
    anyhow::ensure!(
        config.http_port != config.https_port,
        "Caddy HTTP and HTTPS ports must differ"
    );
    Ok(())
}

/// Validate the subset of Caddy configuration that Keystone safely supports.
pub fn validate_config(config: &CaddyConfig) -> Result<()> {
    validate_settings(config, crate::ssh::enabled_port())
}

/// [`validate_config`] with the SSH port supplied by the caller instead of read
/// from the system, so the same checks can run on stored configuration.
pub fn validate_settings(config: &CaddyConfig, ssh_port: Option<u16>) -> Result<()> {
    validate_ports(config, ssh_port)?;
    keystone_core::validation::hostname_or_ip(&config.server_address)
        .map_err(anyhow::Error::msg)?;
    keystone_core::validation::single_line_fields(&config.server_address)
        .map_err(anyhow::Error::msg)?;
    if !config.bind_interface.is_empty() {
        keystone_core::validation::interface_name(&config.bind_interface)
            .map_err(anyhow::Error::msg)?;
    }
    if config.https_mode == CaddyHttpsMode::AcmeCustom {
        keystone_core::validation::custom_tls_config(&config.custom_tls_config)
            .map_err(anyhow::Error::msg)?;
    }
    Ok(())
}

/// Resolve a LAN interface against the same authoritative `interface_config`
/// table as networkd and the interface management API.
async fn lan_interface_name(pool: &SqlitePool, selected: &str) -> Result<String> {
    let lans: Vec<(String,)> = sqlx::query_as(
        "SELECT interface_name FROM interface_config WHERE enabled = 1 AND role = 'LAN' ORDER BY interface_name",
    )
    .fetch_all(pool)
    .await?;
    let name = if selected.is_empty() {
        lans.first().map(|row| row.0.as_str())
    } else {
        lans.iter()
            .find(|row| row.0 == selected)
            .map(|row| row.0.as_str())
    }
    .ok_or_else(|| anyhow::anyhow!("Select an enabled LAN interface before enabling Caddy"))?;
    Ok(name.to_string())
}

/// The input accepts Keystone must generate for Caddy: its LAN interface and
/// listening ports. `None` while Caddy is disabled or has no LAN interface.
pub async fn load_input_accept(pool: &SqlitePool) -> Result<Option<CaddyInputAccept>> {
    let config = super::db::load_caddy_config(pool).await?;
    let Ok(interface) = lan_interface_name(pool, &config.bind_interface).await else {
        return Ok(None);
    };
    Ok(input_accept(&config, interface))
}

fn input_accept(config: &CaddyConfig, interface: String) -> Option<CaddyInputAccept> {
    if !config.enabled || config.server_address.is_empty() {
        return None;
    }
    // The HTTP port serves the redirect and ACME HTTP challenges when HTTPS is
    // on, and the site itself when it is off.
    let mut ports = vec![config.http_port];
    if config.https_mode != CaddyHttpsMode::Disabled {
        ports.push(config.https_port);
    }
    Some(CaddyInputAccept { interface, ports })
}

/// Return only an address of an enabled LAN interface. Caddy must never use
/// its implicit all-interfaces bind when acting as Keystone's proxy.
async fn lan_bind_ip(pool: &SqlitePool, selected: &str) -> Result<String> {
    let name = lan_interface_name(pool, selected).await?;
    // networkd configures the address asynchronously, so right after a unified
    // apply it may not be assigned yet.
    for _ in 0..LAN_IP_WAIT_ATTEMPTS {
        if let Some(ip) = get_interface_ip(&name) {
            return Ok(ip);
        }
        tokio::time::sleep(LAN_IP_WAIT_INTERVAL).await;
    }
    get_interface_ip(&name)
        .ok_or_else(|| anyhow::anyhow!("No assigned IPv4 address on LAN interface {name}"))
}

const LAN_IP_WAIT_ATTEMPTS: u32 = 20;
const LAN_IP_WAIT_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// DNS challenge providers are optional Caddy modules, not in Arch's base
/// binary. Report a missing provider before trying to adapt the generated
/// Caddyfile.
fn ensure_required_dns_modules(config: &CaddyConfig) -> Result<()> {
    if config.https_mode != CaddyHttpsMode::AcmeCustom {
        return Ok(());
    }
    let Some(provider) = config
        .custom_tls_config
        .lines()
        .find_map(keystone_core::validation::dns_provider)
    else {
        return Ok(());
    };
    let output = Command::new("caddy")
        .arg("list-modules")
        .output()
        .context("Failed to inspect Caddy modules")?;
    anyhow::ensure!(output.status.success(), "Failed to list Caddy modules");
    let modules = String::from_utf8_lossy(&output.stdout);
    anyhow::ensure!(
        has_dns_provider_module(&modules, provider),
        "Caddy is missing the {provider} DNS provider (dns.providers.{provider}). Install a Caddy build that includes it (for example github.com/caddy-dns/{provider}) before enabling DNS challenge TLS."
    );
    Ok(())
}

fn has_dns_provider_module(modules: &str, provider: &str) -> bool {
    let wanted = format!("dns.providers.{provider}");
    modules.lines().any(|line| line.trim() == wanted)
}

/// Generate the Caddyfile content from the configuration
pub fn generate_caddyfile(config: &CaddyConfig, bind_ip: Option<&str>) -> String {
    if !config.enabled || config.server_address.is_empty() {
        return "# Caddy is disabled or not configured\n".to_string();
    }

    let mut lines = Vec::new();

    // Add header comment
    lines.push("# Keystone Web UI - Generated by keystone-daemon".to_string());
    lines.push("# Do not edit manually - changes will be overwritten".to_string());
    lines.push(String::new());

    // Build the site address
    let site_address = build_site_address(config);
    lines.push(format!("{} {{", site_address));

    // Add bind directive if binding to specific interface
    if let Some(ip) = bind_ip {
        lines.push(format!("    bind {}", ip));
    }

    // Add TLS configuration based on mode
    match config.https_mode {
        CaddyHttpsMode::Disabled => {
            // No TLS block needed for HTTP-only
        }
        CaddyHttpsMode::SelfSigned => {
            lines.push("    tls internal".to_string());
        }
        CaddyHttpsMode::AcmeCustom => {
            // Insert custom TLS configuration
            if !config.custom_tls_config.is_empty() {
                // Indent the custom config properly
                for line in config.custom_tls_config.lines() {
                    lines.push(format!("    {}", line));
                }
            }
        }
    }

    // Add reverse proxy to keystone-web-ui
    lines.push(String::new());
    lines.push(format!(
        "    reverse_proxy localhost:{}",
        KEYSTONE_WEB_UI_PORT
    ));

    // Add logging
    lines.push(String::new());
    lines.push("    log {".to_string());
    lines.push("        output file /var/log/caddy/keystone-access.log".to_string());
    lines.push("    }".to_string());

    lines.push("}".to_string());

    // Add HTTP to HTTPS redirect if HTTPS is enabled
    if config.https_mode != CaddyHttpsMode::Disabled {
        lines.push(String::new());
        lines.push("# HTTP to HTTPS redirect".to_string());
        let http_address = build_http_redirect_address(config);
        lines.push(format!("{} {{", http_address));

        // Add bind directive for redirect block too
        if let Some(ip) = bind_ip {
            lines.push(format!("    bind {}", ip));
        }

        let https_redirect = if config.https_port == 443 {
            format!(
                "    redir https://{}{{uri}} permanent",
                config.server_address
            )
        } else {
            format!(
                "    redir https://{}:{}{{uri}} permanent",
                config.server_address, config.https_port
            )
        };
        lines.push(https_redirect);
        lines.push("}".to_string());
    }

    lines.join("\n") + "\n"
}

/// Build the site address for the Caddyfile
///
/// Caddy site address format:
/// - For HTTPS (default): `example.com` or `example.com:8443`
/// - For HTTP only: `http://example.com` or `http://example.com:8080`
fn build_site_address(config: &CaddyConfig) -> String {
    let port = if config.https_mode == CaddyHttpsMode::Disabled {
        config.http_port
    } else {
        config.https_port
    };

    // For HTTP-only mode, we need the http:// prefix to prevent automatic HTTPS
    if config.https_mode == CaddyHttpsMode::Disabled {
        if port == 80 {
            format!("http://{}", config.server_address)
        } else {
            format!("http://{}:{}", config.server_address, port)
        }
    } else {
        // For HTTPS modes, just use the domain (Caddy enables HTTPS by default)
        if port == 443 {
            config.server_address.clone()
        } else {
            format!("{}:{}", config.server_address, port)
        }
    }
}

/// Build the HTTP redirect address (for redirecting HTTP to HTTPS)
fn build_http_redirect_address(config: &CaddyConfig) -> String {
    // HTTP redirect always uses http:// prefix
    if config.http_port == 80 {
        format!("http://{}", config.server_address)
    } else {
        format!("http://{}:{}", config.server_address, config.http_port)
    }
}

/// Return the usable LAN IPv4 address rather than whichever address `ip`
/// lists first (a stale 169.254/16 IPv4LL address may precede the LAN IP).
fn parse_interface_global_ipv4(stdout: &str) -> Option<String> {
    for line in stdout.lines() {
        let parts: Vec<_> = line.split_ascii_whitespace().collect();
        if parts.len() < 4 || parts[0] != "inet" {
            continue;
        }
        if !parts.windows(2).any(|pair| pair == ["scope", "global"]) {
            continue;
        }
        let Some(address) = parts[1].split('/').next() else {
            continue;
        };
        if let Ok(ip) = address.parse::<std::net::Ipv4Addr>()
            && !ip.is_link_local()
            && !ip.is_unspecified()
            && !ip.is_multicast()
        {
            return Some(ip.to_string());
        }
    }
    None
}

/// Get the LAN interface's assigned global-scope IPv4 address.
pub fn get_interface_ip(interface: &str) -> Option<String> {
    let output = Command::new("ip")
        .args(["-4", "addr", "show", interface])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_interface_global_ipv4(&String::from_utf8_lossy(&output.stdout))
}

/// Ensure the Caddy configuration directory exists
pub fn ensure_caddy_dir() -> Result<()> {
    let path = Path::new(CADDY_CONF_DIR);
    if !path.exists() {
        fs::create_dir_all(path).with_context(|| {
            format!(
                "Failed to create Caddy config directory: {}",
                CADDY_CONF_DIR
            )
        })?;
    }
    Ok(())
}

/// Comment out the stock Arch `http:// { root * /usr/share/caddy; file_server }`
/// welcome site. It is a catch-all for port 80, so it shadows Keystone's
/// host-specific sites and visitors get Caddy's default page instead of the UI.
/// Only the unmodified packaged block is touched; returns `None` if absent.
fn disable_stock_welcome_site(content: &str) -> Option<String> {
    let lines: Vec<&str> = content.lines().collect();
    let start = lines.iter().position(|l| l.trim_end() == "http:// {")?;
    let end = start + lines[start..].iter().position(|l| l.trim_end() == "}")?;
    let block = &lines[start..=end];
    if !block.iter().any(|l| l.trim() == "root * /usr/share/caddy") {
        return None;
    }
    let mut out: Vec<String> = Vec::with_capacity(lines.len() + 1);
    out.extend(lines[..start].iter().map(|l| l.to_string()));
    out.push(
        "# Disabled by Keystone: this catch-all site shadows the Keystone web UI.".to_string(),
    );
    out.extend(block.iter().map(|l| format!("# {l}")));
    out.extend(lines[end + 1..].iter().map(|l| l.to_string()));
    Some(out.join("\n") + "\n")
}

/// Ensure the main Caddyfile imports our config
pub fn ensure_caddy_import() -> Result<()> {
    let main_config_path = Path::new(CADDY_MAIN_CONFIG);
    let import_line = format!("import {}/*", CADDY_CONF_DIR);

    if main_config_path.exists() {
        let mut content =
            fs::read_to_string(main_config_path).context("Failed to read main Caddyfile")?;

        if let Some(updated) = disable_stock_welcome_site(&content) {
            content = updated;
            fs::write(main_config_path, &content).context("Failed to update main Caddyfile")?;
            info!("Disabled stock Caddy welcome site in main Caddyfile");
        }

        if !content.contains(&import_line) {
            // Append import to the main Caddyfile
            let mut file = fs::OpenOptions::new()
                .append(true)
                .open(main_config_path)
                .context("Failed to open main Caddyfile for append")?;

            writeln!(file, "\n# Import Keystone configuration")?;
            writeln!(file, "{}", import_line)?;

            info!("Added import directive to main Caddyfile");
        }
    } else {
        // Create a minimal main Caddyfile
        fs::write(
            main_config_path,
            format!("{{\n    # Global options\n}}\n\n{}\n", import_line),
        )
        .context("Failed to create main Caddyfile")?;
        info!("Created main Caddyfile with import directive");
    }

    Ok(())
}

/// Validate as the Caddy service user, with the same data/config paths as
/// Arch's caddy.service. Validation provisions modules (including log writers
/// and TLS storage), which must not be accessed as Keystone's restricted root.
/// Feed the Caddyfile over stdin to avoid leaving TLS credentials on disk.
pub fn validate_caddyfile(content: &str) -> Result<(bool, String)> {
    let caddy = nix::unistd::User::from_name("caddy")?
        .context("Caddy service account is missing; install the caddy package")?;
    let mut child = Command::new("caddy")
        .args(["validate", "--config", "-", "--adapter", "caddyfile"])
        .env("XDG_DATA_HOME", "/var/lib")
        .env("XDG_CONFIG_HOME", "/etc")
        // Caddyfile placeholders such as {env.CF_API_TOKEN} resolve against the
        // service's environment, which validation must see as well.
        .envs(caddy_service_env())
        .uid(caddy.uid.as_raw())
        .gid(caddy.gid.as_raw())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to execute caddy validate as the caddy user")?;
    child
        .stdin
        .take()
        .context("Caddy validator stdin unavailable")?
        .write_all(content.as_bytes())
        .context("Failed to pass Caddyfile to validator")?;
    let output = child
        .wait_with_output()
        .context("Failed to wait for caddy validate")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}\n{}", stdout.trim(), stderr.trim())
        .trim()
        .to_string();

    if output.status.success() {
        Ok((true, combined))
    } else {
        Ok((false, combined))
    }
}

/// The environment the caddy service runs with: its `Environment=` values and
/// `EnvironmentFile=` contents, as systemd reports them. Values are only handed
/// to the validator process, never logged. Unreadable pieces are skipped, so a
/// missing variable surfaces as Caddy's own validation error.
fn caddy_service_env() -> Vec<(String, String)> {
    let Ok(output) = Command::new("systemctl")
        .args([
            "show",
            "caddy.service",
            "--property=Environment",
            "--property=EnvironmentFiles",
        ])
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let shown = String::from_utf8_lossy(&output.stdout);
    let mut vars = Vec::new();
    for line in shown.lines() {
        if let Some(value) = line.strip_prefix("EnvironmentFiles=") {
            for path in parse_environment_file_paths(value) {
                if let Ok(content) = fs::read_to_string(&path) {
                    vars.extend(parse_env_file(&content));
                }
            }
        }
    }
    // Environment= wins over EnvironmentFile=, as it does for the service.
    for line in shown.lines() {
        if let Some(value) = line.strip_prefix("Environment=") {
            vars.extend(parse_environment_assignments(value));
        }
    }
    vars
}

/// Paths from `systemctl show -p EnvironmentFiles`, whose entries look like
/// `/etc/caddy/dns.env (ignore_errors=no)`. Glob patterns are skipped.
fn parse_environment_file_paths(value: &str) -> Vec<String> {
    value
        .split(')')
        .filter_map(|entry| entry.split(" (").next())
        .map(str::trim)
        .filter(|path| path.starts_with('/') && !path.contains(['*', '?', '[']))
        .map(str::to_owned)
        .collect()
}

/// `KEY=value` lines of an environment file. Comments and blank lines are
/// ignored and one level of surrounding quotes is removed.
fn parse_env_file(content: &str) -> Vec<(String, String)> {
    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with(['#', ';']))
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            let key = key.trim();
            valid_env_name(key).then(|| (key.to_owned(), unquote(value.trim())))
        })
        .collect()
}

/// Space-separated `KEY=value` words from `systemctl show -p Environment`,
/// where a word containing spaces is double-quoted.
fn parse_environment_assignments(value: &str) -> Vec<(String, String)> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for ch in value.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            c if c.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
        .into_iter()
        .filter_map(|word| {
            let (key, value) = word.split_once('=')?;
            valid_env_name(key).then(|| (key.to_owned(), value.to_owned()))
        })
        .collect()
}

fn valid_env_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn unquote(value: &str) -> String {
    for quote in ['"', '\''] {
        if let Some(inner) = value
            .strip_prefix(quote)
            .and_then(|rest| rest.strip_suffix(quote))
        {
            return inner.to_owned();
        }
    }
    value.to_owned()
}

/// Write Caddyfile configuration
pub fn write_caddyfile(content: &str) -> Result<()> {
    ensure_caddy_dir()?;
    ensure_caddy_import()?;

    fs::write(CADDYFILE_PATH, content)
        .with_context(|| format!("Failed to write Caddyfile to {}", CADDYFILE_PATH))?;

    info!("Wrote Caddyfile configuration to {}", CADDYFILE_PATH);
    Ok(())
}

/// Remove the Keystone Caddyfile
pub fn remove_caddyfile() -> Result<()> {
    let path = Path::new(CADDYFILE_PATH);
    if path.exists() {
        fs::remove_file(path)
            .with_context(|| format!("Failed to remove Caddyfile: {}", CADDYFILE_PATH))?;
        info!("Removed Caddyfile");
    }
    Ok(())
}

/// Check if Caddy service is running
pub fn is_caddy_running() -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", "caddy"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Reload the Caddy service
pub fn reload_caddy() -> Result<()> {
    let output = Command::new("systemctl")
        .args(["reload", "caddy"])
        .output()
        .context("Failed to execute systemctl reload caddy")?;

    if output.status.success() {
        info!("Caddy reloaded successfully");
        return Ok(());
    }

    // If reload fails, try restart
    warn!("Caddy reload failed, attempting restart");
    let output = Command::new("systemctl")
        .args(["restart", "caddy"])
        .output()
        .context("Failed to execute systemctl restart caddy")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to restart Caddy: {}", stderr.trim());
    }

    info!("Caddy restarted successfully");
    Ok(())
}

/// Enable and start Caddy service
pub fn enable_caddy() -> Result<()> {
    // Enable the service
    let output = Command::new("systemctl")
        .args(["enable", "caddy"])
        .output()
        .context("Failed to enable Caddy service")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("Failed to enable Caddy: {}", stderr.trim());
    }

    // Start the service if not running
    if !is_caddy_running() {
        let output = Command::new("systemctl")
            .args(["start", "caddy"])
            .output()
            .context("Failed to start Caddy service")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to start Caddy: {}", stderr.trim());
        }
    }

    info!("Caddy service enabled and started");
    Ok(())
}

/// Disable and stop Caddy service
pub fn disable_caddy() -> Result<()> {
    // Stop the service
    let _ = Command::new("systemctl").args(["stop", "caddy"]).output();

    // Disable the service
    let output = Command::new("systemctl")
        .args(["disable", "caddy"])
        .output()
        .context("Failed to disable Caddy service")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("Failed to disable Caddy: {}", stderr.trim());
    }

    info!("Caddy service disabled and stopped");
    Ok(())
}

/// Apply Caddy configuration from database
///
/// This function:
/// 1. Loads configuration from database
/// 2. Gets the bind interface IP address
/// 3. Generates Caddyfile content
/// 4. Validates the configuration
/// 5. Writes the Caddyfile
/// 6. Reloads Caddy service
pub async fn apply_caddy_config(pool: &SqlitePool) -> Result<()> {
    let _guard = APPLY_LOCK.lock().await;
    apply_caddy_config_locked(pool).await
}

/// Whether Caddy must be re-applied because the LAN address it was configured
/// with differs from the currently assigned one. An unresolvable address
/// (interface down) never triggers a re-apply, which would fail anyway.
fn bind_ip_changed(last_applied: Option<&str>, current: Option<&str>) -> bool {
    current.is_some_and(|current| last_applied != Some(current))
}

fn read_last_bind_ip() -> Option<String> {
    std::fs::read_to_string(LAST_BIND_IP_PATH)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn store_last_bind_ip(ip: Option<&str>) {
    let result = match ip {
        Some(ip) => std::fs::write(LAST_BIND_IP_PATH, ip),
        None => match std::fs::remove_file(LAST_BIND_IP_PATH) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        },
    };
    if let Err(error) = result {
        warn!("Failed to record Caddy bind address: {error}");
    }
}

async fn reconcile(pool: &SqlitePool, last_attempt: &mut Option<String>) -> Result<()> {
    let config = load_caddy_config(pool).await?;
    if !config.enabled {
        return Ok(());
    }
    let current = lan_bind_ip(pool, &config.bind_interface).await.ok();
    if bind_ip_changed(read_last_bind_ip().as_deref(), current.as_deref()) {
        // Try each new address once so a persistent failure doesn't re-run
        // Caddy validation every few seconds; a later address change retries.
        if *last_attempt == current {
            return Ok(());
        }
        *last_attempt = current.clone();
        info!("Caddy LAN address changed to {current:?}; re-applying Caddy configuration");
        apply_caddy_config(pool).await?;
    }
    Ok(())
}

/// Periodically re-apply Caddy when the LAN address it binds to changes.
pub fn start_reconciler(pool: SqlitePool) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        let mut last_attempt = None;
        loop {
            interval.tick().await;
            if let Err(err) = reconcile(&pool, &mut last_attempt).await {
                warn!("Caddy address reconciliation: {err:#}");
            }
        }
    });
}

async fn apply_caddy_config_locked(pool: &SqlitePool) -> Result<()> {
    // Load configuration from database
    let config = load_caddy_config(pool).await?;

    // Check if Caddy is enabled
    if !config.enabled {
        info!("Caddy is disabled, removing config and stopping service");
        remove_caddyfile()?;
        disable_caddy()?;
        update_validation_status(pool, "Disabled").await?;
        store_last_bind_ip(None);
        return Ok(());
    }

    // Validate required fields
    validate_config(&config)?;
    ensure_required_dns_modules(&config)?;
    let bind_ip = Some(lan_bind_ip(pool, &config.bind_interface).await?);
    let applied_ip = bind_ip.clone();

    // Generate Caddyfile
    let content = generate_caddyfile(&config, bind_ip.as_deref());

    // Validate configuration
    let (valid, output) = validate_caddyfile(&content)?;
    if !valid {
        update_validation_status(pool, &format!("Validation failed: {}", output)).await?;
        anyhow::bail!("Caddyfile validation failed: {}", output);
    }

    // Write configuration
    write_caddyfile(&content)?;
    update_validation_status(pool, "Valid").await?;

    // Enable and reload/restart service
    enable_caddy()?;
    reload_caddy()?;
    store_last_bind_ip(applied_ip.as_deref());

    info!("Caddy configuration applied successfully");
    Ok(())
}

/// Generate a preview of the Caddyfile without applying
pub async fn preview_caddyfile(pool: &SqlitePool) -> Result<String> {
    let config = load_caddy_config(pool).await?;
    if !config.enabled {
        return Ok(generate_caddyfile(&config, None));
    }
    validate_config(&config)?;
    let bind_ip = lan_bind_ip(pool, &config.bind_interface).await?;
    Ok(generate_caddyfile(&config, Some(&bind_ip)))
}

/// Validate the current configuration from database
pub async fn validate_caddy_config(pool: &SqlitePool) -> Result<(bool, String)> {
    let config = load_caddy_config(pool).await?;

    if !config.enabled {
        return Ok((true, "Caddy is disabled".to_string()));
    }

    if config.server_address.is_empty() {
        return Ok((false, "Server address is required".to_string()));
    }

    validate_config(&config)?;
    ensure_required_dns_modules(&config)?;
    let bind_ip = lan_bind_ip(pool, &config.bind_interface).await?;
    let content = generate_caddyfile(&config, Some(&bind_ip));
    let result = validate_caddyfile(&content)?;

    // Update status in database
    let status = if result.0 {
        "Valid".to_string()
    } else {
        format!("Invalid: {}", result.1)
    };
    update_validation_status(pool, &status).await?;

    Ok(result)
}

/// Get the current Caddy service status
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CaddyServiceStatus {
    pub running: bool,
    pub enabled: bool,
    pub config_exists: bool,
}

/// Check the current status of the Caddy service
pub fn get_caddy_status() -> CaddyServiceStatus {
    let running = is_caddy_running();

    let enabled = Command::new("systemctl")
        .args(["is-enabled", "--quiet", "caddy"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    let config_exists = Path::new(CADDYFILE_PATH).exists();

    CaddyServiceStatus {
        running,
        enabled,
        config_exists,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use keystone_core::{InterfaceConfig, InterfaceRole};

    fn config_with_ports(http: u16, https: u16) -> CaddyConfig {
        CaddyConfig {
            enabled: true,
            server_address: "router.lan".into(),
            http_port: http,
            https_port: https,
            ..Default::default()
        }
    }

    #[test]
    fn input_accept_follows_enabled_state_and_https_mode() {
        let mut config = config_with_ports(80, 443);
        config.server_address = "router.lan".into();
        config.enabled = false;
        assert_eq!(input_accept(&config, "lan0".into()), None);
        config.enabled = true;
        config.https_mode = CaddyHttpsMode::SelfSigned;
        let accept = input_accept(&config, "lan0".into()).unwrap();
        assert_eq!(accept.interface, "lan0");
        assert_eq!(accept.ports, vec![80, 443]);
        config.https_mode = CaddyHttpsMode::Disabled;
        assert_eq!(
            input_accept(&config, "lan0".into()).unwrap().ports,
            vec![80]
        );
    }

    #[test]
    fn service_environment_parsing() {
        assert_eq!(
            parse_environment_file_paths(
                "/etc/caddy/dns.env (ignore_errors=no) /etc/x.env (ignore_errors=yes)"
            ),
            vec!["/etc/caddy/dns.env", "/etc/x.env"]
        );
        assert!(parse_environment_file_paths("/etc/caddy/*.env (ignore_errors=no)").is_empty());
        assert_eq!(
            parse_env_file("# c\nCF_API_TOKEN=abc\nQ=\"x y\"\nbad-name=1\n\n"),
            vec![
                ("CF_API_TOKEN".to_string(), "abc".to_string()),
                ("Q".to_string(), "x y".to_string())
            ]
        );
        assert_eq!(
            parse_environment_assignments("XDG_DATA_HOME=/var/lib \"A=b c\" T=1"),
            vec![
                ("XDG_DATA_HOME".to_string(), "/var/lib".to_string()),
                ("A".to_string(), "b c".to_string()),
                ("T".to_string(), "1".to_string())
            ]
        );
    }

    #[test]
    fn port_validation_rejects_collisions() {
        assert!(validate_ports(&config_with_ports(80, 443), Some(22)).is_ok());
        assert!(validate_ports(&config_with_ports(8443, 8443), None).is_err());
        assert!(validate_ports(&config_with_ports(0, 443), None).is_err());
        assert!(validate_ports(&config_with_ports(80, 0), None).is_err());
        assert!(validate_ports(&config_with_ports(8080, 443), None).is_err());
        assert!(validate_ports(&config_with_ports(80, 8080), None).is_err());
        assert!(validate_ports(&config_with_ports(80, 2222), Some(2222)).is_err());
        assert!(validate_ports(&config_with_ports(53, 443), None).is_err());
        assert!(validate_ports(&config_with_ports(80, 67), None).is_err());
    }

    #[test]
    fn bind_ip_change_decision() {
        assert!(bind_ip_changed(Some("192.168.1.1"), Some("10.0.0.1")));
        assert!(bind_ip_changed(None, Some("10.0.0.1")));
        assert!(!bind_ip_changed(Some("10.0.0.1"), Some("10.0.0.1")));
        assert!(!bind_ip_changed(Some("10.0.0.1"), None));
        assert!(!bind_ip_changed(None, None));
    }

    #[tokio::test]
    async fn caddy_lan_selection_reads_authoritative_interface_table() {
        let db = Database::new_in_memory().await.unwrap();
        for (name, role, enabled) in [
            ("wan0", InterfaceRole::WAN, true),
            ("lan1", InterfaceRole::LAN, true),
            ("lan0", InterfaceRole::LAN, true),
            ("down0", InterfaceRole::LAN, false),
        ] {
            db.save_interface_config(&InterfaceConfig {
                name: name.to_string(),
                role,
                enabled,
                ..Default::default()
            })
            .await
            .unwrap();
        }
        // Use the production migrations. The old `interface_configs` table
        // does not exist, so this also catches stale-schema queries.
        assert_eq!(lan_interface_name(db.pool(), "").await.unwrap(), "lan0");
        assert_eq!(lan_interface_name(db.pool(), "lan1").await.unwrap(), "lan1");
        assert!(lan_interface_name(db.pool(), "wan0").await.is_err());
        assert!(lan_interface_name(db.pool(), "down0").await.is_err());
        assert!(lan_interface_name(db.pool(), "missing").await.is_err());
    }

    #[test]
    fn caddy_prefers_global_lan_address_over_ipv4_link_local() {
        let ip_output = "    inet 169.254.41.250/16 metric 2048 brd 169.254.255.255 scope link enp2s0\n    inet 192.168.1.1/24 brd 192.168.1.255 scope global enp2s0\n";
        assert_eq!(
            parse_interface_global_ipv4(ip_output).as_deref(),
            Some("192.168.1.1")
        );
        assert!(parse_interface_global_ipv4("inet 169.254.41.250/16 scope link enp2s0").is_none());
    }

    // Run with the installed daemon unit's hardening options (see systemd-run
    // integration smoke check). This catches process-launch failures that a
    // normal unconfined root test would miss.
    #[test]
    #[ignore = "requires the caddy system user and a sandboxed root process"]
    fn caddy_validator_runs_with_service_identity() {
        let content = "http://127.0.0.1:18080 {\n    respond \"ok\"\n    log {\n        output file /var/log/caddy/keystone-access.log\n    }\n}\n";
        let (valid, message) = validate_caddyfile(content).unwrap();
        assert!(valid, "{message}");
    }

    #[test]
    fn packaged_sandbox_supports_caddy_validation_and_configuration() {
        let unit = include_str!("../../../packaging/arch/keystone-daemon.service");
        let configured_paths: Vec<&str> = unit
            .lines()
            .filter_map(|line| line.strip_prefix("ReadWritePaths="))
            .flat_map(str::split_ascii_whitespace)
            .collect();
        for path in [
            "/etc/caddy",
            "-/var/log/caddy",
            "-/var/lib/caddy",
            "-/run/caddy",
        ] {
            assert!(
                configured_paths.contains(&path),
                "missing {path} sandbox access"
            );
        }
        // Optional (-) paths are skipped when missing, so the log directory
        // must be provisioned by tmpfiles before the sandbox is built.
        let tmpfiles = include_str!("../../../packaging/arch/tmpfiles.conf");
        assert!(
            tmpfiles
                .lines()
                .any(|line| line.starts_with("d /var/log/caddy ")),
            "tmpfiles must create /var/log/caddy"
        );
        let caddy_dropin = include_str!("../../../packaging/arch/caddy.service.d/keystone.conf");
        assert!(
            caddy_dropin
                .lines()
                .any(|line| line == "LogsDirectory=caddy"),
            "caddy.service must get a writable /var/log/caddy"
        );
        assert!(unit.lines().any(|line| {
            line.strip_prefix("ConfigurationDirectory=")
                .is_some_and(|dirs| {
                    dirs.split_ascii_whitespace()
                        .any(|d| d == "caddy/Caddyfile.d")
                })
        }));
        // Rust's CommandExt::gid/uid needs these in both sets. Bounding
        // without ambient capabilities fails at setuid() with EPERM.
        for directive in ["CapabilityBoundingSet=", "AmbientCapabilities="] {
            let caps = unit
                .lines()
                .find_map(|line| line.strip_prefix(directive))
                .unwrap();
            for cap in ["CAP_SETUID", "CAP_SETGID"] {
                assert!(
                    caps.split_ascii_whitespace().any(|c| c == cap),
                    "{directive} missing {cap}"
                );
            }
        }
    }

    #[test]
    fn stock_welcome_site_is_commented_out() {
        let stock = "{\n\tadmin \"unix//run/caddy/admin.socket\"\n}\n\nhttp:// {\n\troot * /usr/share/caddy\n\tfile_server\n}\n\nimport /etc/caddy/Caddyfile.d/*\n";
        let updated = disable_stock_welcome_site(stock).unwrap();
        assert!(updated.contains("# http:// {"));
        assert!(updated.contains("# \tfile_server"));
        assert!(updated.contains("\n}\n\n# Disabled"));
        assert!(updated.contains("\nimport /etc/caddy/Caddyfile.d/*\n"));
        // Idempotent, and custom http:// sites are left alone.
        assert!(disable_stock_welcome_site(&updated).is_none());
        assert!(disable_stock_welcome_site("http:// {\n\trespond \"hi\"\n}\n").is_none());
    }

    #[test]
    fn dns_provider_detection_requires_exact_provider() {
        assert!(has_dns_provider_module(
            "tls.issuance.acme\ndns.providers.cloudflare\n",
            "cloudflare"
        ));
        assert!(!has_dns_provider_module(
            "dns.providers.cloudflare_extra\n",
            "cloudflare"
        ));
        assert!(!has_dns_provider_module(
            "dns.providers.route53\n",
            "cloudflare"
        ));
    }
}
