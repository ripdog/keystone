//! Shell completion support: registration scripts and live candidates.
//!
//! Completions are dynamic (the shell calls back into `keystonectl`), which
//! handles arbitrarily nested subcommands in every shell and lets arguments
//! such as zone names complete from the running daemon.

use std::time::Duration;

use clap_complete::CompletionCandidate;
use clap_complete::engine::ArgValueCandidates;
use keystone_core::FirewallZonesResponse;

use crate::SOCKET_PATH;
use crate::client::DaemonClient;
use crate::token::load_token;

/// Completion must never hang the user's prompt.
const LOOKUP_TIMEOUT: Duration = Duration::from_millis(1500);

/// Zone names from the daemon. Silently empty if the daemon is unreachable or
/// the user is not logged in: a completion has nowhere to report errors.
pub fn zone_names() -> ArgValueCandidates {
    ArgValueCandidates::new(|| {
        fetch_zone_names()
            .unwrap_or_default()
            .into_iter()
            .map(CompletionCandidate::new)
            .collect::<Vec<_>>()
    })
}

fn fetch_zone_names() -> Option<Vec<String>> {
    let token = std::env::var("KEYSTONE_TOKEN")
        .ok()
        .filter(|t| !t.trim().is_empty())
        .or_else(|| load_token().ok())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;
    let client = DaemonClient::new(SOCKET_PATH.to_string());
    let authed = client.authed(token);
    let response: FirewallZonesResponse = runtime
        .block_on(async {
            tokio::time::timeout(
                LOOKUP_TIMEOUT,
                authed.get::<FirewallZonesResponse>("/firewall/zones"),
            )
            .await
        })
        .ok()?
        .ok()?;
    Some(response.zones.into_iter().map(|z| z.name).collect())
}

/// Write the shell hook that routes completion requests back to this binary.
pub fn write_registration(shell: clap_complete::Shell) -> std::io::Result<()> {
    let shells = clap_complete::env::Shells::builtins();
    let completer = shells
        .completer(&shell.to_string())
        .ok_or_else(|| std::io::Error::other(format!("no completer for {shell}")))?;
    completer.write_registration(
        "COMPLETE",
        "keystonectl",
        "keystonectl",
        "keystonectl",
        &mut std::io::stdout(),
    )
}
