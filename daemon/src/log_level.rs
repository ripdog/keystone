//! Runtime-adjustable log verbosity.
//!
//! The tracing filter is installed behind a reload handle so the level chosen
//! in the web UI takes effect immediately, without restarting the daemon.

use keystone_core::LogLevel;
use std::sync::OnceLock;
use tracing_subscriber::{
    EnvFilter, Layer, Registry, fmt, layer::SubscriberExt, reload, util::SubscriberInitExt,
};

type FilterHandle = reload::Handle<EnvFilter, Registry>;

static HANDLE: OnceLock<FilterHandle> = OnceLock::new();

/// Filter directives for a level. Only the daemon's own crate and its HTTP
/// request tracing follow the setting; dependencies stay at warnings.
fn directives(level: LogLevel) -> String {
    let level = level.as_str();
    format!("warn,keystone_daemon={level},keystone_core={level},tower_http={level}")
}

/// Install the global subscriber, starting at `RUST_LOG` when set and the
/// default level otherwise. Call [`apply`] once the stored setting is known.
pub fn init() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(directives(LogLevel::default())));
    let (filter, handle) = reload::Layer::new(filter);
    // The journal stamps every line itself, and colour codes are for terminals.
    let terminal = std::io::IsTerminal::is_terminal(&std::io::stderr());
    let fmt_layer = fmt::layer().with_ansi(terminal);
    let fmt_layer = if terminal {
        fmt_layer.boxed()
    } else {
        fmt_layer.without_time().boxed()
    };
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .init();
    let _ = HANDLE.set(handle);
}

/// Switch the running daemon to `level`.
pub fn apply(level: LogLevel) {
    let Some(handle) = HANDLE.get() else {
        return;
    };
    if let Err(error) = handle.reload(EnvFilter::new(directives(level))) {
        tracing::warn!("Failed to change log level to {}: {error}", level.as_str());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_level_produces_a_valid_filter() {
        for level in LogLevel::ALL {
            EnvFilter::try_new(directives(level)).expect("directives parse");
        }
    }

    #[test]
    fn levels_round_trip_through_their_names() {
        for level in LogLevel::ALL {
            assert_eq!(level.as_str().parse::<LogLevel>(), Ok(level));
        }
        assert!("loud".parse::<LogLevel>().is_err());
    }
}
