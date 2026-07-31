//! Configuration file handling
//!
//! Reads keystone.toml for daemon settings.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use tracing::{info, warn};

const DEFAULT_CONFIG_PATH: &str = "/etc/keystone/keystone.toml";

/// Keystone daemon configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    /// Daemon-specific settings
    #[serde(default)]
    pub daemon: DaemonConfig,
}

/// Daemon-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// Unix socket path to bind
    #[serde(default = "default_socket_path")]
    pub socket_path: String,

    /// Group name for the socket (permissions are set to socket_mode)
    #[serde(default = "default_socket_group")]
    pub socket_group: String,

    /// Socket permissions (octal, e.g. 0o660)
    #[serde(default = "default_socket_mode")]
    pub socket_mode: u32,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            socket_path: default_socket_path(),
            socket_group: default_socket_group(),
            socket_mode: default_socket_mode(),
        }
    }
}

fn default_socket_path() -> String {
    "/run/keystone/keystone.sock".to_string()
}

fn default_socket_group() -> String {
    "keystone".to_string()
}

fn default_socket_mode() -> u32 {
    0o660
}

impl Config {
    /// Load configuration from the default path
    pub fn load() -> Result<Self> {
        Self::load_from(DEFAULT_CONFIG_PATH)
    }

    /// Load configuration from a specific path
    pub fn load_from(path: &str) -> Result<Self> {
        info!("Loading configuration from {}", path);

        if !Path::new(path).exists() {
            warn!("Config file not found at {}, creating default", path);
            return Self::create_default(path);
        }

        let content =
            fs::read_to_string(path).context(format!("Failed to read config file at {}", path))?;

        let config: Config = toml::from_str(&content).context("Failed to parse config file")?;

        info!("Configuration loaded successfully");
        Ok(config)
    }

    /// Create a default configuration file
    fn create_default(path: &str) -> Result<Self> {
        warn!("Creating default config");

        let config = Config {
            daemon: DaemonConfig::default(),
        };

        // Create directory if it doesn't exist
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent).context("Failed to create config directory")?;
        }

        // Write the config file
        let toml_content = toml::to_string_pretty(&config).context("Failed to serialize config")?;

        fs::write(path, toml_content).context("Failed to write config file")?;

        // Set restrictive permissions (600 - owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .context("Failed to set config file permissions")?;
        }

        info!("Default configuration created at {}", path);
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_create_default_config() {
        let temp_dir = env::temp_dir();
        let config_path = temp_dir.join("test_keystone.toml");
        let config_path_str = config_path.to_str().unwrap();

        // Clean up if exists
        let _ = fs::remove_file(&config_path);

        let config = Config::create_default(config_path_str).unwrap();

        assert_eq!(config.daemon.socket_path, default_socket_path());
        assert!(Path::new(config_path_str).exists());

        // Clean up
        fs::remove_file(config_path_str).unwrap();
    }

    #[test]
    fn test_load_config() {
        let temp_dir = env::temp_dir();
        let config_path = temp_dir.join("test_keystone_load.toml");
        let config_path_str = config_path.to_str().unwrap();
        let test_config = Config {
            daemon: DaemonConfig::default(),
        };

        let toml_content = toml::to_string_pretty(&test_config).unwrap();
        fs::write(&config_path, toml_content).unwrap();

        // Load it back
        let loaded = Config::load_from(config_path_str).unwrap();
        assert_eq!(loaded.daemon.socket_path, default_socket_path());

        // Clean up
        fs::remove_file(config_path_str).unwrap();
    }
}
