//! Configuration file handling
//!
//! Reads keystone.toml which contains the admin password hash.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use tracing::{info, warn};

const DEFAULT_CONFIG_PATH: &str = "/etc/keystone/keystone.toml";

/// Keystone daemon configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Admin password hash (Argon2)
    pub admin_password_hash: String,
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

    /// Create a default configuration file with a default password
    fn create_default(path: &str) -> Result<Self> {
        use argon2::{
            Argon2,
            password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
        };

        warn!("Creating default config with password 'admin' - CHANGE THIS IMMEDIATELY!");

        // Hash the default password "admin"
        let password = "admin";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("Failed to hash default password: {}", e))?
            .to_string();

        let config = Config {
            admin_password_hash: hash,
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

        assert!(!config.admin_password_hash.is_empty());
        assert!(Path::new(config_path_str).exists());

        // Clean up
        fs::remove_file(config_path_str).unwrap();
    }

    #[test]
    fn test_load_config() {
        use argon2::{
            Argon2,
            password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
        };

        let temp_dir = env::temp_dir();
        let config_path = temp_dir.join("test_keystone_load.toml");
        let config_path_str = config_path.to_str().unwrap();
        // Create a test config
        let password = "test123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        let test_config = Config {
            admin_password_hash: hash.clone(),
        };

        let toml_content = toml::to_string_pretty(&test_config).unwrap();
        fs::write(&config_path, toml_content).unwrap();

        // Load it back
        let loaded = Config::load_from(config_path_str).unwrap();
        assert_eq!(loaded.admin_password_hash, hash);

        // Clean up
        fs::remove_file(config_path_str).unwrap();
    }
}
