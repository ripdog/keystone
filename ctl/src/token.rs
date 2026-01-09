use anyhow::{Context, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

/// Get the path to the token file
pub fn get_token_path() -> Result<PathBuf> {
    let state_dir = if let Ok(dir) = std::env::var("XDG_STATE_HOME") {
        PathBuf::from(dir)
    } else {
        let home = std::env::var("HOME").context("HOME environment variable not set")?;
        PathBuf::from(home).join(".local/state")
    };

    let keystone_dir = state_dir.join("keystone");
    fs::create_dir_all(&keystone_dir).context("Failed to create keystone state directory")?;

    Ok(keystone_dir.join("token"))
}

/// Save token to file with 0600 permissions
pub fn save_token(token: &str) -> Result<()> {
    let token_path = get_token_path()?;
    fs::write(&token_path, token).context("Failed to write token file")?;

    // Set permissions to 0600 (owner read/write only)
    fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600))
        .context("Failed to set token file permissions")?;

    Ok(())
}

/// Load token from file
pub fn load_token() -> Result<String> {
    let token_path = get_token_path()?;
    fs::read_to_string(&token_path)
        .context("Failed to read token file. Use 'keystonectl login' to authenticate.")
}

/// Get token from argument, environment variable, or stored file
pub fn get_token(token_arg: Option<String>) -> Result<String> {
    if let Some(token) = token_arg {
        return Ok(token);
    }

    if let Ok(token) = std::env::var("KEYSTONE_TOKEN") {
        return Ok(token);
    }

    load_token()
}
