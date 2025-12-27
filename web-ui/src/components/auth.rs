//! Authentication utilities

const TOKEN_KEY: &str = "keystone_auth_token";

/// Get the stored auth token from localStorage
pub fn get_stored_token() -> Option<String> {
    let window = web_sys::window()?;
    let storage = window.local_storage().ok()??;
    storage.get_item(TOKEN_KEY).ok()?
}

/// Store the auth token in localStorage
pub fn set_stored_token(token: &str) {
    if let Some(window) = web_sys::window()
        && let Ok(Some(storage)) = window.local_storage()
    {
        let _ = storage.set_item(TOKEN_KEY, token);
    }
}

/// Clear the stored auth token
pub fn clear_stored_token() {
    if let Some(window) = web_sys::window()
        && let Ok(Some(storage)) = window.local_storage()
    {
        let _ = storage.remove_item(TOKEN_KEY);
    }
}
