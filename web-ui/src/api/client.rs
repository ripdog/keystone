//! HTTP client helpers for API requests
//!
//! Provides centralized request handling with consistent error handling
//! and authentication support.

use serde::{Serialize, de::DeserializeOwned};

/// Perform a GET request with authentication
pub async fn get<T: DeserializeOwned>(url: &str, token: &str) -> Result<T, String> {
    let response = gloo_net::http::Request::get(url)
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    handle_response(response).await
}

/// Perform a GET request without authentication (for public endpoints)
pub async fn get_public<T: DeserializeOwned>(url: &str) -> Result<T, String> {
    let response = gloo_net::http::Request::get(url)
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    handle_response(response).await
}

/// Perform a POST request with authentication and JSON body
pub async fn post<T: DeserializeOwned, B: Serialize>(
    url: &str,
    token: &str,
    body: &B,
) -> Result<T, String> {
    let response = gloo_net::http::Request::post(url)
        .header("Authorization", &format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(body).unwrap())
        .map_err(|e| format!("Failed to build request: {}", e))?
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    handle_response(response).await
}

/// Perform a POST request without authentication (for login)
pub async fn post_public<T: DeserializeOwned, B: Serialize>(
    url: &str,
    body: &B,
) -> Result<T, String> {
    let response = gloo_net::http::Request::post(url)
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(body).unwrap())
        .map_err(|e| format!("Failed to build request: {}", e))?
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    handle_response(response).await
}

/// Perform a POST request with empty body (for apply operations)
pub async fn post_empty<T: DeserializeOwned>(url: &str, token: &str) -> Result<T, String> {
    let response = gloo_net::http::Request::post(url)
        .header("Authorization", &format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body("{}")
        .map_err(|e| format!("Failed to build request: {}", e))?
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    handle_response(response).await
}

/// Perform a PUT request that returns no meaningful body (just success/failure)
pub async fn put_no_response<B: Serialize>(url: &str, token: &str, body: &B) -> Result<(), String> {
    let response = gloo_net::http::Request::put(url)
        .header("Authorization", &format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(body).unwrap())
        .map_err(|e| format!("Failed to build request: {}", e))?
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        Ok(())
    } else {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        Err(error_message(status, &body))
    }
}

/// Perform a DELETE request with authentication
pub async fn delete<T: DeserializeOwned>(url: &str, token: &str) -> Result<T, String> {
    let response = gloo_net::http::Request::delete(url)
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    handle_response(response).await
}

/// Perform a DELETE request that returns no meaningful body
pub async fn delete_no_response(url: &str, token: &str) -> Result<(), String> {
    let response = gloo_net::http::Request::delete(url)
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        Ok(())
    } else {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        Err(error_message(status, &body))
    }
}

/// Perform a DELETE request with a JSON body
pub async fn delete_with_body<T: DeserializeOwned, B: Serialize>(
    url: &str,
    token: &str,
    body: &B,
) -> Result<T, String> {
    let response = gloo_net::http::Request::delete(url)
        .header("Authorization", &format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(body).unwrap())
        .map_err(|e| format!("Failed to build request: {}", e))?
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    handle_response(response).await
}

/// Handle response parsing and error checking
async fn handle_response<T: DeserializeOwned>(
    response: gloo_net::http::Response,
) -> Result<T, String> {
    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    } else {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        Err(error_message(status, &body))
    }
}

/// Extract the meaningful error text returned by the daemon, not just HTTP 500.
/// KeystoneError currently serializes as a tagged object: {"Internal":"..."}.
fn error_message(status: u16, body: &str) -> String {
    let detail = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|json| {
            if let Some(message) = json.as_str() {
                return Some(message.to_string());
            }
            [
                "message",
                "error",
                "Internal",
                "Validation",
                "InvalidInput",
                "InvalidConfig",
                "SystemCommandFailed",
                "NotFound",
                "PermissionDenied",
            ]
            .into_iter()
            .find_map(|key| {
                json.get(key)
                    .and_then(|value| value.as_str())
                    .map(str::to_string)
            })
        })
        .filter(|message| !message.trim().is_empty());
    match detail {
        Some(message) => format!("Server error ({status}): {message}"),
        None => format!("Server error ({status})"),
    }
}

#[cfg(test)]
mod tests {
    use super::error_message;

    #[test]
    fn displays_daemon_validation_errors() {
        assert_eq!(
            error_message(500, r#"{"Internal":"Unsupported DHCPv6 WithoutRA mode"}"#),
            "Server error (500): Unsupported DHCPv6 WithoutRA mode"
        );
        assert_eq!(
            error_message(400, r#"{"message":"Invalid interface configuration"}"#),
            "Server error (400): Invalid interface configuration"
        );
        assert_eq!(
            error_message(503, "<html>broken</html>"),
            "Server error (503)"
        );
    }
}

/// Common response type for save operations that return an ID
#[derive(serde::Deserialize)]
pub struct SaveIdResponse {
    pub success: bool,
    pub message: String,
    pub id: Option<i64>,
}

/// Extract ID from a save response, returning error if not successful
pub fn extract_id(response: SaveIdResponse) -> Result<i64, String> {
    if response.success {
        Ok(response.id.unwrap_or(0))
    } else {
        Err(response.message)
    }
}
