//! HTTP client helpers for API requests
//!
//! Provides centralized request handling with consistent error handling
//! and authentication support.

use serde::{de::DeserializeOwned, Serialize};

/// Perform a GET request with authentication
pub async fn get<T: DeserializeOwned>(url: &str, token: &str) -> Result<T, String> {
    let response = gloo_net::http::Request::get(url)
        .header("Authorization", &format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    handle_response(response).await
}

/// Perform a GET request without authentication (for login, etc.)
#[allow(dead_code)]
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

/// Perform a PUT request with authentication and JSON body
#[allow(dead_code)]
pub async fn put<T: DeserializeOwned, B: Serialize>(
    url: &str,
    token: &str,
    body: &B,
) -> Result<T, String> {
    let response = gloo_net::http::Request::put(url)
        .header("Authorization", &format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(body).unwrap())
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
        Err(format!("Server error: {}", response.status()))
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
        Err(format!("Server error: {}", response.status()))
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
        Err(format!("Server error: {}", response.status()))
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
