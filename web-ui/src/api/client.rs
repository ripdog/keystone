//! HTTP client helpers for API requests
//!
//! Provides centralized request handling with consistent error handling
//! and authentication support.
//!
//! Requests that carry a JSON body go through [`call`], [`call_with`] or
//! [`call_public`], which take a typed [`Endpoint`] so the path, method,
//! request type and response type always match the daemon's route. There are
//! deliberately no helpers that accept an arbitrary `Serialize` body.

use keystone_core::api::{Endpoint, HttpMethod, render_path};
use serde::de::DeserializeOwned;

/// Prefix the web UI proxy uses for daemon routes.
const API_PREFIX: &str = "/api";

fn builder(method: HttpMethod, url: &str) -> gloo_net::http::RequestBuilder {
    match method {
        HttpMethod::Get => gloo_net::http::Request::get(url),
        HttpMethod::Post => gloo_net::http::Request::post(url),
        HttpMethod::Put => gloo_net::http::Request::put(url),
        HttpMethod::Delete => gloo_net::http::Request::delete(url),
    }
}

fn authorize(
    request: gloo_net::http::RequestBuilder,
    token: Option<&str>,
) -> gloo_net::http::RequestBuilder {
    match token {
        Some(token) => request.header("Authorization", &format!("Bearer {}", token)),
        None => request,
    }
}

async fn send<T: DeserializeOwned>(
    request: Result<gloo_net::http::Request, gloo_net::Error>,
) -> Result<T, String> {
    let response = request
        .map_err(|e| format!("Failed to build request: {}", e))?
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;
    handle_response(response).await
}

async fn call_inner<E: Endpoint>(
    token: Option<&str>,
    path: &str,
    req: &E::Request,
) -> Result<E::Response, String> {
    let body =
        serde_json::to_string(req).map_err(|e| format!("Failed to encode request: {}", e))?;
    let url = format!("{API_PREFIX}{path}");
    let request = authorize(builder(E::METHOD, &url), token)
        .header("Content-Type", "application/json")
        .body(body);
    send(request).await
}

/// Call a typed endpoint with authentication.
pub async fn call<E: Endpoint>(token: &str, req: &E::Request) -> Result<E::Response, String> {
    call_inner::<E>(Some(token), E::PATH, req).await
}

/// Call a typed endpoint whose path has `{name}` parameters.
pub async fn call_with<E: Endpoint>(
    token: &str,
    params: &[(&str, &str)],
    req: &E::Request,
) -> Result<E::Response, String> {
    call_inner::<E>(Some(token), &render_path(E::PATH, params), req).await
}

/// Call a typed endpoint without authentication (login).
pub async fn call_public<E: Endpoint>(req: &E::Request) -> Result<E::Response, String> {
    call_inner::<E>(None, E::PATH, req).await
}

/// Perform a GET request with authentication
pub async fn get<T: DeserializeOwned>(url: &str, token: &str) -> Result<T, String> {
    send(authorize(builder(HttpMethod::Get, url), Some(token)).build()).await
}

/// Perform a GET request without authentication (for public endpoints)
pub async fn get_public<T: DeserializeOwned>(url: &str) -> Result<T, String> {
    send(builder(HttpMethod::Get, url).build()).await
}

/// Perform a POST request with empty body (for apply operations)
pub async fn post_empty<T: DeserializeOwned>(url: &str, token: &str) -> Result<T, String> {
    let request = authorize(builder(HttpMethod::Post, url), Some(token))
        .header("Content-Type", "application/json")
        .body("{}");
    send(request).await
}

/// Perform a GET request with authentication and return the raw body bytes
/// (file downloads such as configuration snapshots).
pub async fn get_bytes(url: &str, token: &str) -> Result<Vec<u8>, String> {
    let response = authorize(builder(HttpMethod::Get, url), Some(token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }
    if response.ok() {
        response
            .binary()
            .await
            .map_err(|e| format!("Failed to read response: {}", e))
    } else {
        Err(read_error(response).await)
    }
}

/// Perform a POST request whose body is raw bytes (for example a `File` chosen
/// in a file input). The browser streams the file; no JSON encoding happens.
pub async fn post_raw<T: DeserializeOwned>(
    url: &str,
    token: &str,
    body: impl Into<wasm_bindgen::JsValue>,
) -> Result<T, String> {
    let request = authorize(builder(HttpMethod::Post, url), Some(token))
        .header("Content-Type", "application/octet-stream")
        .body(body);
    send(request).await
}

/// Perform a DELETE request with authentication
pub async fn delete<T: DeserializeOwned>(url: &str, token: &str) -> Result<T, String> {
    send(authorize(builder(HttpMethod::Delete, url), Some(token)).build()).await
}

/// Perform a DELETE request that returns no meaningful body
pub async fn delete_no_response(url: &str, token: &str) -> Result<(), String> {
    let response = authorize(builder(HttpMethod::Delete, url), Some(token))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if response.status() == 401 {
        return Err("Unauthorized".to_string());
    }

    if response.ok() {
        Ok(())
    } else {
        Err(read_error(response).await)
    }
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
        Err(read_error(response).await)
    }
}

async fn read_error(response: gloo_net::http::Response) -> String {
    let status = response.status();
    let reason = response.status_text();
    let body = response.text().await.unwrap_or_default();
    error_message(status, &reason, &body)
}

/// Longest plain-text error body shown to the user.
const MAX_ERROR_CHARS: usize = 500;

/// Pick the most useful text from a failed response: a JSON `message` or
/// `error` field, otherwise the trimmed plain-text body (e.g. axum's request
/// rejections), otherwise `HTTP <code> <reason>`.
fn error_message(status: u16, reason: &str, body: &str) -> String {
    let trimmed = body.trim();
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(trimmed) {
        if let Some(message) = json_message(&json) {
            return truncate(&message);
        }
        // Valid JSON without a usable message field: don't dump it raw.
        return http_status(status, reason);
    }
    if !trimmed.is_empty() && !trimmed.starts_with('<') {
        return truncate(trimmed);
    }
    http_status(status, reason)
}

/// `message`/`error` fields, plus the externally tagged `KeystoneError` shape
/// (`{"Internal": "..."}`) that older daemons returned.
fn json_message(json: &serde_json::Value) -> Option<String> {
    if let Some(message) = json.as_str() {
        return Some(message.to_string()).filter(|m| !m.trim().is_empty());
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
    .find_map(|key| json.get(key).and_then(|value| value.as_str()))
    .map(str::trim)
    .filter(|message| !message.is_empty())
    .map(str::to_string)
}

fn http_status(status: u16, reason: &str) -> String {
    format!("HTTP {status} {reason}").trim_end().to_string()
}

fn truncate(message: &str) -> String {
    if message.chars().count() <= MAX_ERROR_CHARS {
        message.to_string()
    } else {
        let cut: String = message.chars().take(MAX_ERROR_CHARS).collect();
        format!("{cut}...")
    }
}

#[cfg(test)]
mod tests {
    use super::error_message;

    #[test]
    fn prefers_json_message_or_error_field() {
        assert_eq!(
            error_message(500, "", r#"{"error":"Unsupported DHCPv6 mode"}"#),
            "Unsupported DHCPv6 mode"
        );
        assert_eq!(
            error_message(400, "", r#"{"message":"Invalid interface configuration"}"#),
            "Invalid interface configuration"
        );
        assert_eq!(
            error_message(500, "", r#"{"Internal":"legacy shape"}"#),
            "legacy shape"
        );
    }

    #[test]
    fn falls_back_to_plain_text_then_status() {
        assert_eq!(
            error_message(
                422,
                "Unprocessable Entity",
                "Failed to deserialize the JSON body: missing field `config`\n"
            ),
            "Failed to deserialize the JSON body: missing field `config`"
        );
        assert_eq!(
            error_message(503, "Service Unavailable", ""),
            "HTTP 503 Service Unavailable"
        );
        assert_eq!(
            error_message(502, "Bad Gateway", "<html>broken</html>"),
            "HTTP 502 Bad Gateway"
        );
        assert_eq!(error_message(500, "", "{}"), "HTTP 500");
    }

    #[test]
    fn truncates_long_bodies() {
        let long = "x".repeat(900);
        let message = error_message(500, "", &long);
        assert_eq!(message.chars().count(), 503);
        assert!(message.ends_with("..."));
    }
}
