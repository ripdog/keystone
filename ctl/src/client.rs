use anyhow::{Context, Result};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::net::UnixStream;

/// HTTP client for Unix socket communication
pub struct DaemonClient {
    socket_path: String,
}

pub struct AuthedDaemonClient<'a> {
    client: &'a DaemonClient,
    token: String,
}

impl DaemonClient {
    pub fn new(socket_path: String) -> Self {
        Self { socket_path }
    }

    pub fn authed(&self, token: String) -> AuthedDaemonClient<'_> {
        AuthedDaemonClient {
            client: self,
            token,
        }
    }

    async fn request<T: DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        body: Option<&impl Serialize>,
        token: Option<&str>,
    ) -> Result<T> {
        // Connect to Unix socket
        let stream = UnixStream::connect(&self.socket_path)
            .await
            .with_context(|| format!("Failed to connect to daemon at {}", self.socket_path))?;

        let io = TokioIo::new(stream);

        // Create HTTP/1 connection
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .context("Failed to establish HTTP connection")?;

        // Spawn connection handler
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                eprintln!("Connection error: {}", e);
            }
        });

        // Build request
        let body_bytes = match body {
            Some(b) => serde_json::to_vec(b).context("Failed to serialize request body")?,
            None => Vec::new(),
        };

        let mut req_builder = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header("Content-Type", "application/json");

        if let Some(t) = token {
            req_builder = req_builder.header("Authorization", format!("Bearer {}", t));
        }

        let req = req_builder
            .body(Full::new(Bytes::from(body_bytes)))
            .context("Failed to build request")?;

        // Send request
        let response = sender
            .send_request(req)
            .await
            .context("Failed to send request to daemon")?;

        let status = response.status();
        let body_bytes = response
            .into_body()
            .collect()
            .await
            .context("Failed to read response body")?
            .to_bytes();

        if !status.is_success() {
            let error_msg = String::from_utf8_lossy(&body_bytes);
            anyhow::bail!("Request failed with status {}: {}", status, error_msg);
        }

        serde_json::from_slice(&body_bytes).context("Failed to parse response JSON")
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str, token: Option<&str>) -> Result<T> {
        self.request::<T>("GET", path, None::<&()>, token).await
    }

    pub async fn post<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &impl Serialize,
        token: Option<&str>,
    ) -> Result<T> {
        self.request("POST", path, Some(body), token).await
    }

    pub async fn delete<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &impl Serialize,
        token: Option<&str>,
    ) -> Result<T> {
        self.request("DELETE", path, Some(body), token).await
    }
}

impl<'a> AuthedDaemonClient<'a> {
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.client.get(path, Some(&self.token)).await
    }

    pub async fn post<T: DeserializeOwned>(&self, path: &str, body: &impl Serialize) -> Result<T> {
        self.client.post(path, body, Some(&self.token)).await
    }

    pub async fn delete<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> Result<T> {
        self.client.delete(path, body, Some(&self.token)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authed_client_retains_token() {
        let client = DaemonClient::new("/nope".to_string());
        let authed = client.authed("abc123".to_string());
        assert_eq!(authed.token, "abc123");
    }
}
