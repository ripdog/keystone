//! A minimal HTTP/1.1 client for Blocky's API on loopback.
//!
//! Blocky's API is bound to `127.0.0.1` only and has no authentication, so it
//! is reachable only from this host. Every request has a timeout.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use keystone_core::blocky::BlockyBlockingStatus;
use serde::Deserialize;
use tokio::net::TcpStream;

use super::config::BLOCKY_HTTP_PORT;

/// Ordinary calls, such as status, enable and disable.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// List refresh downloads every list, so it can take much longer.
const REFRESH_TIMEOUT: Duration = Duration::from_secs(120);

/// The body of `GET /api/blocking/status`. Other fields are ignored.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BlockingStatusBody {
    enabled: bool,
    #[serde(default)]
    auto_enable_in_sec: u64,
}

/// Blocking state: enabled, and seconds until a pause ends.
pub async fn blocking_status() -> Result<BlockyBlockingStatus> {
    let body = request("GET", "/api/blocking/status", REQUEST_TIMEOUT).await?;
    let status: BlockingStatusBody =
        serde_json::from_slice(&body).context("Blocky returned an unexpected blocking status")?;
    Ok(BlockyBlockingStatus {
        enabled: status.enabled,
        auto_enable_in_secs: status.auto_enable_in_sec,
    })
}

pub async fn enable_blocking() -> Result<()> {
    request("GET", "/api/blocking/enable", REQUEST_TIMEOUT).await?;
    Ok(())
}

/// Pause blocking for `minutes`. The caller checks the range.
pub async fn disable_blocking(minutes: u32) -> Result<()> {
    let path = format!("/api/blocking/disable?duration={minutes}m");
    request("GET", &path, REQUEST_TIMEOUT).await?;
    Ok(())
}

pub async fn refresh_lists() -> Result<()> {
    request("POST", "/api/lists/refresh", REFRESH_TIMEOUT).await?;
    Ok(())
}

pub async fn flush_cache() -> Result<()> {
    request("POST", "/api/cache/flush", REQUEST_TIMEOUT).await?;
    Ok(())
}

async fn request(method: &str, path: &str, timeout: Duration) -> Result<Vec<u8>> {
    match tokio::time::timeout(timeout, send(method, path)).await {
        Ok(result) => result,
        Err(_) => bail!("Blocky's API did not answer within {}s", timeout.as_secs()),
    }
}

async fn send(method: &str, path: &str) -> Result<Vec<u8>> {
    let stream = TcpStream::connect(("127.0.0.1", BLOCKY_HTTP_PORT))
        .await
        .context("could not connect to Blocky's API")?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        // The connection ends when the response has been read; errors after
        // that do not matter.
        let _ = connection.await;
    });

    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("Host", "127.0.0.1")
        .body(Empty::<Bytes>::new())?;
    let response = sender.send_request(request).await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    if !status.is_success() {
        bail!("Blocky's API answered {status} for {path}");
    }
    Ok(body.to_vec())
}
