//! Unprivileged frontend server. Listens only on loopback and actual LAN IPs.

#[cfg(feature = "server")]
use axum::{
    Router,
    body::Body,
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{any, get},
};
#[cfg(feature = "server")]
use http_body_util::BodyExt;
#[cfg(feature = "server")]
use hyper_util::rt::TokioIo;
#[cfg(feature = "server")]
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};
#[cfg(feature = "server")]
use tokio::{
    net::{TcpListener, UnixStream},
    task::JoinHandle,
    time::{self, Duration},
};
#[cfg(feature = "server")]
use tower_http::services::{ServeDir, ServeFile};
#[cfg(feature = "server")]
use tracing::{error, info, warn};

#[cfg(feature = "server")]
const DAEMON_SOCKET: &str = "/run/keystone/keystone.sock";
#[cfg(feature = "server")]
const HTTP_PORT: u16 = 8080;

#[cfg(feature = "server")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "keystone_web_ui=info,tower_http=info".into()),
        )
        .init();

    let exe_path = std::env::current_exe()?;
    let exe_dir = exe_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("No executable directory"))?;
    let dist_dir = std::env::var("KEYSTONE_DIST_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| exe_dir.join("dist"));

    let app = build_router(&dist_dir);

    // Never bind a wildcard socket, not even temporarily. Reconcile numeric
    // addresses so DHCP renewals, interface role changes and configured VLANs
    // are reflected without restarting the web process.
    let mut listeners: HashMap<SocketAddr, JoinHandle<()>> = HashMap::new();
    let mut interval = time::interval(Duration::from_secs(5));
    loop {
        interval.tick().await;
        let desired = match fetch_lan_bind_addresses().await {
            Ok(addresses) => addresses,
            Err(e) => {
                warn!("Cannot refresh LAN bindings: {e}");
                // Fail closed on role-discovery failures. Keep loopback usable.
                loopback_addresses()
            }
        };

        for address in listeners.keys().copied().collect::<Vec<_>>() {
            if !desired.contains(&address)
                && let Some(handle) = listeners.remove(&address)
            {
                handle.abort();
                info!("Unbound HTTP listener {address}");
            }
        }
        for address in desired {
            if listeners.contains_key(&address) {
                continue;
            }
            match TcpListener::bind(address).await {
                Ok(listener) => {
                    let router = app.clone();
                    let handle = tokio::spawn(async move {
                        if let Err(err) = axum::serve(listener, router).await {
                            error!("HTTP server on {address} exited: {err}");
                        }
                    });
                    listeners.insert(address, handle);
                    info!("Serving Keystone on {address}");
                }
                Err(e) => warn!("Unable to bind {address}: {e}"),
            }
        }
    }
}

/// Serve real assets normally, but return the SPA entry point for client-side
/// routes such as /interfaces/enp3s0. The API and health routes take priority.
#[cfg(feature = "server")]
fn build_router(dist_dir: &std::path::Path) -> Router {
    Router::new()
        .route("/api/{*path}", any(proxy_to_daemon))
        .route("/health", get(health_check))
        .fallback_service(
            ServeDir::new(dist_dir).fallback(ServeFile::new(dist_dir.join("index.html"))),
        )
}

#[cfg(feature = "server")]
fn loopback_addresses() -> HashSet<SocketAddr> {
    [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), HTTP_PORT),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), HTTP_PORT),
    ]
    .into_iter()
    .collect()
}

#[cfg(feature = "server")]
fn addresses_to_bind(addrs: &[String]) -> HashSet<SocketAddr> {
    let mut result = loopback_addresses();
    for candidate in addrs {
        if let Ok(ip) = candidate.parse::<IpAddr>() {
            // Never permit wildcard/multicast or unscoped link-local sockets.
            if ip.is_unspecified()
                || ip.is_multicast()
                || matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local())
            {
                continue;
            }
            result.insert(SocketAddr::new(ip, HTTP_PORT));
        }
    }
    result
}

#[cfg(feature = "server")]
async fn fetch_lan_bind_addresses() -> anyhow::Result<HashSet<SocketAddr>> {
    let stream = UnixStream::connect(DAEMON_SOCKET).await?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            error!("Daemon connection error: {e}");
        }
    });

    let req = Request::builder()
        .uri("/lan-bind-addresses")
        .header("Host", "localhost")
        .body(Body::empty())?;
    let response = sender.send_request(req).await?;
    if !response.status().is_success() {
        anyhow::bail!("Daemon LAN query failed: {}", response.status());
    }
    let body = response.into_body().collect().await?.to_bytes();
    let payload: keystone_core::LanBindAddressesResponse = serde_json::from_slice(&body)?;
    Ok(addresses_to_bind(&payload.addresses))
}

#[cfg(feature = "server")]
async fn health_check() -> impl IntoResponse {
    axum::Json(serde_json::json!({"status":"healthy", "service":"keystone-web-ui"}))
}

#[cfg(feature = "server")]
async fn proxy_to_daemon(req: Request) -> Result<Response, StatusCode> {
    // Keep the query string: several daemon endpoints require it.
    let uri = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let path = uri.strip_prefix("/api").unwrap_or(uri).to_string();

    let stream = UnixStream::connect(DAEMON_SOCKET).await.map_err(|e| {
        error!("Failed to connect to daemon socket: {e}");
        StatusCode::BAD_GATEWAY
    })?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            error!("Daemon connection error: {e}");
        }
    });

    let (parts, body) = req.into_parts();
    let mut builder = Request::builder()
        .method(parts.method)
        .uri(path)
        .version(parts.version);
    for (key, value) in &parts.headers {
        if key != axum::http::header::HOST {
            builder = builder.header(key, value);
        }
    }
    let new_req = builder
        .header("Host", "localhost")
        .body(body)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let response = sender
        .send_request(new_req)
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    Ok(response.map(Body::new))
}

#[cfg(all(test, feature = "server"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn deep_links_serve_spa_without_breaking_assets_or_health() {
        use tower::ServiceExt;

        let dist =
            std::env::temp_dir().join(format!("keystone-web-router-test-{}", std::process::id()));
        std::fs::create_dir_all(&dist).unwrap();
        std::fs::write(dist.join("index.html"), "<html>Keystone app</html>").unwrap();
        std::fs::write(dist.join("app.js"), "console.log('app');").unwrap();
        let router = build_router(&dist);

        for path in ["/", "/interfaces", "/interfaces/enp3s0", "/status"] {
            let response = router
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(&body[..], b"<html>Keystone app</html>", "{path}");
        }
        let asset = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/app.js")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(asset.status(), StatusCode::OK);
        assert_eq!(
            &asset.into_body().collect().await.unwrap().to_bytes()[..],
            b"console.log('app');"
        );

        let health = router
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);
        std::fs::remove_dir_all(&dist).unwrap();
    }

    #[test]
    fn only_specific_lan_addresses() {
        let bindings = addresses_to_bind(&[
            "192.168.1.1".into(),
            "fd00::1".into(),
            "0.0.0.0".into(),
            "::".into(),
            "fe80::1".into(),
        ]);
        assert!(bindings.contains(&"192.168.1.1:8080".parse().unwrap()));
        assert!(bindings.contains(&"[fd00::1]:8080".parse().unwrap()));
        assert!(bindings.contains(&"127.0.0.1:8080".parse().unwrap()));
        assert!(!bindings.contains(&"0.0.0.0:8080".parse().unwrap()));
        assert!(!bindings.contains(&"[::]:8080".parse().unwrap()));
        assert!(!bindings.contains(&"[fe80::1]:8080".parse().unwrap()));
    }
}
