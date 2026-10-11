# Keystone web UI

Keystone's web component consists of an unprivileged Rust HTTP server and a Leptos/WASM frontend.

## Build

From the repository root, build the native server and CLI:

```bash
cargo build --workspace
```

Build the browser frontend with [Trunk](https://trunkrs.dev/):

```bash
rustup target add wasm32-unknown-unknown
(cd web-ui && trunk build)
```

The static frontend is output to `web-ui/dist/`. Run the server alongside a running Keystone daemon:

```bash
KEYSTONE_DIST_DIR="$PWD/web-ui/dist" target/debug/keystone-web-ui
```

The HTTP server listens only on loopback and configured LAN addresses on port 8080, and proxies API requests to the root daemon over a permission-restricted Unix socket. There is no default login: create an administrator locally using `sudo keystonectl bootstrap-admin` (or `sudo target/debug/keystonectl bootstrap-admin` for a development build).

See the [top-level README](../README.md) for initial setup, security model, and testing.
