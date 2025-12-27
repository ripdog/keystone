# Keystone Web UI

## Current Status

The web UI now has a complete login system implemented:

- Login page with password input
- Token storage in browser localStorage  
- Logout functionality
- Protected routes requiring authentication
- API integration with the daemon

## Building

### Server Binary

The server binary includes the `server` feature by default, so you can build it simply with:

```bash
cargo build -p keystone-web-ui
# or for release:
cargo build -p keystone-web-ui --release
# or using justfile:
just build-web
```

To run directly:
```bash
cargo run -p keystone-web-ui
```

### WASM Frontend

The WASM frontend is built separately without the server feature:

```bash
cd web-ui
cargo build --lib --target wasm32-unknown-unknown --release --no-default-features
```

**Note:** To properly serve the WASM app, you need to generate JavaScript bindings using a tool like `trunk` (recommended) or `wasm-bindgen`.

### Using Trunk (Recommended)

Install trunk:
```bash
cargo install trunk
```

Build and serve:
```bash
cd web-ui
trunk build --release
# Or for development with hot reload:
trunk serve
```

The built files will be in `web-ui/dist/`.

## Running

### Development Mode (with Hot Reload)

For hot-reload development, you only need **2 terminals**:

1. **Terminal 1** - Start the daemon in dev mode:
```bash
sudo just dev-daemon
# Runs on http://localhost:3000 with HTTP listener (instead of Unix socket)
```

2. **Terminal 2** - Start the frontend with hot reload:
```bash
just serve-wasm
# Runs on http://localhost:8080, proxies /api/* to the daemon
```

3. Access the UI at **http://localhost:8080**

Any changes to the frontend code will automatically rebuild and hot-reload in the browser!

### Production Mode

In production, the architecture is:
- **Daemon** listens on Unix socket only (security)
- **Web UI server** serves static files and proxies `/api/*` to the daemon

1. Build everything:
```bash
just build-wasm
just build-release
```

2. Run the daemon (as root):
```bash
sudo ./target/release/keystone-daemon
```

3. Run the web UI:
```bash
./target/release/keystone-web-ui
```

4. Access the UI at http://localhost:3000

Default login: password `admin` (change in production!)

## Architecture

- **Server** (`main.rs` with `server` feature): HTTP server that proxies API calls to daemon's Unix socket
- **Client** (`lib.rs`, app.rs): Leptos WASM application with login UI and router management interface
- **Shared** (`keystone-core`): Common types for daemon/web-ui communication

