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

### Quick Start

1. Build the WASM frontend (one-time):
```bash
cd web-ui
~/.cargo/bin/trunk build --release
cd ..
```

2. Start the web UI server:
```bash
cargo run -p keystone-web-ui
# or
./target/release/keystone-web-ui
```

3. Access the UI at http://localhost:8080

**Note:** The daemon must be running for API calls to work. Start it with:
```bash
sudo ./target/release/keystone-daemon
```

Default login: password `admin` (change in production!)

## Architecture

- **Server** (`main.rs` with `server` feature): HTTP server that proxies API calls to daemon's Unix socket
- **Client** (`lib.rs`, app.rs): Leptos WASM application with login UI and router management interface
- **Shared** (`keystone-core`): Common types for daemon/web-ui communication

