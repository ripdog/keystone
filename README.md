# Keystone - Linux Router/Firewall Manager

A secure, split-privilege web interface for configuring an Arch Linux machine as a home router.

## Architecture

Keystone uses a **strict separation of privileges** between the unprivileged web frontend and the privileged system daemon:

```
┌─────────────────────────────────────────────────────────────┐
│                         Browser                              │
│              (Leptos WASM Single Page App)                   │
└──────────────────────┬──────────────────────────────────────┘
                       │ HTTP (localhost:8080)
┌──────────────────────▼──────────────────────────────────────┐
│                   Web UI (Unprivileged)                      │
│              Axum Server + Static Files                      │
└──────────────────────┬──────────────────────────────────────┘
                       │ Unix Domain Socket (/run/keystone.sock)
┌──────────────────────▼──────────────────────────────────────┐
│                  Daemon (Root Privileges)                    │
│         System Mutations (nftables, networkd, etc.)          │
└─────────────────────────────────────────────────────────────┘
```

## Project Structure

```
keystone/
├── core/           # Shared type definitions (structs, enums)
├── daemon/         # Privileged backend (runs as root)
└── web-ui/         # Unprivileged web server + WASM frontend
```

### Core (`keystone-core`)

The shared library containing all type definitions:
- `Interface` - Network interface configuration
- `FirewallRule` - nftables firewall rules
- `SystemState` - Complete router configuration
- All types are `Serialize + Deserialize` for type-safe IPC

### Daemon (`keystone-daemon`)

The privileged backend service:
- **Runs as:** `root`
- **Listens on:** Unix Domain Socket at `/run/keystone.sock`
- **Responsibilities:**
  - Read current system state
  - Apply configuration changes
  - Manage systemd-networkd
  - Configure nftables firewall
  - Control system services

**API Endpoints:**
- `GET /state` - Retrieve current system configuration
- `POST /apply` - Apply new configuration
- `GET /health` - Health check

### Web UI (`keystone-web-ui`)

The unprivileged web interface:
- **Runs as:** Regular user (e.g., `nobody` or `http`)
- **Listens on:** `http://127.0.0.1:8080`
- **Components:**
  - **Server:** Axum HTTP server that proxies API calls to daemon
  - **Client:** Leptos WASM SPA running in browser

## Technology Stack

- **Language:** Rust 2021 Edition
- **Frontend:** Leptos (compiles to WASM)
- **Backend:** Axum (async web framework)
- **Runtime:** Tokio (async runtime)
- **Serialization:** Serde (JSON)
- **System Tools:** nftables, systemd-networkd, dnsmasq

## Building

### Prerequisites

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add WASM target
rustup target add wasm32-unknown-unknown

# Install trunk (for building WASM frontend)
cargo install trunk
```

### Build All Crates

```bash
# Build everything
cargo build --release

# Or build individually
cargo build -p keystone-core
cargo build -p keystone-daemon --release
cargo build -p keystone-web-ui --release
```

### Development

```bash
# Run daemon (requires root)
sudo target/release/keystone-daemon

# Run web UI (in another terminal)
target/release/keystone-web-ui

# Visit http://localhost:8080
```

## Security Model

### Privilege Separation

1. **Web UI** runs as unprivileged user
   - Cannot modify system configuration directly
   - Can only communicate via Unix socket

2. **Daemon** runs as root
   - Only accessible via Unix socket (no network exposure)
   - Socket permissions: 0660 (owner + group only)
   - Validates all input using strongly-typed requests

### Communication Flow

```
User Input → Browser (WASM) → HTTP Request → Web UI Server 
  → Unix Socket → Daemon → System Changes
```

All data is validated at each boundary using shared types from `keystone-core`.

## Configuration

### System Requirements

- **OS:** Arch Linux (or compatible systemd-based distro)
- **Required packages:**
  - `systemd` (with systemd-networkd)
  - `nftables`
  - `dnsmasq` (optional, for DHCP)

### Deployment

1. Build release binaries
2. Install systemd service files
3. Configure socket permissions
4. Enable and start services

```bash
# Example systemd service
sudo systemctl enable keystone-daemon
sudo systemctl start keystone-daemon
sudo systemctl enable keystone-web-ui
sudo systemctl start keystone-web-ui
```

## Development Status

🚧 **Current Status:** Initial setup complete

- [x] Workspace structure
- [x] Core type definitions
- [x] Daemon skeleton (Unix socket server)
- [x] Web UI skeleton (HTTP proxy + WASM frontend)
- [ ] System state reading (networkd, nftables)
- [ ] Configuration application
- [ ] WASM frontend integration
- [ ] TailwindCSS styling
- [ ] Systemd service files

## Contributing

This is a security-focused project. Please ensure:
- No `unsafe` code without thorough justification
- All errors are properly handled (no unwraps in production code)
- Input validation at all trust boundaries
- Comprehensive testing

## License

MIT

## Authors

Keystone Project Team
