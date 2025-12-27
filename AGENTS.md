# Keystone - Agent Instructions

This document contains technical instructions for AI agents working on the Keystone project.

## Project Overview

**Keystone** is a split-privilege Linux router/firewall manager for Arch Linux written in Rust.

### Architecture

```
┌─────────────┐     HTTP      ┌─────────────┐   Unix Socket   ┌─────────────┐
│   Browser   │ ←────────────→│  Web UI     │ ←──────────────→│   Daemon    │
│   (WASM)    │  localhost:   │ (unprivileged)│  /run/keystone │   (root)    │
│             │    8080       │             │      .sock      │             │
└─────────────┘               └─────────────┘                 └─────────────┘
```

### Workspace Structure

```
keystone/
├── core/          # Shared types (Interface, FirewallRule, SystemState)
├── daemon/        # Root-privileged backend (Unix socket server)
└── web-ui/        # Unprivileged frontend (HTTP proxy + Leptos WASM)
```

## Development Commands

### Build & Test

```bash
# Build all crates
just build          # or: cargo build

# Build release
just build-release  # or: cargo build --release

# Run tests
just test           # or: cargo test --all

# Check code quality
just check          # or: cargo clippy --all-targets --all-features
```

### Run Services

```bash
# Start daemon (requires root)
just run-daemon     # or: sudo target/release/keystone-daemon

# Start web UI (unprivileged)
just run-web        # or: target/release/keystone-web-ui

# Run both (separate terminals)
just run-all

# Or test in Vagrant VM:
just vagrant-up
just vagrant-build
just vagrant-install
just vagrant-run-daemon  # Terminal 1
just vagrant-run-web     # Terminal 2
# Access at http://192.168.56.10:8080
```

### Code Quality

```bash
# Lint with clippy
just clippy         # or: cargo clippy --all-targets --all-features

# Format code
just fmt            # or: cargo fmt --all

# Check formatting
just fmt-check      # or: cargo fmt --all -- --check

# Run all checks (CI)
just ci             # clippy + fmt-check + test
```

## Coding Standards

### Rust Guidelines

1. **No Unsafe Code**: Avoid `unsafe` unless absolutely necessary and thoroughly documented
2. **Error Handling**: Use `anyhow::Result` or `thiserror` - no unwraps in production code
3. **Type Safety**: All IPC must use strongly-typed structs from `keystone-core`
4. **Async**: Use Tokio for all async operations
5. **Logging**: Use `tracing` for structured logging

### Security Requirements

1. **Privilege Separation**: Web UI must never have root access
2. **Input Validation**: Validate all data at trust boundaries (core types enforce this)
3. **Socket Permissions**: Unix socket must be 0660 (owner + group only)
4. **No Network Exposure**: Daemon only accessible via Unix socket
5. **Safe Commands**: When executing system commands, use validated inputs only

### Code Style

- **Formatting**: Use `rustfmt` with default settings
- **Linting**: All clippy warnings must be addressed
- **Documentation**: Public APIs must have doc comments
- **Tests**: Add tests for new functionality in `core/`
- Do *not* create .md files unless explicitly requested.

## Key Implementation Details

### Core Types (`keystone-core`)

All types must be:
- `Serialize + Deserialize` (Serde)
- `Clone` (for passing between components)
- `Debug` (for logging)

Critical types:
- `SystemState` - Complete router configuration
- `Interface` - Network interface config
- `FirewallRule` - nftables rule definition
- `KeystoneError` - All error types

### Daemon (`keystone-daemon`)

- **Must run as root**: Check with `nix::unistd::Uid::effective().is_root()`
- **Unix Socket**: Bind to `/run/keystone.sock`, permissions 0660
- **API Endpoints**:
  - `GET /health` - Health check
  - `GET /state` - Return current `SystemState`
  - `POST /apply` - Accept `ApplyConfigRequest`, return `ApplyConfigResponse`
- **System Integration**: Use `std::process::Command` for `nft`, `ip`, `systemctl`

### Web UI (`keystone-web-ui`)

- **Server** (`main.rs`):
  - HTTP server on `localhost:8080`
  - Proxies `/api/*` to daemon's Unix socket
  - Serves static files / WASM bundle
- **Client** (`app.rs`):
  - Leptos WASM SPA
  - Components: `InterfacesPanel`, `FirewallPanel`, `SystemSettingsPanel`
  - State management with Leptos signals

## Common Tasks

### Adding a New Core Type

1. Add struct to `core/src/lib.rs`
2. Derive `Serialize, Deserialize, Clone, Debug`
3. Add to `SystemState` if needed
4. Write serialization test
5. Update daemon API handlers
6. Update web UI components

### Adding a New API Endpoint

1. Add handler function in `daemon/src/main.rs`
2. Register route in `Router::new()`
3. Update web UI proxy if needed
4. Add corresponding frontend call in `app.rs`

### System Command Execution

```rust
use std::process::Command;
use anyhow::Context;

fn reload_networkd() -> anyhow::Result<()> {
    let output = Command::new("systemctl")
        .args(["restart", "systemd-networkd"])
        .output()
        .context("Failed to execute systemctl")?;
    
    if !output.status.success() {
        anyhow::bail!("systemctl failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    
    Ok(())
}
```

## Testing Guidelines

### Unit Tests

- Add to relevant modules with `#[cfg(test)]`
- Test serialization of all core types
- Mock system calls in daemon tests

### Integration Tests

Use Vagrant for integration testing:

```bash
# Start Vagrant VM
just vagrant-up

# Build and install
just vagrant-install

# Run integration tests
just vagrant-integration

# Access services
curl http://192.168.56.10:8080/health
curl http://192.168.56.10:8080/api/state
```

### Manual Testing

1. Start Vagrant VM: `just vagrant-up`
2. Build: `just vagrant-build`
3. Install: `just vagrant-install`
4. SSH in: `just vagrant-ssh`
5. Start services manually and test

See [VAGRANT.md](VAGRANT.md) for detailed testing scenarios.

## Dependencies

### Core Dependencies

- `serde` - Serialization
- `tokio` - Async runtime
- `axum` - Web framework
- `leptos` - Frontend framework
- `nix` - Unix utilities

### Adding Dependencies

```bash
# Add to specific crate
cargo add <package> -p keystone-core

# Add to workspace (shared)
# Edit Cargo.toml [workspace.dependencies]
```

## Troubleshooting

### Compilation Issues

1. Check Rust version: `rustc --version` (need 1.70+)
2. Clean build: `cargo clean && cargo build`
3. Update dependencies: `cargo update`

### Runtime Issues

1. **Permission denied on socket**: Daemon must run as root
2. **Address in use (8080)**: Another service using port, change `LISTEN_ADDR`
3. **Connection refused**: Ensure daemon is running before web UI

### Leptos/WASM Issues

- WASM target: `rustup target add wasm32-unknown-unknown`
- Use `trunk` for WASM builds: `cargo install trunk`
- Dev server: `trunk serve` from `web-ui/` directory

## CI/CD Pipeline

```bash
# Full CI check
just ci

# Individual steps
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
cargo build --release
```

## File Ownership & Permissions

### Daemon

- Binary: `chown root:root keystone-daemon`
- Permissions: `chmod 0750 keystone-daemon`
- Socket: Created with 0660 permissions

### Web UI

- Binary: Regular user ownership
- Permissions: `chmod 0755 keystone-web-ui`

## Deployment Considerations

### Systemd Services

Create files:
- `/etc/systemd/system/keystone-daemon.service` (runs as root)
- `/etc/systemd/system/keystone-web-ui.service` (runs as http/nobody)

### Configuration Files

- Networkd: `/etc/systemd/network/*.network`
- nftables: `/etc/nftables.conf`
- Keystone: `/etc/keystone/config.json` (future)

## Next Development Priorities

1. **System State Reading**: Parse existing networkd and nftables configs
2. **Configuration Application**: Write configs and reload services
3. **API Integration**: Wire up frontend to actual API calls
4. ~~**Authentication**: Add user authentication (future)~~ **✓ COMPLETED**
5. **HTTPS**: Add TLS support for web UI (future)

## Authentication System

Keystone now includes a JWT-based authentication system with the following features:

### Architecture

- **Password Storage**: Admin password is hashed with Argon2 and stored in `/etc/keystone/keystone.toml`
- **JWT Tokens**: The daemon issues JWTs signed with an ephemeral key (regenerated on restart)
- **Token Expiry**: Tokens are valid for 24 hours
- **Protected Endpoints**: All mutation endpoints (`/state`, `/apply`) require authentication

### Configuration File

On first run, the daemon creates `/etc/keystone/keystone.toml` with:
- Default password: `admin` (⚠️ CHANGE IMMEDIATELY IN PRODUCTION)
- Restrictive permissions: `chmod 600` (owner read/write only)

Example configuration:
```toml
admin_password_hash = "$argon2id$v=19$m=19456,t=2,p=1$..."
```

### API Endpoints

**Public Endpoints** (no authentication required):
- `GET /health` - Health check
- `POST /login` - Login with password to receive JWT token

**Protected Endpoints** (require `Authorization: Bearer <token>` header):
- `GET /state` - Retrieve current system state
- `POST /apply` - Apply new configuration

### Usage Example

```bash
# 1. Login to get token
curl -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"password": "admin"}'

# Response: {"success": true, "token": "eyJhbGc...", "message": "Login successful"}

# 2. Use token for authenticated requests
TOKEN="eyJhbGc..."
curl -X GET http://localhost:8080/api/state \
  -H "Authorization: Bearer $TOKEN"
```

### Security Features

1. **Privilege Separation**: Web UI never has root access
2. **Ephemeral Keys**: JWT signing keys are generated in-memory on daemon startup
3. **Automatic Logout**: Restarting daemon invalidates all tokens
4. **Argon2 Hashing**: Industry-standard password hashing (resistant to GPU attacks)
5. **No Network Exposure**: Daemon only accessible via Unix socket

### Changing the Admin Password

To change the admin password, manually update `/etc/keystone/keystone.toml` with a new Argon2 hash:

```bash
# Generate hash (using a tool or script)
# Then update the config file
sudo vim /etc/keystone/keystone.toml

# Restart daemon to load new config
sudo systemctl restart keystone-daemon
```

## Resources

- [Axum Documentation](https://docs.rs/axum/)
- [Leptos Book](https://leptos.dev/)
- [systemd-networkd](https://www.freedesktop.org/software/systemd/man/systemd-networkd.html)
- [nftables Wiki](https://wiki.nftables.org/)

## Version Information

- Rust Edition: 2021
- MSRV: 1.70.0
- Leptos: 0.6
- Axum: 0.7

---

**Last Updated**: 2025-12-26
**Maintained By**: Keystone Project Team
