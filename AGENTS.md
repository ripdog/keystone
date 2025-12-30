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
├── ctl/           # CLI tool (keystonectl) for scripting and automation
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

### Documentation-First Development

**⚠️ CRITICAL: Always consult documentation before implementing framework-specific features!**

1. **Leptos Features**: Before implementing any Leptos UI component, signal, or reactive pattern:
   - Use the `leptos-mcp-list-sections` tool to see available documentation
   - Use `leptos-mcp-get-documentation` to read relevant sections
   - Search web for "Leptos [feature] documentation" if needed
   - **Common pitfalls**:
     - `For` component reactivity requires proper key functions
     - Signal reactivity patterns (`.get()`, `.set()`, `.update()`)
     - Component lifecycle and effects

2. **Other Frameworks**: When working with unfamiliar libraries/frameworks:
   - Search official documentation first using `web_search`
   - Check for MCP tools that provide documentation access
   - Verify implementation patterns match current best practices
   - Don't assume patterns from other frameworks apply

3. **Why This Matters**:
   - Saves debugging time on subtle reactivity issues
   - Ensures idiomatic code that follows framework conventions
   - Prevents implementing workarounds for non-existent problems

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
  - **No Warning Suppression**: Do not suppress warnings with `#[allow(...)]` unless strictly necessary
  - **Dead Code**: Delete unused code rather than suppressing warnings - it can be regenerated if needed later
  - **Exceptions**: Only suppress warnings for:
    - False positives that are verifiably incorrect
    - Generated code or external macros you cannot control
    - Temporary code with immediate plans (same PR/session) to use it
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

- **User Management**: Multiple users with username, optional email, and Argon2-hashed passwords stored in SQLite database
- **JWT Tokens**: The daemon issues JWTs signed with a persistent key stored in database (survives daemon restarts)
- **Token Expiry**: Tokens are valid for 24 hours
- **Protected Endpoints**: All mutation endpoints (`/state`, `/apply`, `/users`) require authentication

### Database Storage

The daemon uses SQLite at `/var/lib/keystone/keystone.db` with tables:
- `users` - User accounts (id, username, email, password_hash, created_at)
- `jwt_key` - Persistent JWT signing key
- `managed_interfaces` - Interface configurations

### User Management

**Web UI** (Settings page):
- Add/edit/delete users with username, email (optional), and password
- Cannot delete the last user (prevents lockout)
- Password changes require entering new password
- User list updates reactively when modified

**Default User**:
- On first run, creates default user: `admin` / `admin`
- ⚠️ CHANGE IMMEDIATELY IN PRODUCTION
- Automatically migrates from old `/etc/keystone/keystone.toml` if present

### API Endpoints

**Public Endpoints** (no authentication required):
- `GET /health` - Health check
- `POST /login` - Login with username and password to receive JWT token

**Protected Endpoints** (require `Authorization: Bearer <token>` header):
- `GET /state` - Retrieve current system state
- `POST /apply` - Apply new configuration
- `GET /users` - List all users (without password hashes)
- `POST /users` - Create or update user
- `DELETE /users` - Delete user (prevents deleting last user)

### Usage Example

```bash
# 1. Login to get token
curl -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin"}'

# Response: {"success": true, "token": "eyJhbGc...", "message": "Login successful"}

# 2. Use token for authenticated requests
TOKEN="eyJhbGc..."
curl -X GET http://localhost:8080/api/state \
  -H "Authorization: Bearer $TOKEN"

# 3. Create a new user
curl -X POST http://localhost:8080/api/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "email": "alice@example.com", "password": "secure_password"}'

# 4. Update user email (password optional)
curl -X POST http://localhost:8080/api/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"id": 2, "username": "alice", "email": "alice.new@example.com"}'
```

### Security Features

1. **Privilege Separation**: Web UI never has root access
2. **Persistent Keys**: JWT signing keys stored in database, survive daemon restarts
3. **Multi-User Support**: Multiple users with unique credentials
4. **Argon2 Hashing**: Industry-standard password hashing (resistant to GPU attacks)
5. **No Network Exposure**: Daemon only accessible via Unix socket
6. **Database Security**: SQLite database at `/var/lib/keystone/keystone.db` with restricted permissions

## keystonectl - Command Line Interface

`keystonectl` provides a command-line interface for scripting and automation. It communicates directly with the daemon over the Unix socket.

### Installation & Access

In production, Keystone typically runs with a dedicated user and group:
- The daemon runs as root but sets the socket group to allow authorized access
- Add yourself to the keystone group to use keystonectl without sudo
- Or use sudo to access the socket directly

### Commands

```bash
# Check daemon health (no auth required)
keystonectl health

# Login to get a JWT token (prompts for password securely)
keystonectl login -u admin
# Token is automatically saved to ~/.local/state/keystone/token (mode 0600)
# ✓ Token saved to /home/user/.local/state/keystone/token
#   You can now run commands without specifying a token

# Get system state (automatically uses saved token)
keystonectl state

# Get dashboard with interface counters
keystonectl dashboard

# Apply configuration from file
keystonectl apply -f config.json

# Apply configuration from stdin
cat config.json | keystonectl apply

# User management (all use saved token)
keystonectl users list
keystonectl users create -U newuser -e user@example.com  # prompts for password
keystonectl users update --id 2 -U newname
keystonectl users delete --id 2

# Interface management
keystonectl interfaces list
keystonectl interfaces save -f interfaces.json

# Firewall management
keystonectl firewall zones list
keystonectl firewall zones add --name wan --interfaces eth0 --input-policy drop --forward-policy drop
keystonectl firewall zones delete --id 1

keystonectl firewall zone-forwards list
keystonectl firewall zone-forwards add --source lan --dest wan --policy accept
keystonectl firewall zone-forwards delete --id 1

keystonectl firewall port-forwards list
keystonectl firewall port-forwards add --name "SSH to server" --protocol tcp --external-port 2222 --dest-ip 192.168.1.100 --dest-port 22
keystonectl firewall port-forwards delete --id 1

keystonectl firewall input-rules list
keystonectl firewall input-rules add --name "Allow SSH" --zone lan --protocol tcp --port 22 --action accept
keystonectl firewall input-rules delete --id 1

keystonectl firewall forward-rules list
keystonectl firewall forward-rules add --name "Block traffic" --source-zone guest --dest-zone lan --action drop
keystonectl firewall forward-rules delete --id 1

keystonectl firewall preview    # Preview generated nftables ruleset
keystonectl firewall apply      # Apply firewall (60s rollback timeout)
keystonectl firewall confirm --session-id <id>  # Confirm changes
keystonectl firewall rollback   # Rollback to previous config
keystonectl firewall status     # Check pending confirmation status

# Override saved token with -t flag or KEYSTONE_TOKEN env var
export KEYSTONE_TOKEN="different_token"
keystonectl state  # uses env var
keystonectl state -t "explicit_token"  # uses -t flag
```

### JSON Output Mode

Use `--json` (or `-j`) for machine-readable output:

```bash
# Get state as raw JSON for scripting
keystonectl state --json | jq '.interfaces[].name'

# Check health in scripts
if keystonectl health --json | jq -e '.status == "healthy"' > /dev/null; then
    echo "Daemon is healthy"
fi
```

### Custom Socket Path

```bash
# Use alternate socket location
keystonectl -s /custom/path/keystone.sock health
```

### Leptos Reactivity Lessons Learned

**`For` Component Keys**: When using `<For/>` to iterate over lists where items can be updated in-place:
- The `key` function must include all fields that should trigger a re-render
- **Wrong**: `key=|user| user.id` - won't update when username/email changes
- **Correct**: `key=|user| (user.id, user.username.clone(), user.email.clone())` - updates when any field changes
- Alternative: Make individual fields reactive signals (more complex)
- See: https://book.leptos.dev/view/04b_iteration.html

## Resources

- **[Leptos Book](https://book.leptos.dev/)** - Primary reference for Leptos framework
- **[Leptos Iteration Docs](https://book.leptos.dev/view/04_iteration.html)** - For component reactivity
- [Axum Documentation](https://docs.rs/axum/)
- [systemd-networkd](https://www.freedesktop.org/software/systemd/man/systemd-networkd.html)
- [nftables Wiki](https://wiki.nftables.org/)

## Version Information

- Rust Edition: 2021
- MSRV: 1.70.0
- Leptos: 0.6
- Axum: 0.7

---

**Last Updated**: 2025-12-29
**Maintained By**: Keystone Project Team
