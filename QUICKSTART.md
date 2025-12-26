# Keystone - Quick Start Guide

## Project Setup Complete! ✅

Your Keystone router/firewall manager project has been successfully initialized with a clean workspace structure.

## Project Structure

```
keystone/
├── Cargo.toml              # Workspace configuration
├── README.md               # Full project documentation
├── .gitignore             # Git ignore rules
│
├── core/                  # Shared type definitions
│   ├── Cargo.toml
│   └── src/
│       └── lib.rs         # SystemState, Interface, FirewallRule, etc.
│
├── daemon/                # Root-privileged backend
│   ├── Cargo.toml
│   └── src/
│       └── main.rs        # Unix socket server (runs as root)
│
└── web-ui/                # Unprivileged web interface
    ├── Cargo.toml
    └── src/
        ├── main.rs        # HTTP server + proxy
        ├── lib.rs         # WASM entry point
        └── app.rs         # Leptos UI components
```

## Build Status

✅ All crates compile successfully  
✅ Tests pass (2/2 in core)  
✅ Release binaries built:
- `target/release/keystone-daemon` (5.3 MB)
- `target/release/keystone-web-ui` (5.3 MB)

## Quick Commands

### Build Everything
```bash
cargo build                  # Debug build
cargo build --release        # Release build
```

### Build Individual Crates
```bash
cargo build -p keystone-core
cargo build -p keystone-daemon
cargo build -p keystone-web-ui
```

### Run Tests
```bash
cargo test --all            # All tests
cargo test -p keystone-core # Just core tests
```

### Check Code
```bash
cargo check --all           # Fast compilation check
cargo clippy --all          # Linting
```

## Running the System

### 1. Start the Daemon (as root)
```bash
sudo target/release/keystone-daemon
```

The daemon will:
- Create Unix socket at `/run/keystone.sock`
- Set permissions to 0660
- Listen for configuration requests
- Log to stdout

### 2. Start the Web UI (as regular user)
```bash
target/release/keystone-web-ui
```

The web UI will:
- Start HTTP server on `http://127.0.0.1:8080`
- Serve the web interface
- Proxy API calls to daemon

### 3. Access the Interface
Open your browser to: **http://localhost:8080**

## API Endpoints

### Daemon (Unix Socket: /run/keystone.sock)
- `GET /health` - Health check
- `GET /state` - Get current system configuration
- `POST /apply` - Apply new configuration

### Web UI (HTTP: localhost:8080)
- `GET /` - Web interface (HTML)
- `GET /health` - Health check
- `GET /api/state` - Proxied to daemon
- `POST /api/apply` - Proxied to daemon

## Dependencies Added

### Core Crate
- `serde` - Serialization
- `serde_json` - JSON support
- `thiserror` - Error handling

### Daemon Crate
- `axum` - Web framework
- `tokio` - Async runtime
- `tower` + `tower-http` - HTTP middleware
- `hyper` + `hyper-util` - HTTP primitives
- `nix` - Unix utilities (root check)
- `tracing` - Logging

### Web UI Crate
- All daemon dependencies, plus:
- `leptos` - Frontend framework
- `leptos_router` - Routing
- `leptos_meta` - Meta tags
- `leptos_axum` - Server integration
- `reqwest` - HTTP client
- `wasm-bindgen` - WASM bindings
- `console_error_panic_hook` - WASM debugging

## Current Implementation Status

### ✅ Completed
- [x] Workspace structure
- [x] Core type definitions with serialization tests
- [x] Daemon skeleton with Unix socket server
- [x] Web UI HTTP server with proxy
- [x] Leptos frontend components (basic UI)
- [x] All crates compile without errors
- [x] Documentation (README + this guide)

### 🚧 Next Steps (TODO)
- [ ] Implement system state reading (parse networkd configs, nftables)
- [ ] Implement configuration application (write configs, reload services)
- [ ] Add actual API calls in frontend (fetch/post to /api/*)
- [ ] Build WASM frontend with trunk
- [ ] Add TailwindCSS integration
- [ ] Create systemd service files
- [ ] Add comprehensive error handling
- [ ] Add validation logic
- [ ] Implement DHCP server configuration (dnsmasq)
- [ ] Add authentication/authorization

## Development Tips

### Watch Mode
```bash
# Terminal 1: Watch and rebuild on changes
cargo watch -x "build -p keystone-daemon"

# Terminal 2: Watch web-ui
cargo watch -x "build -p keystone-web-ui"
```

### Testing Without Root
The daemon requires root to run normally. For testing:
1. Comment out the root check in `daemon/src/main.rs`
2. Use a different socket path in `/tmp/`
3. Test the API with curl or similar

### WASM Development
To build the Leptos frontend as WASM:
```bash
# Install trunk
cargo install trunk

# Build WASM (from web-ui directory)
cd web-ui
trunk build
trunk serve  # Dev server with hot reload
```

## Security Notes

⚠️ **Important Security Considerations:**

1. **Daemon** runs as root - minimize attack surface
2. **Web UI** runs unprivileged - cannot modify system directly
3. **Unix Socket** permissions set to 0660 (owner + group only)
4. **No network exposure** - daemon only on Unix socket
5. **Type safety** - all IPC uses strongly-typed Serde structures
6. **Input validation** - validate all data at trust boundaries

## Troubleshooting

### "Permission denied" on socket
- Ensure daemon is running as root
- Check socket permissions: `ls -l /run/keystone.sock`
- Verify user is in correct group

### "Address already in use" (port 8080)
- Another service is using port 8080
- Change `LISTEN_ADDR` in `web-ui/src/main.rs`

### Compilation errors
- Ensure Rust toolchain is up to date: `rustup update`
- Clean build: `cargo clean && cargo build`

## Next Development Tasks

1. **System Integration**
   - Read current networkd configuration
   - Parse nftables rules
   - Execute system commands safely

2. **Frontend Enhancement**
   - Wire up API calls
   - Add form validation
   - Implement state management
   - Add loading states and error handling

3. **Configuration Management**
   - Write systemd-networkd `.network` files
   - Generate nftables configuration
   - Implement safe service reloads

4. **Deployment**
   - Create systemd service files
   - Add installation script
   - Package for Arch Linux (PKGBUILD)

## Resources

- [Leptos Documentation](https://leptos.dev/)
- [Axum Documentation](https://docs.rs/axum/)
- [systemd-networkd](https://www.freedesktop.org/software/systemd/man/systemd-networkd.html)
- [nftables Wiki](https://wiki.nftables.org/)

## License

MIT - See README.md for full license text.

---

**Project initialized successfully! Happy coding! 🚀**
