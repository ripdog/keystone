# Keystone - Linux Router/Firewall Manager

A secure, split-privilege web interface for configuring an Arch Linux machine as a home router.

## Quick Start

```bash
# Build release
just build-release

# Terminal 1 (as root)
just run-daemon

# Terminal 2 (as user)
just run-web

# Open browser
xdg-open http://localhost:8080
```

## Features

- 🔐 **Privilege Separation**: Unprivileged web UI communicates with root daemon via Unix socket
- 🌐 **Network Management**: Configure interfaces, IP addresses, DHCP
- 🛡️ **Firewall Control**: Manage nftables rules through clean web interface  
- ⚡ **Modern Stack**: Rust + Axum + Leptos (WASM)
- 🔒 **Secure by Default**: No network exposure for privileged daemon

## Architecture

```
Browser (WASM) → Web UI (HTTP :8080) → Daemon (Unix Socket) → System
                 [unprivileged]         [root only]             [nftables, networkd]
```

## Development

```bash
just check      # Run clippy
just test       # Run tests
just fmt        # Format code
just ci         # Full CI pipeline
```

### Vagrant Testing

Isolated Arch Linux VM for safe testing:

```bash
just vagrant-up     # Start VM (auto-provisions)
just vagrant-ssh    # SSH into VM
just vagrant-build  # Build in VM
just vagrant-test   # Test in VM
```

Access web UI at: http://192.168.56.10:8080

See [VAGRANT.md](VAGRANT.md) for complete testing guide.

See [AGENTS.md](AGENTS.md) for detailed development instructions.

## Documentation

- [README.md](README.md) - This file (overview)
- [QUICKSTART.md](QUICKSTART.md) - Detailed setup guide
- [AGENTS.md](AGENTS.md) - Technical documentation for developers/AI agents
- [VAGRANT.md](VAGRANT.md) - Vagrant VM testing guide

## Requirements

- Arch Linux (or systemd-based distribution)
- Rust 1.70+
- systemd-networkd
- nftables

## License

MIT
