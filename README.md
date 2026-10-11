# Keystone

Keystone is a web-based router and firewall manager for **Arch Linux**. It provides a browser UI and command-line tooling for managing a dedicated Linux router without exposing its privileged management daemon directly to the network.

> **Status:** In development. Network and firewall changes can disconnect a router. Test on a spare machine or VM and maintain console access while configuring a real router.

## Features

- **Networking:** Configure WAN and LAN interfaces using systemd-networkd, including IPv4, IPv6, DHCP, and IPv6 prefix delegation.
- **Firewall:** Manage nftables rules, NAT, and IPv4/IPv6 port forwarding.
- **Services:** Configure dnsmasq for DNS/DHCP, Caddy for HTTPS, and OpenSSH access on the router.
- **Monitoring:** Inspect interface state, traffic counters, and WAN gateway reachability.
- **First-run setup:** Interactive `keystonectl setup` wizard and local administrator creation.

## Security model

Keystone has three components:

```text
Browser ──HTTP(S)──> keystone-web-ui (unprivileged)
                                  │
                       permission-restricted Unix socket
                                  │
                          keystone-daemon (root)
                                  │
                      networkd / nftables / services
```

The daemon listens on a Unix socket at `/run/keystone/keystone.sock`, **not** a public HTTP port. The web service listens on port **8080**, restricted to loopback and configured LAN addresses (never WAN). An optional Caddy reverse proxy can provide HTTPS.

There is **no default administrator password or remote bootstrap account**. Create the initial administrator locally at the console.

## Installation

Keystone currently targets Arch Linux with systemd. Runtime services include **systemd-networkd, nftables, and dnsmasq**; Caddy and OpenSSH integration are optional. The repository contains an Arch `PKGBUILD`, service definitions in `packaging/arch/`, and an image-building script at `scripts/create-keystone-usb.sh` for a dedicated router.

For a development build, install Rust (see `rust-toolchain.toml` when present), the `wasm32-unknown-unknown` target, [Trunk](https://trunkrs.dev/), and the system SQLite development library. Then build both the native binaries and the browser frontend:

```bash
cargo build --workspace
(cd web-ui && trunk build)
```

The three native executables are `target/debug/keystone-daemon`, `target/debug/keystone-web-ui`, and `target/debug/keystonectl`. The frontend is generated in `web-ui/dist/`.

### Initial setup

On a **dedicated test/router machine**, from the repository root:

1. Create an administrator locally:
   ```bash
   sudo target/debug/keystonectl bootstrap-admin
   ```
2. Start the daemon (in a separate terminal):
   ```bash
   sudo target/debug/keystone-daemon
   ```
3. Run the interactive router configuration wizard:
   ```bash
   sudo target/debug/keystonectl setup
   ```
4. Start the unprivileged web server (in another terminal):
   ```bash
   KEYSTONE_DIST_DIR="$PWD/web-ui/dist" target/debug/keystone-web-ui
   ```

Open `http://127.0.0.1:8080` on the router, or `http://<router-LAN-address>:8080` from a LAN device, and log in with the account you created. For installed packages, use the supplied systemd services instead of starting processes manually.

**Do not perform initial network configuration over your only SSH connection.** Apply networking and firewall changes with console access available.

## Development

```bash
just check       # Cargo compile checks
just test        # Rust tests
just fmt-check   # Rust formatting check
just ci          # Formatting, Clippy, and tests
```

`just build` builds native binaries; building the frontend also requires `trunk build` in `web-ui/`. The `justfile` and [VAGRANT.md](VAGRANT.md) contain developer and VM-testing commands. [AGENTS.md](AGENTS.md) describes the repository layout and coding rules.

## License

Keystone is licensed under the **GNU General Public License version 3.0 only** (`GPL-3.0-only`). See [LICENSE](LICENSE) for the complete license.
