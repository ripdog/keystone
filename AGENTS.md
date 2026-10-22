# Keystone agent guide

Keystone is an Arch Linux router/firewall manager written in Rust (edition 2024; toolchain pinned in `rust-toolchain.toml`).

## Where to look

- `core/` — shared Serde models and API types.
- `daemon/` — root-privileged backend; Unix socket at `/run/keystone/keystone.sock`.
- `web-ui/` — unprivileged HTTP proxy and Leptos/WASM frontend.
- `ctl/` — `keystonectl` CLI, including local first-admin setup (`sudo keystonectl bootstrap-admin`).
- `justfile` — development commands; `docs/` — installation, architecture, development and VM/integration testing guides.

## Development

- `just check` — compile check; `just test` — tests; `just ci` — formatting, Clippy and tests.
- `just fmt` — format; `just run-daemon` / `just run-web` — local services.
- `just vagrant-integration` — integration tests in the Vagrant VM.
- Use debug builds for development; don't switch to release builds without a reason.
- Commit `Cargo.lock` updates for reproducible package and USB builds.

## Project rules

- Preserve privilege separation: the web UI must never run as root; the daemon is reachable only through its permission-restricted Unix socket.
- Treat all web/API input as untrusted. Validate at the daemon boundary and use typed request/response models from `core/`. Never pass unvalidated input to system commands or a shell.
- For every feature that accesses files, audit all required config, state, log, and runtime paths against the relevant systemd service sandbox (`ProtectSystem`, `ReadWritePaths`, etc.). Ensure writable paths exist before sandboxing, have correct ownership/permissions, and are tested under the service's actual restrictions.
- Add focused tests for changed behavior; keep Clippy and formatting clean.
- Don't create ancillary Markdown files unless requested.
- **Commit work autonomously**, without asking for permission, in small logical chunks with descriptive messages. Stage only files relevant to each chunk; don't include unrelated pre-existing worktree changes.
