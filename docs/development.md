# Development

See [architecture.md](architecture.md) for how the pieces fit together and [AGENTS.md](../AGENTS.md) for the project rules (privilege separation, input validation, sandbox audits, tests).

## Toolchain

The Rust toolchain is pinned in [`rust-toolchain.toml`](../rust-toolchain.toml) (with `clippy`, `rustfmt` and the `wasm32-unknown-unknown` target), so `rustup` installs it on first use. You also need:

- [Trunk](https://trunkrs.dev/) (CI uses 0.21.14) to build the frontend; it downloads the Tailwind CLI itself.
- The system SQLite library (`sqlite` on Arch, `libsqlite3-dev` on Debian/Ubuntu); Keystone links to it rather than bundling its own.
- [`just`](https://github.com/casey/just) for the shortcuts below.

Use debug builds during development.

## Everyday commands

```bash
just check        # cargo check --all
just test         # cargo test --all
just clippy       # cargo clippy --all-targets --all-features
just fmt          # format; `just fmt-check` only verifies
just ci           # fmt-check + clippy + test, as CI does
just --list       # everything else
```

The same checks run in [GitHub Actions](../.github/workflows/linux.yml) on every push and pull request, along with a debug build of the workspace and the frontend.

## Running locally

The daemon needs root (it writes network configuration and nftables rules), so **run it on a VM or a spare machine, not your daily driver**. Using the [Vagrant lab](vagrant.md) is the safest option.

Hot-reload workflow, in two terminals:

```bash
just dev-daemon   # root daemon with an extra loopback HTTP listener on :3000 (KEYSTONE_DEV=1)
just run-web      # `trunk serve` on :8080, proxying /api to the daemon
```

Or run the pieces exactly as they run in production (daemon on its Unix socket, web server serving a built `web-ui/dist`):

```bash
cargo build --workspace && (cd web-ui && trunk build)
sudo target/debug/keystonectl bootstrap-admin
sudo target/debug/keystone-daemon
KEYSTONE_DIST_DIR="$PWD/web-ui/dist" target/debug/keystone-web-ui
```

Environment variables you may want: `KEYSTONE_DEV` (daemon dev listener), `KEYSTONE_DIST_DIR` (frontend directory for the web server), `KEYSTONE_TOKEN` (token for `keystonectl`), and `RUST_LOG` for log filtering.

## Tests

- Unit tests live next to the code (`cargo test --all`) and need no privileges.
- The traffic-shaping tests that need a real network namespace and the `tc` tool run only when `KEYSTONE_NETNS_TESTS=1` (as root, see `daemon/src/sqm/apply.rs`).
- End-to-end tests run in the Vagrant lab: `just vagrant-integration`.

## Packaging and releases

```bash
makepkg -f        # builds keystone-router-<version>-1-x86_64.pkg.tar.zst in the repo root
```

The package version comes from `[workspace.package]` in the root `Cargo.toml`. The `PKGBUILD` builds with `--locked`, so commit `Cargo.lock` with every dependency change. A release bumps the workspace version (and `Cargo.lock`) in a `release: vX.Y.Z` commit.

Whenever a change touches files the daemon reads or writes, update the sandbox in [`packaging/arch/keystone-daemon.service`](../packaging/arch/keystone-daemon.service) (`ReadWritePaths`, `ConfigurationDirectory`) and [`tmpfiles.conf`](../packaging/arch/tmpfiles.conf), and test it under the real unit.
