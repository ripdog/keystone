# Architecture

## Components

| Crate | Binary | Runs as | Role |
|---|---|---|---|
| [`core/`](../core) | (library) | n/a | Serde models and API types shared by everything else; validation helpers |
| [`daemon/`](../daemon) | `keystone-daemon` | root | Owns the SQLite database, validates all input, generates system config files and applies them |
| [`web-ui/`](../web-ui) | `keystone-web-ui` | `keystone` user | Unprivileged HTTP server that serves the Leptos/WASM frontend and proxies `/api` to the daemon |
| [`ctl/`](../ctl) | `keystonectl` | any user (root for `bootstrap-admin`) | Command-line client for the same daemon API, plus the interactive setup wizard and login banner |

```text
Browser ──HTTP(S)──> keystone-web-ui (unprivileged, :8080 on loopback + LAN only)
                                  │
                        Unix socket, group keystone, mode 0660
                                  │          ▲
                          keystone-daemon    └── keystonectl
                            (root, SQLite)
                                  │
   systemd-networkd · nftables · dnsmasq · Blocky · miniupnpd · hostapd · Caddy · avahi · tc
```

## Security model

- **Privilege separation.** The web server never runs as root and has no direct access to the system. The daemon is reachable only through its Unix socket (`/run/keystone/keystone.sock`); there is no daemon TCP port. (Development mode, `KEYSTONE_DEV=1`, adds a loopback HTTP listener; never use it on a real router.)
- **No default credentials.** The first administrator is created locally by root with `keystonectl bootstrap-admin`, which only works while no users exist. Passwords are hashed with Argon2; sessions are JWTs signed with a key generated on first start and stored in the database. Failed logins are rate-limited.
- **Untrusted input.** Everything arriving over the API is validated at the daemon boundary against typed models from `core/`. Input is never interpolated into shell commands; external tools are invoked with argument vectors, and generated config files are written atomically.
- **Network exposure.** The web service asks the daemon for the router's LAN addresses and binds only those plus loopback, never a wildcard address and never the WAN. Use Caddy for HTTPS.
- **Sandboxing.** `keystone-daemon.service` runs with `ProtectSystem=strict` and an explicit `ReadWritePaths=` list covering only the files Keystone generates, a bounded capability set, and `NoNewPrivileges`. The web UI and Blocky units are sandboxed more tightly still (see [`packaging/arch/`](../packaging/arch)). Writable directories are pre-created by `tmpfiles.d` so they exist before the sandbox is built.

## Configuration lifecycle

All configuration lives in the SQLite database and is split into independent **components**: `networkd`, `firewall`, `sqm`, `upnp`, `blocky`, `wireless`, `dnsmasq` and `caddy`. Each is generated into its own files or kernel state by its own apply step.

1. **Edit.** Changes made in the UI or CLI are saved to the database only; they are *pending*. `keystonectl changes` (or the pending-changes banner in the UI) shows what differs from the last applied state, per component, and `keystonectl discard` reverts it.
2. **Apply.** Applying generates the files, swaps them in, and restarts or reloads the affected services. Network and firewall applies start a **60-second rollback timer**.
3. **Confirm or roll back.** If you confirm in time, the new configuration becomes the baseline. If you don't (because the change cut you off), the previous network and firewall state is restored automatically, and components whose files a rollback doesn't cover are re-applied from the restored configuration.
4. **Snapshots.** Each successful apply records a snapshot (the newest 50 are kept). Snapshots can be diffed, restored (as pending changes), exported to a file and imported again.

## Firewall

The firewall is zone-based. Interfaces belong to zones; the policy between zones is set with zone forwards, and rules can be added to the input (traffic to the router) and forward (traffic between zones) chains. Port forwards, address/port groups and "simple" forward pairs are higher-level objects compiled into nftables rules.

Keystone owns its own nftables tables (`keystone` for filtering, `keystone_nat` for NAT, and `keystone_upnp` for UPnP mappings) and replaces them atomically; it never flushes tables that belong to anything else. The generated ruleset can be previewed before applying, and the web UI includes a packet tester, a live log and a connection viewer for checking the result.

## Source layout

```text
core/src/        shared models: interfaces, firewall, dnsmasq, SQM, UPnP, Blocky, wireless, changes, API types
daemon/src/      one module per managed service (firewall/, dnsmasq/, caddy/, blocky/, sqm/, …),
                 plus auth, db/, snapshots, rollback, networkd, diagnostics and capture
daemon/migrations/   sqlx migrations, applied automatically on start
web-ui/src/      pages/ (one per screen), components/, api/ client; Trunk builds it to web-ui/dist
ctl/src/         clap command definitions, handlers, setup wizard, banner, shell completions
packaging/arch/  systemd units and drop-ins, sysusers/tmpfiles, kernel modules, login banner
scripts/         USB image builder and the Vagrant provisioning/integration scripts
```
