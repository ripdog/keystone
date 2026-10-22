# Changelog

All notable changes to Keystone are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/). Keystone ships frequent patch releases, so the 0.x history below is grouped by minor version.

## [Unreleased]

## [0.5.0] - 2026-10-22

The first minor release since the 0.4 series. It adds no new router features; it makes the project ready to share: documentation, CI and dependency hygiene.

### Added
- Documentation moved to `docs/` (installation, architecture, development, Vagrant testing), a rewritten README with screenshots, and this changelog. The package now installs the docs.
- CI runs `cargo fmt --check`, Clippy (warnings are errors) and the test suite on every push and pull request, and a weekly `cargo audit` of `Cargo.lock`.
- Releases are tagged in git (`vX.Y.Z`), including the earlier 0.x releases.

### Security
- Updated `quick-xml` to 0.42, fixing RUSTSEC-2026-0194 and RUSTSEC-2026-0195 (denial of service) in the firewall connection-tracking parser.
- RUSTSEC-2023-0071 (`rsa` Marvin attack, no fix available) is acknowledged in `.cargo/audit.toml`: Keystone only uses HS256 session tokens, so no RSA operation runs.

### Fixed
- The systemd units' `Documentation=` URL pointed at a placeholder repository.

## [0.4.x] - 2026-10-15 to 2026-10-22 (latest: 0.4.29)

### Added
- **Wi-Fi access point** managed through hostapd as a new `wireless` component, with its own web UI page.
- **Bridges:** convert a LAN interface into a bridge as one staged edit, keeping the port's MAC address.
- **Diagnostics:** network tools (ping, traceroute, DNS lookup, TCP check) with streamed output, and a packet capture page backed by tcpdump with OR filter groups and DHCP/ISP debugging filters.
- **Multicast DNS:** per-interface mDNS toggle (avahi) so the router answers to `<hostname>.local`.
- **Caddy:** any DNS-challenge provider with environment-variable credentials; automatic firewall input accepts for its LAN ports; IPv6 listeners on the LAN interface's global addresses.
- **WAN:** *Reset DHCP session* action for DHCPv4 uplinks, and the lease is released before renaming a DHCPv4 interface.
- **Firewall:** IPv6 host targeting by interface-identifier suffix (with a LAN device picker), zone selection from a list, and enabling or disabling individual port forwards.
- **dnsmasq:** the router's own `resolv.conf` follows dnsmasq while it serves DNS; common DHCP options chosen from a list.
- **keystonectl:** console login banner, shell completions (bash, zsh, fish), contextual help, friendlier errors, and `apply --confirm` / session-less `confirm`.
- **Logging:** configurable daemon log level in Settings, a full-timestamps toggle in the log viewer, and an unconditional *Re-apply all* button.
- Dashboard system information and service control widgets.

### Changed
- The package is named `keystone-router` (the `extra/keystone` package uses the old name).
- Never-applied components return to the installation defaults, and rolled-back applies are undone in the database as well as on disk.
- The "Local AdGuard Home" upstream mode was removed in favour of Blocky.

### Fixed
- mDNS is applied again after a rolled-back network apply.
- The web service can bind a LAN bridge's member ports.
- Several Caddy sandbox and validation problems (access-log directory, service environment, waiting for the LAN address after a networkd apply).
- The Blocky client name falls back to the DHCP lease hostname when it would otherwise be a bare address.

## [0.3.x] - 2026-10-14

### Added
- **Configuration snapshots** recorded on every apply, with per-component coverage, pending-change reporting, discard, restore, diff, and export/import (web UI history page and `keystonectl snapshots`). Invalid snapshots are refused at import and restore.
- **Traffic shaping (SQM)** with CAKE on the WAN, with live counters.
- **UPnP IGD and NAT-PMP/PCP** port mapping via miniupnpd.
- **DNS filtering** with Blocky: ad-blocking, encrypted upstreams, client groups and a query log. The firewall can redirect LAN DNS queries aimed at outside servers to the router.
- **Firewall tooling:** packet tester, live log, connection-tracking view, named address/port groups, rule hit counters and reordering.
- **Clients page:** unified LAN device inventory with vendor lookup, plus a Ctrl-K command palette.
- Per-device traffic graphs on the Clients page, persistent custom names for physical interfaces, a paged journal viewer for managed services, and a single status bar for pending, applying and confirmation states.

## [0.2.x] - 2026-10-13

### Added
- Confirm-or-revert timer for systemd-networkd changes, matching the firewall's.
- Validation of firewall rules on save and before apply, rejection of nonsensical configuration and warnings for suspicious configuration.
- A refusal to apply public-key-only SSH when no user has authorized keys, and Caddy port validation.
- Typed API endpoints shared between the daemon, the web UI and the CLI.

## [0.1.x] - 2026-10-13

First numbered releases, packaging the work below as an Arch Linux package with systemd units, tmpfiles and sysusers definitions, a USB image builder and a Vagrant test lab.

## Before 0.1 - 2025-12-27 to 2026-01-10

Initial development: the daemon/web-ui/ctl workspace and Vagrant lab; systemd-networkd interface configuration (DHCPv4/v6, router advertisements, VLANs, bridges, MTU, live preview); the zone-based nftables firewall with apply/confirm/rollback, NAT, port forwards and hairpin NAT; dnsmasq DNS/DHCP management; Caddy configuration; a unified apply system with service management; and the first-run setup wizard.
