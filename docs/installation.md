# Installation and first-run setup

Keystone targets **Arch Linux** (x86_64) with systemd. It is packaged as `keystone-router` and ships systemd units, tmpfiles/sysusers definitions and shell completions.

> Network and firewall changes can cut you off from a router. Install on a spare machine or VM, and keep console (not just SSH) access while you configure it.

## Requirements

Installed automatically as package dependencies: `nftables`, `conntrack-tools`, `dnsmasq`, `iproute2`, `iputils`, `ldns`, `sqlite`, `hwdata` and `systemd` (which provides `systemd-networkd`).

Optional features, each enabled by installing its package:

| Feature | Package | Notes |
|---|---|---|
| DNS ad-blocking, encrypted upstream DNS | `blocky-bin` (AUR) | Keystone supplies its own `keystone-blocky.service` |
| UPnP / NAT-PMP | `miniupnpd-nft` (AUR) | The `extra/miniupnpd` build uses iptables and is **not** supported |
| HTTPS for the web UI | `caddy` | Configured from the web UI; supports DNS-challenge certificates |
| `<hostname>.local` name | `avahi` | Per-interface mDNS toggle |
| Wi-Fi access point | `hostapd`, `iw` | Managed as the "Wireless" component |
| Packet capture page | `tcpdump` | Diagnostics → Packet Capture |
| SQM traffic shaping | kernel modules `sch_cake`, `ifb`, `act_mirred`, `cls_matchall` | Loaded at boot by the package |

## Build and install the package

Build dependencies: `rust`, `cargo`, `trunk` (and the `wasm32-unknown-unknown` target; `rustup target add wasm32-unknown-unknown` if you use rustup), `git`.

```bash
git clone https://github.com/ripdog/keystone.git
cd keystone
makepkg -si
```

This produces and installs `keystone-router-<version>-1-x86_64.pkg.tar.zst`.

### Dedicated router on a USB drive

[`scripts/create-keystone-usb.sh`](../scripts/create-keystone-usb.sh) builds a persistent Arch Linux install with Keystone on a USB drive, from an Arch ISO and a built package. **The target device is erased.**

```bash
sudo ./scripts/create-keystone-usb.sh \
  --iso archlinux-x86_64.iso --device /dev/sdX \
  --keystone keystone-router-<version>-1-x86_64.pkg.tar.zst
```

To upgrade Keystone on an existing drive without reformatting, use `--upgrade-keystone` instead of `--iso`. Run the script with `--help` for all options (hostname, working directory, tests).

## First-run setup

There is **no default administrator account**. Create one locally, as root:

```bash
sudo keystonectl bootstrap-admin          # prompts for a password (12+ characters); refuses to run if users already exist
sudo systemctl enable --now keystone-daemon keystone-web-ui
```

Then configure the router, either:

- **In the browser:** open `http://<router-LAN-address>:8080` (or `http://127.0.0.1:8080` on the router itself), log in, and follow the setup wizard; or
- **In the terminal:** run `keystonectl setup` for the same interactive wizard.

The wizard assigns your WAN and LAN interfaces and stages a complete dual-stack router profile: DHCP (and IPv6 prefix delegation) on the WAN, a static LAN address with a dnsmasq DHCP range, NAT and default firewall zones.

Nothing is changed on the system until you **apply**. Applying runs with a rollback timer: if you do not confirm within 60 seconds, the previous network and firewall configuration is restored. This is what protects you from locking yourself out; always confirm from a session that survives the change.

### Day-to-day CLI

```bash
keystonectl login -u admin       # saves a token for later commands
keystonectl changes              # what is staged but not applied
keystonectl apply                # apply everything, then…
keystonectl confirm              # …confirm within the rollback window
keystonectl snapshots list       # configuration history (last 50 kept)
keystonectl --help               # everything else; shell completions are installed
```

## Where things live

| Path | Purpose |
|---|---|
| `/etc/keystone/keystone.toml` | Optional daemon settings (socket path/group/mode) |
| `/var/lib/keystone/keystone.db` | SQLite database holding all configuration (mode 0700 directory) |
| `/run/keystone/keystone.sock` | Daemon API socket (group `keystone`, mode 0660) |
| `/usr/share/keystone/dist/` | Compiled web frontend |
| `/etc/systemd/network/`, `/etc/nftables.conf`, `/etc/dnsmasq.conf`, `/etc/caddy/`, `/etc/hostapd/`, `/etc/miniupnpd/`, `/etc/keystone-blocky/`, `/etc/avahi/` | Files Keystone generates for the services it manages. Don't edit them by hand; changes are overwritten on the next apply |

The web UI listens on port **8080**, only on loopback and the router's configured LAN addresses, never on the WAN.

## Uninstalling

`pacman -R keystone-router` stops the services but preserves `/var/lib/keystone/` and `/etc/keystone/`; remove them yourself if you no longer need them.
