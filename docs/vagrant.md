# Testing in Vagrant

Keystone reconfigures networking and firewalls, so test it on something you can't lock yourself out of. The repository ships a two-VM [Vagrant](https://www.vagrantup.com/) lab (libvirt provider) that exercises the whole stack: DHCP, NAT, firewall rules and the apply/confirm/rollback flow.

## The lab

```text
Host (internet)
  │  NAT (vagrant-libvirt management network, SSH + package downloads)
┌─┴──────────────────────┐
│ router  (Arch Linux)   │  eth0: management
│ Keystone built from    │  eth1: LAN 192.168.100.1/24
│ /src (rsynced)         │
└──────────┬─────────────┘
           │  isolated libvirt network "keystone-lan"
┌──────────┴─────────────┐
│ client  (Alpine)       │  eth1: DHCP lease from the router's dnsmasq
└────────────────────────┘
```

All test traffic crosses `eth1` → router → internet, so firewall rules are tested on LAN traffic and never on the management link that Vagrant uses for SSH.

## Prerequisites

On an Arch host:

```bash
sudo pacman -S vagrant libvirt qemu-full
sudo systemctl enable --now libvirtd
sudo usermod -aG libvirt "$USER"      # log out and back in afterwards
vagrant plugin install vagrant-libvirt
```

## Commands

Everything is wrapped in the [justfile](../justfile). Builds inside the VM are debug builds.

| Command | Does |
|---|---|
| `just vagrant-up` | Create and provision the VMs (first run downloads the boxes) |
| `just vagrant-ssh` | Shell into the router VM |
| `just vagrant-build` | `cargo build` inside the VM (`/src` is rsynced from your checkout) |
| `just vagrant-test` | `cargo test --all` inside the VM |
| `just vagrant-install` | Copy the debug binaries to `/usr/local/bin` in the VM |
| `just vagrant-run-daemon` / `vagrant-run-web` / `vagrant-run-all` | Start the services in the background |
| `just vagrant-stop-services` | Stop them again |
| `just vagrant-integration` | Full end-to-end test, leaving the VMs running |
| `just vagrant-integration-quick` | Same, skipping the build |
| `just vagrant-integration-clean` | Same, destroying the VMs afterwards |
| `just vagrant-halt` / `vagrant-destroy` / `vagrant-rebuild` | VM lifecycle |

After editing code on the host, re-sync with `vagrant rsync` (or let the `just vagrant-*` recipes do it) and rebuild in the VM. If file ownership in `/src` gets confused after an rsync as root, run `just vagrant-fix-perms`.

## What the integration test does

[`scripts/integration-test.sh`](../scripts/integration-test.sh) (flags: `--skip-build`, `--skip-provision`, `--keep-vms`):

1. Brings up the router and client VMs.
2. Builds Keystone and starts the daemon on the router.
3. Runs the default router setup with `keystonectl` (WAN/LAN roles, dnsmasq, firewall zones).
4. Checks that the client receives a DHCP lease from the router.
5. Checks client → router → internet connectivity and that firewall rules are enforced.

## Troubleshooting

- **VM won't start:** `vagrant status`, then `sudo systemctl status libvirtd`. As a last resort `just vagrant-rebuild`.
- **`/src` is empty:** `vagrant rsync`, or `vagrant reload`.
- **Services unreachable:** `vagrant ssh -c "ps aux | grep keystone"`, and check the daemon with `sudo journalctl -u keystone-daemon` if you installed the systemd units, or run it in the foreground with `RUST_LOG=debug`.
- **Inspect the firewall:** `vagrant ssh -c "sudo nft list ruleset"`.

The VM resources (RAM/CPUs) and networks are set in the [Vagrantfile](../Vagrantfile); the provisioning scripts are in [`scripts/`](../scripts).
