# Vagrant Testing Guide

This guide explains how to use Vagrant for testing Keystone in an isolated Arch Linux VM.

## Overview

The Vagrant setup provides:
- **Arch Linux VM** with all dependencies pre-installed
- **Two networks**: WAN (NAT for internet) and LAN (private network at 192.168.56.10)
- **Synced folder**: Your code is mounted at `/src` in the VM
- **Automatic provisioning**: Installs Rust, cargo, nftables, dnsmasq on first boot

## Prerequisites

Install Vagrant and a provider:

```bash
# Arch Linux
sudo pacman -S vagrant libvirt qemu-full

# Enable libvirt
sudo systemctl enable --now libvirtd
sudo usermod -a -G libvirt $USER
```

## Quick Start

```bash
# 1. Start the VM (provisions on first run)
just vagrant-up

# 2. SSH into the VM
just vagrant-ssh

# 3. Inside VM, build Keystone
cd /src
cargo build --release

# 4. Run the services
sudo ./target/release/keystone-daemon &
./target/release/keystone-web-ui &

# 5. From host, access the UI
firefox http://192.168.56.10:8080
```

## Architecture

```
Host Machine
│
├── Vagrantfile
├── Source Code (synced to /src in VM)
│
└── Vagrant VM (Arch Linux)
    ├── Network 1 (eth0): NAT - Internet access
    ├── Network 2 (eth1): 192.168.56.10 - Private network
    │
    ├── /src → Your source code (synced)
    │
    └── Services:
        ├── keystone-daemon (root, Unix socket)
        └── keystone-web-ui (user, HTTP :8080)
```

## Just Commands

### VM Lifecycle

```bash
just vagrant-up          # Start VM
just vagrant-ssh         # SSH into VM
just vagrant-halt        # Stop VM
just vagrant-destroy     # Destroy VM
just vagrant-rebuild     # Destroy and recreate VM
just vagrant-status      # Show VM status
```

### Build & Test

```bash
just vagrant-build       # Build Keystone in VM
just vagrant-test        # Run tests in VM
just vagrant-install     # Build and install to /usr/local/bin
just vagrant-integration # Full integration test
```

### Run Services

```bash
just vagrant-run-daemon  # Start daemon (foreground)
just vagrant-run-web     # Start web UI (foreground)
```

## Manual Usage

### Start VM

```bash
vagrant up
```

First time will download the Arch box (~500MB) and provision it:
- Update system packages
- Install Rust toolchain
- Install nftables, dnsmasq
- Enable systemd-networkd

### SSH Access

```bash
vagrant ssh

# Inside VM
cd /src
ls  # Your source code is here
```

### Build in VM

```bash
vagrant ssh -c "cd /src && cargo build --release"
```

### Run Services in VM

```bash
# Terminal 1: Start daemon
vagrant ssh -c "cd /src && sudo ./target/release/keystone-daemon"

# Terminal 2: Start web UI
vagrant ssh -c "cd /src && ./target/release/keystone-web-ui"

# Terminal 3: Access from host
curl http://192.168.56.10:8080/health
```

### Access Web UI

From your host machine:
```bash
firefox http://192.168.56.10:8080
```

## Network Configuration

### WAN Interface (eth0)
- **Type**: NAT (Vagrant default)
- **Purpose**: Internet access, package downloads
- **Managed by**: Vagrant

### LAN Interface (eth1)
- **Type**: Private network
- **IP**: 192.168.56.10/24
- **Purpose**: Access services from host
- **Managed by**: Vagrant + systemd-networkd

### Port Forwarding

Services in the VM are accessible at:
- **Web UI**: http://192.168.56.10:8080
- **SSH**: `vagrant ssh` (Vagrant handles port forwarding automatically)

## Testing Scenarios

### Scenario 1: Basic Functionality

```bash
# Start VM and build
just vagrant-up
just vagrant-build

# Install services
just vagrant-install

# Test manually
vagrant ssh
sudo /usr/local/bin/keystone-daemon &
/usr/local/bin/keystone-web-ui &
exit

# Access from host
curl http://192.168.56.10:8080/health
```

### Scenario 2: Network Configuration

```bash
vagrant ssh

# Inside VM, test network interfaces
ip addr show
ip route

# Test systemd-networkd
systemctl status systemd-networkd
networkctl status

# Configure with Keystone
sudo /usr/local/bin/keystone-daemon &
# ... use web UI or API to configure interfaces ...
```

### Scenario 3: Firewall Testing

```bash
vagrant ssh

# Check nftables
sudo nft list ruleset

# Start Keystone and configure firewall
sudo /usr/local/bin/keystone-daemon &
# ... configure rules via web UI ...

# Verify rules applied
sudo nft list ruleset
```

### Scenario 4: Integration Testing

```bash
# Automated integration test
just vagrant-integration

# Services will be running, access:
curl http://192.168.56.10:8080/api/state
firefox http://192.168.56.10:8080
```

## Development Workflow

### Edit-Build-Test Cycle

```bash
# 1. Edit code on host (in your favorite editor)
vim daemon/src/main.rs

# 2. Build in VM (code is synced)
just vagrant-build

# 3. Test in VM
just vagrant-test

# 4. Run and verify
just vagrant-install
vagrant ssh -c "sudo /usr/local/bin/keystone-daemon &"
curl http://192.168.56.10:8080/health
```

### Debugging

```bash
# SSH into VM with debug logging
vagrant ssh
cd /src
RUST_LOG=debug sudo ./target/release/keystone-daemon

# Or from host
vagrant ssh -c "cd /src && RUST_LOG=debug sudo ./target/release/keystone-daemon"
```

### Iterative Testing

```bash
# Keep VM running, rebuild as needed
vagrant ssh

# Inside VM (stays connected)
cd /src
while true; do
    cargo build && sudo pkill keystone-daemon; sudo ./target/release/keystone-daemon &
    sleep 5
done
```

## Provisioning

The Vagrantfile includes automatic provisioning that runs on first `vagrant up`:

```ruby
config.vm.provision "shell", inline: <<-SHELL
  pacman -Syu archlinux-keyring
  pacman -Syu --noconfirm
  pacman -S --noconfirm rust cargo git nftables dnsmasq
  systemctl enable systemd-networkd
  systemctl start systemd-networkd
SHELL
```

### Re-provision

To re-run provisioning:
```bash
vagrant provision
```

### Custom Provisioning

Edit `Vagrantfile` to add more setup steps.

## Troubleshooting

### VM Won't Start

```bash
# Check Vagrant status
vagrant status

# Check libvirt
sudo systemctl status libvirtd

# Destroy and recreate
vagrant destroy -f
vagrant up
```

### Build Fails in VM

```bash
vagrant ssh
cd /src

# Check Rust installation
rustc --version
cargo --version

# Update Rust
rustup update

# Clean and rebuild
cargo clean
cargo build
```

### Services Not Accessible

```bash
# Check if VM is running
vagrant status

# Check IP address
vagrant ssh -c "ip addr show eth1"

# Verify services are running in VM
vagrant ssh -c "ps aux | grep keystone"

# Test from inside VM
vagrant ssh -c "curl http://localhost:8080/health"

# Test firewall
vagrant ssh -c "sudo nft list ruleset"
```

### Synced Folder Issues

```bash
# Check if /src is mounted
vagrant ssh -c "ls -la /src"

# If not, try reloading
vagrant reload

# Or destroy and recreate
vagrant destroy -f
vagrant up
```

## Performance Tips

### Speed up builds

```bash
# Inside VM, use all CPU cores
vagrant ssh
cd /src
export MAKEFLAGS="-j$(nproc)"
cargo build --release
```

### Persistent cargo cache

The cargo cache is stored in the VM, so it persists across rebuilds but not VM destruction.

## Cleanup

```bash
# Stop VM (preserves state)
just vagrant-halt

# Destroy VM (removes everything)
just vagrant-destroy

# Remove Vagrant box (frees disk space)
vagrant box remove generic/arch
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Integration Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Install Vagrant
        run: |
          sudo apt-get update
          sudo apt-get install -y vagrant libvirt-daemon-system
      
      - name: Start VM
        run: vagrant up
      
      - name: Build
        run: vagrant ssh -c "cd /src && cargo build --release"
      
      - name: Test
        run: vagrant ssh -c "cd /src && cargo test --all"
      
      - name: Integration Test
        run: |
          vagrant ssh -c "cd /src && sudo ./target/release/keystone-daemon &"
          vagrant ssh -c "cd /src && ./target/release/keystone-web-ui &"
          sleep 5
          vagrant ssh -c "curl http://localhost:8080/health"
```

## Advanced Configuration

### Custom VM Resources

Edit `Vagrantfile`:

```ruby
config.vm.provider "libvirt" do |vb|
  vb.memory = "4096"  # Increase RAM
  vb.cpus = 4         # More CPUs
end
```

### Additional Networks

Add more private networks for testing:

```ruby
# Third network interface
config.vm.network "private_network", ip: "192.168.57.10"
```

### Custom Provisioning Script

```ruby
config.vm.provision "shell", path: "scripts/provision.sh"
```

## Comparison with Manual VM Setup

| Feature | Vagrant | Manual QEMU |
|---------|---------|-------------|
| Setup | `vagrant up` | Multi-step process |
| Networking | Automatic | Manual configuration |
| Synced folders | Built-in | Requires setup |
| Reproducible | Yes | Manual |
| Port forwarding | Automatic | Manual |
| Snapshots | `vagrant snapshot` | QEMU snapshots |
| Multi-machine | Easy | Complex |

## Resources

- [Vagrant Documentation](https://www.vagrantup.com/docs)
- [Vagrant Arch Box](https://app.vagrantup.com/generic/boxes/arch)
- [Libvirt Provider](https://github.com/vagrant-libvirt/vagrant-libvirt)

---

**Last Updated**: 2025-12-26
**Status**: ✅ Production ready
