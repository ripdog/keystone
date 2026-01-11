#!/usr/bin/env bash
# Keystone Router VM Provisioning Script
# Minimal setup - Keystone will manage dnsmasq and nftables!
set -e

echo "=== Keystone Router Provisioning ==="

# 1. Set up fast NZ mirrors
echo "Configuring pacman mirrors..."
cat > /etc/pacman.d/mirrorlist << 'EOF'
Server = https://mirror.2degrees.nz/archlinux/$repo/os/$arch
Server = https://mirror.fsmg.org.nz/archlinux/$repo/os/$arch
EOF

# 2. Update system and install packages
echo "Updating system and installing dependencies..."
pacman -Sy --noconfirm archlinux-keyring
pacman -Syu --noconfirm
pacman -S --noconfirm \
    rust cargo git \
    nftables dnsmasq \
    base-devel \
    iproute2

# 3. Enable IP forwarding (critical for routing)
echo "Enabling IP forwarding..."
cat > /etc/sysctl.d/99-keystone-router.conf << 'EOF'
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
sysctl -p /etc/sysctl.d/99-keystone-router.conf

# 4. Disable systemd-resolved so dnsmasq can bind :53
# Arch enables systemd-resolved by default, which occupies 127.0.0.53:53.
echo "Disabling systemd-resolved (dnsmasq needs port 53)..."
systemctl disable --now systemd-resolved || true
systemctl mask systemd-resolved || true
rm -f /etc/resolv.conf
cat > /etc/resolv.conf << 'EOF'
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF

# 5. Enable systemd-networkd (keystone uses this)
echo "Enabling systemd-networkd..."
systemctl enable systemd-networkd
systemctl start systemd-networkd

# 6. Create keystone directories
echo "Creating keystone directories..."
mkdir -p /var/lib/keystone
mkdir -p /etc/keystone

# 6. Configure LAN interface (eth1) persistently with systemd-networkd
echo "Configuring LAN interface..."
cat > /etc/systemd/network/eth1.network << 'EOF'
[Match]
Name=eth1

[Network]
Address=192.168.100.1/24
EOF
# Reload networkd to apply the configuration
systemctl restart systemd-networkd
# Wait for interface to come up
sleep 2

echo ""
echo "=== Provisioning Complete ==="
echo ""
echo "Network interfaces:"
ip -br addr
echo ""
echo "IP forwarding:"
sysctl net.ipv4.ip_forward
echo ""
echo "=== Ready for Keystone ==="
echo "Build and run keystone:"
echo "  cd /src && cargo build --release"
echo "  sudo ./target/release/keystone-daemon &"
echo "  ./target/release/keystone-web-ui &"
echo ""
echo "IMPORTANT: Configure keystone to allow SSH on WAN before applying firewall rules!"
