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

# 4. Enable systemd-networkd (keystone uses this)
echo "Enabling systemd-networkd..."
systemctl enable systemd-networkd
systemctl start systemd-networkd

# 5. Create keystone directories
echo "Creating keystone directories..."
mkdir -p /var/lib/keystone
mkdir -p /etc/keystone

# 6. Ensure LAN interface is up with the right IP
echo "Configuring LAN interface..."
ip addr show eth1 | grep -q "192.168.100.1" || ip addr add 192.168.100.1/24 dev eth1
ip link set eth1 up

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
