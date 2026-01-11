#!/bin/sh
# Keystone Client VM Provisioning Script (Alpine Linux)
# This sets up the Alpine Linux client VM for testing keystone routing
set -e

# DHCP on eth1 depends on router/Keystone; don't fail provision
set +o pipefail 2>/dev/null || true

echo "=== Keystone Client Provisioning ==="

# 1. Update packages
echo "Updating packages..."
apk update

# 2. Install useful testing tools
echo "Installing test tools..."
apk add --no-cache \
    curl \
    wget \
    bind-tools \
    iputils \
    tcpdump \
    netcat-openbsd \
    iperf3

# 3. Configure eth1 (LAN interface) to use DHCP from router
# Alpine uses /etc/network/interfaces
echo "Configuring LAN interface for DHCP..."
cat >> /etc/network/interfaces << 'EOF'

# LAN interface - gets IP from keystone router
auto eth1
iface eth1 inet dhcp
EOF

# Bring up eth1 (DHCP will succeed once router/Keystone is running)
echo "Bringing up eth1 (DHCP may not be available yet)..."
ifup eth1 || true

# Display network configuration without requiring a DHCP lease
echo ""
echo "=== Network Configuration (post-provision) ==="
echo ""
echo "Interfaces:"
ip -br addr || true
echo ""
echo "Routes:"
ip route || true
echo ""
echo "DNS:"
cat /etc/resolv.conf 2>/dev/null || echo "(no resolv.conf yet)"
echo ""

echo "=== Client Provisioning Complete ==="
echo "Client LAN (eth1) is configured for DHCP; Keystone test will validate."
