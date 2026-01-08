#!/bin/sh
# Keystone Client VM Provisioning Script (Alpine Linux)
# This sets up the Alpine Linux client VM for testing keystone routing
set -e

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

# Bring up eth1 with DHCP
echo "Bringing up eth1..."
ifup eth1 || true

# 4. Wait for DHCP and show network info
echo "Waiting for DHCP lease..."
sleep 3

# 5. Display network configuration
echo ""
echo "=== Network Configuration ==="
echo ""
echo "Interfaces:"
ip -br addr
echo ""
echo "Routes:"
ip route
echo ""
echo "DNS:"
cat /etc/resolv.conf 2>/dev/null || echo "(no resolv.conf yet)"
echo ""

# 6. Test connectivity to router
echo "Testing connectivity to router (192.168.100.1)..."
ping -c 2 192.168.100.1 || echo "Router not reachable yet (router may not be fully configured)"

echo ""
echo "=== Client Provisioning Complete ==="
echo ""
echo "This client should get its IP via DHCP from the keystone router."
echo "Use this client to test:"
echo "  - Internet access through the router: curl https://example.com"
echo "  - DNS resolution: nslookup google.com"
echo "  - Firewall rules: Test blocked/allowed ports"
echo ""
echo "Current LAN IP (eth1):"
ip addr show eth1 2>/dev/null | grep "inet " || echo "  (waiting for DHCP)"
