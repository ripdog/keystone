#!/usr/bin/env bash
# Keystone Vagrant Provisioning Script
set -e

echo "=== Keystone Provisioning ==="

# Update system
echo "Updating system..."
pacman -Syu --noconfirm

# Install dependencies
echo "Installing dependencies..."
pacman -S --noconfirm rust cargo git nftables dnsmasq base-devel

# Enable systemd-networkd
echo "Enabling systemd-networkd..."
systemctl enable systemd-networkd
systemctl start systemd-networkd

echo "=== Provisioning Complete ==="
echo "Access at: http://192.168.56.10:8080"
