#!/usr/bin/env bash
# Keystone Vagrant Provisioning Script
set -e

echo "=== Keystone Provisioning ==="

# Update system
echo "Updating system..."
# 2. FORCE fast NZ mirrors to the top immediately
# (We don't need python/reflector for this, just echo)
echo "Server = https://mirror.2degrees.nz/archlinux/\$repo/os/\$arch" > /etc/pacman.d/mirrorlist
echo "Server = https://mirror.fsmg.org.nz/archlinux/\$repo/os/\$arch" >> /etc/pacman.d/mirrorlist

pacman -Sy --noconfirm archlinux-keyring
pacman -Syu --noconfirm rust cargo git nftables dnsmasq

# Find the top 10 fastest mirrors in NZ/AU and overwrite the list
#reflector --country 'New Zealand',Australia --protocol https --latest 10 --sort rate --save /etc/pacman.d/mirrorlist


# Install dependencies
echo "Installing dependencies..."
pacman -S --noconfirm rust cargo git nftables dnsmasq base-devel

# Enable systemd-networkd
echo "Enabling systemd-networkd..."
systemctl enable systemd-networkd
systemctl start systemd-networkd

echo "=== Provisioning Complete ==="
echo "Access at: http://192.168.56.10:8080"
