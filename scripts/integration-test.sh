#!/usr/bin/env bash
# Keystone End-to-End Integration Test
# 
# This script runs a full integration test of Keystone in a multi-VM environment:
# 1. Starts router and client VMs
# 2. Builds and deploys keystone
# 3. Configures firewall zones and rules via keystonectl
# 4. Verifies connectivity from client through router to internet
#
# Prerequisites:
# - Vagrant with libvirt provider
# - VMs defined in Vagrantfile (router + client)
#
# Usage:
#   ./scripts/integration-test.sh [--skip-build] [--skip-provision] [--keep-vms]

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ROUTER_IP="192.168.121.223"  # May vary, we'll detect it
CLIENT_LAN_IP="192.168.100.10"
ROUTER_LAN_IP="192.168.100.1"
KEYSTONECTL="/src/target/debug/keystonectl"
DAEMON_BIN="/src/target/debug/keystone-daemon"

# Options
SKIP_BUILD=false
SKIP_PROVISION=false
KEEP_VMS=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --skip-provision)
            SKIP_PROVISION=true
            shift
            ;;
        --keep-vms)
            KEEP_VMS=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--skip-build] [--skip-provision] [--keep-vms]"
            echo ""
            echo "Options:"
            echo "  --skip-build      Skip cargo build (use existing binaries)"
            echo "  --skip-provision  Skip VM provisioning (VMs must be running)"
            echo "  --keep-vms        Don't destroy VMs after test"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  $1${NC}"
    echo -e "${GREEN}========================================${NC}"
}

# Cleanup function
cleanup() {
    local exit_code=$?
    if [[ "$KEEP_VMS" == "false" && "$SKIP_PROVISION" == "false" ]]; then
        log_info "Cleaning up VMs..."
        cd "$PROJECT_DIR"
        vagrant destroy -f 2>/dev/null || true
    fi
    if [[ $exit_code -ne 0 ]]; then
        log_error "Integration test FAILED with exit code $exit_code"
    fi
    exit $exit_code
}

# Set up cleanup trap
trap cleanup EXIT

# Helper to run commands on router VM (filter out vagrant's annoying .1 IP warning)
router_ssh() {
    vagrant ssh router -c "$1" 2>&1 | grep -v "You assigned a static IP ending in" | grep -v "This is very often used by the router" | grep -v "network to not work properly" | grep -v "^==>" | grep -v "^\[fog\]\[WARNING\]"
}

# Run command on router, return exit code only (for checks)
router_ssh_check() {
    vagrant ssh router -c "$1" >/dev/null 2>&1
}

router_ssh_sudo() {
    vagrant ssh router -c "sudo $1" 2>&1 | grep -v "You assigned a static IP ending in" | grep -v "This is very often used by the router" | grep -v "network to not work properly" | grep -v "^==>" | grep -v "^\[fog\]\[WARNING\]"
}

# Run sudo command on router, return exit code only (for checks)
router_ssh_sudo_check() {
    vagrant ssh router -c "sudo $1" >/dev/null 2>&1
}

# Helper to run commands on client VM
client_ssh() {
    vagrant ssh client -c "$1" 2>&1 | grep -v "You assigned a static IP ending in" | grep -v "This is very often used by the router" | grep -v "network to not work properly" | grep -v "^==>" | grep -v "^\[fog\]\[WARNING\]"
}

# Wait for a command to succeed with timeout
wait_for() {
    local description="$1"
    local command="$2"
    local timeout="${3:-30}"
    local interval="${4:-2}"
    
    log_info "Waiting for: $description (timeout: ${timeout}s)"
    
    local elapsed=0
    while [[ $elapsed -lt $timeout ]]; do
        if eval "$command" >/dev/null 2>&1; then
            log_success "$description"
            return 0
        fi
        sleep "$interval"
        elapsed=$((elapsed + interval))
    done
    
    log_error "Timeout waiting for: $description"
    return 1
}

# ============================================================
# MAIN TEST EXECUTION
# ============================================================

cd "$PROJECT_DIR"

log_step "Step 1: Environment Setup"

# Check prerequisites
log_info "Checking prerequisites..."

if ! command -v vagrant &> /dev/null; then
    log_error "Vagrant not found. Please install vagrant."
    exit 1
fi
log_success "Vagrant found"

if ! command -v cargo &> /dev/null; then
    log_error "Cargo not found. Please install Rust."
    exit 1
fi
log_success "Cargo found"

# Start VMs if not skipping provision
if [[ "$SKIP_PROVISION" == "false" ]]; then
    log_step "Step 2: Starting VMs"
    
    log_info "Starting router and client VMs..."
    vagrant up 2>&1 | grep -E "^==>|Booting|Waiting|Machine booted" || true

    # Arch box updates kernel during provision; reboot once so new kernel/modules are active.
    log_info "Rebooting router once after first provision..."
    vagrant reload router 2>&1 | grep -E "^==>|Machine" || true
    sleep 10
    wait_for "Router SSH" "router_ssh_check 'echo ok'" 120 5
    log_success "Router rebooted"

    log_success "VMs started"
else
    log_info "Skipping VM provisioning (--skip-provision)"
    
    # Verify VMs are running
    if ! vagrant status router 2>/dev/null | grep -q "running"; then
        log_error "Router VM is not running"
        exit 1
    fi
    if ! vagrant status client 2>/dev/null | grep -q "running"; then
        log_error "Client VM is not running"
        exit 1
    fi
    log_success "VMs are running"
fi

# Check for kernel module mismatch by testing nftables
log_info "Checking for kernel module compatibility..."

# Keystone relies on nf_tables kernel modules. If the Arch box updates the kernel
# during provisioning, a reboot is required so /lib/modules matches uname -r.
KERNEL="$(router_ssh "uname -r" | tail -n 1)"
if ! router_ssh_check "test -d /lib/modules/${KERNEL}"; then
    log_warn "Kernel modules for ${KERNEL} missing; rebooting router VM..."
    vagrant reload router 2>&1 | grep -E "^==>|Machine" || true
    log_info "Waiting for router to come back up..."
    sleep 10
    wait_for "Router SSH" "router_ssh_check 'echo ok'" 120 5
fi

# Smoke-test nft command itself (ignore empty ruleset)
NFT_ERROR=$(router_ssh_sudo "nft list ruleset 2>&1" | grep -i "cache initialization failed\|Invalid argument\|not found in directory" || true)
if [[ -n "$NFT_ERROR" ]]; then
    log_warn "nftables appears broken (${NFT_ERROR}); rebooting router VM..."
    vagrant reload router 2>&1 | grep -E "^==>|Machine" || true
    log_info "Waiting for router to come back up..."
    sleep 10
    wait_for "Router SSH" "router_ssh_check 'echo ok'" 120 5
fi

# Fix libvirt bridge IP conflict: libvirt assigns 192.168.100.1 to the host bridge,
# which conflicts with the router VM's eth1 IP. Remove the IP from the host bridge.
log_info "Fixing host bridge IP conflict..."
BRIDGE_NAME=$(sudo virsh net-dumpxml keystone-lan 2>/dev/null | grep -oP "bridge name='\K[^']+")
if [[ -n "$BRIDGE_NAME" ]]; then
    sudo ip addr del 192.168.100.1/24 dev "$BRIDGE_NAME" 2>/dev/null || true
    log_success "Host bridge IP conflict resolved ($BRIDGE_NAME)"
fi

# Ensure router eth1 is up and configured (may be down after VM reboot)
log_info "Ensuring router LAN interface is configured..."
if ! router_ssh_check "ip addr show eth1 | grep -q 192.168.100.1"; then
    # Create the networkd config if missing and restart networkd
    router_ssh "echo -e '[Match]\nName=eth1\n\n[Network]\nAddress=192.168.100.1/24' | sudo tee /etc/systemd/network/eth1.network > /dev/null"
    router_ssh_sudo "systemctl restart systemd-networkd"
    sleep 2
fi
# Make sure the interface is up
router_ssh_sudo "ip link set eth1 up" || true
log_success "Router LAN interface configured"

# Build keystone
if [[ "$SKIP_BUILD" == "false" ]]; then
    log_step "Step 3: Building Keystone"
    
    log_info "Building keystone-daemon and keystonectl on router VM..."
    router_ssh "cd /src && cargo build -p keystone-daemon -p keystonectl 2>&1" | tail -5
    log_success "Build complete"
else
    log_info "Skipping build (--skip-build)"
    
    # Verify binaries exist
    if ! router_ssh_check "test -x $DAEMON_BIN"; then
        log_error "Daemon binary not found. Run without --skip-build"
        exit 1
    fi
    log_success "Binaries found"
fi

log_step "Step 4: Starting Keystone Daemon"

# Stop any existing daemon
log_info "Stopping any existing daemon..."
router_ssh_sudo "pkill -f keystone-daemon" || true
sleep 1

# Clean up old log file (may be owned by different user)
router_ssh_sudo "rm -f /tmp/keystone-daemon.log" || true

# Start daemon in background
# Use 'sh -c' with proper detachment to avoid SSH waiting for the process
log_info "Starting keystone daemon..."
vagrant ssh router -c "sudo sh -c 'nohup $DAEMON_BIN > /tmp/keystone-daemon.log 2>&1 &'" >/dev/null 2>&1
sleep 3

# Verify daemon is running
if ! router_ssh_check "pgrep -f keystone-daemon"; then
    log_error "Daemon failed to start. Logs:"
    router_ssh_sudo "cat /tmp/keystone-daemon.log" || true
    exit 1
fi

# Wait for socket + health endpoint (daemon can be alive but not ready yet)
wait_for "Daemon socket" "router_ssh_check 'test -S /run/keystone/keystone.sock'" 60 3
wait_for "Daemon health endpoint" "router_ssh_check 'sudo $KEYSTONECTL health --json >/dev/null 2>&1'" 60 3

log_success "Daemon started"

# Login to get token
log_info "Logging in to keystone..."
router_ssh_sudo "$KEYSTONECTL login -u admin -p admin" >/dev/null
log_success "Logged in"

# Mark setup as complete (required before firewall/dnsmasq endpoints are available)
log_info "Completing initial setup..."
SETUP_OUTPUT=$(router_ssh_sudo "$KEYSTONECTL complete-setup-now" || true)
if echo "$SETUP_OUTPUT" | grep -qi "error\|failed"; then
    log_error "Failed to complete setup. Check system prerequisites."
    echo "$SETUP_OUTPUT"
    exit 1
fi
log_success "Setup completed"

# Ensure interface roles/zones are assigned so NAT/forwarding rules can be generated.
# We keep this in the Keystone config layer (not OS-level firewall commands).
log_info "Ensuring Keystone managed interfaces are configured..."
IFACE_COUNT=$(router_ssh_sudo "$KEYSTONECTL interfaces list --json" 2>/dev/null | grep -o '"name"' | wc -l | tr -d '[:space:]' || echo 0)
IFACE_COUNT=${IFACE_COUNT:-0}
if [[ "$IFACE_COUNT" -lt 2 ]]; then
    log_info "No managed interfaces found; seeding WAN=eth0 (DHCP) and LAN=eth1 (192.168.100.1/24)"
    vagrant ssh router -c "cat <<'EOF' | sudo $KEYSTONECTL interfaces save >/dev/null
{
  \"interfaces\": [
    {
      \"name\": \"eth0\",
      \"role\": \"WAN\",
      \"enabled\": true,
      \"dhcp_mode\": \"Yes\",
      \"ip_forward\": \"Yes\",
      \"ip_masquerade\": \"Ipv4\"
    },
    {
      \"name\": \"eth1\",
      \"role\": \"LAN\",
      \"enabled\": true,
      \"addresses\": [
        { \"address\": \"192.168.100.1/24\", \"scope\": \"Global\" }
      ],
      \"ip_forward\": \"Yes\",
      \"ip_masquerade\": \"No\"
    }
  ]
}
EOF"
fi

log_info "Ensuring firewall zones are bound to interfaces..."
ZONES_JSON=$(router_ssh_sudo "$KEYSTONECTL firewall zones list --json" 2>/dev/null || true)
# We only need a simple, robust check here: if wan/lan exist with empty interfaces, update them.
WAN_HAS_IFACE=$(echo "$ZONES_JSON" | grep -A5 '"name"\s*:\s*"wan"' | grep -q '"interfaces"\s*:\s*\[' && echo yes || echo no)
LAN_HAS_IFACE=$(echo "$ZONES_JSON" | grep -A5 '"name"\s*:\s*"lan"' | grep -q '"interfaces"\s*:\s*\[' && echo yes || echo no)

# Create (or overwrite) the zones with the correct interface bindings.
# This is still Keystone-level configuration, and it unblocks NAT generation.
# Update zone interface bindings in-place by recreating each zone with its existing id.
WAN_ZONE_ID=$(echo "$ZONES_JSON" | grep -B2 -A2 '"name"\s*:\s*"wan"' | grep -oP '"id"\s*:\s*\K\d+' | head -1 || true)
LAN_ZONE_ID=$(echo "$ZONES_JSON" | grep -B2 -A2 '"name"\s*:\s*"lan"' | grep -oP '"id"\s*:\s*\K\d+' | head -1 || true)

if [[ -z "$WAN_ZONE_ID" || -z "$LAN_ZONE_ID" ]]; then
    log_error "Expected wizard/setup to create lan/wan zones"
    echo "$ZONES_JSON"
    exit 1
fi

router_ssh_sudo "$KEYSTONECTL firewall zones add --id $WAN_ZONE_ID --name wan --interfaces eth0 --input-policy drop --forward-policy drop --wan --masquerade-ipv4" >/dev/null
router_ssh_sudo "$KEYSTONECTL firewall zones add --id $LAN_ZONE_ID --name lan --interfaces eth1 --input-policy accept --forward-policy accept" >/dev/null

# Ensure LAN -> WAN forwarding exists (idempotent-ish).
router_ssh_sudo "$KEYSTONECTL firewall zone-forwards add --source lan --dest wan --policy accept --enabled true" >/dev/null || true

log_step "Step 5: Keystone Default Router Setup"

log_info "Ensuring SSH won't be cut off by firewall apply..."
# Add a temporary allow SSH rule for management interface (WAN) so we don't lock ourselves out.
# Avoid creating duplicates on repeated test runs.
if ! router_ssh_sudo "$KEYSTONECTL firewall input-rules list" | grep -q "Allow SSH management (test)"; then
    router_ssh_sudo "$KEYSTONECTL firewall input-rules add --name 'Allow SSH management (test)' --zone wan --protocol tcp --port 22 --action accept" >/dev/null
fi

log_info "Applying Keystone firewall/router configuration..."
DEFAULT_APPLY_OUTPUT=$(router_ssh_sudo "$KEYSTONECTL firewall apply" 2>&1 || true)

if echo "$DEFAULT_APPLY_OUTPUT" | grep -q "Session ID"; then
    SESSION_ID=$(echo "$DEFAULT_APPLY_OUTPUT" | grep -oP 'Session ID: \K[a-f0-9-]+')
    log_info "Confirming firewall (session: $SESSION_ID)..."

    # Firewall apply may disrupt SSH if the host network is treated as WAN.
    # Confirm quickly, but don't hang the whole test if SSH drops.
    if timeout 20 vagrant ssh router -c "sudo $KEYSTONECTL firewall confirm --session-id $SESSION_ID" >/dev/null 2>&1; then
        log_success "Firewall applied and confirmed"
    else
        log_warn "Firewall confirm disrupted SSH; reloading router to continue"
        vagrant reload router 2>&1 | grep -E "^==>|Machine" || true
        sleep 10
        wait_for "Router SSH" "router_ssh_check 'echo ok'" 120 5
        log_info "Retrying firewall confirm after reload..."
        router_ssh_sudo "$KEYSTONECTL firewall confirm --session-id $SESSION_ID" >/dev/null || true
        log_warn "Continuing after firewall apply; verify nftables later"
    fi
else
    log_error "Failed to apply firewall:"
    echo "$DEFAULT_APPLY_OUTPUT"
    exit 1
fi

log_info "Configuring Keystone dnsmasq defaults (DHCP for LAN)..."

# Ensure dnsmasq is enabled
router_ssh_sudo "$KEYSTONECTL dnsmasq config set --enabled true" >/dev/null

# Ensure at least one DHCP range exists for eth1
RANGE_COUNT=$(router_ssh_sudo "$KEYSTONECTL dnsmasq ranges list --json" 2>/dev/null | grep -o '"id"' | wc -l | tr -d ' ' | tr -d '\n' || true)
RANGE_COUNT="${RANGE_COUNT:-0}"
if [[ "$RANGE_COUNT" -lt 1 ]]; then
    log_info "Adding default DHCP range for eth1 (192.168.100.50-192.168.100.150)..."
    router_ssh_sudo "$KEYSTONECTL dnsmasq ranges add --name lan --interface eth1 --start 192.168.100.50 --end 192.168.100.150 --lease-time 12h --enabled" >/dev/null
fi

log_info "Applying dnsmasq configuration..."
DNSMASQ_APPLY_OUTPUT=$(router_ssh_sudo "$KEYSTONECTL dnsmasq apply" 2>&1 || true)
if echo "$DNSMASQ_APPLY_OUTPUT" | grep -qi "error\|failed"; then
    log_error "dnsmasq apply failed"
    echo "$DNSMASQ_APPLY_OUTPUT"
    router_ssh_sudo "systemctl status dnsmasq --no-pager" || true
    router_ssh_sudo "journalctl -u dnsmasq --no-pager -n 200" || true
    exit 1
fi

# Make sure dnsmasq is actually serving DHCP (udp/67). We've seen cases where it only
# binds DNS (udp/53), which makes the client DHCP wait flake.
log_info "Verifying dnsmasq is listening for DHCP (udp/67)..."
if ! router_ssh_sudo_check "ss -lunp | grep -q ':67'"; then
    log_warn "dnsmasq not listening on udp/67; restarting service and dumping diagnostics"
    router_ssh_sudo "systemctl restart dnsmasq" || true
    sleep 2
    router_ssh_sudo "systemctl status dnsmasq --no-pager -l" || true
    router_ssh_sudo "journalctl -u dnsmasq --no-pager -n 200" || true
    router_ssh_sudo "ss -lunp | grep -E ':53|:67' || true" || true
    router_ssh_sudo "sed -n '1,220p' /etc/dnsmasq.conf" || true
fi

# If the service still isn't listening on DHCP after a restart, treat it as a failure.
if ! router_ssh_sudo_check "ss -lunp | grep -q ':67'"; then
    log_error "dnsmasq still not listening on udp/67 after restart"
    router_ssh_sudo "systemctl status dnsmasq --no-pager -l" || true
    router_ssh_sudo "journalctl -u dnsmasq --no-pager -n 200" || true
    router_ssh_sudo "ss -lunp | grep -E ':53|:67' || true" || true
    router_ssh_sudo "sed -n '1,260p' /etc/dnsmasq.conf" || true
    exit 1
fi


# Some environments need a moment for services to start
sleep 3

# Assert only one dnsmasq is running (avoid stray foreground debug instance holding udp/67)
DNSMASQ_PIDS=$(router_ssh_sudo "pgrep -x dnsmasq | wc -l" | tr -d '[:space:]' || echo 0)
DNSMASQ_PIDS=${DNSMASQ_PIDS:-0}
if [[ "$DNSMASQ_PIDS" -gt 1 ]]; then
    log_warn "Multiple dnsmasq processes detected; killing extras"
    router_ssh_sudo "pkill -x dnsmasq" || true
    sleep 1
    router_ssh_sudo "systemctl restart dnsmasq" || true
    sleep 2
fi

log_step "Step 6: Client DHCP + Connectivity Tests"

log_info "Ensuring client LAN interface is up for DHCP..."
client_ssh "sudo ip link set eth1 up" || true

log_info "Waiting for client DHCP lease on eth1..."

# Ensure eth1 is configured for DHCP on Alpine (persistently via /etc/network/interfaces)
# Provisioning may have run before Keystone DHCP was active.
client_ssh "grep -q '^auto eth1' /etc/network/interfaces || echo -e '\nauto eth1\niface eth1 inet dhcp\n' | sudo tee -a /etc/network/interfaces >/dev/null" || true

# Kick the interface to trigger DHCP
client_ssh "sudo ifdown eth1 2>/dev/null || true; sudo ifup eth1 2>/dev/null || true" || true

# As a fallback, also run udhcpc directly.
client_ssh "sudo udhcpc -i eth1 -n -q -t 10" || true

if ! wait_for "Client DHCP on eth1" "vagrant ssh client -c 'ip -4 addr show eth1' 2>/dev/null | grep -q 192.168.100\." 120 3; then
    log_error "Client did not receive DHCP lease on eth1"
    log_info "Router dnsmasq diagnostics:"
    router_ssh_sudo "systemctl status dnsmasq --no-pager -l" || true
    router_ssh_sudo "journalctl -u dnsmasq --no-pager -n 200" || true
    router_ssh_sudo "ss -lunp | grep -E ':53|:67' || true" || true
    router_ssh_sudo "sed -n '1,260p' /etc/dnsmasq.conf" || true
    router_ssh_sudo "$KEYSTONECTL dnsmasq active-leases --json" || true

    log_info "Client network diagnostics:"
    client_ssh "cat /etc/network/interfaces" || true
    client_ssh "ip link show eth0; ip link show eth1" || true
    client_ssh "ip -4 addr show eth0; ip -4 addr show eth1" || true
    client_ssh "ip route" || true
    client_ssh "sudo udhcpc -i eth1 -n -q -t 5 -v" || true

    exit 1
fi

log_info "Client network configuration:"
client_ssh "ip addr show eth1 | grep inet" || true
client_ssh "ip route | grep default" || true

log_step "Step 7: Connectivity + Firewall Tests"

# Test 1: Client can ping router LAN
log_info "Test 1: Client -> Router LAN connectivity"
if client_ssh "ping -c 2 -W 5 $ROUTER_LAN_IP" | grep -q "2 received"; then
    log_success "Client can reach router LAN interface"
else
    log_error "Client cannot reach router LAN interface"
    exit 1
fi

# Test 2: Client can reach internet (ping)
log_info "Test 2: Client -> Internet connectivity (ICMP)"
if client_ssh "ping -c 2 -W 5 8.8.8.8" | grep -q "2 received"; then
    log_success "Client can reach internet (8.8.8.8)"
else
    log_error "Client cannot reach internet"
    log_info "Checking forward chain counters..."
    router_ssh_sudo "nft list chain inet keystone forward"
    exit 1
fi

# Test 3: DNS resolution (if DNS is working)
log_info "Test 3: DNS resolution"
if client_ssh "nslookup google.com 2>/dev/null" | grep -q "Address"; then
    log_success "DNS resolution working"
elif client_ssh "ping -c 1 -W 5 google.com 2>/dev/null" | grep -q "1 received"; then
    log_success "DNS resolution working"
else
    log_warn "DNS resolution not working (expected if client not using LAN DNS)"
fi

# Test 4: Force LAN-only path for NAT validation
log_info "Test 4: Forcing client traffic through router LAN"
# The client VM often has a second interface on libvirt NAT (eth0).
# We must ensure that the *default* route used for internet traffic is via eth1.
# Only after that do we take eth0 down, otherwise we can strand ourselves.

log_info "Setting client default route preference to LAN (metric)..."
# Delete any existing eth1 default and re-add with a better metric.
client_ssh "sudo ip route del default via $ROUTER_LAN_IP dev eth1 2>/dev/null || true" || true
client_ssh "sudo ip route replace default via $ROUTER_LAN_IP dev eth1 metric 50" || true

log_info "Client default routes before eth0 down:"
client_ssh "ip route | grep '^default'" || true

# Ensure default route via router LAN (eth1) takes precedence
if client_ssh "ip route show default | head -1 | grep -E '^default via 192\\.168\\.100\\.1 dev eth1'" >/dev/null; then
    log_success "Client preferred default route via LAN"
else
    log_error "Client preferred default route is not via LAN; cannot validate router NAT"
    client_ssh "ip route show default" || true
    exit 1
fi

# IMPORTANT: The client is reached via libvirt NAT on eth0 (Vagrant SSH).
# Taking eth0 down makes the test more "realistic", but it can also cut off SSH
# and make the rest of the test flaky/non-deterministic. Instead we validate
# that the client *prefers* the LAN default route (metric) for internet traffic.
log_info "Keeping client eth0 up (SSH stability); validating NAT via route selection..."

# Test 5: Router is actually doing NAT (masquerade rule exists)
log_info "Test 5: NAT ruleset includes masquerade"
if router_ssh_sudo "nft list chain inet keystone_nat postrouting" | grep -qi "masquerade"; then
    log_success "NAT masquerade rule present"
else
    log_error "No masquerade rule present in keystone_nat postrouting"
    exit 1
fi

# Test 6: NAT counters increment after client traffic
log_info "Test 6: NAT counter increments"

nat_postrouting_packets() {
    # Avoid brittle pipelines (`set -euo pipefail`) and avoid `grep -P`.
    # Parse the first "counter packets N" occurrence using awk.
    router_ssh_sudo "nft --numeric list chain inet keystone_nat postrouting" \
        | awk '/counter packets/ {for (i = 1; i <= NF; i++) if ($i == "packets") {print $(i+1); exit}}' \
        | tr -d '\r'
}

# Generate some internet-bound traffic (should traverse router NAT)
NAT_COUNTER_BEFORE=$(nat_postrouting_packets || true)
if [[ -z "${NAT_COUNTER_BEFORE}" ]]; then
    log_error "Failed to parse NAT postrouting counter (before)"
    router_ssh_sudo "nft --numeric list chain inet keystone_nat postrouting" || true
    exit 1
fi
log_info "Router NAT counter before: $NAT_COUNTER_BEFORE"

client_ssh "ping -c 2 -W 5 8.8.8.8" >/dev/null
sleep 1

NAT_COUNTER_AFTER=$(nat_postrouting_packets || true)
if [[ -z "${NAT_COUNTER_AFTER}" ]]; then
    log_error "Failed to parse NAT postrouting counter (after)"
    router_ssh_sudo "nft --numeric list chain inet keystone_nat postrouting" || true
    exit 1
fi
log_info "Router NAT counter after: $NAT_COUNTER_AFTER"

if [[ "$NAT_COUNTER_AFTER" -gt "$NAT_COUNTER_BEFORE" ]]; then
    log_success "NAT postrouting packets: $NAT_COUNTER_BEFORE -> $NAT_COUNTER_AFTER"
else
    log_error "NAT counter did not increment ($NAT_COUNTER_BEFORE -> $NAT_COUNTER_AFTER)"
    router_ssh_sudo "nft --numeric list chain inet keystone_nat postrouting" || true
    exit 1
fi

# Test 7: Forwarding policy is drop (baseline)
log_info "Test 7: Forward chain has drop policy"
if router_ssh_sudo "nft list chain inet keystone forward" | grep -q "policy drop"; then
    log_success "Forward chain has drop policy"
else
    log_error "Forward chain should have drop policy"
    exit 1
fi

# Test 8: Router drops unsolicited WAN->router traffic (basic)
log_info "Test 8: Router input chain is drop by default"
if router_ssh_sudo "nft list chain inet keystone input" | grep -q "policy drop"; then
    log_success "Input chain has drop policy"
else
    log_error "Input chain should have drop policy"
    exit 1
fi

# Test 9: Router forwarding has established/related accept
log_info "Test 9: Forward chain has established/related accept"
if router_ssh_sudo "nft list chain inet keystone forward" | grep -q "ct state established,related"; then
    log_success "Forward chain accepts established/related"
else
    log_error "Forward chain missing established/related accept"
    exit 1
fi

log_step "Step 9: Summary"

echo ""
log_success "All integration tests passed!"
echo ""
echo "Environment:"
echo "  Router WAN (eth0): $(router_ssh 'ip -4 addr show eth0 | grep -oP "inet \K[0-9.]+"')"
echo "  Router LAN (eth1): $ROUTER_LAN_IP"
echo "  Client LAN (eth1): $CLIENT_LAN_IP"
echo ""
echo "Firewall status:"
router_ssh_sudo "$KEYSTONECTL firewall zones list" | head -10
echo ""

if [[ "$KEEP_VMS" == "true" ]]; then
    log_info "VMs kept running (--keep-vms)"
    echo ""
    echo "To access:"
    echo "  Router: vagrant ssh router"
    echo "  Client: vagrant ssh client"
    echo "  Web UI: http://$(router_ssh 'ip -4 addr show eth0 | grep -oP "inet \K[0-9.]+"'):8080"
else
    log_info "VMs will be destroyed on exit"
fi

echo ""
log_success "Integration test completed successfully!"
