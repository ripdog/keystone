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
KEYSTONECTL="/src/target/release/keystonectl"
DAEMON_BIN="/src/target/release/keystone-daemon"

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

# Helper to run commands on router VM
router_ssh() {
    vagrant ssh router -c "$1" 2>/dev/null
}

router_ssh_sudo() {
    vagrant ssh router -c "sudo $1" 2>/dev/null
}

# Helper to run commands on client VM
client_ssh() {
    vagrant ssh client -c "$1" 2>/dev/null
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

log_step "Step 3: Sync Source Code"

log_info "Syncing source code to router VM..."
vagrant rsync router 2>&1 | grep -v "WARNING" || true
log_success "Source synced"

# Build keystone
if [[ "$SKIP_BUILD" == "false" ]]; then
    log_step "Step 4: Building Keystone"
    
    log_info "Building keystone-daemon and keystonectl on router VM..."
    router_ssh "cd /src && cargo build --release -p keystone-daemon -p keystonectl 2>&1" | tail -5
    log_success "Build complete"
else
    log_info "Skipping build (--skip-build)"
    
    # Verify binaries exist
    if ! router_ssh "test -x $DAEMON_BIN"; then
        log_error "Daemon binary not found. Run without --skip-build"
        exit 1
    fi
    log_success "Binaries found"
fi

log_step "Step 5: Starting Keystone Daemon"

# Stop any existing daemon
log_info "Stopping any existing daemon..."
router_ssh_sudo "pkill -f keystone-daemon" || true
sleep 1

# Start daemon
log_info "Starting keystone daemon..."
router_ssh_sudo "nohup $DAEMON_BIN > /tmp/keystone-daemon.log 2>&1 &"
sleep 2

# Verify daemon is running
if ! router_ssh "pgrep -f keystone-daemon" >/dev/null; then
    log_error "Daemon failed to start. Logs:"
    router_ssh_sudo "cat /tmp/keystone-daemon.log" || true
    exit 1
fi
log_success "Daemon started"

# Login to get token
log_info "Logging in to keystone..."
router_ssh_sudo "$KEYSTONECTL login -u admin -p admin" >/dev/null
log_success "Logged in"

log_step "Step 6: Configuring Firewall"

# Check current zones
log_info "Checking existing zones..."
ZONES=$(router_ssh_sudo "$KEYSTONECTL firewall zones list" 2>/dev/null || true)

# Create WAN zone if not exists
if ! echo "$ZONES" | grep -q "wan"; then
    log_info "Creating WAN zone..."
    router_ssh_sudo "$KEYSTONECTL firewall zones add --name wan --interfaces eth0 --input-policy drop --forward-policy drop"
    log_success "WAN zone created"
else
    log_info "WAN zone already exists"
fi

# Create LAN zone if not exists  
if ! echo "$ZONES" | grep -q "lan"; then
    log_info "Creating LAN zone..."
    router_ssh_sudo "$KEYSTONECTL firewall zones add --name lan --interfaces eth1 --input-policy accept --forward-policy accept"
    log_success "LAN zone created"
else
    log_info "LAN zone already exists"
fi

# Check for zone forward policy
log_info "Checking zone forward policies..."
FORWARDS=$(router_ssh_sudo "$KEYSTONECTL firewall zone-forwards list" 2>/dev/null || true)

if ! echo "$FORWARDS" | grep -q "lan.*wan"; then
    log_info "Creating LAN -> WAN forward policy..."
    router_ssh_sudo "$KEYSTONECTL firewall zone-forwards add --source lan --dest wan --policy accept"
    log_success "Forward policy created"
else
    log_info "LAN -> WAN forward policy exists"
fi

# Add SSH rule for WAN (critical for access)
log_info "Checking input rules..."
INPUT_RULES=$(router_ssh_sudo "$KEYSTONECTL firewall input-rules list" 2>/dev/null || true)

if ! echo "$INPUT_RULES" | grep -q "SSH.*WAN\|WAN.*SSH\|wan.*22"; then
    log_info "Adding SSH rule for WAN..."
    router_ssh_sudo "$KEYSTONECTL firewall input-rules add --name 'Allow SSH on WAN' --zone wan --protocol tcp --port 22 --action accept"
    log_success "SSH rule added"
else
    log_info "SSH rule for WAN exists"
fi

# Add DHCP rule for LAN (needed for client)
if ! echo "$INPUT_RULES" | grep -q "DHCP\|dhcp\|67"; then
    log_info "Adding DHCP rule for LAN..."
    router_ssh_sudo "$KEYSTONECTL firewall input-rules add --name 'Allow DHCP from LAN' --zone lan --protocol udp --port 67 --action accept"
    log_success "DHCP rule added"
fi

# Add DNS rule for LAN
if ! echo "$INPUT_RULES" | grep -q "DNS\|dns\|53"; then
    log_info "Adding DNS rule for LAN..."
    router_ssh_sudo "$KEYSTONECTL firewall input-rules add --name 'Allow DNS from LAN' --zone lan --protocol tcpudp --port 53 --action accept"
    log_success "DNS rule added"
fi

log_step "Step 7: Applying Firewall Rules"

log_info "Applying firewall configuration..."
APPLY_OUTPUT=$(router_ssh_sudo "$KEYSTONECTL firewall apply" 2>&1)

if echo "$APPLY_OUTPUT" | grep -q "Session ID"; then
    # Extract session ID and confirm
    SESSION_ID=$(echo "$APPLY_OUTPUT" | grep -oP 'Session ID: \K[a-f0-9-]+')
    log_info "Confirming firewall (session: $SESSION_ID)..."
    router_ssh_sudo "$KEYSTONECTL firewall confirm --session-id $SESSION_ID"
    log_success "Firewall applied and confirmed"
else
    log_error "Failed to apply firewall:"
    echo "$APPLY_OUTPUT"
    exit 1
fi

# Verify nftables rules are in place
log_info "Verifying nftables rules..."
if ! router_ssh_sudo "nft list table inet keystone" | grep -q "chain forward"; then
    log_error "nftables rules not found"
    exit 1
fi
log_success "nftables rules verified"

log_step "Step 8: Configuring Client Network"

# Configure client with static IP (since DHCP isn't set up yet)
log_info "Configuring client network..."

# Clear any stale ARP on router
router_ssh_sudo "ip neigh flush dev eth1" || true

# Configure client eth1 with static IP
client_ssh "sudo ip addr flush dev eth1 2>/dev/null; sudo ip addr add $CLIENT_LAN_IP/24 dev eth1; sudo ip link set eth1 up"
client_ssh "sudo ip route del default via 192.168.121.1 2>/dev/null || true"
client_ssh "sudo ip route add default via $ROUTER_LAN_IP dev eth1 metric 100"

log_success "Client network configured"

# Show client network config
log_info "Client network configuration:"
client_ssh "ip addr show eth1 | grep inet"
client_ssh "ip route | grep default"

log_step "Step 9: Connectivity Tests"

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
if client_ssh "ping -c 1 -W 5 google.com 2>/dev/null" | grep -q "1 received"; then
    log_success "DNS resolution working"
else
    log_warn "DNS resolution not working (expected if dnsmasq not configured)"
fi

# Test 4: Verify NAT is working
log_info "Test 4: NAT/Masquerade verification"
NAT_COUNTER=$(router_ssh_sudo "nft list chain inet keystone_nat postrouting" | grep -oP 'packets \K\d+' | head -1)
if [[ -n "$NAT_COUNTER" && "$NAT_COUNTER" -gt 0 ]]; then
    log_success "NAT masquerade is working ($NAT_COUNTER packets)"
else
    log_warn "NAT counter is 0 (may be expected if no traffic yet)"
fi

# Test 5: Firewall is blocking unwanted traffic
log_info "Test 5: Firewall blocking verification"
# Check that forward chain policy is drop
if router_ssh_sudo "nft list chain inet keystone forward" | grep -q "policy drop"; then
    log_success "Forward chain has drop policy"
else
    log_error "Forward chain should have drop policy"
    exit 1
fi

log_step "Step 10: Summary"

echo ""
log_success "All integration tests passed!"
echo ""
echo "Environment:"
echo "  Router WAN (eth0): $(router_ssh 'ip -4 addr show eth0 | grep -oP "inet \K[0-9.]+"')"
echo "  Router LAN (eth1): $ROUTER_LAN_IP"
echo "  Client LAN (eth1): $CLIENT_LAN_IP"
echo ""
echo "Firewall status:"
router_ssh_sudo "$KEYSTONECTL firewall zones list" 2>/dev/null | head -10
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
