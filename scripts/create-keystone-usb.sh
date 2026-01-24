#!/bin/bash
#
# create-keystone-usb.sh - Create a persistent Arch Linux USB with Keystone installed
#
# This script takes an Arch Linux ISO and a USB drive, and creates a persistent
# read/write installation with Keystone pre-installed.
#
# Usage: sudo ./create-keystone-usb.sh -i <arch.iso> -d <device> [-k <keystone-pkg>]
#
# Requirements:
#   - Root privileges
#   - Arch Linux host (or compatible with pacman/arch-chroot)
#   - Required tools: parted, mkfs.ext4, mkfs.fat, mount, arch-chroot
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
ISO_PATH=""
DEVICE=""
KEYSTONE_PKG=""
WORKDIR=""
LOGFILE=""
CLEANUP_WORKDIR=false
SKIP_CONFIRM=false
HOSTNAME="keystone-router"
MODE="create"  # create|upgrade-keystone
RUN_TESTS=false
FORCE_BUILD=false

# Print colored output
info() { echo -e "${BLUE}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }

print_help() {
    cat << 'EOF'
Keystone Live USB Creator

USAGE:
  create-keystone-usb.sh --device <blockdev> --iso <arch.iso> [options]
  create-keystone-usb.sh --upgrade-keystone --device <blockdev> --keystone <pkg> [options]

MODES:
  Create (default)
    Partitions and formats the device, installs a persistent Arch Linux system,
    installs GRUB (removable path), and installs Keystone.

  Upgrade Keystone
    Mounts an existing Keystone USB drive and upgrades Keystone in place.
    No repartitioning/formatting, no base OS install.

REQUIRED (Create mode):
  -d, --device <device>       Target USB device (e.g. /dev/sdb) (DESTROYED)
  -i, --iso <path>            Arch Linux ISO path

REQUIRED (Upgrade mode):
  -U, --upgrade-keystone       Upgrade Keystone on an existing drive
  -d, --device <device>        Target USB device (e.g. /dev/sdb)
  -k, --keystone <pkg>          Keystone package (.pkg.tar.zst)

OPTIONAL (Upgrade mode):
  --build                      Build Keystone from repo sources (implies tests)
  --test                       Run tests before installing

OPTIONS:
  -k, --keystone <pkg>          Use pre-built Keystone package
                               If omitted in create mode, builds from repo sources
  -h, --hostname <name>         Hostname for the system (default: keystone-router)
  -w, --workdir <path>          Temp working directory (default: auto-created)
  -l, --logfile <path>          Log path (default: <workdir>/run.log)
  -y, --yes                     Skip confirmation prompts
      --help                    Show this help and exit

EXAMPLES:
  # Create new USB
  sudo ./scripts/create-keystone-usb.sh -i archlinux-2026.01.01-x86_64.iso -d /dev/sde \
    -k pkg/keystone-0.1.0-1-x86_64.pkg.tar.zst

  # Upgrade Keystone only (existing USB)
  sudo ./scripts/create-keystone-usb.sh --upgrade-keystone -d /dev/sde \
    -k pkg/keystone-0.1.0-1-x86_64.pkg.tar.zst
EOF
}

usage() {
    print_help
    exit 0
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -i|--iso)
                ISO_PATH="$2"
                shift 2
                ;;
            -d|--device)
                DEVICE="$2"
                shift 2
                ;;
            -k|--keystone)
                KEYSTONE_PKG="$2"
                shift 2
                ;;
            -U|--upgrade-keystone)
                MODE="upgrade-keystone"
                shift
                ;;
            -h|--hostname)
                HOSTNAME="$2"
                shift 2
                ;;
            --test)
                RUN_TESTS=true
                shift
                ;;
            --build)
                FORCE_BUILD=true
                RUN_TESTS=true
                shift
                ;;
            -w|--workdir)
                WORKDIR="$2"
                shift 2
                ;;
            -l|--logfile)
                LOGFILE="$2"
                shift 2
                ;;
            -y|--yes)
                SKIP_CONFIRM=true
                shift
                ;;
            --help)
                print_help
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                usage
                ;;
        esac
    done
}

# Validate requirements
get_root_disk() {
    local root_src
    root_src=$(findmnt -no SOURCE / 2>/dev/null || true)
    if [[ -z "$root_src" ]]; then
        return 1
    fi

    # If SOURCE is a mapper (LUKS/LVM), try to resolve.
    if [[ "$root_src" == /dev/mapper/* ]]; then
        local pkname
        pkname=$(lsblk -no PKNAME "$root_src" 2>/dev/null || true)
        if [[ -n "$pkname" ]]; then
            echo "/dev/$pkname"
            return 0
        fi
    fi

    local pkname
    pkname=$(lsblk -no PKNAME "$root_src" 2>/dev/null || true)
    if [[ -n "$pkname" ]]; then
        echo "/dev/$pkname"
        return 0
    fi

    # Fallback: if root_src is already a disk.
    if [[ -b "$root_src" && -z $(lsblk -no PKNAME "$root_src" 2>/dev/null || true) ]]; then
        echo "$root_src"
        return 0
    fi

    return 1
}

verify_target_device_safe() {
    local root_disk
    root_disk=$(get_root_disk || true)
    if [[ -n "$root_disk" && "$DEVICE" == "$root_disk" ]]; then
        error "Refusing to operate on root disk: $DEVICE"
        exit 1
    fi

    # Refuse if any partitions on DEVICE are mounted.
    if lsblk -nrpo NAME,MOUNTPOINTS "$DEVICE" 2>/dev/null | awk 'NF>=2 {exit 1}' ; then
        :
    else
        error "Refusing: one or more partitions on $DEVICE are mounted"
        lsblk -o NAME,SIZE,TYPE,MOUNTPOINTS "$DEVICE" 2>/dev/null || true
        exit 1
    fi
}

validate_requirements() {
    info "Validating requirements..."

    # Must be root
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi

    if [[ "$MODE" != "create" && "$MODE" != "upgrade-keystone" ]]; then
        error "Invalid mode: $MODE"
        exit 1
    fi
    
    # Check required tools
    local required_tools=(parted mkfs.ext4 mkfs.fat mount umount losetup arch-chroot pacstrap genfstab wipefs lsblk findmnt)
    local missing_tools=()
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        error "Missing required tools: ${missing_tools[*]}"
        echo "Install with: pacman -S arch-install-scripts dosfstools parted"
        exit 1
    fi
    
    # Validate ISO (create mode only)
    if [[ "$MODE" == "create" ]]; then
        if [[ -z "$ISO_PATH" ]]; then
            error "ISO path is required (-i)"
            exit 1
        fi

        if [[ ! -f "$ISO_PATH" ]]; then
            error "ISO file not found: $ISO_PATH"
            exit 1
        fi
    fi
    
    # Validate device
    if [[ -z "$DEVICE" ]]; then
        error "Device is required (-d)"
        exit 1
    fi
    
    if [[ ! -b "$DEVICE" ]]; then
        error "Device not found or not a block device: $DEVICE"
        exit 1
    fi
    
    # Check if device is removable (safety check)
    local removable_path="/sys/block/$(basename "$DEVICE")/removable"
    if [[ -f "$removable_path" ]]; then
        local removable
        removable=$(cat "$removable_path")
        if [[ "$removable" != "1" ]]; then
            warn "Device $DEVICE does not appear to be removable!"
            warn "This might be your system drive. Are you ABSOLUTELY sure?"
        fi
    fi

    if [[ "$MODE" == "create" ]]; then
        verify_target_device_safe
    else
        # In upgrade mode, refuse if target partitions are mounted.
        if lsblk -nrpo NAME,MOUNTPOINTS "$DEVICE" 2>/dev/null | awk 'NF>=2 {exit 1}' ; then
            :
        else
            error "Refusing: one or more partitions on $DEVICE are mounted"
            lsblk -o NAME,SIZE,TYPE,MOUNTPOINTS "$DEVICE" 2>/dev/null || true
            exit 1
        fi
    fi

    # Validate keystone package if provided
    if [[ -n "$KEYSTONE_PKG" && ! -f "$KEYSTONE_PKG" ]]; then
        error "Keystone package not found: $KEYSTONE_PKG"
        exit 1
    fi

    if [[ "$MODE" == "upgrade-keystone" && "$FORCE_BUILD" == "false" && -z "$KEYSTONE_PKG" ]]; then
        error "Upgrade mode requires --keystone <pkg> (or use --build)"
        exit 1
    fi

    # If no package provided (create mode), check we're in keystone source directory
    if [[ "$MODE" == "create" && -z "$KEYSTONE_PKG" ]]; then
        if [[ ! -f "Cargo.toml" ]] || ! grep -q 'keystone' Cargo.toml 2>/dev/null; then
            error "Not in keystone project directory and no package specified"
            error "Either run from keystone project root or provide -k <package>"
            exit 1
        fi
    fi
    
    success "Requirements validated"
}

# Get device information for confirmation
get_device_info() {
    local device="$1"
    echo ""
    echo "Device: $device"
    lsblk -o NAME,SIZE,TYPE,MOUNTPOINT "$device" 2>/dev/null || true
    echo ""
    
    # Show current partitions
    echo "Current partition table:"
    fdisk -l "$device" 2>/dev/null | head -20 || true
    echo ""
}

# Confirm destructive operation
confirm_operation() {
    if [[ "$MODE" == "upgrade-keystone" ]]; then
        warn "Upgrade mode selected: existing data on $DEVICE will be preserved"
        return 0
    fi

    if [[ "$SKIP_CONFIRM" == "true" ]]; then
        return 0
    fi
    
    echo ""
    echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║                        ⚠ WARNING ⚠                          ║${NC}"
    echo -e "${RED}║                                                              ║${NC}"
    echo -e "${RED}║  ALL DATA ON ${DEVICE} WILL BE PERMANENTLY DESTROYED!  ║${NC}"
    echo -e "${RED}║                                                              ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    get_device_info "$DEVICE"
    
    echo -e "${YELLOW}Target device: $DEVICE${NC}"
    echo -e "${YELLOW}ISO source: $ISO_PATH${NC}"
    echo ""
    
    read -r -p "Type 'YES' (uppercase) to confirm destruction of $DEVICE: " confirm
    if [[ "$confirm" != "YES" ]]; then
        error "Operation cancelled by user"
        exit 1
    fi
    
    echo ""
    read -r -p "Last chance! Type the device name to confirm (e.g., sdb): " confirm_dev
    if [[ "/dev/$confirm_dev" != "$DEVICE" ]]; then
        error "Device name mismatch. Operation cancelled."
        exit 1
    fi
}

# Setup working directory
setup_workdir() {
    if [[ -z "$WORKDIR" ]]; then
        WORKDIR=$(mktemp -d -t keystone-usb.XXXXXX)
        CLEANUP_WORKDIR=true
    fi

    mkdir -p "$WORKDIR"/{iso,rootfs}
    info "Working directory: $WORKDIR"

    if [[ -z "$LOGFILE" ]]; then
        LOGFILE="$WORKDIR/run.log"
    fi
}

# Cleanup function
cleanup() {
    local exit_code=$?

    info "Cleaning up..."

    if [[ -n "$WORKDIR" ]]; then
        # Unmount deepest mounts first; umount -R can fail if something is busy.
        while read -r target; do
            [[ -n "$target" ]] || continue
            umount "$target" 2>/dev/null || true
        done < <(findmnt -R -n -o TARGET "$WORKDIR/rootfs" 2>/dev/null | sort -r || true)

        umount "$WORKDIR/iso" 2>/dev/null || true
    fi

    # Avoid detaching unrelated loop devices (never losetup -D)

    # Remove working directory if we created it
    if [[ "$CLEANUP_WORKDIR" == "true" && -n "$WORKDIR" && -d "$WORKDIR" ]]; then
        rm -rf "$WORKDIR" 2>/dev/null || true
    fi

    if [[ $exit_code -ne 0 ]]; then
        error "Script failed with exit code $exit_code"
        if [[ -n "$LOGFILE" && -f "$LOGFILE" ]]; then
            error "See log for details: $LOGFILE"
        fi
    fi

    exit $exit_code
}

PART_EFI=""
PART_ROOT=""

set_partition_vars() {
    if [[ -b "${DEVICE}1" ]]; then
        PART_EFI="${DEVICE}1"
        PART_ROOT="${DEVICE}2"
    elif [[ -b "${DEVICE}p1" ]]; then
        PART_EFI="${DEVICE}p1"
        PART_ROOT="${DEVICE}p2"
    else
        error "Cannot find partitions on $DEVICE"
        exit 1
    fi
}

# Partition the USB drive
partition_device() {
    info "Partitioning $DEVICE..."
    
    # Unmount any existing partitions on the target device
    while read -r mountpoint; do
        if [[ -n "$mountpoint" ]]; then
            info "Unmounting $mountpoint..."
            umount "$mountpoint" 2>/dev/null || true
        fi
    done < <(lsblk -nrpo MOUNTPOINTS "$DEVICE" 2>/dev/null | tr ' ' '\n' | sed '/^$/d' || true)
    
    # Wait for device to settle
    sleep 1
    sync
    
    # Wipe existing partition table
    wipefs -af "$DEVICE"
    
    # Create GPT partition table with:
    # 1. EFI System Partition (512MB, FAT32)
    # 2. Root partition (rest, ext4)
    parted -s "$DEVICE" mklabel gpt
    parted -s "$DEVICE" mkpart primary fat32 1MiB 513MiB
    parted -s "$DEVICE" set 1 esp on
    parted -s "$DEVICE" mkpart primary ext4 513MiB 100%
    
    # Wait for partitions to appear
    sleep 2
    partprobe "$DEVICE"
    sleep 1
    
    # Determine partition naming scheme
    set_partition_vars
    
    info "Creating filesystems..."
    mkfs.fat -F32 -n KEYEFI "$PART_EFI"
    mkfs.ext4 -L KEYSTONE_ROOT "$PART_ROOT"
    
    success "Partitioning complete"
    success "  EFI: $PART_EFI"
    success "  Root: $PART_ROOT"
}

# Mount the new filesystems
mount_filesystems() {
    info "Mounting filesystems..."

    set_partition_vars

    mount "$PART_ROOT" "$WORKDIR/rootfs"
    mkdir -p "$WORKDIR/rootfs/boot"
    mount "$PART_EFI" "$WORKDIR/rootfs/boot"

    success "Filesystems mounted"
}

# Mount the ISO
mount_iso() {
    info "Mounting ISO..."
    mount -o loop,ro "$ISO_PATH" "$WORKDIR/iso"
    success "ISO mounted"
}

# Create an isolated pacman.conf so host repos don't leak in
write_pacman_conf() {
    info "Writing isolated pacman.conf..."

    local pacman_conf="$WORKDIR/pacman.conf"
    local mirrorlist="$WORKDIR/mirrorlist"

    cat > "$mirrorlist" << 'EOF'
Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch
Server = https://mirror.rackspace.com/archlinux/$repo/os/$arch
Server = https://mirrors.kernel.org/archlinux/$repo/os/$arch
EOF

    cat > "$pacman_conf" << EOF
[options]
HoldPkg     = pacman glibc
Architecture = auto
CheckSpace
SigLevel    = Required DatabaseOptional
LocalFileSigLevel = Optional

# Keep these deterministic and non-interactive
Color
ParallelDownloads = 5

[core]
Include = $mirrorlist

[extra]
Include = $mirrorlist
EOF


    success "Wrote $pacman_conf"
}

# Install base system
install_base_system() {
    info "Installing base Arch Linux system (this will take a while)..."

    write_pacman_conf

    # Use pacstrap to install base system with isolated repos.
    pacstrap -K -C "$WORKDIR/pacman.conf" "$WORKDIR/rootfs" \
        base \
        linux \
        linux-firmware \
        grub \
        networkmanager \
        openssh \
        sudo \
        vim \
        nano \
        htop \
        nftables \
        iproute2 \
        bridge-utils \
        tcpdump \
        ethtool \
        pciutils \
        usbutils

    success "Base system installed"
}

# Generate fstab
generate_fstab() {
    info "Generating fstab..."
    genfstab -U "$WORKDIR/rootfs" >> "$WORKDIR/rootfs/etc/fstab"
    success "fstab generated"
}

# Configure the system
configure_system() {
    info "Configuring system..."
    
    # Set hostname
    echo "$HOSTNAME" > "$WORKDIR/rootfs/etc/hostname"
    
    # Set hosts file
    cat > "$WORKDIR/rootfs/etc/hosts" << EOF
127.0.0.1   localhost
::1         localhost
127.0.1.1   $HOSTNAME.localdomain $HOSTNAME
EOF
    
    # Set timezone (UTC for routers)
    ln -sf /usr/share/zoneinfo/UTC "$WORKDIR/rootfs/etc/localtime"
    
    # Set locale
    echo "en_US.UTF-8 UTF-8" > "$WORKDIR/rootfs/etc/locale.gen"
    echo "LANG=en_US.UTF-8" > "$WORKDIR/rootfs/etc/locale.conf"
    
    # Enable services
    arch-chroot "$WORKDIR/rootfs" systemctl enable NetworkManager
    arch-chroot "$WORKDIR/rootfs" systemctl enable sshd
    
    # Generate locale
    arch-chroot "$WORKDIR/rootfs" locale-gen
    
    # Set root password (temporary, user should change)
    echo "root:keystone" | arch-chroot "$WORKDIR/rootfs" chpasswd
    
    # Create keystone user
    arch-chroot "$WORKDIR/rootfs" useradd -m -G wheel -s /bin/bash keystone
    echo "keystone:keystone" | arch-chroot "$WORKDIR/rootfs" chpasswd
    
    # Enable sudo for wheel group
    echo "%wheel ALL=(ALL:ALL) ALL" > "$WORKDIR/rootfs/etc/sudoers.d/wheel"
    chmod 440 "$WORKDIR/rootfs/etc/sudoers.d/wheel"
    
    success "System configured"
}

# Install bootloader
assert_expected_mounts() {
    local expected_root="$1"
    local expected_boot="$2"

    local actual_root actual_boot
    actual_root=$(findmnt -no SOURCE "$WORKDIR/rootfs" 2>/dev/null || true)
    actual_boot=$(findmnt -no SOURCE "$WORKDIR/rootfs/boot" 2>/dev/null || true)

    if [[ "$actual_root" != "$expected_root" ]]; then
        error "Root mount mismatch: expected $expected_root, got $actual_root"
        exit 1
    fi

    if [[ "$actual_boot" != "$expected_boot" ]]; then
        error "Boot(ESP) mount mismatch: expected $expected_boot, got $actual_boot"
        exit 1
    fi

    # Hard fail if any mounts under the chroot are not from the target device.
    local device_base
    device_base=$(basename "$DEVICE")
    while read -r source target; do
        [[ -z "$source" || -z "$target" ]] && continue

        # Allowed sources:
        # - the target disk partitions
        # - pseudo filesystems mounted by pacstrap (proc/sys/dev)
        if [[ "$source" == "$DEVICE"* || "$source" == "/dev/$device_base"* || "$source" == proc || "$source" == sysfs || "$source" == devtmpfs ]]; then
            continue
        fi

        error "Unexpected mount inside chroot: $source mounted on $target"
        error "Refusing to continue to avoid touching host filesystems"
        findmnt -R "$WORKDIR/rootfs" || true
        exit 1
    done < <(findmnt -R -n -o SOURCE,TARGET "$WORKDIR/rootfs" 2>/dev/null || true)
}

install_bootloader() {
    info "Installing UEFI bootloader (no NVRAM modifications)..."

    assert_expected_mounts "$PART_ROOT" "$PART_EFI"

    # Install GRUB to the USB's ESP using the removable media fallback path.
    # This should write EFI/BOOT/BOOTX64.EFI on the USB and not touch host NVRAM.
    arch-chroot "$WORKDIR/rootfs" grub-install \
        --target=x86_64-efi \
        --efi-directory=/boot \
        --bootloader-id=KEYSTONE \
        --removable \
        --no-nvram

    arch-chroot "$WORKDIR/rootfs" grub-mkconfig -o /boot/grub/grub.cfg

    success "Bootloader installed (removable path)"
}

# Build keystone package if needed
build_keystone_package() {
    if [[ "$FORCE_BUILD" == "false" && -n "$KEYSTONE_PKG" ]]; then
        info "Using pre-built package: $KEYSTONE_PKG"
        return 0
    fi
    
    info "Building Keystone package from source..."
    
    # Install build dependencies in chroot
    arch-chroot "$WORKDIR/rootfs" pacman -S --noconfirm --needed \
        base-devel \
        rust \
        cargo \
        sqlite
    
    # Install trunk for WASM builds
    arch-chroot "$WORKDIR/rootfs" cargo install trunk
    arch-chroot "$WORKDIR/rootfs" rustup target add wasm32-unknown-unknown
    
    # Copy source to chroot
    local src_dest="$WORKDIR/rootfs/tmp/keystone-src"
    mkdir -p "$src_dest"
    
    # Copy source files (excluding target directory and other large files)
    rsync -a --exclude='target' --exclude='.git' --exclude='*.iso' \
        "$(pwd)/" "$src_dest/"
    
    if [[ "$RUN_TESTS" == "true" ]]; then
        info "Running tests in chroot..."
        arch-chroot "$WORKDIR/rootfs" bash -c "
            cd /tmp/keystone-src
            cargo test --all
        "
    fi

    # Build the package
    arch-chroot "$WORKDIR/rootfs" bash -c "
        cd /tmp/keystone-src
        makepkg -sf --noconfirm
    "
    
    # Find the built package
    KEYSTONE_PKG=$(find "$WORKDIR/rootfs/tmp/keystone-src" -maxdepth 1 -name '*.pkg.tar.zst' | head -1)
    
    if [[ -z "$KEYSTONE_PKG" || ! -f "$KEYSTONE_PKG" ]]; then
        error "Failed to build keystone package"
        exit 1
    fi
    
    success "Package built: $KEYSTONE_PKG"
}

# Install keystone package
install_keystone() {
    info "Installing Keystone..."

    local host_pkg="$KEYSTONE_PKG"
    if [[ -z "$host_pkg" ]]; then
        error "Keystone package path is empty"
        exit 1
    fi

    if [[ ! -f "$host_pkg" ]]; then
        error "Keystone package not found: $host_pkg"
        exit 1
    fi

    # Always install from a path that exists *inside* the chroot.
    # If user provided a host-relative path (e.g. pkg/foo.pkg.tar.zst), make it absolute.
    if [[ "$host_pkg" != /* ]]; then
        host_pkg="$(pwd)/$host_pkg"
    fi

    local pkg_filename
    pkg_filename=$(basename "$host_pkg")

    # Put the package somewhere that won't be a tmpfs.
    local chroot_pkg="/root/$pkg_filename"

    cp -f "$host_pkg" "$WORKDIR/rootfs$chroot_pkg"

    if [[ ! -f "$WORKDIR/rootfs$chroot_pkg" ]]; then
        error "Keystone package not copied into chroot: $WORKDIR/rootfs$chroot_pkg"
        exit 1
    fi

    # Install the package from inside the chroot.
    arch-chroot "$WORKDIR/rootfs" pacman -U --noconfirm -- "$chroot_pkg"
    
    # Enable keystone services
    arch-chroot "$WORKDIR/rootfs" systemctl enable keystone-daemon
    arch-chroot "$WORKDIR/rootfs" systemctl enable keystone-web-ui
    
    success "Keystone installed and enabled"
}

# Create welcome message
create_welcome_message() {
    cat > "$WORKDIR/rootfs/etc/motd" << 'EOF'

 ╔═══════════════════════════════════════════════════════════════╗
 ║                                                               ║
 ║   ██╗  ██╗███████╗██╗   ██╗███████╗████████╗ ██████╗ ███╗   ██╗║
 ║   ██║ ██╔╝██╔════╝╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔═══██╗████╗  ██║║
 ║   █████╔╝ █████╗   ╚████╔╝ ███████╗   ██║   ██║   ██║██╔██╗ ██║║
 ║   ██╔═██╗ ██╔══╝    ╚██╔╝  ╚════██║   ██║   ██║   ██║██║╚██╗██║║
 ║   ██║  ██╗███████╗   ██║   ███████║   ██║   ╚██████╔╝██║ ╚████║║
 ║   ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝║
 ║                                                               ║
 ║              Linux Router/Firewall Manager                    ║
 ║                                                               ║
 ╚═══════════════════════════════════════════════════════════════╝

 Web UI:     http://<this-ip>:8080
 Default credentials: admin / admin  ← CHANGE IMMEDIATELY!

 Quick commands:
   keystonectl health     Check daemon status
   keystonectl state      View current state
   journalctl -u keystone-daemon -f    View daemon logs

 Default passwords (CHANGE THESE!):
   root:keystone
   keystone:keystone

EOF
}

# Final cleanup in chroot
finalize_installation() {
    info "Finalizing installation..."
    
    # Clean package cache
    arch-chroot "$WORKDIR/rootfs" pacman -Scc --noconfirm
    
    # Remove build artifacts
    rm -rf "$WORKDIR/rootfs/tmp/"*
    
    # Create welcome message
    create_welcome_message
    
    success "Installation finalized"
}

# Print completion message
print_completion() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    Installation Complete!                    ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Your Keystone USB drive is ready!"
    echo ""
    echo "To use:"
    echo "  1. Boot your router hardware from the USB drive"
    echo "  2. Login as root/keystone or keystone/keystone"
    echo "  3. CHANGE THE DEFAULT PASSWORDS IMMEDIATELY:"
    echo "       passwd root"
    echo "       passwd keystone"
    echo "  4. Access the web UI at http://<router-ip>:8080"
    echo "  5. Login with admin/admin and change the password"
    echo ""
    echo "Keystone services will start automatically on boot."
    echo ""
    echo "Device: $DEVICE"
    echo "Hostname: $HOSTNAME"
    echo ""
}

# Main function
main() {
    parse_args "$@"

    if [[ $# -eq 0 ]]; then
        usage
    fi

    if [[ "$MODE" != "upgrade-keystone" ]]; then
        echo ""
        echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║           Keystone Live USB Creator                         ║${NC}"
        echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
    fi

    validate_requirements
    confirm_operation

    # Set up trap for cleanup
    trap cleanup EXIT

    setup_workdir

    mkdir -p "$(dirname "$LOGFILE")"
    : > "$LOGFILE"
    exec > >(tee -a "$LOGFILE") 2>&1
    info "Logging to: $LOGFILE"

    if [[ "$MODE" == "upgrade-keystone" ]]; then
        mount_filesystems
        build_keystone_package
        install_keystone

        CLEANUP_WORKDIR=false
        success "Keystone upgraded"
        return 0
    fi

    partition_device
    mount_filesystems
    mount_iso
    install_base_system
    generate_fstab
    configure_system
    install_bootloader
    build_keystone_package
    install_keystone
    finalize_installation

    # Success - disable cleanup trap for workdir
    CLEANUP_WORKDIR=false

    print_completion
}

main "$@"
