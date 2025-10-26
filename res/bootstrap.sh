#!/bin/bash
# Bootstrap script for nftsim
# Builds custom UML kernel and creates rootfs with modules
# Run as regular user - will use sudo only when needed
# Can also run as root (for container/test environments)
#
# Usage: bootstrap.sh <build_dir> <kernel_config_path>

set -euo pipefail

# Add system binary paths (needed for debootstrap, mkfs.ext4, etc.)
export PATH="/usr/sbin:/sbin:$PATH"

# Accept build directory and kernel config as parameters
BUILD_BASE_DIR="${1:-./build}"
KERNEL_CONFIG="${2:-kernel.config}"

# Resolve to absolute paths
BUILD_BASE_DIR="$(cd "$(dirname "$BUILD_BASE_DIR")" && pwd)/$(basename "$BUILD_BASE_DIR")"

ROOTFS_IMAGE="$BUILD_BASE_DIR/rootfs.img"
ROOTFS_MOUNT_DIR="$BUILD_BASE_DIR/mnt_rootfs"
IMAGE_SIZE_MB=2048
UML_BINARY="$BUILD_BASE_DIR/linux/linux"
DEBIAN_CODENAME="bookworm"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}==>${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}Warning:${NC} $*"
}

log_error() {
    echo -e "${RED}Error:${NC} $*" >&2
}

# Detect if running as root
if [[ $EUID -eq 0 ]]; then
    log_warn "Running as root - skipping sudo for privileged operations"
    RUNNING_AS_ROOT=true
else
    log_info "Running as regular user - will use sudo when needed"
    RUNNING_AS_ROOT=false
fi

# Helper function to conditionally use sudo
maybe_sudo() {
    if [[ "$RUNNING_AS_ROOT" = true ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

log_info "Starting nftsim bootstrap process"

# Check for required commands
if [[ "$RUNNING_AS_ROOT" = true ]]; then
    REQUIRED_CMDS="debootstrap dd mkfs.ext4 mount umount make gcc flex bison bc"
else
    REQUIRED_CMDS="debootstrap dd mkfs.ext4 mount umount make gcc flex bison bc sudo"
fi

for cmd in $REQUIRED_CMDS; do
    if ! command -v "$cmd" &> /dev/null; then
        log_error "Required command '$cmd' not found"
        exit 1
    fi
done

# Test sudo access early (only if not root)
if [[ "$RUNNING_AS_ROOT" = false ]]; then
    if ! sudo -v; then
        log_error "sudo access required for mount/debootstrap operations"
        exit 1
    fi
fi

# Check for kernel.config
if [[ ! -f "$KERNEL_CONFIG" ]]; then
    log_error "Kernel config file '$KERNEL_CONFIG' not found"
    exit 1
fi

# Find kernel source in /usr/src
log_info "Looking for UML kernel source in /usr/src"
KERNEL_SRC=""

# Try to find user-mode-linux source package
for src in /usr/src/user-mode-linux-*; do
    if [[ -d "$src" ]]; then
        KERNEL_SRC="$src"
        break
    fi
done

# Try to find unpacked linux source
if [[ -z "$KERNEL_SRC" ]]; then
    for src in /usr/src/linux-source-* /usr/src/linux-*; do
        if [[ -d "$src" ]]; then
            KERNEL_SRC="$src"
            break
        fi
    done
fi

# Try to find and extract tarball
if [[ -z "$KERNEL_SRC" ]]; then
    for tarball in /usr/src/linux-source-*.tar.xz /usr/src/linux-source-*.tar.bz2; do
        if [[ -f "$tarball" ]]; then
            log_info "Extracting kernel source from $tarball"
            maybe_sudo tar -C /usr/src -xf "$tarball"
            KERNEL_SRC="${tarball%.tar.*}"
            break
        fi
    done
fi

if [[ -z "$KERNEL_SRC" ]]; then
    log_error "Could not find kernel source in /usr/src"
    log_error "Please install: apt-get install linux-source"
    exit 1
fi

log_info "Found kernel source: $KERNEL_SRC"

# Build UML kernel
BUILD_DIR="$BUILD_BASE_DIR/linux"

# Check if we need to rebuild the kernel
REBUILD_KERNEL=false
if [[ ! -f "$UML_BINARY" ]]; then
    log_info "Kernel binary not found, will build"
    REBUILD_KERNEL=true
elif [[ ! -d "$BUILD_DIR" ]]; then
    log_info "Kernel build directory not found, will build"
    REBUILD_KERNEL=true
elif [[ "$KERNEL_CONFIG" -nt "$UML_BINARY" ]]; then
    log_info "Kernel config newer than binary, will rebuild"
    REBUILD_KERNEL=true
fi

if [[ "$REBUILD_KERNEL" = true ]]; then
    log_info "Building UML kernel with custom config"

    # Create kernel build directory if it doesn't exist
    if [[ ! -d "$BUILD_DIR" ]]; then
        log_info "Creating kernel build directory: $BUILD_DIR"
        mkdir -p "$BUILD_DIR"
        cp -r "$KERNEL_SRC"/* "$BUILD_DIR/"
    fi

    cd "$BUILD_DIR"

    # Copy the known-working kernel config
    log_info "Copying kernel.config to build directory..."
    cp "$KERNEL_CONFIG" .config

    # Update config for new kernel options without prompting
    log_info "Updating config for kernel version compatibility..."
    make ARCH=um olddefconfig > /dev/null 2>&1

    # Verify critical features are present
    log_info "Verifying kernel configuration..."
    if ! grep -q "CONFIG_HOSTFS=y" .config; then
        log_error "CONFIG_HOSTFS not enabled in kernel.config"
        exit 1
    fi
    if ! grep -q "CONFIG_NF_TABLES_INET=" .config; then
        log_error "CONFIG_NF_TABLES_INET not enabled in kernel.config"
        exit 1
    fi

    log_info "Kernel config verified - all features present"

    # Build the kernel and modules
    log_info "Compiling UML kernel (this may take several minutes)..."
    make ARCH=um -j$(nproc) linux modules

    log_info "Preparing modules directory..."
    make ARCH=um INSTALL_MOD_PATH=./prefix modules_install

    if [[ ! -f linux ]]; then
        log_error "Kernel build failed - linux binary not found"
        exit 1
    fi

    log_info "Kernel built successfully (all features built-in)"

    # Return to project directory
    cd "$OLDPWD"
else
    log_info "Kernel binary is up to date, skipping build"
fi

# Check if rootfs already exists
if [[ -f "$ROOTFS_IMAGE" ]]; then
    log_warn "Root filesystem image '$ROOTFS_IMAGE' already exists"
    read -p "Delete and recreate? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Keeping existing rootfs, only updating kernel"
        log_info "Bootstrap complete (kernel only)"
        exit 0
    fi
    rm -f "$ROOTFS_IMAGE"
fi

# Create rootfs image
log_info "Creating ${IMAGE_SIZE_MB}MB disk image"
dd if=/dev/zero of="$ROOTFS_IMAGE" bs=1M count=$IMAGE_SIZE_MB status=progress

log_info "Creating ext4 filesystem"
mkfs.ext4 -F "$ROOTFS_IMAGE"

# Mount image (needs sudo)
mkdir -p "$ROOTFS_MOUNT_DIR"
log_info "Mounting image to $ROOTFS_MOUNT_DIR"
maybe_sudo mount -o loop "$ROOTFS_IMAGE" "$ROOTFS_MOUNT_DIR"

# Ensure unmount on exit
cleanup() {
    log_info "Cleaning up..."
    if mountpoint -q "$ROOTFS_MOUNT_DIR" 2>/dev/null; then
        maybe_sudo umount "$ROOTFS_MOUNT_DIR" || log_warn "Failed to unmount $ROOTFS_MOUNT_DIR"
    fi
    rm -rf "$ROOTFS_MOUNT_DIR"
}
trap cleanup EXIT

# Run debootstrap (needs sudo)
CACHE_DIR="$BUILD_BASE_DIR/rootfs-cache"
mkdir -p "$CACHE_DIR"

log_info "Running debootstrap for $DEBIAN_CODENAME (will take a while)..."
log_info "Using package cache directory: $CACHE_DIR"
PACKAGES="nftables,tcpdump,iproute2,iputils-ping,socat,coreutils,kmod"
maybe_sudo debootstrap --cache-dir="$CACHE_DIR" --include="$PACKAGES" "$DEBIAN_CODENAME" "$ROOTFS_MOUNT_DIR"

log_info "Debootstrap complete"

# Create mount point directory (needs sudo since rootfs is owned by root)
log_info "Creating /mnt/host directory in rootfs"
maybe_sudo mkdir -p "$ROOTFS_MOUNT_DIR/mnt/host"

# No modules to copy - all features are built-in to kernel
log_info "All netfilter features built into kernel (no modules needed)"

# Create static init script (needs sudo)
log_info "Creating static init script"
maybe_sudo tee "$ROOTFS_MOUNT_DIR/sbin/init.sh" > /dev/null << 'EOF'
#!/bin/sh
set -e
echo "NFTsim static init started"

# Mount proc and sys to read kernel cmdline
mount -t proc none /proc
mount -t sysfs none /sys

# Parse kernel command line for nftsim parameters
CMDLINE=$(cat /proc/cmdline)

# Extract nftsim_tmpdir parameter
TMPDIR_PATH=""
for param in $CMDLINE; do
  case "$param" in
    nftsim_tmpdir=*)
      TMPDIR_PATH="${param#nftsim_tmpdir=}"
      ;;
  esac
done

# Mount tmpdir to /mnt/host
if [ -z "$TMPDIR_PATH" ]; then
  echo "FATAL: nftsim_tmpdir not found in kernel cmdline"
  sleep 10
  exit 1
fi

echo "Mounting tmpdir from: $TMPDIR_PATH"
mkdir -p /mnt/host
mount -t hostfs -o "$TMPDIR_PATH" hostfs /mnt/host

# Extract nftsim_modules parameter and mount if present
MODULES_PATH=""
for param in $CMDLINE; do
  case "$param" in
    nftsim_modules=*)
      MODULES_PATH="${param#nftsim_modules=}"
      ;;
  esac
done

if [ -n "$MODULES_PATH" ]; then
  echo "Mounting kernel modules from: $MODULES_PATH"
  mkdir -p /lib/modules
  mount -t hostfs -o "$MODULES_PATH" hostfs /lib/modules

  # Load required netfilter modules
  echo "Loading netfilter modules..."
  modprobe nf_tables || true
  modprobe nft_counter || true
  modprobe nft_ct || true
  modprobe nft_limit || true
  modprobe nft_nat || true
  modprobe nft_quota || true
  modprobe nft_reject || true
  modprobe nft_reject_inet || true
  modprobe nf_tables_inet || true
  modprobe nf_conntrack || true
  modprobe nf_nat || true
  modprobe nf_defrag_ipv4 || true
  modprobe nf_defrag_ipv6 || true
  modprobe nf_conntrack_netlink || true
  echo "Module loading complete"
fi

# Execute entrypoint script
if [ -x "/mnt/host/entrypoint.sh" ]; then
  exec /mnt/host/entrypoint.sh
else
  echo "FATAL: /mnt/host/entrypoint.sh not found or not executable."
  sleep 10
  exit 1
fi
EOF

maybe_sudo chmod +x "$ROOTFS_MOUNT_DIR/sbin/init.sh"

# Unmount (needs sudo, cleanup trap will handle this, but do it explicitly)
log_info "Unmounting rootfs"
maybe_sudo umount "$ROOTFS_MOUNT_DIR"

log_info "Bootstrap complete!"
log_info "  Kernel: $UML_BINARY"
log_info "  Rootfs: $ROOTFS_IMAGE"
log_info ""
log_info "You can now run tests:"
log_info "  nftsim test <ruleset.nft> <config.toml>"
