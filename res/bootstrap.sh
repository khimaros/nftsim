#!/bin/bash
# bootstrap script for nftsim: builds the custom UML kernel and a Debian rootfs.
# runs as a regular user with sudo for privileged steps, or directly as root
# in container/test environments.
#
# usage: bootstrap.sh <build_dir> <kernel_config_path>

set -euo pipefail

# debootstrap, mkfs.ext4 and friends live in the sbin directories
export PATH="/usr/sbin:/sbin:$PATH"

BUILD_BASE_DIR="${1:-./build}"
KERNEL_CONFIG="${2:-kernel.config}"

BUILD_BASE_DIR="$(cd "$(dirname "$BUILD_BASE_DIR")" && pwd)/$(basename "$BUILD_BASE_DIR")"

ROOTFS_IMAGE="$BUILD_BASE_DIR/rootfs.img"
ROOTFS_MOUNT_DIR="$BUILD_BASE_DIR/mnt_rootfs"
IMAGE_SIZE_MB=2048
UML_BINARY="$BUILD_BASE_DIR/linux/linux"
DEBIAN_CODENAME="bookworm"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}==>${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}warning:${NC} $*"
}

log_error() {
    echo -e "${RED}error:${NC} $*" >&2
}

if [[ $EUID -eq 0 ]]; then
    log_warn "running as root, skipping sudo for privileged operations"
    RUNNING_AS_ROOT=true
else
    log_info "running as regular user, will use sudo when needed"
    RUNNING_AS_ROOT=false
fi

# run a privileged command, using sudo only when not already root
maybe_sudo() {
    if [[ "$RUNNING_AS_ROOT" = true ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

log_info "starting nftsim bootstrap process"

if [[ "$RUNNING_AS_ROOT" = true ]]; then
    REQUIRED_CMDS="debootstrap dd mkfs.ext4 mount umount make gcc flex bison bc"
else
    REQUIRED_CMDS="debootstrap dd mkfs.ext4 mount umount make gcc flex bison bc sudo"
fi

for cmd in $REQUIRED_CMDS; do
    if ! command -v "$cmd" &> /dev/null; then
        log_error "required command '$cmd' not found"
        exit 1
    fi
done

# prompt for the sudo password up front instead of midway through a long build
if [[ "$RUNNING_AS_ROOT" = false ]]; then
    if ! sudo -v; then
        log_error "sudo access required for mount/debootstrap operations"
        exit 1
    fi
fi

if [[ ! -f "$KERNEL_CONFIG" ]]; then
    log_error "kernel config file '$KERNEL_CONFIG' not found"
    exit 1
fi

# prefer the user-mode-linux source package, then an unpacked linux source
# tree, then a linux-source tarball that still needs extracting
log_info "looking for UML kernel source in /usr/src"
KERNEL_SRC=""

for src in /usr/src/user-mode-linux-*; do
    if [[ -d "$src" ]]; then
        KERNEL_SRC="$src"
        break
    fi
done

if [[ -z "$KERNEL_SRC" ]]; then
    for src in /usr/src/linux-source-* /usr/src/linux-*; do
        if [[ -d "$src" ]]; then
            KERNEL_SRC="$src"
            break
        fi
    done
fi

if [[ -z "$KERNEL_SRC" ]]; then
    for tarball in /usr/src/linux-source-*.tar.xz /usr/src/linux-source-*.tar.bz2; do
        if [[ -f "$tarball" ]]; then
            log_info "extracting kernel source from $tarball"
            maybe_sudo tar -C /usr/src -xf "$tarball"
            KERNEL_SRC="${tarball%.tar.*}"
            break
        fi
    done
fi

if [[ -z "$KERNEL_SRC" ]]; then
    log_error "could not find kernel source in /usr/src"
    log_error "please install: apt-get install linux-source"
    exit 1
fi

log_info "found kernel source: $KERNEL_SRC"

BUILD_DIR="$BUILD_BASE_DIR/linux"

REBUILD_KERNEL=false
if [[ ! -f "$UML_BINARY" ]]; then
    log_info "kernel binary not found, will build"
    REBUILD_KERNEL=true
elif [[ ! -d "$BUILD_DIR" ]]; then
    log_info "kernel build directory not found, will build"
    REBUILD_KERNEL=true
elif [[ "$KERNEL_CONFIG" -nt "$UML_BINARY" ]]; then
    log_info "kernel config newer than binary, will rebuild"
    REBUILD_KERNEL=true
fi

if [[ "$REBUILD_KERNEL" = true ]]; then
    log_info "building UML kernel with custom config"

    if [[ ! -d "$BUILD_DIR" ]]; then
        log_info "creating kernel build directory: $BUILD_DIR"
        mkdir -p "$BUILD_DIR"
        cp -r "$KERNEL_SRC"/* "$BUILD_DIR/"
    fi

    cd "$BUILD_DIR"

    log_info "copying kernel.config to build directory..."
    cp "$KERNEL_CONFIG" .config

    # fill in options the source tree has but kernel.config predates
    log_info "updating config for kernel version compatibility..."
    make ARCH=um olddefconfig > /dev/null 2>&1

    log_info "verifying kernel configuration..."
    if ! grep -q "CONFIG_HOSTFS=y" .config; then
        log_error "CONFIG_HOSTFS not enabled in kernel.config"
        exit 1
    fi
    if ! grep -q "CONFIG_NF_TABLES_INET=" .config; then
        log_error "CONFIG_NF_TABLES_INET not enabled in kernel.config"
        exit 1
    fi
    # the guest's interfaces are vector devices; without the driver the guest
    # panics at boot when it cannot find vec0
    if ! grep -q "CONFIG_UML_NET_VECTOR=y" .config; then
        log_error "CONFIG_UML_NET_VECTOR not enabled after olddefconfig (does this kernel need another UML_NET option?)"
        exit 1
    fi

    log_info "kernel config verified, all features present"

    log_info "compiling UML kernel (this may take several minutes)..."
    make ARCH=um -j"$(nproc)" linux modules

    log_info "preparing modules directory..."
    make ARCH=um INSTALL_MOD_PATH=./prefix modules_install

    if [[ ! -f linux ]]; then
        log_error "kernel build failed, linux binary not found"
        exit 1
    fi

    log_info "kernel built successfully (all features built-in)"

    cd "$OLDPWD"
else
    log_info "kernel binary is up to date, skipping build"
fi

if [[ -f "$ROOTFS_IMAGE" ]]; then
    log_warn "root filesystem image '$ROOTFS_IMAGE' already exists"
    read -p "delete and recreate? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "keeping existing rootfs, only updating kernel"
        log_info "bootstrap complete (kernel only)"
        exit 0
    fi
    rm -f "$ROOTFS_IMAGE"
fi

log_info "creating ${IMAGE_SIZE_MB}MB disk image"
dd if=/dev/zero of="$ROOTFS_IMAGE" bs=1M count=$IMAGE_SIZE_MB status=progress

log_info "creating ext4 filesystem"
mkfs.ext4 -F "$ROOTFS_IMAGE"

mkdir -p "$ROOTFS_MOUNT_DIR"
log_info "mounting image to $ROOTFS_MOUNT_DIR"
maybe_sudo mount -o loop "$ROOTFS_IMAGE" "$ROOTFS_MOUNT_DIR"

# unmount the loop image on any exit so a failed debootstrap does not leave it mounted
cleanup() {
    log_info "cleaning up..."
    if mountpoint -q "$ROOTFS_MOUNT_DIR" 2>/dev/null; then
        maybe_sudo umount "$ROOTFS_MOUNT_DIR" || log_warn "failed to unmount $ROOTFS_MOUNT_DIR"
    fi
    rm -rf "$ROOTFS_MOUNT_DIR"
}
trap cleanup EXIT

CACHE_DIR="$BUILD_BASE_DIR/rootfs-cache"
mkdir -p "$CACHE_DIR"

log_info "running debootstrap for $DEBIAN_CODENAME (will take a while)..."
log_info "using package cache directory: $CACHE_DIR"
PACKAGES="nftables,tcpdump,iproute2,iputils-ping,socat,coreutils,kmod"
maybe_sudo debootstrap --cache-dir="$CACHE_DIR" --include="$PACKAGES" "$DEBIAN_CODENAME" "$ROOTFS_MOUNT_DIR"

log_info "debootstrap complete"

# the rootfs is owned by root, so even mkdir needs privileges
log_info "creating /mnt/host directory in rootfs"
maybe_sudo mkdir -p "$ROOTFS_MOUNT_DIR/mnt/host"

log_info "all netfilter features built into kernel (no modules needed)"

# init.sh mounts the per-run hostfs directories named on the kernel cmdline,
# then hands off to the entrypoint nftsim placed there
log_info "creating static init script"
maybe_sudo tee "$ROOTFS_MOUNT_DIR/sbin/init.sh" > /dev/null << 'EOF'
#!/bin/sh
set -e
echo "nftsim static init started"

# /proc is needed to read the kernel cmdline
mount -t proc none /proc
mount -t sysfs none /sys

CMDLINE=$(cat /proc/cmdline)

TMPDIR_PATH=""
for param in $CMDLINE; do
  case "$param" in
    nftsim_tmpdir=*)
      TMPDIR_PATH="${param#nftsim_tmpdir=}"
      ;;
  esac
done

if [ -z "$TMPDIR_PATH" ]; then
  echo "fatal: nftsim_tmpdir not found in kernel cmdline"
  sleep 10
  exit 1
fi

echo "mounting tmpdir from: $TMPDIR_PATH"
mkdir -p /mnt/host
mount -t hostfs -o "$TMPDIR_PATH" hostfs /mnt/host

MODULES_PATH=""
for param in $CMDLINE; do
  case "$param" in
    nftsim_modules=*)
      MODULES_PATH="${param#nftsim_modules=}"
      ;;
  esac
done

# nftsim_modules is only set when the user passes a kernel modules path
if [ -n "$MODULES_PATH" ]; then
  echo "mounting kernel modules from: $MODULES_PATH"
  mkdir -p /lib/modules
  mount -t hostfs -o "$MODULES_PATH" hostfs /lib/modules

  echo "loading netfilter modules..."
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
  echo "module loading complete"
fi

if [ -x "/mnt/host/entrypoint.sh" ]; then
  exec /mnt/host/entrypoint.sh
else
  echo "fatal: /mnt/host/entrypoint.sh not found or not executable"
  sleep 10
  exit 1
fi
EOF

maybe_sudo chmod +x "$ROOTFS_MOUNT_DIR/sbin/init.sh"

# unmount explicitly so a failure aborts the build; the trap only warns
log_info "unmounting rootfs"
maybe_sudo umount "$ROOTFS_MOUNT_DIR"

log_info "bootstrap complete"
log_info "  kernel: $UML_BINARY"
log_info "  rootfs: $ROOTFS_IMAGE"
log_info ""
log_info "you can now run tests:"
log_info "  nftsim test <ruleset.nft> <config.toml>"
