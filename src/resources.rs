// resources bundled into the binary at compile time

use anyhow::{Context, Result};
use std::path::PathBuf;

/// builds the UML kernel and creates the rootfs
pub const BOOTSTRAP_SCRIPT: &str = include_str!("../res/bootstrap.sh");

/// runs inside the UML guest
pub const HARNESS_SCRIPT: &str = include_str!("../res/harness.sh");

/// kernel configuration for UML
pub const KERNEL_CONFIG: &str = include_str!("../res/kernel.config");

/// per-user build directory, $HOME/.local/share/nftsim
pub fn get_build_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME environment variable not set")?;
    Ok(PathBuf::from(home).join(".local/share/nftsim"))
}

/// custom UML kernel binary built by bootstrap
pub fn get_kernel_binary_path() -> Result<PathBuf> {
    Ok(get_build_dir()?.join("linux/linux"))
}

/// rootfs image built by bootstrap
pub fn get_rootfs_path() -> Result<PathBuf> {
    Ok(get_build_dir()?.join("rootfs.img"))
}
