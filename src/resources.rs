// src/resources.rs
//
// Embedded resources bundled into the binary at compile time

use anyhow::{Context, Result};
use std::path::PathBuf;

/// Bootstrap script for building UML kernel and creating rootfs
pub const BOOTSTRAP_SCRIPT: &str = include_str!("../res/bootstrap.sh");

/// Harness script that runs inside the UML guest
pub const HARNESS_SCRIPT: &str = include_str!("../res/harness.sh");

/// Kernel configuration for UML
pub const KERNEL_CONFIG: &str = include_str!("../res/kernel.config");

/// Get the build directory path in $HOME/.local/share/nftsim
pub fn get_build_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME environment variable not set")?;
    Ok(PathBuf::from(home).join(".local/share/nftsim"))
}

/// Get the kernel binary path
pub fn get_kernel_binary_path() -> Result<PathBuf> {
    Ok(get_build_dir()?.join("linux/linux"))
}

/// Get the rootfs image path
pub fn get_rootfs_path() -> Result<PathBuf> {
    Ok(get_build_dir()?.join("rootfs.img"))
}
