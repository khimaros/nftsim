// src/commands/bootstrap.rs

use crate::cli::BootstrapArgs;
use crate::resources;
use anyhow::{bail, Context, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use tempfile::TempDir;

/// Handle the `bootstrap` command by calling bootstrap.sh
pub async fn handle_bootstrap(_args: BootstrapArgs) -> Result<()> {
    println!("--- Starting bootstrap process ---");

    // Get build directory in $HOME
    let build_dir = resources::get_build_dir()?;
    println!("Build directory: {}", build_dir.display());

    // Create build directory if it doesn't exist
    fs::create_dir_all(&build_dir)
        .context("Failed to create build directory in $HOME/.local/share/nftsim")?;

    // Create a temporary directory for the bootstrap script and kernel config
    let temp_dir = TempDir::new().context("Failed to create temporary directory")?;

    // Write bundled bootstrap script to temp file
    let bootstrap_script_path = temp_dir.path().join("bootstrap.sh");
    fs::write(&bootstrap_script_path, resources::BOOTSTRAP_SCRIPT)
        .context("Failed to write bootstrap script")?;
    fs::set_permissions(&bootstrap_script_path, fs::Permissions::from_mode(0o755))
        .context("Failed to set bootstrap script permissions")?;

    // Write bundled kernel config to temp file
    let kernel_config_path = temp_dir.path().join("kernel.config");
    fs::write(&kernel_config_path, resources::KERNEL_CONFIG)
        .context("Failed to write kernel config")?;

    println!("Running bootstrap.sh (will prompt for sudo when needed)...\n");

    // Run bootstrap script with build directory and kernel config as arguments
    let status = Command::new(&bootstrap_script_path)
        .arg(&build_dir)
        .arg(&kernel_config_path)
        .status()
        .context("Failed to run bootstrap.sh")?;

    if !status.success() {
        bail!(
            "Bootstrap failed with exit code: {}",
            status.code().unwrap_or(-1)
        );
    }

    Ok(())
}
