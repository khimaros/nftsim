use crate::cli::BootstrapArgs;
use crate::resources;
use anyhow::{bail, Context, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use tempfile::TempDir;

/// handle the `bootstrap` command by running the bundled bootstrap.sh
pub async fn handle_bootstrap(_args: BootstrapArgs) -> Result<()> {
    println!("--- starting bootstrap process ---");

    let build_dir = resources::get_build_dir()?;
    println!("build directory: {}", build_dir.display());

    fs::create_dir_all(&build_dir)
        .context("failed to create build directory in $HOME/.local/share/nftsim")?;

    // the script and kernel config are bundled in the binary, so stage them on disk
    let temp_dir = TempDir::new().context("failed to create temporary directory")?;

    let bootstrap_script_path = temp_dir.path().join("bootstrap.sh");
    fs::write(&bootstrap_script_path, resources::BOOTSTRAP_SCRIPT)
        .context("failed to write bootstrap script")?;
    fs::set_permissions(&bootstrap_script_path, fs::Permissions::from_mode(0o755))
        .context("failed to set bootstrap script permissions")?;

    let kernel_config_path = temp_dir.path().join("kernel.config");
    fs::write(&kernel_config_path, resources::KERNEL_CONFIG)
        .context("failed to write kernel config")?;

    println!("running bootstrap.sh (will prompt for sudo when needed)...\n");

    let status = Command::new(&bootstrap_script_path)
        .arg(&build_dir)
        .arg(&kernel_config_path)
        .status()
        .context("failed to run bootstrap.sh")?;

    if !status.success() {
        bail!(
            "bootstrap failed with exit code: {}",
            status.code().unwrap_or(-1)
        );
    }

    Ok(())
}
