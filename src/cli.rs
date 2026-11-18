use clap::{Parser, Subcommand};

use std::path::PathBuf;

/// simulate and test nftables rulesets using User-Mode Linux
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// build the UML kernel and root filesystem
    Bootstrap(BootstrapArgs),
    /// run a simulation test
    Test(TestArgs),
}

#[derive(Parser, Debug, Clone)]
pub struct BootstrapArgs {}

#[derive(Parser, Debug, Clone)]
pub struct TestArgs {
    /// path to the nftables.conf file to test, or to a test definition TOML file
    /// that names its ruleset with a `ruleset` key
    #[arg(required = true)]
    pub ruleset_file: PathBuf,

    /// paths to one or more test definition TOML files (optional if using embedded tests)
    #[arg(num_args = 0..)]
    pub config_files: Vec<PathBuf>,

    /// write the result of every test case, with the reason for each failure,
    /// to this path as JSON
    #[arg(long)]
    pub report: Option<PathBuf>,

    /// enable detailed nftables trace output for debugging
    #[arg(long)]
    pub trace: bool,

    /// show verbose output including all packet details
    #[arg(short, long)]
    pub verbose: bool,

    /// keep temporary directory after test completion for debugging
    #[arg(long)]
    pub keep_temp: bool,

    /// timeout in seconds for the simulation
    #[arg(long, default_value = "120")]
    pub timeout: u64,

    /// use the custom-built kernel from ~/.local/share/nftsim/linux/ (overrides kernel-binary-path and kernel-modules-path)
    #[arg(long, default_value = "true")]
    pub kernel_custom: bool,

    /// path to UML kernel binary
    #[arg(long, default_value = "/usr/bin/linux.uml")]
    pub kernel_binary_path: PathBuf,

    /// path to UML kernel modules on host (set empty to skip)
    #[arg(long, default_value = "/usr/lib/uml/modules")]
    pub kernel_modules_path: String,
}
