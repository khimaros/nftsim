// src/cli.rs

use clap::{Parser, Subcommand};

use std::path::PathBuf;

/// A tool for simulating and testing nftables rulesets using User-Mode Linux.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Create the UML root filesystem.
    Bootstrap(BootstrapArgs),
    /// Run a simulation test.
    Test(TestArgs),
}

#[derive(Parser, Debug, Clone)]
pub struct BootstrapArgs {
    // No arguments for bootstrap yet, but this is where they would go.
}

#[derive(Parser, Debug, Clone)]
pub struct TestArgs {
    /// Path to the nftables.conf file to test.
    #[arg(required = true)]
    pub ruleset_file: PathBuf,

    /// Paths to one or more test definition TOML files.
    #[arg(required = true, num_args = 1..)]
    pub config_files: Vec<PathBuf>,

    /// Enable detailed nftables trace output for debugging
    #[arg(long)]
    pub trace: bool,

    /// Show verbose output including all packet details
    #[arg(short, long)]
    pub verbose: bool,

    /// Keep temporary directory after test completion for debugging
    #[arg(long)]
    pub keep_temp: bool,

    /// Timeout in seconds for the simulation (default: 120)
    #[arg(long, default_value = "120")]
    pub timeout: u64,

    /// Use custom-built kernel from ./build/linux/ (overrides kernel-binary-path and kernel-modules-path)
    #[arg(long, default_value = "true")]
    pub kernel_custom: bool,

    /// Path to UML kernel binary (default: /usr/bin/linux.uml)
    #[arg(long, default_value = "/usr/bin/linux.uml")]
    pub kernel_binary_path: PathBuf,

    /// Path to UML kernel modules on host (default: /usr/lib/uml/modules, set empty to skip)
    #[arg(long, default_value = "/usr/lib/uml/modules")]
    pub kernel_modules_path: String,
}
