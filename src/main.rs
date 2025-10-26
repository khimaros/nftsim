// src/main.rs

mod cli;
mod commands;
mod config;
mod resources;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Bootstrap(args) => {
            commands::bootstrap::handle_bootstrap(args).await?;
        }
        Commands::Test(args) => {
            commands::test::handle_test(args).await?;
        }
    }

    Ok(())
}
