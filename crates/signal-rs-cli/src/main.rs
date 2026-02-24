use clap::Parser;
use color_eyre::Result;

mod cli;
mod commands;
mod output;

fn main() -> Result<()> {
    color_eyre::install()?;
    let cli = cli::Cli::parse();

    // Setup logging
    let filter = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| filter.into()),
        )
        .init();

    // Build tokio runtime and dispatch
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(commands::dispatch(cli))
}
