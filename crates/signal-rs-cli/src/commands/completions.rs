use clap::CommandFactory;
use clap_complete::Shell;
use color_eyre::Result;

#[derive(clap::Args)]
pub struct CompletionsArgs {
    #[arg(help = "Shell to generate completions for")]
    pub shell: Shell,
}

pub async fn execute(args: CompletionsArgs) -> Result<()> {
    let mut cmd = crate::cli::Cli::command();
    clap_complete::generate(args.shell, &mut cmd, "signal-rs", &mut std::io::stdout());
    Ok(())
}
