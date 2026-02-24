use color_eyre::Result;

#[derive(clap::Args)]
pub struct SubmitRateLimitChallengeArgs {
    #[arg(long, help = "Challenge token")]
    pub challenge: String,

    #[arg(long, help = "CAPTCHA token")]
    pub captcha: String,
}

pub async fn execute(args: SubmitRateLimitChallengeArgs) -> Result<()> {
    let manager = super::load_manager(None, None, None)?;

    use signal_rs_manager::manager::SignalManager;

    manager
        .submit_rate_limit_challenge(&args.challenge, &args.captcha)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to submit rate limit challenge: {e}"))?;

    eprintln!("Rate limit challenge submitted successfully.");
    Ok(())
}
