use color_eyre::Result;

use signal_rs_manager::manager::SignalManager;

use super::{load_manager, parse_recipient, GlobalOpts};

#[derive(clap::Args)]
pub struct TrustArgs {
    #[arg(help = "Recipient phone number or UUID to trust")]
    pub recipient: String,

    #[arg(long, help = "Trust all known keys for this recipient")]
    pub trust_all_known_keys: bool,

    #[arg(long, help = "Verify safety number")]
    pub verified_safety_number: Option<String>,
}

pub async fn execute(args: TrustArgs, global: &GlobalOpts) -> Result<()> {
    let manager = load_manager(global.account.as_deref(), global.config.as_deref(), global.db_passphrase.as_deref())?;
    let recipient = parse_recipient(&args.recipient);

    if args.trust_all_known_keys {
        manager.trust_identity_all_keys(&recipient).await
            .map_err(|e| color_eyre::eyre::eyre!("failed to trust identity: {e}"))?;
        eprintln!("All keys trusted for {}.", args.recipient);
    } else if let Some(safety_number) = &args.verified_safety_number {
        manager.trust_identity_verified(&recipient, safety_number).await
            .map_err(|e| color_eyre::eyre::eyre!("failed to verify identity: {e}"))?;
        eprintln!("Identity verified for {}.", args.recipient);
    } else {
        return Err(color_eyre::eyre::eyre!(
            "specify --trust-all-known-keys or --verified-safety-number"
        ));
    }

    Ok(())
}
