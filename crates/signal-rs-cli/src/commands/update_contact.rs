use color_eyre::Result;

use signal_rs_manager::manager::SignalManager;

use super::{load_manager, parse_recipient, GlobalOpts};

#[derive(clap::Args)]
pub struct UpdateContactArgs {
    #[arg(short, long, help = "Recipient phone number or UUID")]
    pub recipient: String,

    #[arg(short, long, help = "Set contact name")]
    pub name: Option<String>,

    #[arg(long, help = "Set message expiration timer in seconds")]
    pub expiration: Option<u32>,
}

pub async fn execute(args: UpdateContactArgs, global: &GlobalOpts) -> Result<()> {
    let manager = load_manager(global.account.as_deref(), global.config.as_deref(), global.db_passphrase.as_deref())?;
    let recipient = parse_recipient(&args.recipient);

    if let Some(name) = &args.name {
        // Split name into given/family at the first space
        let (given, family) = match name.split_once(' ') {
            Some((g, f)) => (g, Some(f)),
            None => (name.as_str(), None),
        };

        manager.set_contact_name(&recipient, given, family).await
            .map_err(|e| color_eyre::eyre::eyre!("failed to set contact name: {e}"))?;
        eprintln!("Contact name updated.");
    }

    if let Some(seconds) = args.expiration {
        manager.set_expiration_timer(&recipient, seconds).await
            .map_err(|e| color_eyre::eyre::eyre!("failed to set expiration timer: {e}"))?;
        if seconds == 0 {
            eprintln!("Disappearing messages disabled.");
        } else {
            eprintln!("Disappearing messages set to {seconds} seconds.");
        }
    }

    Ok(())
}
