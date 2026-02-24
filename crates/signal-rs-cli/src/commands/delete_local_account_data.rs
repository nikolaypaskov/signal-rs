use color_eyre::Result;

use super::{data_dir, GlobalOpts};

#[derive(clap::Args)]
pub struct DeleteLocalAccountDataArgs {
    #[arg(long, help = "Confirm deletion without prompting")]
    pub yes: bool,
}

pub async fn execute(args: DeleteLocalAccountDataArgs, global: &GlobalOpts) -> Result<()> {
    let dir = global
        .config
        .as_ref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(data_dir);

    let db_path = if let Some(ref phone) = global.account {
        let normalized = phone.replace('+', "");
        dir.join(format!("{normalized}.db"))
    } else {
        // Find any .db file
        let entries = std::fs::read_dir(&dir)
            .map_err(|e| color_eyre::eyre::eyre!("cannot read directory: {e}"))?;
        let mut found = None;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("db") {
                found = Some(path);
                break;
            }
        }
        found.ok_or_else(|| color_eyre::eyre::eyre!("no database found in {}", dir.display()))?
    };

    if !db_path.exists() {
        eprintln!("No database found at {}", db_path.display());
        return Ok(());
    }

    if !args.yes {
        let confirm = inquire::Confirm::new(&format!(
            "Delete local account data at {}?",
            db_path.display()
        ))
        .with_default(false)
        .prompt()
        .map_err(|e| color_eyre::eyre::eyre!("prompt failed: {e}"))?;

        if !confirm {
            eprintln!("Cancelled.");
            return Ok(());
        }
    }

    std::fs::remove_file(&db_path)
        .map_err(|e| color_eyre::eyre::eyre!("failed to delete database: {e}"))?;

    eprintln!("Local account data deleted: {}", db_path.display());
    Ok(())
}
