use color_eyre::Result;

use super::data_dir;

#[derive(clap::Args)]
pub struct ListAccountsArgs {}

pub async fn execute(_args: ListAccountsArgs) -> Result<()> {
    let dir = data_dir();

    if !dir.exists() {
        eprintln!("No data directory found at {}", dir.display());
        return Ok(());
    }

    let entries = std::fs::read_dir(&dir)
        .map_err(|e| color_eyre::eyre::eyre!("cannot read directory: {e}"))?;

    let mut found = false;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("db") {
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("?");
            // Try to format as phone number (add + prefix)
            let display = if stem.chars().all(|c| c.is_ascii_digit()) {
                format!("+{stem}")
            } else {
                stem.to_string()
            };
            println!("{display}");
            found = true;
        }
    }

    if !found {
        println!("(no accounts found)");
    }

    Ok(())
}
