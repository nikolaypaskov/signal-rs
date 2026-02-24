use color_eyre::Result;

use signal_rs_store::database::account_keys;

use super::{load_database, GlobalOpts};

#[derive(clap::Args)]
pub struct StatusArgs {}

pub async fn execute(_args: StatusArgs, global: &GlobalOpts) -> Result<()> {
    let db = load_database(global.account.as_deref(), global.config.as_deref(), global.db_passphrase.as_deref())?;

    println!("Account Status");
    println!("{}", "-".repeat(40));

    // Phone number
    let phone = db.get_kv_string(account_keys::PHONE_NUMBER)
        .map_err(|e| color_eyre::eyre::eyre!("failed to read phone number: {e}"))?;
    println!("Phone number:  {}", phone.as_deref().unwrap_or("(not set)"));

    // ACI UUID
    let aci = db.get_kv_string(account_keys::ACI_UUID)
        .map_err(|e| color_eyre::eyre::eyre!("failed to read ACI: {e}"))?;
    println!("ACI UUID:      {}", aci.as_deref().unwrap_or("(not set)"));

    // PNI UUID
    let pni = db.get_kv_string(account_keys::PNI_UUID)
        .map_err(|e| color_eyre::eyre::eyre!("failed to read PNI: {e}"))?;
    println!("PNI UUID:      {}", pni.as_deref().unwrap_or("(not set)"));

    // Device ID
    let device_id = db.get_kv_string(account_keys::DEVICE_ID)
        .map_err(|e| color_eyre::eyre::eyre!("failed to read device ID: {e}"))?;
    println!("Device ID:     {}", device_id.as_deref().unwrap_or("1"));

    // Is primary device
    let is_primary = db.get_kv_string(account_keys::IS_PRIMARY_DEVICE)
        .map_err(|e| color_eyre::eyre::eyre!("failed to read primary device flag: {e}"))?;
    let primary_str = match is_primary.as_deref() {
        Some("true") | Some("1") => "Yes",
        Some("false") | Some("0") => "No (linked device)",
        _ => "Unknown",
    };
    println!("Primary:       {primary_str}");

    // Registration status
    let registered = db.get_kv_string(account_keys::REGISTERED)
        .map_err(|e| color_eyre::eyre::eyre!("failed to read registration status: {e}"))?;
    let reg_str = match registered.as_deref() {
        Some("true") | Some("1") => "Registered",
        Some("false") | Some("0") => "Not registered",
        _ => "Unknown",
    };
    println!("Registration:  {reg_str}");

    // Stats
    println!();
    println!("Database Statistics");
    println!("{}", "-".repeat(40));

    let contacts = db.list_contacts()
        .map_err(|e| color_eyre::eyre::eyre!("failed to count contacts: {e}"))?;
    println!("Contacts:      {}", contacts.len());

    let groups = db.list_all_groups()
        .map_err(|e| color_eyre::eyre::eyre!("failed to count groups: {e}"))?;
    println!("Groups:        {}", groups.len());

    let threads = db.list_threads()
        .map_err(|e| color_eyre::eyre::eyre!("failed to count threads: {e}"))?;
    println!("Conversations: {}", threads.len());

    let unread = db.get_total_unread_count()
        .map_err(|e| color_eyre::eyre::eyre!("failed to get unread count: {e}"))?;
    println!("Unread:        {unread}");

    Ok(())
}
