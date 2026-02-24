use color_eyre::Result;

use super::{load_database, GlobalOpts};

#[derive(clap::Args)]
pub struct HistoryArgs {
    /// Conversation identifier: phone number (+1...), UUID, or thread ID
    pub conversation: String,

    #[arg(short, long, default_value = "50", help = "Number of messages to show")]
    pub limit: u32,

    #[arg(long, help = "Show messages before this timestamp (for pagination)")]
    pub before: Option<i64>,

    #[arg(long, help = "Output as JSON")]
    pub json: bool,
}

pub async fn execute(args: HistoryArgs, global: &GlobalOpts) -> Result<()> {
    let db = load_database(global.account.as_deref(), global.config.as_deref(), global.db_passphrase.as_deref())?;

    // Resolve the conversation to a thread ID
    let thread_id = resolve_thread(&db, &args.conversation)?;

    let messages = db
        .get_messages_by_thread(thread_id, args.limit, args.before)
        .map_err(|e| color_eyre::eyre::eyre!("failed to load messages: {e}"))?;

    if messages.is_empty() {
        eprintln!("No messages found.");
        return Ok(());
    }

    if args.json {
        let json = serde_json::to_string_pretty(&messages)
            .map_err(|e| color_eyre::eyre::eyre!("failed to serialize: {e}"))?;
        println!("{json}");
        return Ok(());
    }

    // Get thread info for the header
    let thread_name = get_thread_display_name(&db, thread_id);
    println!("--- History for {} ({} messages) ---\n", thread_name, messages.len());

    for msg in &messages {
        let sender_name = msg
            .sender_id
            .and_then(|sid| db.get_recipient_by_id(sid).ok().flatten())
            .map(|r| r.display_name())
            .unwrap_or_else(|| "You".to_string());

        let ts = format_timestamp_millis(msg.timestamp);
        let body = msg.body.as_deref().unwrap_or("[no text]");

        let attachment_indicator = if msg.attachments_json.is_some() {
            " [attachment]"
        } else {
            ""
        };

        println!("[{ts}] {sender_name}: {body}{attachment_indicator}");
    }

    if messages.len() as u32 == args.limit {
        let oldest_ts = messages.first().map(|m| m.timestamp).unwrap_or(0);
        eprintln!(
            "\n(showing {} messages, use --before {} to see older)",
            messages.len(),
            oldest_ts
        );
    }

    Ok(())
}

/// Resolve a conversation identifier to a thread ID.
fn resolve_thread(
    db: &signal_rs_store::Database,
    conversation: &str,
) -> Result<i64> {
    // Try as a numeric thread ID first
    if let Ok(thread_id) = conversation.parse::<i64>()
        && db
            .get_thread_by_id(thread_id)
            .map_err(|e| color_eyre::eyre::eyre!("db error: {e}"))?
            .is_some()
        {
            return Ok(thread_id);
        }

    // Try as a phone number
    if conversation.starts_with('+') {
        let recipient = db
            .get_recipient_by_number(conversation)
            .map_err(|e| color_eyre::eyre::eyre!("db error: {e}"))?;
        if let Some(r) = recipient {
            let thread = db
                .get_or_create_thread_for_recipient(r.id)
                .map_err(|e| color_eyre::eyre::eyre!("db error: {e}"))?;
            return Ok(thread.id);
        }
        return Err(color_eyre::eyre::eyre!(
            "no contact found for number '{conversation}'"
        ));
    }

    // Try as a UUID (ACI)
    if uuid::Uuid::parse_str(conversation).is_ok() {
        let recipient = db
            .get_recipient_by_aci(conversation)
            .map_err(|e| color_eyre::eyre::eyre!("db error: {e}"))?;
        if let Some(r) = recipient {
            let thread = db
                .get_or_create_thread_for_recipient(r.id)
                .map_err(|e| color_eyre::eyre::eyre!("db error: {e}"))?;
            return Ok(thread.id);
        }
        return Err(color_eyre::eyre::eyre!(
            "no contact found for UUID '{conversation}'"
        ));
    }

    // Try as a username
    let recipient = db
        .get_recipient_by_username(conversation)
        .map_err(|e| color_eyre::eyre::eyre!("db error: {e}"))?;
    if let Some(r) = recipient {
        let thread = db
            .get_or_create_thread_for_recipient(r.id)
            .map_err(|e| color_eyre::eyre::eyre!("db error: {e}"))?;
        return Ok(thread.id);
    }

    Err(color_eyre::eyre::eyre!(
        "could not resolve conversation '{conversation}'"
    ))
}

/// Get a display name for a thread.
fn get_thread_display_name(db: &signal_rs_store::Database, thread_id: i64) -> String {
    if let Ok(Some(thread)) = db.get_thread_by_id(thread_id) {
        if let Some(recipient_id) = thread.recipient_id
            && let Ok(Some(r)) = db.get_recipient_by_id(recipient_id) {
                return r.display_name();
            }
        if let Some(group_id) = thread.group_id {
            return format!("group #{group_id}");
        }
    }
    format!("thread #{thread_id}")
}

/// Format a millisecond timestamp into a human-readable string.
fn format_timestamp_millis(ts_millis: i64) -> String {
    use std::time::{Duration, UNIX_EPOCH};
    let d = Duration::from_millis(ts_millis as u64);
    let dt = UNIX_EPOCH + d;
    let secs = dt.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02} {hours:02}:{minutes:02}:{seconds:02}")
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
