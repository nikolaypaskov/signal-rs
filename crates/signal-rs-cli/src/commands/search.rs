use color_eyre::Result;

use super::{load_database, GlobalOpts};

#[derive(clap::Args)]
pub struct SearchArgs {
    /// Search query string
    pub query: String,

    #[arg(long, help = "Filter by conversation (phone number, UUID, or thread ID)")]
    pub conversation: Option<String>,

    #[arg(long, default_value = "50", help = "Maximum number of results")]
    pub limit: usize,
}

pub async fn execute(args: SearchArgs, global: &GlobalOpts) -> Result<()> {
    let db = load_database(global.account.as_deref(), global.config.as_deref(), global.db_passphrase.as_deref())?;

    let mut results = db.search_messages(&args.query)
        .map_err(|e| color_eyre::eyre::eyre!("search failed: {e}"))?;

    // Optionally filter by conversation / thread
    if let Some(ref conversation) = args.conversation {
        // Try to interpret as thread ID first
        if let Ok(thread_id) = conversation.parse::<i64>() {
            results.retain(|m| m.thread_id == thread_id);
        } else {
            // Try to find the recipient by phone number or ACI
            let recipient = if conversation.starts_with('+') {
                db.get_recipient_by_number(conversation)
                    .ok()
                    .flatten()
            } else {
                db.get_recipient_by_aci(conversation)
                    .ok()
                    .flatten()
            };

            if let Some(r) = recipient {
                // Find all threads for this recipient and filter
                if let Ok(thread) = db.get_or_create_thread_for_recipient(r.id) {
                    results.retain(|m| m.thread_id == thread.id);
                }
            } else {
                eprintln!("Warning: could not find conversation for '{conversation}', showing all results.");
            }
        }
    }

    // Limit results
    results.truncate(args.limit);

    if results.is_empty() {
        eprintln!("No messages found matching '{}'.", args.query);
        return Ok(());
    }

    println!("Found {} result(s) for '{}':\n", results.len(), args.query);

    for msg in &results {
        let sender_name = msg.sender_id
            .and_then(|sid| db.get_recipient_by_id(sid).ok().flatten())
            .map(|r| r.display_name())
            .unwrap_or_else(|| "You".to_string());

        let ts = format_timestamp_millis(msg.timestamp);
        let body = msg.body.as_deref().unwrap_or("");

        // Highlight the snippet around the match
        let snippet = make_snippet(body, &args.query, 80);

        // Thread info
        let thread_info = get_thread_info(&db, msg.thread_id);

        println!("[{ts}] {sender_name} in {thread_info}:");
        println!("  {snippet}");
        println!();
    }

    Ok(())
}

/// Format a millisecond timestamp into a human-readable string.
fn format_timestamp_millis(ts_millis: i64) -> String {
    use std::time::{Duration, UNIX_EPOCH};
    let d = Duration::from_millis(ts_millis as u64);
    let dt = UNIX_EPOCH + d;
    // Use a simple format: YYYY-MM-DD HH:MM:SS
    let secs = dt.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Simple date calculation from days since epoch
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02} {hours:02}:{minutes:02}:{seconds:02}")
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
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

/// Make a snippet around the first match of `query` in `text`, padded to `max_len`.
fn make_snippet(text: &str, query: &str, max_len: usize) -> String {
    let lower_text = text.to_lowercase();
    let lower_query = query.to_lowercase();

    if let Some(pos) = lower_text.find(&lower_query) {
        let start = pos.saturating_sub(max_len / 2);
        let end = (pos + query.len() + max_len / 2).min(text.len());

        let mut snippet = String::new();
        if start > 0 {
            snippet.push_str("...");
        }
        snippet.push_str(&text[start..end]);
        if end < text.len() {
            snippet.push_str("...");
        }
        snippet
    } else {
        // Shouldn't happen since we searched, but truncate anyway
        if text.len() > max_len {
            format!("{}...", &text[..max_len])
        } else {
            text.to_string()
        }
    }
}

/// Get a display string for a thread (e.g. contact name or group).
fn get_thread_info(db: &signal_rs_store::Database, thread_id: i64) -> String {
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
