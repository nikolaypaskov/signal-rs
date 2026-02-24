use color_eyre::Result;

#[derive(clap::Args)]
pub struct ReceiveArgs {
    #[arg(short, long, default_value = "5", help = "Timeout in seconds (0 for infinite)")]
    pub timeout: u64,

    #[arg(long, help = "Maximum number of messages to receive")]
    pub max_messages: Option<u32>,

    #[arg(long, help = "Output messages as JSON")]
    pub json: bool,

    #[arg(long, help = "Send read receipts for received messages")]
    pub send_read_receipts: bool,
}

pub async fn execute(args: ReceiveArgs, global: &super::GlobalOpts) -> Result<()> {
    let manager = super::load_manager(global.account.as_deref(), global.config.as_deref(), global.db_passphrase.as_deref())?;

    use signal_rs_manager::manager::SignalManager;

    let messages = manager.receive_messages(args.timeout).await
        .map_err(|e| color_eyre::eyre::eyre!("failed to receive messages: {e}"))?;

    let messages = if let Some(max) = args.max_messages {
        &messages[..messages.len().min(max as usize)]
    } else {
        &messages
    };

    if args.json {
        let json = serde_json::to_string_pretty(messages)
            .map_err(|e| color_eyre::eyre::eyre!("failed to serialize messages: {e}"))?;
        println!("{json}");
    } else {
        if messages.is_empty() {
            eprintln!("No new messages.");
        }
        for msg in messages {
            let sender = msg.sender.as_deref().unwrap_or("unknown");
            let timestamp = format_timestamp(msg.timestamp);

            // Group prefix
            let group_prefix = msg.group_id.as_ref()
                .map(|g| format!("[group:{g}] "))
                .unwrap_or_default();

            // View-once marker
            let view_once = if msg.is_view_once { " [view-once]" } else { "" };

            // Main message line
            let text = msg.text.as_deref().unwrap_or("");
            println!("{group_prefix}{sender} ({timestamp}){view_once}: {text}");

            // Attachments with detail
            for att in &msg.attachments {
                println!("  Attachment: {att}");
            }

            // Reaction display
            if let Some(ref reaction) = msg.reaction {
                println!("  Reaction: {reaction}");
            }

            // Quote / reply display
            if let Some(ref quote) = msg.quote {
                let quote_text = quote.text.as_deref().unwrap_or("...");
                println!("  Reply to {}: \"{}\"", quote.author, truncate(quote_text, 60));
            }
        }
    }

    Ok(())
}

/// Format a millisecond epoch timestamp into a human-readable string.
fn format_timestamp(ts_millis: u64) -> String {
    use std::time::{Duration, UNIX_EPOCH};
    let d = Duration::from_millis(ts_millis);
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

/// Truncate a string to a maximum length, adding "..." if truncated.
fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max])
    } else {
        s.to_string()
    }
}
