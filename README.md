# signal-rs

A 100% Rust implementation of a Signal messenger client with CLI and TUI interfaces.

## Features

- **Device linking** - Link as a secondary device to an existing Signal account
- **Send & receive messages** - Full end-to-end encrypted messaging
- **Sealed sender** - Unidentified delivery for metadata protection
- **Groups v2** - Create, update, join, and manage group conversations
- **Post-quantum cryptography** - PQXDH with Kyber1024 key exchange
- **Attachments** - Upload and download media
- **Reactions & editing** - React to messages, edit and delete sent messages
- **Contacts & profiles** - Manage contacts, fetch profiles, username lookup
- **Storage sync** - Synchronize data across linked devices
- **Sticker packs** - Upload, install, and send stickers
- **Polls** - Create, vote, and manage polls
- **Disappearing messages** - Timer-based message expiration
- **Typing indicators & read receipts** - Real-time presence signals

## Status

| Category | Feature | Status |
|----------|---------|--------|
| Account | Device linking (secondary) | Working |
| Account | Registration | Working |
| Messaging | Send/receive (1:1) | Working |
| Messaging | Groups v2 | Working |
| Messaging | Sealed sender | Working |
| Messaging | Reactions | Working |
| Messaging | Edit/delete messages | Working |
| Messaging | Typing indicators | Working |
| Messaging | Read/delivery receipts | Working |
| Messaging | Disappearing messages | Working |
| Messaging | Polls | Working |
| Media | Attachments (send/receive) | Working |
| Media | Sticker packs | Working |
| Contacts | Profile fetch/update | Working |
| Contacts | Username lookup | Working |
| Contacts | Contact sync (storage service) | Working |
| Crypto | X3DH/PQXDH key exchange | Working |
| Crypto | Double ratchet | Working |
| Crypto | Post-quantum (Kyber1024) | Working |
| Storage | SQLCipher encrypted database | Working |
| TUI | Real-time messaging UI | Working |
| TUI | Conversation list & search | Working |
| Bridge | Claude Code via Signal | Working |
| Bridge | Session handover (desktop → phone) | Working |
| Calls | Voice/video calls | Not implemented |
| Backup | Remote backup/restore | Not implemented |
| Stories | Stories | Not implemented |

## Architecture

```
signal-rs workspace (8 crates)

  signal-rs-cli ──────┐
  signal-rs-tui ──────┤
  signal-rs-bridge ───┤
                      ▼
              signal-rs-manager    Orchestration & business logic
                 │         │
     signal-rs-service  signal-rs-store
     HTTP/WS comms      SQLCipher encrypted persistence
                 │
          signal-rs-protocol       Signal Protocol crypto
                 │
          signal-rs-protos         Protobuf definitions
```

| Crate | Purpose |
|-------|---------|
| `signal-rs-protos` | Protocol buffer message definitions |
| `signal-rs-protocol` | Signal Protocol: X3DH/PQXDH, double ratchet, sealed sender |
| `signal-rs-store` | SQLCipher encrypted persistence layer |
| `signal-rs-service` | HTTP REST + WebSocket communication |
| `signal-rs-manager` | High-level operations orchestration |
| `signal-rs-cli` | Command-line interface with 58+ commands |
| `signal-rs-tui` | Terminal UI with real-time messaging |
| `signal-rs-bridge` | Claude Code via Signal — interact with Claude from your phone |

## Prerequisites

- Rust 1.88+ (edition 2024) — install via [rustup](https://rustup.rs)
- A C compiler (for SQLCipher/OpenSSL bundled build)
  - macOS: `xcode-select --install`
  - Ubuntu/Debian: `apt install build-essential`
  - Fedora: `dnf install gcc`
- cmake (required by libsignal's boring-sys)
  - macOS: `brew install cmake`
  - Ubuntu/Debian: `apt install cmake`
- An existing Signal account on a phone (for device linking)

## Building

```bash
cargo build --release
```

The binaries will be at:
- `target/release/signal-rs` (CLI)
- `target/release/signal-rs-tui` (TUI)
- `target/release/signal-rs-bridge` (Claude Code bridge)

## Usage

### 1. Link as a secondary device

```bash
signal-rs link -n "my-device"
```

This displays a QR code. Scan it from your primary Signal app (Settings > Linked Devices).

### 2. Sync contacts

```bash
signal-rs send_sync_request
signal-rs receive
signal-rs list_contacts
```

### 3. Send a message

```bash
signal-rs send -r "+1234567890" -m "Hello from signal-rs"
```

### 4. Receive messages

```bash
signal-rs receive
```

### 5. Launch the TUI

```bash
signal-rs-tui
```

### 6. Claude Code Bridge

Run Claude Code from your phone via Signal messages:

```bash
# Link a dedicated Signal account for the bot
signal-rs link -n "claude-bot"

# Start the bridge
signal-rs-bridge \
  --owner <your-uuid-or-phone> \
  --directory /path/to/project \
  --dangerously-skip-permissions
```

Send messages from your phone to the bot's Signal number — they're piped to `claude --print` and the response is sent back.

**Bridge commands** (send via Signal):

| Command | Action |
|---------|--------|
| `/sessions` | List recent Claude sessions in the working directory |
| `/resume [id]` | Resume a specific session (handover from desktop) |
| `/reset` | Start a fresh Claude conversation |
| `/model [name]` | Show or switch the Claude model |
| `/status` | Show bridge uptime and session info |
| `/help` | Show all commands |

**Options**: `--claude-command <alias>` for custom claude aliases, `--model <name>`, `--max-message-length <n>`.

### CLI commands

Run `signal-rs --help` for the full command list. Key commands:

```
Account:     link, register, verify, unregister
Messaging:   send, receive, send_reaction, remote_delete
Groups:      update_group, join_group, quit_group, list_groups
Contacts:    list_contacts, update_contact, list_identities
Devices:     add_device, remove_device, list_devices
Stickers:    upload_sticker_pack, list_sticker_packs
Polls:       poll_create, poll_vote, poll_terminate
Other:       daemon, backup, search, history
```

### Output formats

```bash
signal-rs list_contacts --output json
signal-rs list_contacts --output table
signal-rs list_contacts --output plain
```

## Testing

```bash
cargo test
cargo clippy
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on building, testing, and submitting pull requests.

## Dependencies

Key dependencies:
- [libsignal](https://github.com/signalapp/libsignal) v0.87.4 - Official Signal crypto (Kyber KEM)
- [rusqlite](https://github.com/rusqlite/rusqlite) - SQLCipher encrypted database
- [tokio](https://tokio.rs) - Async runtime
- [reqwest](https://github.com/seanmonstar/reqwest) + [tokio-tungstenite](https://github.com/snapview/tokio-tungstenite) - HTTP & WebSocket
- [ratatui](https://ratatui.rs) - Terminal UI framework
- [clap](https://github.com/clap-rs/clap) - CLI argument parsing

## License

AGPL-3.0-only
