# signal-rs

100% Rust Signal messenger client. Workspace with 8 crates: protos, protocol, store, service, manager, cli, tui, bridge.

## Build & Test

```bash
cargo build
cargo test
cargo clippy
```

## Architecture Notes

- Device linking: provisioning WebSocket -> provision message -> PUT /v1/devices/link -> post-link setup
- Storage Service: separate host (storage.signal.org), two-step auth (GET /v1/storage/auth on chat server -> use returned credentials for storage)
- Proto field numbers matter for wire format, not field names
- WebSocket message receiving: use `connect_message_pipe()` + `process_incoming_ws_request()` for persistent connections (TUI/bridge pattern), not `receive_messages()` which creates a new WebSocket per call
- WebSocket 4409 "Connected elsewhere": server kicks when two clients connect as the same device; handled with exponential backoff
- signal-rs-bridge: pipes Signal messages to `claude --print` via `zsh -i -c` (for alias support); supports `--continue`/`--resume` for session handover

## Commit Rules

- Never include Co-Authored-By lines in commit messages.
