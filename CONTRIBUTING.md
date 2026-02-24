# Contributing to signal-rs

Thanks for your interest in contributing!

## Building and testing

```bash
cargo build
cargo test
cargo clippy
```

See the [Prerequisites](README.md#prerequisites) section in the README for required system dependencies.

## Code style

- Format code with `rustfmt` (`cargo fmt`)
- Follow existing patterns in the codebase
- Run `cargo clippy` before submitting — no warnings

## Pull request process

1. Fork the repository and create a feature branch
2. Make your changes
3. Run `cargo test` and `cargo clippy` to verify
4. Open a pull request against `main`

## License

By contributing to signal-rs, you agree that your contributions will be licensed under the AGPL-3.0-only license.
