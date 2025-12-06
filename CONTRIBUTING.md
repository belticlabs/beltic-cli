# Contributing to Beltic CLI

Thanks for helping improve Beltic. This guide keeps contributions fast and predictable.

## Development setup
- Use Rust 1.70+ with `cargo` available.
- Fork and clone the repo, then `cargo build` to confirm the toolchain works.
- Keep pull requests focused and small; open an issue first for bigger changes.

## Before you open a PR
- Format and lint: `cargo fmt --all` then `cargo clippy --all-targets --all-features -D warnings`.
- Run tests: `cargo test --all`.
- Update docs when CLI flags, manifests, or schemas change.

## Commit and review tips
- Prefer conventional, concise messages (e.g., `feat:`, `fix:`, `docs:`, `chore:`).
- Include context in the PR description (problem, approach, testing).
- Add or adjust tests for behavior changes; note any coverage gaps explicitly.

## Security and data handling
- Do not commit secrets or real credentials; use redacted or sample data in fixtures.
- Treat generated private keys as sensitive and ensure they remain gitignored.
