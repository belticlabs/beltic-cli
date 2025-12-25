# AGENTS.md

This file provides guidance to AI coding agents when working with code in this repository.

## Philosophy & Guidelines

### Core Philosophy
- **Safety First**: Never risk user data. Always use secure key handling (0600 permissions, zeroize for memory). When in doubt, ask.
- **Incremental Progress**: Break complex tasks into manageable stages.
- **Clear Intent**: Prioritize readability and maintainability over clever hacks.
- **Native Performance**: Use Rust for cryptographic operations, interactive prompts for developer experience.

### Eight Honors and Eight Shames
- Shame in guessing APIs, Honor in careful research.
- Shame in vague execution, Honor in seeking confirmation.
- Shame in assuming business logic, Honor in human verification.
- Shame in creating interfaces, Honor in reusing existing ones.
- Shame in skipping validation, Honor in proactive testing.
- Shame in breaking architecture, Honor in following specifications.
- Shame in pretending to understand, Honor in honest ignorance.
- Shame in blind modification, Honor in careful refactoring.

### Quality Standards
- **English Only**: Comments and code must be in English.
- **No Unnecessary Comments**: Code should be self-explanatory.
- **Rust Formatting**: Always run `cargo fmt` before committing.
- **Error Handling**: Use `anyhow::Result` for error propagation, descriptive error messages.
- **CHANGELOG Updates**: Always update CHANGELOG.md when making user-facing changes or significant internal changes.

## Project Identity

**Name**: Beltic CLI  
**Purpose**: A command-line tool for managing and signing verifiable credentials for AI agents.  
**Core Value**: Secure, developer-friendly credential management with interactive and non-interactive modes.

## Technology Stack

- **Language**: Rust 1.70+ (2021 edition)
- **CLI Framework**: clap 4.5+ with derive macros
- **Crypto**: ed25519-dalek 2.1+, p256 0.13+ (EdDSA/ES256)
- **JWT**: jsonwebtoken 9.3+
- **Interactive UI**: dialoguer 0.11+, console 0.15+, indicatif 0.17+
- **Schema Validation**: jsonschema 0.17+ (Draft 2020-12)

## Repository Architecture

```
beltic-cli/
├── src/
│   ├── main.rs              # CLI entry point, command routing
│   ├── lib.rs               # Library exports
│   ├── commands/            # Command implementations
│   ├── manifest/            # Manifest handling
│   ├── crypto/              # Cryptographic operations
│   ├── sandbox/             # Sandbox testing
│   ├── config.rs            # Configuration management
│   ├── credential.rs        # Credential building/validation
│   └── schema.rs            # Schema loading/caching
├── schemas/                 # JSON Schema files
├── tests/                   # Integration tests
└── Cargo.toml               # Project manifest
```

## Key Workflows

### Development
1. **Understand**: Read `src/commands/` to see existing command patterns
2. **Implement**: Follow existing patterns, use safe_* functions for file operations
3. **Verify**: Use `cargo test` and manual testing
4. **Update**: Always update CHANGELOG.md for user-facing changes

### Commands
```bash
# Build
cargo build --release

# Test
cargo test

# Format
cargo fmt

# Lint
cargo clippy

# Run CLI
cargo run -- <command>
```

### Building
```bash
# Development build
cargo build

# Release build (optimized, LTO enabled)
cargo build --release

# Binary location
./target/release/beltic
```

## Implementation Details

### Safety System
**Crucial**: Never use unsafe file operations directly.

**Use**:
- Secure key storage with `0600` permissions
- `zeroize` for clearing sensitive memory
- Schema validation before processing
- Input validation for all user inputs

**Protection**:
- Private keys automatically added to `.gitignore`
- Path validation prevents unsafe operations
- Cryptographically secure RNG for key generation

### Error Handling
```rust
// Use anyhow::Result for error propagation
use anyhow::Result;

fn my_function() -> Result<()> {
    let value = risky_operation()?;  // ? operator for error propagation
    Ok(())
}
```

## Common AI Tasks

### Adding a New Command
1. Create command file: `src/commands/my_command.rs`
2. Add to `src/commands/mod.rs`: `pub mod my_command;`
3. Add to `src/main.rs` Command enum: `MyCommand(commands::my_command::MyCommandArgs)`
4. Handle in main(): `Command::MyCommand(args) => commands::my_command::run(*args)?`
5. Test: `cargo run -- my-command --help`
6. **Update CHANGELOG.md** under Added section

### Adding a New Manifest Field
1. Update `AgentManifest` struct in `src/manifest/schema.rs`
2. Add prompt logic in `src/manifest/prompts.rs`
3. Update template defaults in `src/manifest/templates.rs`
4. Add validation in `src/manifest/validator.rs` if needed
5. Update `.beltic.yaml.example` if field is configurable
6. **Update CHANGELOG.md** under Added or Changed section

### Modifying Cryptographic Operations
1. Understand current implementation in `src/crypto/`
2. Make changes carefully - crypto is security-critical
3. Add test vectors in `tests/jws_vectors.rs`
4. Test thoroughly: `cargo test crypto::`
5. **Update CHANGELOG.md** with security implications

### Fixing a Bug
1. Reproduce with a test case
2. Add test to `tests/` if missing
3. Fix the bug
4. Verify: `cargo test`
5. **Update CHANGELOG.md** under Fixed section

## Git Workflow

### Commits
- Use conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`
- Keep commits focused and atomic
- Write clear commit messages
- **Always update CHANGELOG.md** for user-facing changes or significant internal changes

### Releases
- Version in `Cargo.toml` follows semantic versioning
- **Update CHANGELOG.md** for each release with date
- Tag releases: `v0.2.0`

## Boundaries

### Never Commit
- **Private keys** (`.beltic/*-private.pem`, `*-key.pem`)
- **Credentials** (`.jwt`, `credential.json` with real data)
- **API keys** or secrets
- **Personal credentials** or test data

### Security Rules
1. **Private keys**: Always use `0600` permissions, never commit
2. **Memory**: Use `zeroize` to clear sensitive data
3. **Key generation**: Use cryptographically secure RNG (`OsRng`)
4. **Input validation**: Validate all inputs against schemas
5. **Error messages**: Don't leak sensitive info in errors

