# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Philosophy & Guidelines

### Core Philosophy
- **Safety First**: Never risk user data. Always use secure key handling (0600 permissions, zeroize for memory). When in doubt, ask.
- **Incremental Progress**: Break complex tasks into manageable stages.
- **Clear Intent**: Prioritize readability and maintainability over clever hacks.
- **Native Performance**: Use Rust for cryptographic operations, interactive prompts for developer experience.

### Quality Standards
- **English Only**: Comments and code must be in English.
- **No Unnecessary Comments**: Code should be self-explanatory.
- **Rust Formatting**: Always run `cargo fmt` before committing.
- **Error Handling**: Use `anyhow::Result` for error propagation, descriptive error messages.

## Project Identity

**Name**: Beltic CLI  
**Purpose**: A command-line tool for managing and signing verifiable credentials for AI agents.  
**Core Value**: Secure, developer-friendly credential management with interactive and non-interactive modes.

## Quick Commands

```bash
# Build release binary
cargo build --release

# Run all tests
cargo test

# Run CLI command
cargo run -- <command>

# Format code
cargo fmt

# Lint code
cargo clippy

# Generate documentation
cargo doc --open
```

## Stack

- **Language**: Rust 1.70+ (2021 edition)
- **CLI Framework**: clap 4.5+ with derive macros
- **Crypto**: ed25519-dalek 2.1+, p256 0.13+ (EdDSA/ES256)
- **JWT**: jsonwebtoken 9.3+
- **Interactive UI**: dialoguer 0.11+, console 0.15+, indicatif 0.17+
- **Schema Validation**: jsonschema 0.17+ (Draft 2020-12)

## Project Overview

Beltic CLI is a Rust-based command-line tool for managing AI agent credentials and manifests. It provides functionality for:
- Creating agent manifests with fingerprinting
- Generating cryptographic keypairs (ES256/EdDSA) with smart defaults
- Signing agent credentials as JWS tokens
- Verifying JWS signatures
- Signing HTTP requests per RFC 9421 (Web Bot Auth)
- Managing key directories for HTTP Message Signatures

The CLI features interactive mode with auto-discovery of keys and credentials, making it developer-friendly for local development while supporting non-interactive mode for CI/CD.

## Commands

### Building
```bash
# Development build
cargo build

# Release build (optimized, LTO enabled)
cargo build --release

# The release binary will be at:
./target/release/beltic
```

### Testing
```bash
# Run all tests
cargo test

# Run specific test
cargo test <test_name>

# Run tests without building
cargo test --no-run

# Build and run tests with output
cargo test -- --nocapture
```

### Running the CLI
```bash
# After building in release mode
./target/release/beltic <command>

# Or use cargo run for development
cargo run -- <command>
```

## CLI Commands

The Beltic CLI provides these commands:

1. **init** - Initialize a new agent manifest with interactive prompts
   ```bash
   beltic init [--output path] [--config path] [--force] [--non-interactive]
   ```

2. **dev-init** - Create a self-attested developer credential
   ```bash
   beltic dev-init [--name name] [--email email] [--website url] [--non-interactive]
   ```

3. **fingerprint** - Update the code fingerprint in an existing manifest
   ```bash
   beltic fingerprint [--manifest path] [--config path] [--verbose]
   ```

4. **keygen** - Generate a new cryptographic keypair (interactive mode with auto-naming)
   ```bash
   beltic keygen [--alg EdDSA|ES256] [--name name] [--out path] [--pub path] [--non-interactive]
   ```

5. **sign** - Sign a JSON payload into a JWS token (interactive mode with auto-discovery)
   ```bash
   beltic sign [--key path] [--payload path] [--kid id] [--out path] [--non-interactive]
   ```

6. **verify** - Verify a JWS token and print its payload (interactive mode with auto-discovery)
   ```bash
   beltic verify [--key path] [--token path-or-string] [--non-interactive]
   ```

7. **http-sign** - Sign HTTP requests per RFC 9421 for Web Bot Auth
   ```bash
   beltic http-sign --method GET|POST|... --url <url> --key <path> --key-directory <url>
   ```

8. **directory** - Manage key directories for HTTP Message Signatures
   ```bash
   beltic directory generate --public-key <path> --out <path>
   beltic directory thumbprint --public-key <path>
   ```

9. **sandbox** - Run agent in sandboxed environment for compliance testing
   ```bash
   beltic sandbox --manifest path --command "npm start"
   ```

10. **schema** - Manage schema caching and updates
    ```bash
    beltic schema status
    beltic schema refresh
    beltic schema clear
    ```

11. **auth** - Authentication commands
    ```bash
    beltic auth login
    beltic auth logout
    ```

12. **api-key** - Manage API keys
    ```bash
    beltic api-key create
    beltic api-key list
    beltic api-key revoke <id>
    ```

13. **register** - Register a new developer account
    ```bash
    beltic register
    ```

14. **whoami** - Display current authenticated developer info
    ```bash
    beltic whoami
    ```

15. **credential-id** - Extract credential ID from JSON or JWT file
    ```bash
    beltic credential-id --file credential.json
    ```

## Code Architecture

### Module Structure

```
src/
├── main.rs           # CLI entry point with clap command definitions
├── lib.rs            # Library exports (commands, crypto, manifest modules)
├── credential.rs     # Credential building, detection, and validation
├── commands/         # CLI command implementations
│   ├── init.rs       # Agent manifest initialization
│   ├── fingerprint.rs # Fingerprint generation
│   ├── keygen.rs     # Keypair generation (interactive mode)
│   ├── sign.rs       # JWS signing (interactive mode)
│   ├── verify.rs     # JWS verification (interactive mode)
│   ├── http_sign.rs  # HTTP request signing (Web Bot Auth, RFC 9421)
│   ├── directory.rs  # Key directory management
│   ├── prompts.rs    # Shared interactive prompts for CLI commands
│   └── discovery.rs  # Key/token auto-discovery and gitignore management
├── crypto/           # Cryptographic operations
│   ├── mod.rs        # SignatureAlg enum and constants
│   ├── signer.rs     # JWS signing with ES256/EdDSA
│   └── verifier.rs   # JWS verification
└── manifest/         # Agent manifest management
    ├── mod.rs        # Manifest initialization orchestration
    ├── schema.rs     # AgentManifest struct and related types
    ├── config.rs     # BelticConfig (.beltic.yaml parser)
    ├── detector.rs   # Auto-detection of project context
    ├── fingerprint.rs # SHA256 fingerprinting of codebase
    ├── prompts.rs    # Interactive prompts for manifest fields
    ├── templates.rs  # Default values and templates
    └── validator.rs  # Manifest validation logic
```

### Key Design Patterns

**Manifest Generation Flow:**
1. `commands/init.rs` receives CLI arguments
2. Calls `manifest::init_manifest()` with `InitOptions`
3. Loads `.beltic.yaml` config if present (via `config.rs`)
4. Auto-detects project context (via `detector.rs`)
5. Prompts user for missing fields (via `prompts.rs`)
6. Generates code fingerprint (via `fingerprint.rs`)
7. Validates final manifest (via `validator.rs`)
8. Writes `agent-manifest.json` to output path

**Cryptographic Operations:**
- ES256 (P-256/secp256r1) and EdDSA (Ed25519) are the only supported signature algorithms
- Keys are loaded from PEM files
- JWS tokens use the custom type header: `application/beltic-agent+jwt`
- Signing and verification are separate operations with distinct key types (private vs public)

**Fingerprinting:**
- Uses SHA256 to hash file contents deterministically
- Respects include/exclude patterns from `.beltic.yaml`
- Tracks both internal and external dependencies
- Generates `FingerprintMetadata` with timestamp and scope

## Configuration Files

### .beltic.yaml
The `.beltic.yaml` file configures agent manifest generation:
- `agent.paths.include` - Glob patterns for files to include in fingerprint
- `agent.paths.exclude` - Glob patterns for files to exclude
- `agent.dependencies.internal` - Internal module dependencies
- `agent.dependencies.external` - External package dependencies
- `agent.deployment.type` - Deployment type (standalone, monorepo, embedded, plugin, serverless)

Example file is at `.beltic.yaml.example`.

### agent-manifest.json
The output manifest follows the Beltic v1 specification with fields including:
- Agent identity (id, name, version, description)
- Developer credential ID
- Model configuration (provider, family, context window)
- Tools and capabilities
- Data handling policies
- Compliance certifications
- Fingerprint metadata

Full schema is defined in `src/manifest/schema.rs` with the `AgentManifest` struct.

## Important Implementation Details

### Interactive Prompts
The `init` command defaults to interactive mode. It uses the `dialoguer` crate to prompt for:
- Agent name, version, description
- Model provider and family
- Tools and capabilities
- Data categories processed
- Compliance certifications

Use `--non-interactive` flag to skip prompts and use defaults/config values only.

### Fingerprint Algorithm
- Algorithm: SHA256
- Scope: Files matching include patterns minus exclude patterns
- Deterministic: Same files always produce same hash
- Timestamp: Recorded in `FingerprintMetadata`

### Signature Algorithms
- **ES256**: ECDSA with P-256 curve and SHA-256
  - Key format: SEC1/PKCS#8 PEM
  - Use for NIST compliance requirements
- **EdDSA**: Ed25519 signatures
  - Key format: PKCS#8 PEM
  - Use for modern, high-performance applications

### Error Handling
The codebase uses `anyhow::Result` for error propagation throughout. Commands should return `Result<()>` and use `?` operator for error handling. User-facing errors should be descriptive.

## Test Agent

The `test-agent/` directory contains a TypeScript reference implementation of a customer support agent that demonstrates Beltic integration. It's useful for testing the CLI commands end-to-end.

## SDK Development Reference

The `sdk.md` file contains a comprehensive blueprint for building TypeScript and Python SDKs that wrap the functionality provided by this CLI. It outlines:
- SDK architecture (manifest, credentials, crypto, DID modules)
- API design patterns (builders, fluent interfaces)
- Type definitions matching the Rust schema
- Mock services for development
- Future integration points (credential platform, KMS, DID resolution)

When implementing SDK features, ensure they align with the CLI's behavior and data structures.

## Common Development Workflows

### Adding a New Manifest Field
1. Update `AgentManifest` struct in `src/manifest/schema.rs`
2. Add prompt logic in `src/manifest/prompts.rs`
3. Update template defaults in `src/manifest/templates.rs`
4. Add validation in `src/manifest/validator.rs` if needed
5. Update `.beltic.yaml.example` if field is configurable

### Adding a New Cryptographic Algorithm
1. Add variant to `SignatureAlg` enum in `src/crypto/mod.rs`
2. Implement signing in `src/crypto/signer.rs`
3. Implement verification in `src/crypto/verifier.rs`
4. Add test vectors in `tests/jws_vectors.rs`
5. Update CLI help text and argument parsers

### Modifying Fingerprint Logic
The fingerprint generation is centralized in `src/manifest/fingerprint.rs`. Key functions:
- `generate_fingerprint()` - Main entry point
- `collect_files()` - Applies include/exclude patterns
- `hash_files()` - Generates SHA256 hash

Changes here affect how code changes are tracked in agent credentials.

## Code Style

### Formatting
- Use `cargo fmt` - enforces standard Rust style
- Line length: 100 characters (default)
- Indentation: 4 spaces

### Linting
- Use `cargo clippy` - catches common mistakes
- Fix all warnings before committing
- Use `#[allow(clippy::...)]` sparingly with justification

### Error Handling
```rust
// Use anyhow::Result for error propagation
use anyhow::Result;

fn my_function() -> Result<()> {
    let value = risky_operation()?;  // ? operator for error propagation
    Ok(())
}
```

## Git Workflow

### Commits
- Use conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`
- Keep commits focused and atomic
- Write clear commit messages

### Releases
- Version in `Cargo.toml` follows semantic versioning
- Update `CHANGELOG.md` for each release
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

## Debugging Tips

### Common Issues

**Key not found errors:**
- Check file permissions (should be 0600 for private keys)
- Verify key format (PKCS#8 PEM)
- Ensure algorithm matches (EdDSA vs ES256)

**Schema validation failures:**
- Run `beltic schema refresh` to update schemas
- Check credential against schema manually: `beltic verify --skip-schema false`

**Interactive prompts not working:**
- Ensure terminal supports ANSI colors
- Check if `--non-interactive` flag is set
- Verify `dialoguer` crate is working

### Debug Commands

```bash
# Verbose fingerprint generation
beltic fingerprint --verbose

# Skip schema validation (for testing)
beltic sign --skip-schema

# Check schema cache status
beltic schema status
```
