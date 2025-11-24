# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Beltic CLI is a Rust-based command-line tool for managing AI agent credentials and manifests. It provides functionality for:
- Creating agent manifests with fingerprinting
- Generating cryptographic keypairs (ES256/EdDSA)
- Signing agent credentials as JWS tokens
- Verifying JWS signatures

## Build and Development Commands

### Building
```bash
# Development build
cargo build

# Release build (optimized)
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

The Beltic CLI provides five main commands:

1. **init** - Initialize a new agent manifest with interactive prompts
   ```bash
   beltic init [--output path] [--config path] [--force] [--non-interactive]
   ```

2. **fingerprint** - Update the code fingerprint in an existing manifest
   ```bash
   beltic fingerprint [--manifest path] [--config path]
   ```

3. **keygen** - Generate a new cryptographic keypair
   ```bash
   beltic keygen --algorithm <ES256|EdDSA> --output <path>
   ```

4. **sign** - Sign a JSON payload into a JWS token
   ```bash
   beltic sign --payload <path> --key <path> --algorithm <ES256|EdDSA>
   ```

5. **verify** - Verify a JWS token and print its payload
   ```bash
   beltic verify --token <path-or-string> --key <path>
   ```

## Code Architecture

### Module Structure

```
src/
├── main.rs           # CLI entry point with clap command definitions
├── lib.rs            # Library exports (commands, crypto, manifest modules)
├── commands/         # CLI command implementations
│   ├── init.rs       # Agent manifest initialization
│   ├── fingerprint.rs # Fingerprint generation
│   ├── keygen.rs     # Keypair generation
│   ├── sign.rs       # JWS signing
│   └── verify.rs     # JWS verification
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
