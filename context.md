# Beltic CLI Context

## Project Identity

**Name**: Beltic CLI  
**Purpose**: A command-line tool for managing and signing verifiable credentials for AI agents. Provides cryptographic verification of agent identity, capabilities, and compliance.  
**Core Value**: Secure, developer-friendly credential management with interactive and non-interactive modes.  
**Mechanism**:
- Manifest Management: Create agent manifests with metadata and fingerprinting
- Cryptographic Operations: Generate keypairs (Ed25519/P-256) and sign credentials as JWS tokens
- Verification: Verify signatures and validate payloads against JSON schemas
- HTTP Signatures: Sign HTTP requests per RFC 9421 for Web Bot Auth

## Quick Commands

```bash
# Build release binary
cargo build --release

# Run tests
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
- **Serialization**: serde, serde_json, serde_yaml
- **Interactive UI**: dialoguer 0.11+, console 0.15+, indicatif 0.17+
- **File I/O**: walkdir 2.5+, ignore 0.4+ (respects .gitignore)
- **Schema Validation**: jsonschema 0.17+ (Draft 2020-12)
- **HTTP**: reqwest 0.11+ (blocking, rustls-tls)
- **Key Management**: zeroize 1.7+ (secure memory clearing)

## Project Structure

```
beltic-cli/
├── src/
│   ├── main.rs              # CLI entry point, command routing
│   ├── lib.rs               # Library exports
│   ├── commands/            # Command implementations
│   │   ├── init.rs          # Agent manifest initialization
│   │   ├── dev_init.rs      # Developer credential creation
│   │   ├── fingerprint.rs   # Code fingerprinting
│   │   ├── keygen.rs        # Keypair generation
│   │   ├── sign.rs          # JWS signing
│   │   ├── verify.rs         # JWS verification
│   │   ├── http_sign.rs     # HTTP Message Signatures (RFC 9421)
│   │   ├── directory.rs     # Key directory management
│   │   ├── sandbox.rs       # Compliance testing
│   │   ├── schema.rs         # Schema caching
│   │   ├── auth.rs          # Authentication
│   │   ├── api_key.rs       # API key management
│   │   ├── register.rs      # Developer registration
│   │   ├── whoami.rs        # Identity display
│   │   ├── credential_id.rs # ID extraction
│   │   ├── prompts.rs       # Shared interactive prompts
│   │   └── discovery.rs     # Auto-discovery utilities
│   ├── manifest/            # Manifest handling
│   │   ├── config.rs        # .beltic.yaml parsing
│   │   ├── detector.rs      # Project auto-detection
│   │   ├── fingerprint.rs   # SHA256 fingerprinting
│   │   ├── prompts.rs       # Manifest field prompts
│   │   ├── schema.rs         # AgentManifest struct
│   │   ├── templates.rs     # Default values
│   │   └── validator.rs     # Manifest validation
│   ├── crypto/              # Cryptographic operations
│   │   ├── mod.rs           # SignatureAlg enum
│   │   ├── signer.rs        # JWS signing
│   │   └── verifier.rs      # JWS verification
│   ├── sandbox/             # Sandbox testing
│   │   ├── policy.rs        # Policy extraction
│   │   ├── monitor.rs       # Process monitoring
│   │   └── report.rs        # JSON report generation
│   ├── config.rs            # Configuration management
│   ├── credential.rs        # Credential building/validation
│   └── schema.rs            # Schema loading/caching
├── schemas/                 # JSON Schema files
│   ├── agent/v1/            # AgentCredential v1 schema
│   ├── agent/v2/            # AgentCredential v2 schema
│   ├── developer/v1/        # DeveloperCredential v1 schema
│   └── developer/v2/        # DeveloperCredential v2 schema
├── tests/                   # Integration tests
│   └── jws_vectors.rs       # JWS test vectors
├── Cargo.toml               # Project manifest
└── install.sh               # Installation script
```

## Commands

### Building

```bash
# Development build (faster, includes debug info)
cargo build

# Release build (optimized, LTO enabled)
cargo build --release

# Binary location after release build
./target/release/beltic
```

### Testing

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name

# Run tests with output
cargo test -- --nocapture

# Compile tests without running
cargo test --no-run

# Run integration tests
cargo test --test jws_vectors
```

### Running CLI

```bash
# Development mode (cargo run)
cargo run -- init
cargo run -- sign --key private.pem --payload cred.json

# Release binary
./target/release/beltic init
./target/release/beltic sign --key private.pem --payload cred.json

# Help
cargo run -- --help
cargo run -- init --help
```

### Code Quality

```bash
# Format code
cargo fmt

# Check formatting
cargo fmt --check

# Lint
cargo clippy

# Lint with all warnings
cargo clippy -- -W clippy::all

# Type check (no compilation)
cargo check
```

### Documentation

```bash
# Generate docs
cargo doc

# Open docs in browser
cargo doc --open

# Generate docs for all dependencies
cargo doc --all-features
```

## Testing

### Test Structure

- **Unit tests**: Inline with `#[cfg(test)]` modules
- **Integration tests**: `tests/` directory
- **Test fixtures**: `tests/fixtures/` (JSON credentials)

### Running Tests

```bash
# All tests
cargo test

# Specific module
cargo test manifest::

# Specific test
cargo test test_ed25519_signing

# With output
cargo test -- --nocapture --test-threads=1
```

### Test Examples

```rust
// Example from tests/jws_vectors.rs
#[test]
fn test_ed25519_signing() {
    let keypair = generate_keypair(SignatureAlg::EdDSA);
    let token = sign_credential(&payload, &keypair.private_key, &options)?;
    assert!(verify_token(&token, &keypair.public_key).is_ok());
}
```

## Code Style

### Formatting

- Use `cargo fmt` - enforces standard Rust style
- Line length: 100 characters (default)
- Indentation: 4 spaces

### Linting

- Use `cargo clippy` - catches common mistakes
- Fix all warnings before committing
- Use `#[allow(clippy::...)]` sparingly with justification

### Naming Conventions

- **Functions**: `snake_case`
- **Types**: `PascalCase`
- **Constants**: `SCREAMING_SNAKE_CASE`
- **Modules**: `snake_case`
- **Files**: `snake_case.rs`

### Error Handling

```rust
// Use anyhow::Result for error propagation
use anyhow::Result;

fn my_function() -> Result<()> {
    let value = risky_operation()?;  // ? operator for error propagation
    Ok(())
}

// Use thiserror for structured errors
#[derive(Debug, thiserror::Error)]
enum MyError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}
```

### Code Examples

```rust
// Good: Clear error handling
pub fn sign_credential(
    payload: &[u8],
    private_key: &[u8],
    options: &SignOptions,
) -> Result<String> {
    let key = load_private_key(private_key, options.alg)?;
    let token = create_jws(payload, &key, options)?;
    Ok(token)
}

// Good: Interactive prompts with defaults
let algorithm = dialoguer::Select::new()
    .with_prompt("Select signature algorithm")
    .items(&["EdDSA (Ed25519)", "ES256 (P-256)"])
    .default(0)
    .interact()?;
```

## Git Workflow

### Branching

- `main` - Production-ready code
- `develop` - Integration branch (if used)
- Feature branches: `feature/command-name`
- Bug fixes: `fix/issue-description`

### Commits

- Use conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`
- Keep commits focused and atomic
- Write clear commit messages

```bash
# Good commit messages
git commit -m "feat: add HTTP signature verification"
git commit -m "fix: handle missing kid header gracefully"
git commit -m "docs: update README with new commands"
```

### Releases

- Version in `Cargo.toml` follows semantic versioning
- Update `CHANGELOG.md` for each release
- Tag releases: `v0.2.0`
- Release workflow builds binaries for multiple platforms

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

### What This Repo Does

- ✅ Manages agent manifests and credentials
- ✅ Generates cryptographic keypairs
- ✅ Signs and verifies JWS tokens
- ✅ Creates HTTP Message Signatures (RFC 9421)
- ✅ Validates credentials against JSON schemas
- ✅ Provides interactive CLI experience
- ✅ Supports CI/CD with non-interactive mode

### What This Repo Doesn't Do

- ❌ Host credentials or keys (only generates/manages them)
- ❌ Provide a credential issuance service (use KYA platform)
- ❌ Run agent code (only signs credentials)
- ❌ Store credentials long-term (filesystem only)
- ❌ Network credential distribution (use platform APIs)

## Examples

### Adding a New Command

```rust
// 1. Create command file: src/commands/my_command.rs
use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
pub struct MyCommandArgs {
    #[arg(long)]
    pub input: String,
}

pub fn run(args: MyCommandArgs) -> Result<()> {
    // Implementation
    Ok(())
}

// 2. Add to src/commands/mod.rs
pub mod my_command;

// 3. Add to src/main.rs Command enum
MyCommand(commands::my_command::MyCommandArgs),

// 4. Handle in main()
Command::MyCommand(args) => commands::my_command::run(*args)?,
```

### Interactive Prompt Example

```rust
use dialoguer::{Input, Select};

// Text input
let name: String = Input::new()
    .with_prompt("Agent name")
    .default("my-agent".to_string())
    .interact()?;

// Selection
let alg = Select::new()
    .with_prompt("Algorithm")
    .items(&["EdDSA", "ES256"])
    .default(0)
    .interact()?;
```

### Key Generation Example

```rust
use beltic::crypto::{generate_keypair, SignatureAlg};

let (private_key, public_key) = generate_keypair(SignatureAlg::EdDSA)?;

// Save with restricted permissions
std::fs::write("private.pem", private_key.as_pem()?)?;
std::fs::set_permissions("private.pem", Permissions::from_mode(0o600))?;
```

### Signing Example

```rust
use beltic::crypto::signer::sign_credential;
use beltic::crypto::SignatureAlg;

let token = sign_credential(
    &credential_json,
    &private_key,
    &SignOptions {
        alg: SignatureAlg::EdDSA,
        issuer_did: "did:web:example.com".to_string(),
        subject_did: "did:web:agent.example.com".to_string(),
        key_id: "key-1".to_string(),
        ..Default::default()
    },
)?;
```

### Configuration Example

```yaml
# .beltic.yaml
version: "1.0"
agent:
  paths:
    include:
      - "src/**"
      - "Cargo.toml"
    exclude:
      - "**/test/**"
      - "**/target/**"
  deployment:
    type: "standalone"
```

## Common Workflows

### Complete Credential Creation

```bash
# 1. Initialize manifest
beltic init

# 2. Generate fingerprint
beltic fingerprint

# 3. Generate keys
beltic keygen --alg EdDSA

# 4. Sign credential
beltic sign --key .beltic/eddsa-*-private.pem --payload agent-manifest.json

# 5. Verify
beltic verify --key .beltic/eddsa-*-public.pem --token agent-credential.jwt
```

### CI/CD Workflow

```bash
# Non-interactive mode
beltic keygen --alg EdDSA --non-interactive
beltic sign --key private.pem --payload cred.json --kid key-1 --non-interactive
```

### HTTP Signature Workflow

```bash
# Generate key directory
beltic directory generate --public-key public.pem --out directory.json

# Sign HTTP request
beltic http-sign \
  --method POST \
  --url https://api.example.com/data \
  --key private.pem \
  --key-directory https://agent.example.com/.well-known/http-message-signatures-directory
```

