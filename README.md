# Beltic CLI

A command-line tool for managing and signing credentials for AI agents, providing cryptographic verification of agent identity, capabilities, and compliance.

## Overview

Beltic CLI enables developers to create verifiable credentials for AI agents with deterministic code fingerprinting and strong cryptographic signatures. It provides a complete workflow for initializing agent manifests, generating cryptographic keys, signing credentials as JWS tokens, and verifying signatures.

## Features

- **Agent Manifest Management** - Create agent manifests with metadata including name, version, tools, and deployment configuration
- **Deterministic Fingerprinting** - Generate SHA256 fingerprints of your codebase with configurable include/exclude patterns
- **Cryptographic Key Generation** - Support for Ed25519 (EdDSA) and P-256 (ES256) algorithms
- **JWS Token Signing** - Schema-aware signing for Agent/Developer Credential v1 with `vc` claim, `kid` header, and Beltic media types
- **Signature Verification** - Verify signatures plus issuer/audience/time claims and validate payloads against the official JSON Schemas
- **Flexible Configuration** - YAML-based configuration supporting multiple deployment types (standalone, monorepo, embedded, plugin, serverless)
- **Interactive Setup** - User-friendly initialization with optional non-interactive mode for automation

## Installation

### Prerequisites

- Rust 1.70 or later (2021 edition)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/belticlabs/beltic-cli.git
cd beltic/beltic-cli

# Build release binary
cargo build --release

# The binary will be available at:
./target/release/beltic
```

### Install Locally

```bash
cargo install --path .
```

## Quick Start

Here's a complete workflow to create and sign an agent credential:

```bash
# 1. Initialize agent manifest (interactive)
beltic init

# 2. Generate code fingerprint
beltic fingerprint

# 3. Generate cryptographic keypair
beltic keygen --alg EdDSA --out private-key.pem --pub public-key.pem

# 4. Sign the manifest
beltic sign --key private-key.pem --payload agent-manifest.json --out credential.jwt

# 5. Verify the signature
beltic verify --key public-key.pem --token credential.jwt
```

## Commands Reference

### `init` - Initialize Agent Manifest

Create a new agent manifest with interactive prompts or command-line options.

```bash
# Interactive mode (default)
beltic init

# With custom output path
beltic init --output my-manifest.json

# Use existing config file
beltic init --config .beltic.yaml

# Non-interactive with specific deployment type
beltic init --non-interactive --type standalone

# Specify developer credential ID
beltic init --developer-id <uuid>

# Force overwrite existing manifest
beltic init --force

# Skip validation
beltic init --no-validate

# Custom include/exclude patterns
beltic init --include "src/**" --exclude "**/*.test.*"
```

**Options:**
- `-o, --output <PATH>` - Output path for manifest (default: `./agent-manifest.json`)
- `-c, --config <PATH>` - Path to `.beltic.yaml` configuration file
- `-i, --include <PATTERN>` - Include file patterns (can be specified multiple times)
- `-x, --exclude <PATTERN>` - Exclude file patterns (can be specified multiple times)
- `-t, --type <TYPE>` - Deployment type: `standalone`, `monorepo`, `embedded`, `plugin`, or `serverless`
- `-d, --developer-id <UUID>` - Developer credential ID
- `-f, --force` - Overwrite existing manifest
- `--non-interactive` - Disable interactive prompts
- `--no-validate` - Skip validation of generated manifest

### `fingerprint` - Generate Code Fingerprint

Update or generate the SHA256 fingerprint of your codebase.

```bash
# Basic fingerprint generation
beltic fingerprint

# With specific manifest path
beltic fingerprint --manifest agent-manifest.json

# With custom config
beltic fingerprint --config custom.yaml

# Include dependency fingerprints
beltic fingerprint --deps

# Verify mode (without updating manifest)
beltic fingerprint --verify
```

**Options:**
- `-m, --manifest <PATH>` - Path to manifest file (default: `./agent-manifest.json`)
- `-c, --config <PATH>` - Path to `.beltic.yaml` configuration file
- `--deps` - Include dependency fingerprints
- `--verify` - Verify fingerprint without updating manifest
- `-v, --verbose` - Show detailed file list and hashing progress

### `keygen` - Generate Cryptographic Keypair

Generate a new Ed25519 or P-256 keypair for signing credentials.

```bash
# Generate Ed25519 keypair (recommended)
beltic keygen --alg EdDSA --out private-key.pem --pub public-key.pem

# Generate P-256 keypair
beltic keygen --alg ES256 --out private-key.pem --pub public-key.pem
```

**Options:**
- `-a, --alg <ALGORITHM>` - Signature algorithm: `EdDSA` (Ed25519) or `ES256` (P-256)
- `-o, --out <PATH>` - Output path for private key (PEM format)
- `-p, --pub <PATH>` - Output path for public key (PEM format)

**Note:** Keys are generated in PKCS#8 PEM format and securely cleared from memory after writing.

### `sign` - Sign Credential

Sign a Beltic credential as a JWT with Beltic media types and a `vc` claim (iss/sub/jti/nbf/exp derived from the payload).

```bash
# Sign an agent credential (subject DID required for agents)
beltic sign --key private-key.pem --alg EdDSA \
  --payload agent-credential.json \
  --subject did:web:agent.example.com \
  --kid did:web:beltic.test#agent-key-1 \
  --out credential.jwt

# Sign a developer credential (uses subjectDid from payload)
beltic sign --key private-key.pem --alg ES256 \
  --payload developer-credential.json \
  --kid did:web:beltic.test#dev-key-1 \
  --audience did:web:verifier.example \
  --out developer.jwt
```

**Options:**
- `-k, --key <PATH>` - Path to private key (PEM format)
- `-a, --alg <ALGORITHM>` - Signature algorithm: `EdDSA` or `ES256`
- `-p, --payload <PATH>` - Path to JSON payload file (AgentCredential or DeveloperCredential)
- `-o, --out <PATH>` - Output path for JWT
- `--kid <ID>` - Key identifier to include in JWS header (required by spec)
- `--issuer <DID>` - Override issuer DID for `iss` (defaults to `issuerDid` in payload)
- `--subject <DID>` - Subject DID for `sub` (required for agents if payload lacks `subjectDid`)
- `--audience <AUDIENCE>` - Audience claim (repeat to add multiple)
- `--credential-type <TYPE>` - Force type detection (`agent` or `developer`)
- `--skip-schema` - Skip JSON Schema validation before signing

**Output:** A compact JWT with `typ` set to `application/beltic-agent+jwt` or `application/beltic-developer+jwt` and `cty` set to `application/json`.

### `verify` - Verify Signature

Verify a Beltic credential token (Agent/Developer) including signature, issuer/audience claims, and JSON Schema validation.

```bash
# Verify token from file
beltic verify --key public-key.pem --token credential.jwt

# Verify token from string
beltic verify --key public-key.pem --token "eyJhbGc..."
```

**Options:**
- `-k, --key <PATH>` - Path to public key (PEM format)
- `-t, --token <PATH|STRING>` - Path to JWT file or token string
- `--issuer <DID>` - Expected issuer DID (`iss`)
- `--audience <AUDIENCE>` - Expected audience value(s)
- `--credential-type <TYPE>` - Expected credential type (`agent` or `developer`)
- `--skip-schema` - Skip JSON Schema validation of the `vc` claim

**Output:**
- On success: "VALID" with credential type/alg/kid/iss/sub/jti plus the pretty-printed `vc` payload
- On failure: "INVALID" with error details

## Configuration

### `.beltic.yaml`

The `.beltic.yaml` file configures agent manifest generation and fingerprinting.

#### Basic Structure

```yaml
version: "1.0"

agent:
  paths:
    include:
      - "src/**"
      - "Cargo.toml"
      - "README.md"
    exclude:
      - "**/*.test.*"
      - "**/test/**"
      - "**/target/**"
      - "**/.git/**"
      - "**/node_modules/**"

  dependencies:
    internal:
      - "../shared-utils"
    external:
      - "openai@^3.0.0"

  deployment:
    type: "standalone"
```

#### Configuration Fields

- **`version`** - Configuration version (currently "1.0")
- **`agent.paths.include`** - Glob patterns for files to include in fingerprint
- **`agent.paths.exclude`** - Glob patterns for files to exclude
- **`agent.dependencies.internal`** - Paths to internal module dependencies (for monorepos)
- **`agent.dependencies.external`** - External package dependencies with versions
- **`agent.deployment.type`** - Deployment architecture type
- **`agent.deployment.location`** - Path within repository (for monorepos)
- **`agent.deployment.runtime`** - Runtime environment (e.g., "node:18-alpine", "python:3.11")

#### Deployment Types

1. **`standalone`** - Single-file or single-directory agent
2. **`monorepo`** - Agent within a monorepo with shared dependencies
3. **`embedded`** - Agent embedded within a larger application
4. **`plugin`** - Extension or plugin for another application
5. **`serverless`** - Serverless function (AWS Lambda, etc.)

#### Example Configurations

**Monorepo Agent:**
```yaml
version: "1.0"
agent:
  paths:
    include:
      - "agents/customer-service/**"
      - "packages/shared-ai/**"
      - "packages/prompts/**"
    exclude:
      - "**/test/**"
      - "**/node_modules/**"
  dependencies:
    internal:
      - "packages/shared-ai"
      - "packages/auth"
  deployment:
    type: "monorepo"
    location: "agents/customer-service"
```

**Serverless Function:**
```yaml
version: "1.0"
agent:
  paths:
    include:
      - "src/**"
      - "handler.js"
      - "serverless.yml"
    exclude:
      - "**/*.test.js"
      - "**/.serverless/**"
  deployment:
    type: "serverless"
    runtime: "nodejs18.x"
```

**Plugin/Extension:**
```yaml
version: "1.0"
agent:
  paths:
    include:
      - "src/extension/**"
      - "manifest.json"
      - "assets/**"
    exclude:
      - "**/test/**"
  deployment:
    type: "plugin"
    host_application: "vscode"
```

See `.beltic.yaml.example` for more examples.

## Examples

### Complete Workflow: Standalone Agent

```bash
# 1. Create .beltic.yaml configuration
cat > .beltic.yaml <<EOF
version: "1.0"
agent:
  paths:
    include:
      - "src/**"
      - "package.json"
    exclude:
      - "**/*.test.*"
      - "**/node_modules/**"
  deployment:
    type: "standalone"
EOF

# 2. Initialize manifest (interactive)
beltic init

# 3. Generate fingerprint
beltic fingerprint --verbose

# 4. Generate Ed25519 keypair
beltic keygen --alg EdDSA --out agent-key.pem --pub agent-key.pub.pem

# 5. Sign the manifest
beltic sign \
  --key agent-key.pem \
  --alg EdDSA \
  --payload agent-manifest.json \
  --out agent-credential.jwt \
  --kid agent-key-1

# 6. Verify the signature
beltic verify --key agent-key.pub.pem --token agent-credential.jwt
```

### Test Agent Example

The `test-agent/` directory contains a complete TypeScript customer support agent that demonstrates Beltic integration:

```bash
cd test-agent

# Initialize Beltic for the test agent
../target/release/beltic init

# Generate fingerprint
../target/release/beltic fingerprint

# Generate keys
../target/release/beltic keygen --alg ES256 --out test-key.pem --pub test-key.pub.pem

# Sign the manifest
../target/release/beltic sign --key test-key.pem --payload agent-manifest.json --out credential.jwt

# Verify
../target/release/beltic verify --key test-key.pub.pem --token credential.jwt
```

See `test-agent/README.md` for more details about the customer support agent implementation.

## Development

### Project Structure

```
beltic-cli/
├── src/
│   ├── main.rs              # CLI entry point
│   ├── lib.rs               # Library exports
│   ├── commands/            # Command implementations
│   │   ├── init.rs          # Initialize manifest
│   │   ├── fingerprint.rs   # Generate fingerprint
│   │   ├── keygen.rs        # Generate keys
│   │   ├── sign.rs          # Sign credentials
│   │   └── verify.rs        # Verify signatures
│   ├── manifest/            # Manifest handling
│   │   ├── config.rs        # Configuration parsing
│   │   ├── detector.rs      # Auto-detection logic
│   │   ├── fingerprint.rs   # Fingerprint generation
│   │   ├── prompts.rs       # Interactive prompts
│   │   ├── schema.rs        # JSON schemas
│   │   ├── templates.rs     # Configuration templates
│   │   └── validator.rs     # Schema validation
│   └── crypto/              # Cryptographic operations
│       ├── mod.rs           # Crypto utilities
│       ├── signer.rs        # JWS signing
│       └── verifier.rs      # JWS verification
├── tests/                   # Integration tests
│   └── jws_vectors.rs       # JWS test vectors
├── test-agent/              # Example TypeScript agent
├── Cargo.toml               # Project manifest
└── README.md                # This file
```

### Building for Development

```bash
# Development build
cargo build

# Release build (optimized, with LTO)
cargo build --release

# Run directly without building
cargo run -- <command>
```

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test
cargo test <test_name>

# Run tests with output
cargo test -- --nocapture

# Run tests without running them (compile only)
cargo test --no-run
```

### Key Dependencies

- **clap** - CLI argument parsing with derive macros
- **ed25519-dalek** - Ed25519 cryptographic signatures
- **p256** - P-256/ECDSA cryptography
- **jsonwebtoken** - JWS token support
- **serde** / **serde_json** / **serde_yaml** - Serialization
- **sha2** - SHA256 hashing
- **uuid** - UUID generation and parsing
- **chrono** - Timestamp handling
- **walkdir** - File system traversal
- **dialoguer** / **console** - Interactive CLI
- **indicatif** - Progress bars

## Security

### Key Management

- Private keys are stored in PKCS#8 PEM format
- Keys are securely cleared from memory using the `zeroize` crate
- Uses cryptographically secure random number generation (`OsRng`)
- No hardcoded keys or secrets in the codebase

### Signature Algorithms

**EdDSA (Ed25519)** - Recommended
- Modern, high-performance signature algorithm
- 256-bit security level
- Fast signing and verification

**ES256 (ECDSA P-256)**
- NIST-standardized algorithm
- Use for compliance requirements
- Widely supported in enterprise environments

### Best Practices

1. **Never commit private keys** - Add `*.pem` and `*-key.*` to `.gitignore`
2. **Use strong key storage** - Consider using hardware security modules (HSM) or key management services (KMS) in production
3. **Rotate keys regularly** - Implement key rotation policies for production deployments
4. **Validate inputs** - The CLI validates all inputs against schemas and patterns
5. **Audit fingerprints** - Regularly regenerate and compare fingerprints to detect unauthorized changes

## Roadmap

Beltic CLI is the foundation for a larger credential management ecosystem. Planned features include:

- **TypeScript and Python SDKs** - Native language bindings for popular platforms
- **W3C Verifiable Credentials** - Support for VC Data Model 1.1
- **DID Resolution** - Integration with decentralized identity networks
- **Credential Platform** - Centralized issuance and revocation service
- **KMS/HSM Integration** - Hardware-backed key security
- **Status List 2021** - Advanced credential revocation mechanisms
- **Real-time Verification** - Webhook-based credential status updates

See `sdk.md` for detailed SDK development plans.

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.
