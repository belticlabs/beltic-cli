# Beltic CLI

A command-line tool for managing and signing credentials for AI agents, providing cryptographic verification of agent identity, capabilities, and compliance.

## Overview

Beltic CLI enables developers to create verifiable credentials for AI agents with deterministic code fingerprinting and strong cryptographic signatures. It provides a complete workflow for initializing agent manifests, generating cryptographic keys, signing credentials as JWS tokens, and verifying signatures.

## Features

- **Agent Manifest Management** - Create agent manifests with metadata including name, version, tools, and deployment configuration
- **Deterministic Fingerprinting** - Generate SHA256 fingerprints of your codebase with configurable include/exclude patterns
- **Cryptographic Key Generation** - Support for Ed25519 (EdDSA) and P-256 (ES256) algorithms with smart defaults
- **JWS Token Signing** - Schema-aware signing for Agent/Developer Credential v1 with `vc` claim, `kid` header, and Beltic media types
- **Signature Verification** - Verify signatures plus issuer/audience/time claims and validate payloads against the official JSON Schemas
- **HTTP Message Signatures** - Sign HTTP requests per RFC 9421 for Web Bot Auth compatibility
- **Sandbox Compliance Testing** - Run agents in a sandbox with manifest-derived policy enforcement and JSON reports
- **Key Directory Management** - Generate and serve key directories for HTTP Message Signatures
- **Flexible Configuration** - YAML-based configuration supporting multiple deployment types (standalone, monorepo, embedded, plugin, serverless)
- **Interactive Mode** - Developer-friendly prompts with auto-discovery of keys and credentials
- **Smart Defaults** - Keys automatically stored in `.beltic/` with private keys gitignored

## Installation

### Quick Install (Recommended)

**Shell (macOS/Linux):**
```bash
curl -fsSL https://raw.githubusercontent.com/belticlabs/beltic-cli/master/install.sh | sh
```

**Homebrew (macOS/Linux):**
```bash
brew tap belticlabs/tap
brew install beltic
```

**Cargo (Rust):**
```bash
cargo install beltic
```

### Build from Source

Requires Rust 1.70 or later (2021 edition).

```bash
# Clone the repository
git clone https://github.com/belticlabs/beltic-cli.git
cd beltic-cli

# Build release binary
cargo build --release

# The binary will be available at:
./target/release/beltic

# Or install locally
cargo install --path .
```

## Quick Start

Here's a complete workflow to create and sign an agent credential:

```bash
# 1. Create developer credential (optional, for agent manifests)
beltic dev-init

# 2. Initialize agent manifest (interactive)
beltic init

# 3. Generate code fingerprint
beltic fingerprint

# 4. Generate cryptographic keypair (interactive - keys saved to .beltic/)
beltic keygen

# 5. Sign the credential (interactive - auto-discovers keys and payloads)
beltic sign

# 6. Verify the signature (interactive - auto-discovers keys and tokens)
beltic verify

# 7. Run sandbox for a compliance smoke test
beltic sandbox --manifest agent-manifest.json --command "npm start"
```

The CLI uses smart defaults and interactive mode by default. Keys are automatically saved to `.beltic/` with timestamp-based names (e.g., `eddsa-2024-11-26-private.pem`), and private keys are automatically added to `.gitignore`.

For CI/CD or scripting, use `--non-interactive` mode with explicit paths:

```bash
beltic keygen --alg EdDSA --out private.pem --pub public.pem --non-interactive
beltic sign --key private.pem --payload credential.json --kid my-key --non-interactive
beltic verify --key public.pem --token credential.jwt --non-interactive
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

### `dev-init` - Create Developer Credential

Create a self-attested developer credential for use with agent credentials. This credential identifies you as the developer of AI agents.

```bash
# Interactive mode (default)
beltic dev-init
# → Prompts for legal name, entity type, country, website, email, public key (optional), and output path
# → Creates developer-credential.json by default

# With specific options
beltic dev-init \
  --name "Acme Corp" \
  --entity-type corporation \
  --country US \
  --website https://acme.com \
  --email dev@acme.com \
  --output my-developer-credential.json

# Include public key in credential
beltic dev-init \
  --name "John Doe" \
  --entity-type individual \
  --country US \
  --website https://johndoe.dev \
  --email john@johndoe.dev \
  --public-key .beltic/eddsa-2024-11-26-public.pem

# Non-interactive mode (for CI/CD)
beltic dev-init \
  --name "Acme Corp" \
  --entity-type corporation \
  --country US \
  --website https://acme.com \
  --email dev@acme.com \
  --non-interactive
```

**Options:**
- `-o, --output <PATH>` - Output path for developer credential (default: `./developer-credential.json`)
- `--name <NAME>` - Legal name of the developer or organization
- `--entity-type <TYPE>` - Entity type: `individual`, `corporation`, `limited_liability_company`, `sole_proprietorship`, `partnership`, `nonprofit`, or `government_agency`
- `--country <CODE>` - Country code (ISO 3166-1 alpha-2, e.g., `US`, `GB`, `DE`)
- `--website <URL>` - Website URL
- `--email <EMAIL>` - Business email address
- `--public-key <PATH>` - Path to public key (PEM) to embed in credential (optional)
- `-f, --force` - Overwrite existing credential file
- `--non-interactive` - Disable interactive prompts (requires `--name`, `--email`, `--website`)

**Output:** A developer credential JSON file with:
- Credential ID (UUID)
- Legal name, entity type, and incorporation jurisdiction
- Website and business email
- Public key (if provided)
- Issuance and expiration dates (90-day validity for self-attested)
- Self-attested assurance metadata

**Next Steps:**
1. Generate a keypair if you haven't: `beltic keygen`
2. Sign the credential: `beltic sign --payload developer-credential.json`
3. Use the credential ID in agent manifests: `beltic init --developer-id <credential-id>`

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

Generate a new Ed25519 or P-256 keypair for signing credentials. In interactive mode (default), prompts for algorithm and key name, with keys saved to `.beltic/`.

```bash
# Interactive mode (recommended for development)
beltic keygen
# → Prompts for algorithm (default: EdDSA) and key name
# → Saves to .beltic/{name}-private.pem and .beltic/{name}-public.pem
# → Automatically adds private keys to .gitignore

# Generate with custom name
beltic keygen --name my-agent-key

# Generate with explicit paths
beltic keygen --alg EdDSA --out private.pem --pub public.pem

# Non-interactive mode (for CI/CD)
beltic keygen --alg ES256 --non-interactive
# → Uses defaults: .beltic/es256-{date}-private.pem
```

**Options:**
- `--alg <ALGORITHM>` - Signature algorithm: `EdDSA` (Ed25519, default) or `ES256` (P-256)
- `--out <PATH>` - Output path for private key (default: `.beltic/{name}-private.pem`)
- `--pub <PATH>` - Output path for public key (default: `.beltic/{name}-public.pem`)
- `--name <NAME>` - Custom name for keypair (default: `{alg}-{YYYY-MM-DD}`)
- `--non-interactive` - Disable prompts and use defaults

**Security:**
- Private keys are written with restricted permissions (`0600` on Unix)
- Keys are generated in PKCS#8 PEM format and securely cleared from memory
- Private keys are automatically added to `.gitignore`

### `sign` - Sign Credential

Sign a Beltic credential as a JWT with Beltic media types and a `vc` claim (iss/sub/jti/nbf/exp derived from the payload). In interactive mode (default), auto-discovers keys and credential files.

```bash
# Interactive mode (recommended)
beltic sign
# → Auto-discovers private keys in .beltic/, ./keys/, ./
# → Auto-discovers credential JSON files
# → Prompts for key, payload, kid, and output path

# Sign with explicit options
beltic sign --key .beltic/eddsa-2024-11-26-private.pem \
  --payload agent-credential.json \
  --kid my-agent-key \
  --out credential.jwt

# Sign an agent credential (subject DID required for agents)
beltic sign --key private.pem \
  --payload agent-credential.json \
  --subject did:web:agent.example.com \
  --kid agent-key-1 \
  --out credential.jwt

# Non-interactive mode (for CI/CD)
beltic sign --key private.pem --payload credential.json --kid my-key --non-interactive
```

**Options:**
- `--key <PATH>` - Path to private key (PEM). Auto-discovered if omitted in interactive mode.
- `--alg <ALGORITHM>` - Signature algorithm: `EdDSA` (default) or `ES256`
- `--payload <PATH>` - Path to JSON credential file. Auto-discovered if omitted.
- `--out <PATH>` - Output path for JWT (default: `{payload}.jwt`)
- `--kid <ID>` - Key identifier for JWS header. Prompted if omitted in interactive mode.
- `--issuer <DID>` - Override issuer DID for `iss` (defaults to `issuerDid` in payload)
- `--subject <DID>` - Subject DID for `sub` (required for agents if payload lacks `subjectDid`)
- `--audience <AUDIENCE>` - Audience claim (repeat to add multiple)
- `--credential-type <TYPE>` - Force type detection (`agent` or `developer`)
- `--skip-schema` - Skip JSON Schema validation before signing
- `--non-interactive` - Disable prompts (requires --key, --payload, --kid)

**Output:** A compact JWT with `typ` set to `application/beltic-agent+jwt` or `application/beltic-developer+jwt` and `cty` set to `application/json`.

### `verify` - Verify Signature

Verify a Beltic credential token (Agent/Developer) including signature, issuer/audience claims, and JSON Schema validation. In interactive mode (default), auto-discovers keys and token files.

```bash
# Interactive mode (recommended)
beltic verify
# → Auto-discovers public keys in .beltic/, ./keys/, ./
# → Auto-discovers token files (.jwt, .jws)
# → Prompts for key and token selection

# Verify with explicit paths
beltic verify --key .beltic/eddsa-2024-11-26-public.pem --token credential.jwt

# Verify token from string
beltic verify --key public.pem --token "eyJhbGc..."

# Non-interactive mode (for CI/CD)
beltic verify --key public.pem --token credential.jwt --non-interactive
```

**Options:**
- `--key <PATH>` - Path to public key (PEM). Auto-discovered if omitted in interactive mode.
- `--token <PATH|STRING>` - Path to JWT file or token string. Auto-discovered if omitted.
- `--issuer <DID>` - Expected issuer DID (`iss`)
- `--audience <AUDIENCE>` - Expected audience value(s)
- `--credential-type <TYPE>` - Expected credential type (`agent` or `developer`)
- `--skip-schema` - Skip JSON Schema validation of the `vc` claim
- `--non-interactive` - Disable prompts (requires --key, --token)

**Output:**
- On success: "VALID" with credential type/alg/kid/iss/sub/jti plus the pretty-printed `vc` payload
- On failure: "INVALID" with error details

### `http-sign` - Sign HTTP Requests (Web Bot Auth)

Sign HTTP requests per RFC 9421 for Web Bot Auth compatibility. This command generates the required `Signature-Agent`, `Signature-Input`, and `Signature` headers.

```bash
# Sign a GET request
beltic http-sign \
  --method GET \
  --url https://api.example.com/data \
  --key .beltic/eddsa-2024-11-26-private.pem \
  --key-directory https://myagent.example.com/.well-known/http-message-signatures-directory

# Sign a POST request with body
beltic http-sign \
  --method POST \
  --url https://api.example.com/submit \
  --key private.pem \
  --key-directory https://myagent.example.com/.well-known/http-message-signatures-directory \
  --body '{"data": "value"}'

# Output as curl command
beltic http-sign \
  --method GET \
  --url https://api.example.com/data \
  --key private.pem \
  --key-directory https://myagent.example.com/.well-known/http-message-signatures-directory \
  --format curl

# Include custom headers in signature
beltic http-sign \
  --method POST \
  --url https://api.example.com/data \
  --key private.pem \
  --key-directory https://myagent.example.com/.well-known/http-message-signatures-directory \
  --header "Content-Type: application/json" \
  --body-file request.json
```

**Options:**
- `--method <METHOD>` - HTTP method (GET, POST, etc.)
- `--url <URL>` - Target URL
- `--key <PATH>` - Path to Ed25519 private key (PEM)
- `--key-directory <URL>` - URL to the agent's key directory (must be HTTPS)
- `--header <HEADER>` - Additional headers to include (format: "Name: Value", repeatable)
- `--component <COMPONENT>` - Signature components (default: @method, @authority, @path, signature-agent)
- `--body <STRING>` - Request body string
- `--body-file <PATH>` - Request body from file
- `--expires-in <SECS>` - Signature validity in seconds (default: 60)
- `--format <FORMAT>` - Output format: `headers` (default) or `curl`

**Output:** Signature headers ready to use in HTTP requests. Also outputs the key ID (JWK thumbprint) and expiration time.

### `directory` - Key Directory Management

Generate and manage key directories for HTTP Message Signatures (Web Bot Auth).

#### `directory generate` - Generate Key Directory

```bash
# Generate key directory from public keys
beltic directory generate \
  --public-key .beltic/eddsa-2024-11-26-public.pem \
  --out .well-known/http-message-signatures-directory

# Generate with multiple keys
beltic directory generate \
  --public-key key1-public.pem \
  --public-key key2-public.pem \
  --out directory.json

# Generate with signed response headers
beltic directory generate \
  --public-key public.pem \
  --out directory.json \
  --sign \
  --private-key private.pem \
  --authority myagent.example.com
```

**Options:**
- `--public-key <PATH>` - Path to Ed25519 public key (PEM, repeatable)
- `--out <PATH>` - Output path for key directory JSON
- `--sign` - Also output signature headers for the response
- `--private-key <PATH>` - Private key for signing (required with --sign)
- `--authority <HOST>` - Authority (host) for signature (required with --sign)

#### `directory thumbprint` - Compute JWK Thumbprint

```bash
# Get the JWK thumbprint for a public key
beltic directory thumbprint --public-key public.pem
```

**Options:**
- `--public-key <PATH>` - Path to Ed25519 public key (PEM)

**Output:** The JWK thumbprint (RFC 7638) used as the key identifier in HTTP Message Signatures.

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

### Web Bot Auth Workflow

Web Bot Auth uses HTTP Message Signatures (RFC 9421) to authenticate AI agents making HTTP requests. Here's a complete workflow:

```bash
# 1. Generate an Ed25519 keypair for your agent
beltic keygen --name my-agent

# 2. Generate the key directory JSON
beltic directory generate \
  --public-key .beltic/my-agent-public.pem \
  --out .well-known/http-message-signatures-directory

# 3. Get the JWK thumbprint (this is your keyid)
beltic directory thumbprint --public-key .beltic/my-agent-public.pem
# Output: S9Zz0...  (use this as keyid)

# 4. Host the key directory at your agent's domain
# The directory should be served at:
#   https://myagent.example.com/.well-known/http-message-signatures-directory
# with Content-Type: application/http-message-signatures-directory+json

# 5. Sign HTTP requests to protected APIs
beltic http-sign \
  --method GET \
  --url https://api.example.com/protected/resource \
  --key .beltic/my-agent-private.pem \
  --key-directory https://myagent.example.com/.well-known/http-message-signatures-directory

# Output:
# Signature-Agent: "https://myagent.example.com/.well-known/http-message-signatures-directory"
# Signature-Input: sig1=("@method" "@authority" "@path" "signature-agent");alg="ed25519";keyid="S9Zz0...";created=...;expires=...;nonce="...";tag="web-bot-auth"
# Signature: sig1=:...:

# 6. Or output as a curl command for testing
beltic http-sign \
  --method POST \
  --url https://api.example.com/submit \
  --key .beltic/my-agent-private.pem \
  --key-directory https://myagent.example.com/.well-known/http-message-signatures-directory \
  --body '{"query": "Hello, API!"}' \
  --format curl
```

**Key Directory Format:**
```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "base64url-encoded-public-key"
    }
  ]
}
```

**How it works:**
1. Your agent hosts a key directory at a well-known URL
2. The `Signature-Agent` header points to this directory
3. The server fetches the directory, finds the key matching `keyid`
4. The server verifies the signature using the public key
5. If valid, the request is authenticated as coming from your agent

## Development

### Project Structure

```
beltic-cli/
├── src/
│   ├── main.rs              # CLI entry point
│   ├── lib.rs               # Library exports
│   ├── credential.rs        # Credential building and validation
│   ├── commands/            # Command implementations
│   │   ├── init.rs          # Initialize manifest
│   │   ├── fingerprint.rs   # Generate fingerprint
│   │   ├── keygen.rs        # Generate keys (interactive mode)
│   │   ├── sign.rs          # Sign credentials (interactive mode)
│   │   ├── verify.rs        # Verify signatures (interactive mode)
│   │   ├── http_sign.rs     # HTTP request signing (Web Bot Auth)
│   │   ├── directory.rs     # Key directory management
│   │   ├── prompts.rs       # Shared interactive prompts
│   │   └── discovery.rs     # Key/token auto-discovery
│   ├── manifest/            # Manifest handling
│   │   ├── config.rs        # Configuration parsing
│   │   ├── detector.rs      # Auto-detection logic
│   │   ├── fingerprint.rs   # Fingerprint generation
│   │   ├── prompts.rs       # Interactive prompts for manifest
│   │   ├── schema.rs        # JSON schemas
│   │   ├── templates.rs     # Configuration templates
│   │   └── validator.rs     # Schema validation
│   └── crypto/              # Cryptographic operations
│       ├── mod.rs           # Crypto utilities
│       ├── signer.rs        # JWS signing
│       └── verifier.rs      # JWS verification
├── schemas/                 # JSON schemas for credentials
├── tests/                   # Integration tests
│   └── jws_vectors.rs       # JWS test vectors
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

- Private keys are stored in PKCS#8 PEM format with restricted permissions (`0600` on Unix)
- Keys are securely cleared from memory using the `zeroize` crate
- Uses cryptographically secure random number generation (`OsRng`)
- Private keys are automatically added to `.gitignore` when stored in `.beltic/`
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

## Hosting Requirements

For agents to participate in Web Bot Auth, they need to host certain files publicly. Here are the options:

### Key Directory Hosting

Your agent's key directory must be accessible at an HTTPS URL. Options:

**GitHub Pages (free):**
```bash
# In your agent's repository
mkdir -p .well-known
beltic directory generate --public-key .beltic/my-agent-public.pem --out .well-known/http-message-signatures-directory

# Enable GitHub Pages for the repo, then your directory is at:
# https://<username>.github.io/<repo>/.well-known/http-message-signatures-directory
```

**Vercel/Netlify (free tier):**
- Deploy a static site with the `.well-known/` directory
- Works automatically with Next.js `public/` folder

**Your own server:**
- Serve the JSON file with `Content-Type: application/http-message-signatures-directory+json`

### Agent Credential JWT Hosting (Optional)

If you want other services to fetch your full credential (not just verify signatures), host the JWT:

```bash
# Add credential URL to your key directory
beltic directory generate \
  --public-key .beltic/my-agent-public.pem \
  --credential-url https://example.com/agent-credential.jwt \
  --out .well-known/http-message-signatures-directory
```

## Related Projects

- **[@belticlabs/kya](https://github.com/belticlabs/beltic-sdk)** - TypeScript SDK for credential verification
- **[beltic-spec](https://github.com/belticlabs/beltic-spec)** - JSON schemas for Agent/Developer credentials
- **[airport](https://github.com/belticlabs/airport)** - Verification endpoint to test credentials

## Roadmap

Beltic CLI is the foundation for a larger credential management ecosystem. Planned features include:

- **W3C Verifiable Credentials** - Support for VC Data Model 1.1
- **DID Resolution** - Integration with decentralized identity networks
- **Credential Platform** - Centralized issuance and revocation service
- **KMS/HSM Integration** - Hardware-backed key security
- **Status List 2021** - Advanced credential revocation mechanisms
- **Real-time Verification** - Webhook-based credential status updates

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.
