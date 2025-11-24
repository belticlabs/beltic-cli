# Testing Guide for Beltic CLI

This guide shows how to test the Beltic CLI with the Customer Support Agent.

## Prerequisites

1. Build the Beltic CLI:
```bash
cd /Users/pranavkarra/beltic/beltic-cli
cargo build --release
```

2. The CLI binary will be at: `./target/release/beltic`

## Test Scenarios

### 1. Generate Fingerprint

Generate a SHA256 fingerprint of the agent codebase:

```bash
cd test-agent
../target/release/beltic fingerprint
```

**Expected Output:**
- Displays SHA256 hash of all included files
- Shows list of files included in fingerprint
- Respects `.beltic.yaml` include/exclude patterns

**Test Variations:**
```bash
# With custom config file
../target/release/beltic fingerprint --config custom.yaml

# Specify paths manually
../target/release/beltic fingerprint --include "src/**/*.ts" --exclude "**/*.test.ts"

# Verbose output
../target/release/beltic fingerprint --verbose
```

### 2. Initialize Agent Manifest

Create a new Beltic agent manifest:

```bash
cd test-agent
../target/release/beltic init
```

**Expected Output:**
- Creates `.beltic.yaml` configuration file
- Auto-detects deployment type (should detect "monorepo" or "standalone")
- Prompts for agent metadata (or uses defaults)

**Test Variations:**
```bash
# Non-interactive mode
../target/release/beltic init --name "Customer Support Agent" --version "1.0.0"

# Specify deployment type
../target/release/beltic init --deployment standalone

# Use example config
cp .beltic.yaml.example .beltic.yaml
../target/release/beltic init --from-config
```

### 3. Generate Cryptographic Keys

Generate signing keys for credentials:

```bash
cd test-agent
../target/release/beltic keygen --algorithm ES256 --output agent-key.pem
```

**Expected Output:**
- Generates P-256 (ES256) or Ed25519 (EdDSA) key pair
- Saves private key to specified file
- Displays public key or key ID

**Test Variations:**
```bash
# Ed25519 key
../target/release/beltic keygen --algorithm EdDSA --output agent-key-ed25519.pem

# Different output formats
../target/release/beltic keygen --algorithm ES256 --format jwk --output agent-key.jwk
../target/release/beltic keygen --algorithm ES256 --format pem --output agent-key.pem
```

### 4. Sign Credentials

Sign an agent credential or manifest:

```bash
# First create a test credential JSON file
cat > credential.json << EOF
{
  "agentName": "Customer Support Agent",
  "agentVersion": "1.0.0",
  "developerCredentialId": "did:web:example.com:developers:12345"
}
EOF

# Sign it
../target/release/beltic sign --input credential.json --key agent-key.pem --output credential.jwt
```

**Expected Output:**
- Creates JWS token
- Uses ES256 or EdDSA algorithm
- Saves to output file or displays to stdout

**Test Variations:**
```bash
# Sign and display
../target/release/beltic sign --input credential.json --key agent-key.pem

# Specify algorithm explicitly
../target/release/beltic sign --input credential.json --key agent-key.pem --alg ES256

# Add custom header claims
../target/release/beltic sign --input credential.json --key agent-key.pem --kid "agent-key-1"
```

### 5. Verify Signatures

Verify a signed credential:

```bash
../target/release/beltic verify --input credential.jwt --key agent-key-public.pem
```

**Expected Output:**
- Validates signature
- Displays verification status (valid/invalid)
- Shows decoded payload

**Test Variations:**
```bash
# Verify and extract payload
../target/release/beltic verify --input credential.jwt --key agent-key-public.pem --output payload.json

# Verify with JWK
../target/release/beltic verify --input credential.jwt --jwk agent-key.jwk

# Verify with DID resolution (future)
../target/release/beltic verify --input credential.jwt --did did:web:example.com:developers:12345
```

## Testing Workflow

### Complete End-to-End Test

```bash
cd test-agent

# 1. Copy example config
cp .beltic.yaml.example .beltic.yaml

# 2. Generate fingerprint
echo "=== Generating Fingerprint ==="
../target/release/beltic fingerprint --verbose

# 3. Generate keys
echo "=== Generating Keys ==="
../target/release/beltic keygen --algorithm ES256 --output test-key.pem

# 4. Create a test manifest
cat > manifest.json << EOF
{
  "agentName": "Customer Support Agent",
  "agentVersion": "1.0.0",
  "developerCredentialId": "did:web:example.com:developers:12345",
  "fingerprint": {
    "hash": "$(../target/release/beltic fingerprint | grep -o '[a-f0-9]\{64\}')",
    "algorithm": "SHA256",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  },
  "tools": [
    {
      "name": "send_email",
      "category": "communication",
      "riskLevel": "medium"
    },
    {
      "name": "query_database",
      "category": "database",
      "riskLevel": "low"
    },
    {
      "name": "create_ticket",
      "category": "communication",
      "riskLevel": "medium"
    },
    {
      "name": "web_search",
      "category": "network",
      "riskLevel": "low"
    }
  ]
}
EOF

# 5. Sign the manifest
echo "=== Signing Manifest ==="
../target/release/beltic sign --input manifest.json --key test-key.pem --output manifest.jwt

# 6. Verify the signature
echo "=== Verifying Signature ==="
../target/release/beltic verify --input manifest.jwt

echo "=== Test Complete ==="
```

## Expected Test Results

### Fingerprint Test
- ✅ Includes all `.ts` files in `src/`
- ✅ Includes `package.json` and `tsconfig.json`
- ✅ Excludes `node_modules/`, `dist/`, test files
- ✅ Produces consistent hash across runs
- ✅ Hash changes when files are modified

### Init Test
- ✅ Creates valid `.beltic.yaml` file
- ✅ Detects deployment type correctly
- ✅ Includes agent metadata from config
- ✅ Validates YAML syntax

### Keygen Test
- ✅ Generates valid P-256 or Ed25519 keys
- ✅ Saves keys in PEM or JWK format
- ✅ Keys can be used for signing
- ✅ Public keys can be extracted

### Sign Test
- ✅ Creates valid JWS tokens
- ✅ Uses correct algorithm (ES256 or EdDSA)
- ✅ Includes all required header claims
- ✅ Produces verifiable signatures

### Verify Test
- ✅ Correctly validates valid signatures
- ✅ Rejects invalid signatures
- ✅ Extracts and displays payload
- ✅ Handles malformed tokens gracefully

## Edge Cases to Test

1. **Empty Directory**: Run fingerprint in empty directory
2. **Large Files**: Add large files and test performance
3. **Invalid Keys**: Try signing with corrupted key file
4. **Malformed JSON**: Test with invalid JSON in manifest
5. **Missing Config**: Run commands without `.beltic.yaml`
6. **Permission Issues**: Test with read-only files
7. **Special Characters**: Include files with unicode names
8. **Symlinks**: Test with symbolic links in codebase

## Performance Benchmarks

```bash
# Benchmark fingerprint generation
time ../target/release/beltic fingerprint

# Expected: < 100ms for typical agent codebase
# Should handle 1000+ files efficiently
```

## Integration with Agent

To test the CLI with the actual running agent:

```bash
# 1. Set up environment
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY

# 2. Install dependencies
npm install

# 3. Generate Beltic credential
../target/release/beltic fingerprint > fingerprint.txt

# 4. Run the agent
npm run dev

# The agent will demonstrate all 4 tools in action
```

## Troubleshooting

### Fingerprint not consistent
- Check for timestamp-based or random content in files
- Ensure file ordering is deterministic
- Verify `.beltic.yaml` patterns are correct

### Signature verification fails
- Confirm public/private key pair matches
- Check algorithm matches between sign and verify
- Validate JSON payload is well-formed

### Init command fails
- Ensure directory has write permissions
- Check for existing `.beltic.yaml` conflicts
- Verify git repository is initialized (if needed)

## Next Steps

After basic CLI testing, you can:

1. **Schema Validation**: Test against full Beltic JSON schemas
2. **Conditional Rules**: Verify conditional validation logic
3. **Status Lists**: Test revocation checking
4. **DID Resolution**: Integrate with DID resolvers
5. **Platform Integration**: Connect to credential issuance platform
