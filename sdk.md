# Beltic SDK Development Blueprint

## Executive Summary

This document outlines the design and implementation strategy for official Beltic SDKs in TypeScript and Python. These SDKs will enable developers to integrate Beltic agent credentials into their applications, providing a secure and standardized way to manage AI agent identity, capabilities, and compliance.

### Design Principles

1. **Developer-First**: Intuitive APIs with excellent documentation and helpful error messages
2. **Type Safety**: Leverage TypeScript interfaces and Python type hints for compile-time safety
3. **Consistency**: Parallel APIs across languages with idiomatic patterns for each
4. **Extensibility**: Plugin architecture for custom validators, resolvers, and key stores
5. **Security**: Secure-by-default with built-in validation and cryptographic best practices
6. **Progressive Enhancement**: Start simple, add complexity as needed

### MVP Scope

The v1 MVP focuses on core functionality without requiring external infrastructure:
- Local agent manifest creation and management
- Fingerprint generation for codebase integrity
- Credential building and validation
- JWS signing and verification
- Mock credential issuance for development

### Future Enhancements

- Integration with production credential issuance platform
- W3C Verifiable Credentials format support
- Advanced revocation with Status List 2021
- DID resolution network integration
- KMS/HSM key management
- Real-time credential status updates

## TypeScript SDK Design

### Package Architecture

```
@beltic/sdk                 # Main SDK package (re-exports all modules)
├── @beltic/core           # Base types, interfaces, and utilities
├── @beltic/manifest       # Manifest creation and fingerprinting
├── @beltic/credentials   # Credential building and validation
├── @beltic/crypto        # Signing, verification, and key management
└── @beltic/did          # DID resolution and identity management
```

### Core APIs

#### BelticClient

```typescript
import { BelticClient } from '@beltic/sdk';

interface BelticConfig {
  network?: 'mainnet' | 'testnet' | 'local';
  resolver?: DIDResolver;
  keyStore?: KeyStore;
  logger?: Logger;
}

class BelticClient {
  constructor(config?: BelticConfig);

  // Manifest operations
  manifest: ManifestManager;

  // Credential operations
  credentials: CredentialManager;

  // Cryptographic operations
  crypto: CryptoManager;

  // DID operations
  did: DIDManager;
}
```

#### ManifestBuilder

```typescript
class ManifestBuilder {
  constructor(client: BelticClient);

  withAgent(info: AgentInfo): this;
  withDeveloper(credentialId: string): this;
  withDeployment(type: DeploymentType): this;
  withTools(tools: Tool[]): this;
  withDataHandling(profile: DataHandlingProfile): this;
  withSafety(config: SafetyConfig): this;
  scan(paths: string | PathConfig): Promise<this>;
  validate(): ValidationResult;
  build(): Promise<AgentManifest>;
}

// Usage example
const manifest = await client.manifest
  .create()
  .withAgent({
    name: 'Customer Support Agent',
    version: '1.0.0',
    description: 'AI agent for customer support automation'
  })
  .withDeveloper('did:web:example.com:developers:12345')
  .withDeployment('standalone')
  .withTools([
    {
      name: 'email_send',
      category: 'communication',
      riskLevel: 'medium',
      requiresAuth: true
    }
  ])
  .scan('./src')
  .build();
```

#### CredentialBuilder

```typescript
class CredentialBuilder {
  constructor(client: BelticClient);

  fromManifest(manifest: AgentManifest): this;
  withSafetyMetrics(metrics: SafetyMetrics): this;
  withCompliance(compliance: ComplianceData): this;
  withOperations(ops: OperationalMetadata): this;
  sign(key: SigningKey): Promise<string>;
  validate(): ValidationResult;
  build(): AgentCredential;
}

// Usage example
const credential = await client.credentials
  .create()
  .fromManifest(manifest)
  .withSafetyMetrics({
    harmfulContentScore: 0.95,
    promptInjectionScore: 0.92,
    toolAbuseScore: 0.88,
    piiLeakageScore: 0.90
  })
  .sign(privateKey);
```

### Type Definitions

```typescript
// Generated from JSON schemas
export interface AgentCredential {
  // Identity
  id: string;
  agentName: string;
  agentVersion: string;
  developerCredentialId: string;

  // Technical profile
  primaryModel: ModelInfo;
  contextWindow: number;
  tools: Tool[];

  // Safety and compliance
  safetyMetrics: SafetyMetrics;
  dataLocationProfile: DataLocationProfile;
  humanOversight: HumanOversightConfig;

  // Cryptographic
  fingerprint: FingerprintMetadata;
  issuer: string;
  issuedAt: string;
  expiresAt?: string;
}

export interface Tool {
  name: string;
  category: ToolCategory;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  description?: string;
  requiresAuth?: boolean;
  requiresHumanApproval?: boolean;
  mitigations?: string[];
}

export interface SafetyMetrics {
  harmfulContentScore: number;
  promptInjectionScore: number;
  toolAbuseScore: number;
  piiLeakageScore: number;
  benchmarkDate: string;
  benchmarkProvider?: string;
}
```

### Error Handling

```typescript
export class BelticError extends Error {
  code: string;
  details?: any;
}

export class ValidationError extends BelticError {
  violations: ValidationViolation[];
}

export class SigningError extends BelticError {
  algorithm?: string;
}

export class VerificationError extends BelticError {
  reason: 'invalid_signature' | 'expired' | 'revoked' | 'malformed';
}

// Usage
try {
  const credential = await builder.build();
} catch (error) {
  if (error instanceof ValidationError) {
    console.error('Validation failed:', error.violations);
  }
}
```

### Testing Strategy

```typescript
// Test fixtures
import { createMockManifest, createMockCredential } from '@beltic/testing';

describe('CredentialBuilder', () => {
  it('should create valid credential from manifest', async () => {
    const manifest = createMockManifest();
    const credential = await new CredentialBuilder()
      .fromManifest(manifest)
      .build();

    expect(credential).toMatchSchema(AgentCredentialSchema);
  });
});
```

## Python SDK Design

### Package Structure

```
beltic/
├── __init__.py           # Main SDK exports
├── core/                 # Base types and utilities
├── manifest/            # Manifest creation and fingerprinting
├── credentials/         # Credential building and validation
├── crypto/             # Signing, verification, and key management
└── did/               # DID resolution and identity management
```

### Core APIs

#### BelticClient

```python
from beltic import BelticClient
from beltic.types import BelticConfig

class BelticClient:
    def __init__(self, config: Optional[BelticConfig] = None):
        self.manifest = ManifestManager(self)
        self.credentials = CredentialManager(self)
        self.crypto = CryptoManager(self)
        self.did = DIDManager(self)

# Usage
client = BelticClient(config={
    'network': 'testnet',
    'resolver': WebDIDResolver()
})
```

#### ManifestBuilder

```python
from beltic.manifest import ManifestBuilder
from beltic.types import AgentInfo, Tool, DeploymentType

class ManifestBuilder:
    def with_agent(self, info: AgentInfo) -> 'ManifestBuilder':
        """Set agent information"""

    def with_developer(self, credential_id: str) -> 'ManifestBuilder':
        """Set developer credential ID"""

    def with_deployment(self, type: DeploymentType) -> 'ManifestBuilder':
        """Set deployment type"""

    def with_tools(self, tools: List[Tool]) -> 'ManifestBuilder':
        """Add tool capabilities"""

    async def scan(self, paths: Union[str, PathConfig]) -> 'ManifestBuilder':
        """Scan codebase and generate fingerprint"""

    def validate(self) -> ValidationResult:
        """Validate manifest against schema"""

    async def build(self) -> AgentManifest:
        """Build the final manifest"""

# Usage example
manifest = await client.manifest.create() \
    .with_agent(AgentInfo(
        name='Customer Support Agent',
        version='1.0.0',
        description='AI agent for customer support automation'
    )) \
    .with_developer('did:web:example.com:developers:12345') \
    .with_deployment('standalone') \
    .with_tools([
        Tool(
            name='email_send',
            category='communication',
            risk_level='medium',
            requires_auth=True
        )
    ]) \
    .scan('./src') \
    .build()
```

#### CredentialBuilder

```python
from beltic.credentials import CredentialBuilder
from beltic.types import SafetyMetrics

class CredentialBuilder:
    def from_manifest(self, manifest: AgentManifest) -> 'CredentialBuilder':
        """Initialize from agent manifest"""

    def with_safety_metrics(self, metrics: SafetyMetrics) -> 'CredentialBuilder':
        """Add safety benchmark scores"""

    def with_compliance(self, compliance: ComplianceData) -> 'CredentialBuilder':
        """Add compliance information"""

    async def sign(self, key: SigningKey) -> str:
        """Sign credential and return JWS token"""

    def validate(self) -> ValidationResult:
        """Validate credential against schema"""

    def build(self) -> AgentCredential:
        """Build the credential object"""

# Usage example
credential_token = await client.credentials.create() \
    .from_manifest(manifest) \
    .with_safety_metrics(SafetyMetrics(
        harmful_content_score=0.95,
        prompt_injection_score=0.92,
        tool_abuse_score=0.88,
        pii_leakage_score=0.90,
        benchmark_date='2024-01-15'
    )) \
    .sign(private_key)
```

### Type Definitions

```python
from dataclasses import dataclass
from typing import Optional, List, Dict, Any
from enum import Enum

@dataclass
class AgentCredential:
    """Agent credential following Beltic v1 schema"""
    # Identity
    id: str
    agent_name: str
    agent_version: str
    developer_credential_id: str

    # Technical profile
    primary_model: ModelInfo
    context_window: int
    tools: List[Tool]

    # Safety and compliance
    safety_metrics: SafetyMetrics
    data_location_profile: DataLocationProfile
    human_oversight: HumanOversightConfig

    # Cryptographic
    fingerprint: FingerprintMetadata
    issuer: str
    issued_at: str
    expires_at: Optional[str] = None

class ToolCategory(Enum):
    COMMUNICATION = 'communication'
    FILE_SYSTEM = 'file_system'
    NETWORK = 'network'
    DATABASE = 'database'
    COMPUTE = 'compute'

@dataclass
class Tool:
    """Tool capability declaration"""
    name: str
    category: ToolCategory
    risk_level: str  # 'low', 'medium', 'high', 'critical'
    description: Optional[str] = None
    requires_auth: bool = False
    requires_human_approval: bool = False
    mitigations: Optional[List[str]] = None

@dataclass
class SafetyMetrics:
    """Safety benchmark scores"""
    harmful_content_score: float
    prompt_injection_score: float
    tool_abuse_score: float
    pii_leakage_score: float
    benchmark_date: str
    benchmark_provider: Optional[str] = None
```

### Error Handling

```python
class BelticError(Exception):
    """Base exception for Beltic SDK"""
    def __init__(self, message: str, code: str, details: Any = None):
        super().__init__(message)
        self.code = code
        self.details = details

class ValidationError(BelticError):
    """Validation failure"""
    def __init__(self, violations: List[ValidationViolation]):
        super().__init__(
            f"Validation failed with {len(violations)} violations",
            'VALIDATION_ERROR',
            violations
        )
        self.violations = violations

class SigningError(BelticError):
    """Signing operation failure"""
    pass

class VerificationError(BelticError):
    """Verification failure"""
    pass

# Usage
try:
    credential = await builder.build()
except ValidationError as e:
    for violation in e.violations:
        print(f"Validation error: {violation.path} - {violation.message}")
```

### Testing Strategy

```python
import pytest
from beltic.testing import create_mock_manifest, create_mock_credential

@pytest.mark.asyncio
async def test_credential_creation():
    """Test credential creation from manifest"""
    manifest = create_mock_manifest()
    builder = CredentialBuilder()
    credential = await builder.from_manifest(manifest).build()

    assert credential.agent_name == manifest.agent_name
    assert credential.fingerprint.hash == manifest.fingerprint.hash

@pytest.fixture
def mock_signing_key():
    """Provide mock signing key for tests"""
    return create_mock_signing_key('ES256')
```

## Core Features for MVP v1

### 1. Agent Manifest Management

**Functionality:**
- Create new agent manifest with required fields
- Auto-detect deployment context (standalone, monorepo, plugin, etc.)
- Generate deterministic SHA256 fingerprints of codebase
- Include/exclude paths using glob patterns
- Track internal and external dependencies

**Implementation:**
```typescript
// TypeScript
const manifest = await sdk.manifest.create()
  .autoDetect() // Auto-detect deployment context
  .scan({
    include: ['src/**/*.ts', 'package.json'],
    exclude: ['**/*.test.ts', 'node_modules']
  })
  .build();

// Python
manifest = await sdk.manifest.create() \
    .auto_detect() \
    .scan(
        include=['src/**/*.py', 'requirements.txt'],
        exclude=['**/*_test.py', '__pycache__']
    ) \
    .build()
```

### 2. Credential Building

**Functionality:**
- Construct AgentCredential from manifest
- Validate against JSON Schema Draft 2020-12
- Apply conditional validation rules
- Support incremental building with validation at each step

**Implementation:**
```typescript
// TypeScript
const credential = sdk.credentials.create()
  .fromManifest(manifest)
  .withSafetyMetrics(safetyScores)
  .withTools(toolDefinitions)
  .validate() // Throws ValidationError if invalid
  .build();

// Python
credential = sdk.credentials.create() \
    .from_manifest(manifest) \
    .with_safety_metrics(safety_scores) \
    .with_tools(tool_definitions) \
    .validate() \
    .build()
```

### 3. Cryptographic Operations

**Functionality:**
- Generate Ed25519 and P-256 key pairs
- Create JWS tokens with ES256 or EdDSA
- Verify JWS signatures
- Extract and validate payloads

**Implementation:**
```typescript
// TypeScript
// Key generation
const keyPair = await sdk.crypto.generateKeyPair('ES256');

// Signing
const token = await sdk.crypto.sign(credential, keyPair.privateKey);

// Verification
const verified = await sdk.crypto.verify(token);
console.log(verified.payload); // Original credential
console.log(verified.header); // JWS header with alg, kid, etc.

// Python
# Key generation
key_pair = await sdk.crypto.generate_key_pair('ES256')

# Signing
token = await sdk.crypto.sign(credential, key_pair.private_key)

# Verification
verified = await sdk.crypto.verify(token)
print(verified.payload)  # Original credential
print(verified.header)   # JWS header
```

### 4. Schema Validation

**Functionality:**
- Validate credentials against Beltic JSON schemas
- Provide detailed error messages with paths
- Support conditional validation rules
- Cache compiled schemas for performance

**Implementation:**
```typescript
// TypeScript
const validator = new SchemaValidator();
const result = validator.validate(credential, 'AgentCredential');
if (!result.valid) {
  result.errors.forEach(error => {
    console.error(`${error.path}: ${error.message}`);
  });
}

// Python
validator = SchemaValidator()
result = validator.validate(credential, 'AgentCredential')
if not result.valid:
    for error in result.errors:
        print(f"{error.path}: {error.message}")
```

### 5. Mock Credential Issuance

**Functionality:**
- Simulate credential issuance for development
- Generate test credentials with realistic data
- Mock DID resolution and key discovery
- Provide test vectors for validation

**Implementation:**
```typescript
// TypeScript
const mockIssuer = new MockCredentialIssuer({
  issuerDID: 'did:web:beltic.localhost:issuer',
  validityPeriod: 90 * 24 * 60 * 60 * 1000 // 90 days
});

const issuedCredential = await mockIssuer.issue(manifest);

// Python
mock_issuer = MockCredentialIssuer(
    issuer_did='did:web:beltic.localhost:issuer',
    validity_period=timedelta(days=90)
)

issued_credential = await mock_issuer.issue(manifest)
```

## Placeholder Infrastructure

### Mock Issuer Service

```typescript
// TypeScript
class MockIssuerService {
  async issueCredential(request: CredentialRequest): Promise<SignedCredential> {
    // Validate request
    this.validateRequest(request);

    // Generate mock credential with test data
    const credential = this.buildCredential(request);

    // Sign with test key
    const signed = await this.sign(credential);

    // Store in local cache for verification
    this.cache.set(credential.id, signed);

    return signed;
  }

  async getCredentialStatus(id: string): Promise<CredentialStatus> {
    // Return mock status from cache
    return this.cache.get(id)?.status || 'unknown';
  }
}
```

### Stub DID Resolver

```python
# Python
class StubDIDResolver:
    """DID resolver with hardcoded responses for development"""

    def __init__(self):
        self.did_documents = {
            'did:web:beltic.localhost:issuer': {
                '@context': ['https://www.w3.org/ns/did/v1'],
                'id': 'did:web:beltic.localhost:issuer',
                'verificationMethod': [{
                    'id': '#key-1',
                    'type': 'JsonWebKey2020',
                    'publicKeyJwk': {
                        'kty': 'EC',
                        'crv': 'P-256',
                        'x': 'base64url_x',
                        'y': 'base64url_y'
                    }
                }]
            }
        }

    async def resolve(self, did: str) -> DIDDocument:
        if did in self.did_documents:
            return DIDDocument(**self.did_documents[did])
        raise DIDNotFoundError(f"DID {did} not found")
```

### Local Key Storage

```typescript
// TypeScript
class LocalKeyStore implements KeyStore {
  private keys = new Map<string, CryptoKeyPair>();

  async store(id: string, keyPair: CryptoKeyPair): Promise<void> {
    // In production, would use KMS/HSM
    this.keys.set(id, keyPair);

    // Save to encrypted file for persistence
    await this.persist();
  }

  async retrieve(id: string): Promise<CryptoKeyPair> {
    const keyPair = this.keys.get(id);
    if (!keyPair) {
      throw new KeyNotFoundError(`Key ${id} not found`);
    }
    return keyPair;
  }

  private async persist(): Promise<void> {
    // Save encrypted keys to ~/.beltic/keys.json
    const encrypted = await this.encrypt(this.keys);
    await fs.writeFile(this.keyPath, encrypted);
  }
}
```

## Future Integration Points

### 1. Production Credential Platform

```typescript
// Future integration interface
interface CredentialPlatform {
  // Developer registration
  registerDeveloper(kyb: KYBData): Promise<DeveloperCredential>;

  // Agent credential issuance
  requestCredential(manifest: AgentManifest): Promise<PendingCredential>;
  getCredential(id: string): Promise<SignedCredential>;

  // Status management
  updateStatus(id: string, status: CredentialStatus): Promise<void>;
  checkRevocation(id: string): Promise<RevocationStatus>;

  // Audit and compliance
  getAuditLog(id: string): Promise<AuditEntry[]>;
  submitComplianceReport(report: ComplianceReport): Promise<void>;
}
```

### 2. Key Management System Integration

```python
# Future KMS interface
class KMSKeyStore(KeyStore):
    def __init__(self, kms_client):
        self.kms = kms_client

    async def generate_key(self, algorithm: str) -> KeyReference:
        # Generate key in HSM
        response = await self.kms.create_key(
            key_spec=algorithm,
            key_usage='SIGN_VERIFY'
        )
        return KeyReference(response.key_id)

    async def sign(self, key_ref: KeyReference, data: bytes) -> bytes:
        # Sign using HSM-protected key
        response = await self.kms.sign(
            key_id=key_ref.id,
            message=data,
            algorithm=key_ref.algorithm
        )
        return response.signature
```

### 3. DID Network Resolution

```typescript
// Future DID resolver
class NetworkDIDResolver implements DIDResolver {
  constructor(private network: DIDNetwork) {}

  async resolve(did: string): Promise<DIDDocument> {
    // Resolve from decentralized network
    const document = await this.network.resolve(did);

    // Verify document integrity
    if (!this.verifyDocument(document)) {
      throw new InvalidDIDDocumentError();
    }

    // Cache for performance
    this.cache.set(did, document);

    return document;
  }

  private verifyDocument(doc: DIDDocument): boolean {
    // Verify cryptographic proofs
    return this.verifyProof(doc.proof);
  }
}
```

### 4. W3C Verifiable Credentials

```python
# Future VC support
class VCFormatter:
    @staticmethod
    def to_vc(credential: AgentCredential) -> VerifiableCredential:
        return {
            '@context': [
                'https://www.w3.org/2018/credentials/v1',
                'https://beltic.ai/contexts/agent/v1'
            ],
            'type': ['VerifiableCredential', 'AgentCredential'],
            'credentialSubject': {
                'id': credential.id,
                'agentName': credential.agent_name,
                'agentVersion': credential.agent_version,
                # ... map all fields
            },
            'issuer': credential.issuer,
            'issuanceDate': credential.issued_at,
            'proof': {
                'type': 'JsonWebSignature2020',
                'created': credential.issued_at,
                'verificationMethod': f"{credential.issuer}#key-1",
                'jws': credential.signature
            }
        }
```

## Implementation Roadmap

### Phase 1: Core Data Models and Validation (Week 1-2)

**TypeScript:**
- Define all TypeScript interfaces from JSON schemas
- Implement schema validator with ajv
- Create type guards and runtime validation
- Set up package structure and build pipeline

**Python:**
- Define dataclasses and TypedDict types
- Implement schema validator with jsonschema
- Create validation decorators
- Set up package structure with poetry/setuptools

**Shared:**
- Create test fixtures and sample data
- Define error types and messages
- Document type definitions

### Phase 2: Manifest and Fingerprinting (Week 2-3)

**Both SDKs:**
- Implement manifest builder with fluent API
- Add deployment context detection
- Create fingerprint generator with deterministic hashing
- Implement path inclusion/exclusion logic
- Add dependency tracking

**Testing:**
- Unit tests for manifest creation
- Integration tests for fingerprinting
- Cross-platform compatibility tests

### Phase 3: Crypto Operations and Signing (Week 3-4)

**Both SDKs:**
- Implement key generation (Ed25519, P-256)
- Create JWS signing functionality
- Add signature verification
- Implement secure key storage interface

**Security:**
- Key material protection
- Timing attack mitigation
- Test vector validation

### Phase 4: Mock Services and Testing (Week 4-5)

**Both SDKs:**
- Create mock credential issuer
- Implement stub DID resolver
- Add test credential generator
- Create development server

**Testing Infrastructure:**
- End-to-end test scenarios
- Performance benchmarks
- Compatibility test suite

### Phase 5: Documentation and Examples (Week 5-6)

**Documentation:**
- API reference documentation
- Getting started guide
- Integration tutorials
- Best practices guide

**Examples:**
- Basic credential creation
- Advanced validation scenarios
- Custom validator plugins
- CI/CD integration

## Code Examples

### TypeScript: Complete Example

```typescript
import { BelticSDK } from '@beltic/sdk';
import { SafetyMetrics, Tool } from '@beltic/types';

async function main() {
  // Initialize SDK
  const sdk = new BelticSDK({
    network: 'testnet',
    logger: console
  });

  // Create agent manifest
  const manifest = await sdk.manifest
    .create()
    .withAgent({
      name: 'Customer Support Agent',
      version: '1.0.0',
      description: 'Automated customer support with email integration',
      repository: 'https://github.com/example/support-agent'
    })
    .withDeveloper('did:web:example.com:developers:12345')
    .withDeployment('serverless')
    .withTools([
      {
        name: 'email_send',
        category: 'communication',
        riskLevel: 'medium',
        requiresAuth: true,
        mitigations: ['Rate limiting', 'Content filtering']
      },
      {
        name: 'database_read',
        category: 'database',
        riskLevel: 'low',
        requiresAuth: true
      }
    ])
    .withDataHandling({
      dataCategories: ['customer_support', 'email'],
      retentionDays: 90,
      encryption: 'at_rest_and_transit'
    })
    .scan({
      include: ['src/**/*.ts', 'package.json'],
      exclude: ['**/*.test.ts', 'node_modules']
    })
    .build();

  console.log('Manifest created:', manifest.id);
  console.log('Fingerprint:', manifest.fingerprint.hash);

  // Build credential
  const credential = sdk.credentials
    .create()
    .fromManifest(manifest)
    .withSafetyMetrics({
      harmfulContentScore: 0.95,
      promptInjectionScore: 0.92,
      toolAbuseScore: 0.88,
      piiLeakageScore: 0.90,
      benchmarkDate: new Date().toISOString(),
      benchmarkProvider: 'SafetyBench'
    })
    .withCompliance({
      gdprCompliant: true,
      ccpaCompliant: true,
      hipaaCovered: false
    })
    .validate()
    .build();

  // Generate keys and sign
  const keyPair = await sdk.crypto.generateKeyPair('ES256');
  const token = await sdk.crypto.sign(credential, keyPair.privateKey);

  console.log('Signed credential token:', token);

  // Verify the token
  const verified = await sdk.crypto.verify(token);
  console.log('Verification successful:', verified.valid);
  console.log('Credential ID:', verified.payload.id);

  // Mock issuance (development only)
  const mockIssuer = sdk.createMockIssuer();
  const issuedToken = await mockIssuer.issue(manifest);
  console.log('Mock issued token:', issuedToken);
}

main().catch(console.error);
```

### Python: Complete Example

```python
import asyncio
from datetime import datetime, timedelta
from beltic import BelticSDK
from beltic.types import (
    AgentInfo,
    Tool,
    SafetyMetrics,
    DataHandlingProfile,
    ComplianceData
)

async def main():
    # Initialize SDK
    sdk = BelticSDK(config={
        'network': 'testnet',
        'logger': True
    })

    # Create agent manifest
    manifest = await sdk.manifest.create() \
        .with_agent(AgentInfo(
            name='Customer Support Agent',
            version='1.0.0',
            description='Automated customer support with email integration',
            repository='https://github.com/example/support-agent'
        )) \
        .with_developer('did:web:example.com:developers:12345') \
        .with_deployment('serverless') \
        .with_tools([
            Tool(
                name='email_send',
                category='communication',
                risk_level='medium',
                requires_auth=True,
                mitigations=['Rate limiting', 'Content filtering']
            ),
            Tool(
                name='database_read',
                category='database',
                risk_level='low',
                requires_auth=True
            )
        ]) \
        .with_data_handling(DataHandlingProfile(
            data_categories=['customer_support', 'email'],
            retention_days=90,
            encryption='at_rest_and_transit'
        )) \
        .scan({
            'include': ['src/**/*.py', 'requirements.txt'],
            'exclude': ['**/*_test.py', '__pycache__']
        }) \
        .build()

    print(f"Manifest created: {manifest.id}")
    print(f"Fingerprint: {manifest.fingerprint.hash}")

    # Build credential
    credential = sdk.credentials.create() \
        .from_manifest(manifest) \
        .with_safety_metrics(SafetyMetrics(
            harmful_content_score=0.95,
            prompt_injection_score=0.92,
            tool_abuse_score=0.88,
            pii_leakage_score=0.90,
            benchmark_date=datetime.now().isoformat(),
            benchmark_provider='SafetyBench'
        )) \
        .with_compliance(ComplianceData(
            gdpr_compliant=True,
            ccpa_compliant=True,
            hipaa_covered=False
        )) \
        .validate() \
        .build()

    # Generate keys and sign
    key_pair = await sdk.crypto.generate_key_pair('ES256')
    token = await sdk.crypto.sign(credential, key_pair.private_key)

    print(f"Signed credential token: {token}")

    # Verify the token
    verified = await sdk.crypto.verify(token)
    print(f"Verification successful: {verified.valid}")
    print(f"Credential ID: {verified.payload.id}")

    # Mock issuance (development only)
    mock_issuer = sdk.create_mock_issuer()
    issued_token = await mock_issuer.issue(manifest)
    print(f"Mock issued token: {issued_token}")

if __name__ == "__main__":
    asyncio.run(main())
```

## Testing Strategy

### Unit Testing

```typescript
// TypeScript with Jest
describe('ManifestBuilder', () => {
  let builder: ManifestBuilder;

  beforeEach(() => {
    builder = new ManifestBuilder();
  });

  test('should create valid manifest with required fields', async () => {
    const manifest = await builder
      .withAgent({ name: 'Test', version: '1.0.0' })
      .withDeveloper('did:test:123')
      .build();

    expect(manifest.agentName).toBe('Test');
    expect(manifest.agentVersion).toBe('1.0.0');
    expect(manifest.developerCredentialId).toBe('did:test:123');
  });

  test('should validate against schema', () => {
    const result = builder.validate();
    expect(result.valid).toBe(false);
    expect(result.errors).toContainEqual(
      expect.objectContaining({ path: '/agentName' })
    );
  });
});
```

```python
# Python with pytest
import pytest
from beltic.manifest import ManifestBuilder
from beltic.types import AgentInfo

@pytest.fixture
def builder():
    return ManifestBuilder()

@pytest.mark.asyncio
async def test_create_valid_manifest(builder):
    manifest = await builder \
        .with_agent(AgentInfo(name='Test', version='1.0.0')) \
        .with_developer('did:test:123') \
        .build()

    assert manifest.agent_name == 'Test'
    assert manifest.agent_version == '1.0.0'
    assert manifest.developer_credential_id == 'did:test:123'

def test_validate_against_schema(builder):
    result = builder.validate()
    assert not result.valid
    assert any(e.path == '/agentName' for e in result.errors)
```

### Integration Testing

```typescript
// End-to-end credential flow
test('complete credential lifecycle', async () => {
  const sdk = new BelticSDK({ network: 'local' });

  // Create and sign credential
  const manifest = await createTestManifest(sdk);
  const credential = await createTestCredential(sdk, manifest);
  const keyPair = await sdk.crypto.generateKeyPair('ES256');
  const token = await sdk.crypto.sign(credential, keyPair.privateKey);

  // Verify round-trip
  const verified = await sdk.crypto.verify(token);
  expect(verified.valid).toBe(true);
  expect(verified.payload).toEqual(credential);

  // Test revocation check
  const status = await sdk.credentials.checkStatus(credential.id);
  expect(status).toBe('active');
});
```

### Performance Testing

```python
# Benchmark fingerprint generation
@pytest.mark.benchmark
def test_fingerprint_performance(benchmark):
    def generate_fingerprint():
        return Fingerprint.generate('./large_codebase')

    result = benchmark(generate_fingerprint)
    assert len(result) == 64  # SHA256 hex length
    assert benchmark.stats['mean'] < 1.0  # Less than 1 second
```

## Security Considerations

### Key Management

1. **Never store private keys in plain text**
2. **Use secure key derivation for encrypted storage**
3. **Implement key rotation mechanisms**
4. **Support hardware security modules (HSMs)**

### Cryptographic Best Practices

1. **Use constant-time comparison for signatures**
2. **Validate all inputs before cryptographic operations**
3. **Use secure random number generation**
4. **Implement proper key zeroization**

### Input Validation

1. **Validate all external inputs against schemas**
2. **Sanitize file paths and prevent directory traversal**
3. **Limit payload sizes to prevent DoS**
4. **Validate JSON structure before parsing**

## Developer Experience Priorities

### 1. Excellent Documentation

- Comprehensive API reference
- Step-by-step tutorials
- Common use case examples
- Troubleshooting guide
- Migration guides for version updates

### 2. Helpful Error Messages

```typescript
// Good error message
throw new ValidationError(
  `Invalid agent name: must be 1-100 characters, got ${name.length}`,
  {
    field: 'agentName',
    value: name,
    constraint: { min: 1, max: 100 },
    suggestion: 'Shorten the agent name or use the description field for details'
  }
);

// Bad error message
throw new Error('Invalid input');
```

### 3. IDE Support

- TypeScript definitions with JSDoc comments
- Python type stubs for autocomplete
- VS Code extension for schema validation
- Snippets for common patterns

### 4. CLI Tools

```bash
# TypeScript SDK CLI
npx @beltic/cli init          # Initialize new project
npx @beltic/cli validate       # Validate manifest/credential
npx @beltic/cli fingerprint    # Generate fingerprint
npx @beltic/cli sign           # Sign credential

# Python SDK CLI
beltic init                    # Initialize new project
beltic validate manifest.json  # Validate manifest/credential
beltic fingerprint ./src       # Generate fingerprint
beltic sign credential.json    # Sign credential
```

## Conclusion

This SDK development blueprint provides a comprehensive foundation for building developer-friendly Beltic SDKs in TypeScript and Python. The design prioritizes:

1. **Developer experience** through intuitive APIs and helpful tooling
2. **Type safety** with strong typing in both languages
3. **Security** with proper key management and cryptographic practices
4. **Extensibility** through plugin architectures and clear interfaces
5. **Future-proofing** with placeholder infrastructure and integration points

The phased implementation approach allows for iterative development while maintaining backward compatibility. By starting with core functionality and mock services, developers can begin integrating Beltic credentials immediately, with production infrastructure seamlessly replacing mocks when available.

Both SDKs will share:
- Common test vectors and fixtures
- Parallel API designs with language-appropriate patterns
- Comprehensive documentation and examples
- Security best practices and validation rules

This approach ensures consistency across platforms while allowing each SDK to leverage language-specific strengths and idioms.