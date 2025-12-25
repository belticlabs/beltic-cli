# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial changelog

## [0.2.0] - 2024-12-XX

### Added
- Agent manifest initialization with interactive prompts (`beltic init`)
- Developer credential creation (`beltic dev-init`)
- Deterministic code fingerprinting with SHA256 (`beltic fingerprint`)
- Cryptographic keypair generation for Ed25519 and P-256 (`beltic keygen`)
- JWS/JWT signing with Beltic media types (`beltic sign`)
- Credential verification with schema validation (`beltic verify`)
- HTTP Message Signatures per RFC 9421 (`beltic http-sign`)
- Key directory management for Web Bot Auth (`beltic directory`)
- Sandbox compliance testing (`beltic sandbox`)
- Schema caching and management (`beltic schema`)
- API key management (`beltic api-key`)
- Authentication commands (`beltic auth login/logout`)
- Developer registration (`beltic register`)
- Current identity display (`beltic whoami`)
- Credential ID extraction (`beltic credential-id`)
- Interactive mode with auto-discovery of keys and credentials
- Non-interactive mode for CI/CD pipelines
- YAML-based configuration (`.beltic.yaml`)
- Support for multiple deployment types (standalone, monorepo, embedded, plugin, serverless)
- JSON Schema validation for credentials
- Support for DeveloperCredential and AgentCredential v1 and v2 schemas

### Changed
- Improved error messages and validation feedback
- Enhanced interactive prompts with better defaults

### Security
- Private keys stored with restricted permissions (0600)
- Secure key clearing from memory using zeroize
- Automatic .gitignore for private keys

