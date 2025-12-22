use std::fs;

use anyhow::Result;
use beltic::credential::{build_claims, ClaimsOptions, CredentialKind, AGENT_TYP, DEVELOPER_TYP};
use beltic::crypto::{sign_jws, verify_jws, SignatureAlg};
use serde_json::Value;
use tempfile::tempdir;

const ES256_PRIVATE: &str = r#"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIDGoJN83LITqdVM0gQkfNsTKd/XqUcd3f2IMpdHkTpV3oAoGCCqGSM49
AwEHoUQDQgAEqkAoBg7OgZwRXkjtOCIwSFzh/iqDrDhg4nxTX6ispLjaHC9Y6wm9
o2EpE1gcrkKffvCvuZF5fzEg4Nb3D67TOQ==
-----END EC PRIVATE KEY-----"#;

const ES256_PUBLIC: &str = r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqkAoBg7OgZwRXkjtOCIwSFzh/iqD
rDhg4nxTX6ispLjaHC9Y6wm9o2EpE1gcrkKffvCvuZF5fzEg4Nb3D67TOQ==
-----END PUBLIC KEY-----"#;

const ED25519_PRIVATE: &str = r#"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPoRSmw90QobH8dba5qbBuU5wl0qClkf/13XimjMXAHE
-----END PRIVATE KEY-----"#;

const ED25519_PUBLIC: &str = r#"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAFxINQgasPfpJkeFJjNcNIxE/QAFWkfb1BkJLVjS2IWg=
-----END PUBLIC KEY-----"#;

#[test]
fn es256_sign_and_verify_agent_credential() -> Result<()> {
    let dir = tempdir()?;
    let private_path = dir.path().join("es256-private.pem");
    let public_path = dir.path().join("es256-public.pem");

    fs::write(&private_path, ES256_PRIVATE.trim())?;
    fs::write(&public_path, ES256_PUBLIC.trim())?;

    let payload: Value = serde_json::from_str(include_str!("fixtures/agent-valid.json"))?;
    let claims = build_claims(
        &payload,
        CredentialKind::Agent,
        ClaimsOptions {
            issuer: None,
            subject: Some("did:web:agent.example.com"),
            audience: &[],
        },
    )?;

    let token = sign_jws(
        &claims,
        &private_path,
        SignatureAlg::Es256,
        Some("did:web:beltic.test#key-1".to_string()),
        AGENT_TYP,
        Some("application/json"),
    )?;
    // No audience in token, so pass None (RFC 7519 compliant - no aud claim to validate)
    let verified = verify_jws(&token, &public_path, None)?;

    assert_eq!(SignatureAlg::Es256, verified.alg);
    assert_eq!(verified.header.typ.as_deref(), Some(AGENT_TYP));
    assert_eq!(
        verified
            .payload
            .get("vc")
            .and_then(|vc| vc.get("credentialId")),
        claims.get("vc").and_then(|vc| vc.get("credentialId"))
    );
    Ok(())
}

#[test]
fn eddsa_sign_and_verify_developer_credential() -> Result<()> {
    let dir = tempdir()?;
    let private_path = dir.path().join("ed25519-private.pem");
    let public_path = dir.path().join("ed25519-public.pem");

    fs::write(&private_path, ED25519_PRIVATE.trim())?;
    fs::write(&public_path, ED25519_PUBLIC.trim())?;

    let payload: Value = serde_json::from_str(include_str!("fixtures/developer-valid.json"))?;
    let claims = build_claims(
        &payload,
        CredentialKind::Developer,
        ClaimsOptions {
            issuer: None,
            subject: None,
            audience: &["did:web:verifier.example.com".to_string()],
        },
    )?;

    let token = sign_jws(
        &claims,
        &private_path,
        SignatureAlg::EdDsa,
        Some("did:web:beltic.test#key-2".to_string()),
        DEVELOPER_TYP,
        Some("application/json"),
    )?;
    // Token has audience claim, so we must provide expected audience for RFC 7519 compliance
    let expected_audience = vec!["did:web:verifier.example.com".to_string()];
    let verified = verify_jws(&token, &public_path, Some(&expected_audience))?;

    assert_eq!(SignatureAlg::EdDsa, verified.alg);
    assert_eq!(verified.header.typ.as_deref(), Some(DEVELOPER_TYP));
    assert_eq!(
        verified
            .payload
            .get("vc")
            .and_then(|vc| vc.get("credentialId")),
        claims.get("vc").and_then(|vc| vc.get("credentialId"))
    );
    Ok(())
}

/// Test that tokens with audience claims are rejected when no expected audience is provided.
/// This verifies RFC 7519 Section 4.1.3 compliance: "If the principal processing the claim
/// does not identify itself with a value in the 'aud' claim when this claim is present,
/// then the JWT MUST be rejected."
#[test]
fn test_audience_claim_rejected_without_expected_audience() -> Result<()> {
    let dir = tempdir()?;
    let private_path = dir.path().join("es256-private.pem");
    let public_path = dir.path().join("es256-public.pem");

    fs::write(&private_path, ES256_PRIVATE.trim())?;
    fs::write(&public_path, ES256_PUBLIC.trim())?;

    let payload: Value = serde_json::from_str(include_str!("fixtures/agent-valid.json"))?;
    let claims = build_claims(
        &payload,
        CredentialKind::Agent,
        ClaimsOptions {
            issuer: None,
            subject: Some("did:web:agent.example.com"),
            // Token has an audience claim
            audience: &["did:web:some-service.example.com".to_string()],
        },
    )?;

    let token = sign_jws(
        &claims,
        &private_path,
        SignatureAlg::Es256,
        Some("did:web:beltic.test#key-1".to_string()),
        AGENT_TYP,
        Some("application/json"),
    )?;

    // Verify with None for expected audience - should fail per RFC 7519
    let result = verify_jws(&token, &public_path, None);
    assert!(
        result.is_err(),
        "Token with audience claim should be rejected when no expected audience is provided"
    );

    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("audience claim"),
        "Error should mention audience claim, got: {}",
        err
    );

    Ok(())
}

/// Test that tokens are rejected when the audience doesn't match
#[test]
fn test_audience_mismatch_rejected() -> Result<()> {
    let dir = tempdir()?;
    let private_path = dir.path().join("es256-private.pem");
    let public_path = dir.path().join("es256-public.pem");

    fs::write(&private_path, ES256_PRIVATE.trim())?;
    fs::write(&public_path, ES256_PUBLIC.trim())?;

    let payload: Value = serde_json::from_str(include_str!("fixtures/agent-valid.json"))?;
    let claims = build_claims(
        &payload,
        CredentialKind::Agent,
        ClaimsOptions {
            issuer: None,
            subject: Some("did:web:agent.example.com"),
            // Token is for service-a
            audience: &["did:web:service-a.example.com".to_string()],
        },
    )?;

    let token = sign_jws(
        &claims,
        &private_path,
        SignatureAlg::Es256,
        Some("did:web:beltic.test#key-1".to_string()),
        AGENT_TYP,
        Some("application/json"),
    )?;

    // Try to verify as service-b - should fail (token substitution attack prevention)
    let wrong_audience = vec!["did:web:service-b.example.com".to_string()];
    let result = verify_jws(&token, &public_path, Some(&wrong_audience));
    assert!(
        result.is_err(),
        "Token should be rejected when audience doesn't match"
    );

    Ok(())
}

/// Test that tokens without audience claims are accepted when no expected audience is provided
#[test]
fn test_no_audience_claim_accepted_without_expected() -> Result<()> {
    let dir = tempdir()?;
    let private_path = dir.path().join("es256-private.pem");
    let public_path = dir.path().join("es256-public.pem");

    fs::write(&private_path, ES256_PRIVATE.trim())?;
    fs::write(&public_path, ES256_PUBLIC.trim())?;

    let payload: Value = serde_json::from_str(include_str!("fixtures/agent-valid.json"))?;
    let claims = build_claims(
        &payload,
        CredentialKind::Agent,
        ClaimsOptions {
            issuer: None,
            subject: Some("did:web:agent.example.com"),
            // No audience claim
            audience: &[],
        },
    )?;

    let token = sign_jws(
        &claims,
        &private_path,
        SignatureAlg::Es256,
        Some("did:web:beltic.test#key-1".to_string()),
        AGENT_TYP,
        Some("application/json"),
    )?;

    // Token has no audience, verifier provides none - should succeed
    let result = verify_jws(&token, &public_path, None);
    assert!(
        result.is_ok(),
        "Token without audience claim should be accepted when no expected audience is provided: {:?}",
        result.err()
    );

    Ok(())
}
