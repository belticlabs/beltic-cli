use std::fs;

use anyhow::Result;
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

const TEST_PAYLOAD: &str = r#"{
  "sub": "did:web:example.com",
  "name": "Test Credential",
  "iat": 1516239022
}"#;

#[test]
fn es256_sign_and_verify_test_vector() -> Result<()> {
    let dir = tempdir()?;
    let private_path = dir.path().join("es256-private.pem");
    let public_path = dir.path().join("es256-public.pem");

    fs::write(&private_path, ES256_PRIVATE.trim())?;
    fs::write(&public_path, ES256_PUBLIC.trim())?;

    let payload: Value = serde_json::from_str(TEST_PAYLOAD)?;
    let token = sign_jws(&payload, &private_path, SignatureAlg::Es256, None)?;
    let verified = verify_jws(&token, &public_path)?;

    assert_eq!(payload, verified.payload);
    assert_eq!(SignatureAlg::Es256, verified.alg);
    Ok(())
}

#[test]
fn eddsa_sign_and_verify_test_vector() -> Result<()> {
    let dir = tempdir()?;
    let private_path = dir.path().join("ed25519-private.pem");
    let public_path = dir.path().join("ed25519-public.pem");

    fs::write(&private_path, ED25519_PRIVATE.trim())?;
    fs::write(&public_path, ED25519_PUBLIC.trim())?;

    let payload: Value = serde_json::from_str(TEST_PAYLOAD)?;
    let token = sign_jws(&payload, &private_path, SignatureAlg::EdDsa, None)?;
    let verified = verify_jws(&token, &public_path)?;

    assert_eq!(payload, verified.payload);
    assert_eq!(SignatureAlg::EdDsa, verified.alg);
    Ok(())
}
