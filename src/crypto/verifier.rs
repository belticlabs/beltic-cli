use std::{collections::HashSet, fs, path::Path};

use anyhow::{Context, Result};
use jsonwebtoken::{decode, decode_header, DecodingKey, Header as JwtHeader, Validation};
use serde_json::Value;

use super::SignatureAlg;

pub struct VerifiedToken {
    pub payload: Value,
    pub header: JwtHeader,
    pub alg: SignatureAlg,
}

pub fn verify_jws(token: &str, public_key_path: &Path) -> Result<VerifiedToken> {
    let header = decode_header(token).context("failed to decode JWS header")?;
    let alg = SignatureAlg::try_from_jwt_alg(header.alg)?;
    let key_pem = fs::read_to_string(public_key_path).with_context(|| {
        format!(
            "failed to read key {}",
            public_key_path.to_str().unwrap_or("<non-utf8-path>")
        )
    })?;
    let decoding_key = decoding_key_from_pem(key_pem.as_bytes(), alg)?;

    let mut validation = Validation::new(alg.as_jwt_alg());
    validation.leeway = 300; // 5 minute skew tolerance
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.validate_aud = false;
    validation.required_spec_claims = HashSet::new(); // Claims validated downstream

    let verified = decode::<Value>(token, &decoding_key, &validation)
        .with_context(|| format!("signature verification failed for alg {}", alg))?;

    Ok(VerifiedToken {
        payload: verified.claims,
        header: verified.header,
        alg,
    })
}

fn decoding_key_from_pem(pem: &[u8], alg: SignatureAlg) -> Result<DecodingKey> {
    let key = match alg {
        SignatureAlg::Es256 => DecodingKey::from_ec_pem(pem)
            .context("invalid ES256 public key (expecting P-256 PEM)")?,
        SignatureAlg::EdDsa => DecodingKey::from_ed_pem(pem)
            .context("invalid EdDSA public key (expecting Ed25519 PEM)")?,
    };

    Ok(key)
}
