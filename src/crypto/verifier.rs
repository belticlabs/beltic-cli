use std::{collections::HashSet, fs, path::Path};

use anyhow::{bail, Context, Result};
use jsonwebtoken::{decode, decode_header, DecodingKey, Header as JwtHeader, Validation};
use serde_json::Value;

use super::SignatureAlg;

#[derive(Debug)]
pub struct VerifiedToken {
    pub payload: Value,
    pub header: JwtHeader,
    pub alg: SignatureAlg,
}

/// Verify a JWS token with audience validation per RFC 7519.
///
/// # Arguments
/// * `token` - The JWS token string to verify
/// * `public_key_path` - Path to the public key PEM file
/// * `expected_audience` - Expected audience value(s) for validation:
///   - `Some(&[...])` with values: validates the token's `aud` claim contains at least one match
///   - `Some(&[])` or `None`: rejects tokens that have an `aud` claim (RFC 7519 compliance)
///
/// # Security
/// Per RFC 7519 Section 4.1.3, if a JWT contains an `aud` claim, the recipient MUST
/// identify itself with a value in that claim, otherwise the JWT MUST be rejected.
/// This function enforces that requirement.
pub fn verify_jws(
    token: &str,
    public_key_path: &Path,
    expected_audience: Option<&[String]>,
) -> Result<VerifiedToken> {
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
    validation.required_spec_claims = HashSet::new(); // Claims validated downstream

    // Configure audience validation based on expected audience
    let has_expected_audience = expected_audience
        .map(|aud| !aud.is_empty())
        .unwrap_or(false);

    if has_expected_audience {
        // Validate that token's aud claim matches one of the expected audiences
        validation.set_audience(expected_audience.unwrap());
    } else {
        // No expected audience provided - we'll check manually after decoding
        // that the token has no aud claim (per RFC 7519)
        validation.validate_aud = false;
    }

    let verified = decode::<Value>(token, &decoding_key, &validation)
        .with_context(|| format!("signature verification failed for alg {}", alg))?;

    // If no expected audience was provided, reject tokens that have an aud claim
    // (RFC 7519: "If the principal processing the claim does not identify itself
    // with a value in the 'aud' claim when this claim is present, then the JWT
    // MUST be rejected.")
    if !has_expected_audience {
        if let Some(aud) = verified.claims.get("aud") {
            // Token has an audience claim but verifier didn't specify expected audience
            let aud_display = match aud {
                Value::String(s) => format!("'{}'", s),
                Value::Array(arr) => format!("{:?}", arr),
                _ => format!("{}", aud),
            };
            bail!(
                "token contains audience claim {} but no expected audience was provided; \
                 per RFC 7519 Section 4.1.3, tokens with audience claims must be validated \
                 against the recipient's identity",
                aud_display
            );
        }
    }

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
