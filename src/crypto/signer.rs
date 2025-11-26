use std::{fs, path::Path};

use anyhow::{Context, Result};
use jsonwebtoken::{encode, EncodingKey, Header};
use p256::SecretKey as P256SecretKey;
use pkcs8::EncodePrivateKey;
use serde_json::Value;
use zeroize::Zeroizing;

use super::SignatureAlg;

pub fn sign_jws(
    payload: &Value,
    key_path: &Path,
    alg: SignatureAlg,
    kid: Option<String>,
    typ: &str,
    content_type: Option<&str>,
) -> Result<String> {
    let pem = Zeroizing::new(
        fs::read_to_string(key_path)
            .with_context(|| format!("failed to read private key at {}", key_path.display()))?,
    );
    let encoding_key = encoding_key_from_pem(pem.as_bytes(), alg)?;

    let mut header = Header::new(alg.as_jwt_alg());
    header.typ = Some(typ.to_string());
    header.cty = content_type.map(|v| v.to_string());
    header.kid = kid;

    encode(&header, payload, &encoding_key).context("failed to encode JWS")
}

fn encoding_key_from_pem(pem: &[u8], alg: SignatureAlg) -> Result<EncodingKey> {
    let key = match alg {
        SignatureAlg::Es256 => match EncodingKey::from_ec_pem(pem) {
            Ok(key) => key,
            Err(_) => {
                let pem_str =
                    std::str::from_utf8(pem).context("ES256 key is not valid UTF-8 PEM content")?;
                let secret = P256SecretKey::from_sec1_pem(pem_str)
                    .context("invalid ES256 private key (expecting P-256 in PEM)")?;
                let der = secret
                    .to_pkcs8_der()
                    .context("failed to convert ES256 key to PKCS#8 DER")?;
                EncodingKey::from_ec_der(der.as_bytes())
            }
        },
        SignatureAlg::EdDsa => EncodingKey::from_ed_pem(pem)
            .context("invalid EdDSA private key (expecting Ed25519 in PEM)")?,
    };

    Ok(key)
}
