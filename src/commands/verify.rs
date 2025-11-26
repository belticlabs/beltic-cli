use std::{fs, path::PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use serde_json::Value;

use crate::credential::{
    credential_kind_from_typ, detect_credential_kind, parse_credential_kind, validate_credential,
    CredentialKind,
};
use crate::crypto::{verify_jws, VerifiedToken};

#[derive(Args)]
pub struct VerifyArgs {
    /// Path to the public key (PEM)
    #[arg(long)]
    pub key: PathBuf,

    /// Path to the JWS token or the token string itself
    #[arg(long)]
    pub token: String,

    /// Expected audience value(s) for the JWT
    #[arg(long, value_name = "AUDIENCE")]
    pub audience: Vec<String>,

    /// Expected issuer DID (iss claim)
    #[arg(long)]
    pub issuer: Option<String>,

    /// Expected credential type (agent|developer)
    #[arg(long, value_parser = parse_credential_kind)]
    pub credential_type: Option<CredentialKind>,

    /// Skip JSON Schema validation
    #[arg(long)]
    pub skip_schema: bool,
}

pub fn run(args: VerifyArgs) -> Result<()> {
    let token = load_token(&args.token)?;

    match verify_jws(token.trim(), &args.key) {
        Ok(verified) => {
            if let Err(err) = validate_verified(verified, &args) {
                eprintln!("INVALID: {err}");
                std::process::exit(1);
            }
            Ok(())
        }
        Err(err) => {
            eprintln!("INVALID: {err}");
            std::process::exit(1);
        }
    }
}

fn load_token(token_input: &str) -> Result<String> {
    let candidate = PathBuf::from(token_input);
    if candidate.exists() {
        fs::read_to_string(&candidate)
            .with_context(|| format!("failed to read token file {}", candidate.display()))
    } else {
        Ok(token_input.to_string())
    }
}

fn validate_verified(verified: VerifiedToken, args: &VerifyArgs) -> Result<()> {
    let header_typ = verified.header.typ.clone();
    if let Some(ref typ) = header_typ {
        if credential_kind_from_typ(typ).is_none() {
            bail!("unexpected typ header '{}'", typ);
        }
    }

    let claims = verified.payload;
    let vc = claims
        .get("vc")
        .ok_or_else(|| anyhow!("vc claim missing from JWT payload"))?;
    if !vc.is_object() {
        bail!("vc claim must be an object");
    }

    let header_kind = header_typ.as_deref().and_then(credential_kind_from_typ);
    let detected_kind = detect_credential_kind(vc);
    let kind = resolve_kind(args.credential_type, header_kind, detected_kind)?;

    let iss = claims
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("iss claim missing"))?;
    let sub = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("sub claim missing"))?;
    let jti = claims
        .get("jti")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("jti claim missing"))?;

    if claims.get("nbf").is_none() || claims.get("exp").is_none() {
        bail!("nbf and exp claims are required");
    }

    if let Some(expected_issuer) = &args.issuer {
        if iss != expected_issuer {
            bail!(
                "issuer mismatch: expected '{}', got '{}'",
                expected_issuer,
                iss
            );
        }
    }

    if !args.audience.is_empty() {
        let actual_aud = extract_audience(&claims)?;
        let missing: Vec<String> = args
            .audience
            .iter()
            .filter(|expected| !actual_aud.contains(&expected.to_string()))
            .cloned()
            .collect();
        if !missing.is_empty() {
            bail!(
                "audience mismatch: missing {:?} from aud claim ({:?})",
                missing,
                actual_aud
            );
        }
    }

    if !args.skip_schema {
        let errors = validate_credential(kind, vc)?;
        if !errors.is_empty() {
            let mut message = String::from("schema validation failed:\n");
            for err in errors {
                message.push_str(&format!("  - {err}\n"));
            }
            bail!(message);
        }
    }

    println!(
        "VALID (type={}, alg={}, kid={}, typ={}, iss={}, sub={}, jti={})",
        kind.display_name(),
        verified.alg,
        verified.header.kid.as_deref().unwrap_or("<none>"),
        header_typ.as_deref().unwrap_or("<missing>"),
        iss,
        sub,
        jti,
    );
    let pretty = serde_json::to_string_pretty(vc)?;
    println!("{pretty}");
    Ok(())
}

fn resolve_kind(
    expected: Option<CredentialKind>,
    header_kind: Option<CredentialKind>,
    detected_kind: Option<CredentialKind>,
) -> Result<CredentialKind> {
    if let Some(expected_kind) = expected {
        if let Some(kind) = header_kind {
            if kind != expected_kind {
                bail!(
                    "credential type mismatch: header says {}, expected {}",
                    kind.display_name(),
                    expected_kind.display_name()
                );
            }
        }
        if let Some(kind) = detected_kind {
            if kind != expected_kind {
                bail!(
                    "credential payload looks like {}, expected {}",
                    kind.display_name(),
                    expected_kind.display_name()
                );
            }
        }
        return Ok(expected_kind);
    }

    if let Some(kind) = header_kind {
        if let Some(detected) = detected_kind {
            if detected != kind {
                bail!(
                    "credential type conflict: header says {}, payload looks like {}",
                    kind.display_name(),
                    detected.display_name()
                );
            }
        }
        return Ok(kind);
    }

    detected_kind.ok_or_else(|| anyhow!("unable to determine credential type"))
}

fn extract_audience(claims: &Value) -> Result<Vec<String>> {
    match claims.get("aud") {
        Some(Value::String(aud)) => Ok(vec![aud.clone()]),
        Some(Value::Array(values)) => {
            let mut result = Vec::new();
            for v in values {
                if let Some(s) = v.as_str() {
                    result.push(s.to_string());
                }
            }
            Ok(result)
        }
        Some(_) => bail!("aud claim must be a string or array"),
        None => Ok(Vec::new()),
    }
}
