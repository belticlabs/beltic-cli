use std::{fs, path::PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use serde_json::Value;

use crate::credential::{
    build_claims, detect_credential_kind, parse_credential_kind, validate_credential,
    ClaimsOptions, CredentialKind,
};
use crate::crypto::{parse_signature_alg, sign_jws, SignatureAlg};

#[derive(Args)]
pub struct SignArgs {
    /// Path to the private key (PEM)
    #[arg(long)]
    pub key: PathBuf,

    /// Algorithm to use for signing (default: EdDSA)
    #[arg(long, default_value = "EdDSA", value_parser = parse_signature_alg)]
    pub alg: SignatureAlg,

    /// JSON payload file to sign
    #[arg(long)]
    pub payload: PathBuf,

    /// Output file for the resulting JWS token
    #[arg(long)]
    pub out: PathBuf,

    /// Key identifier to embed in the JWS header (required by spec)
    #[arg(long)]
    pub kid: Option<String>,

    /// Override issuer DID for the JWT (defaults to issuerDid in credential)
    #[arg(long)]
    pub issuer: Option<String>,

    /// Subject DID for the JWT (required for agents; defaults to subjectDid when present)
    #[arg(long)]
    pub subject: Option<String>,

    /// Audience claim(s) for the JWT (repeat flag to add multiple)
    #[arg(long, value_name = "AUDIENCE")]
    pub audience: Vec<String>,

    /// Credential type (agent|developer). Auto-detected when omitted.
    #[arg(long, value_parser = parse_credential_kind)]
    pub credential_type: Option<CredentialKind>,

    /// Skip JSON Schema validation before signing
    #[arg(long)]
    pub skip_schema: bool,
}

pub fn run(args: SignArgs) -> Result<()> {
    let payload = fs::read_to_string(&args.payload)
        .with_context(|| format!("failed to read payload file {}", args.payload.display()))?;
    let payload_json: Value =
        serde_json::from_str(&payload).context("payload is not valid JSON")?;

    let kind = if let Some(kind) = args.credential_type {
        kind
    } else {
        detect_credential_kind(&payload_json).ok_or_else(|| {
            anyhow!("unable to detect credential type; pass --credential-type explicitly")
        })?
    };

    if args.kid.is_none() {
        bail!("kid is required by the Beltic signing profile; provide --kid");
    }

    if !args.skip_schema {
        let errors = validate_credential(kind, &payload_json)?;
        if !errors.is_empty() {
            let mut message = String::from("schema validation failed:\n");
            for err in errors {
                message.push_str(&format!("  - {err}\n"));
            }
            bail!(message);
        }
    }

    let claims = build_claims(
        &payload_json,
        kind,
        ClaimsOptions {
            issuer: args.issuer.as_deref(),
            subject: args.subject.as_deref(),
            audience: &args.audience,
        },
    )?;

    let token = sign_jws(
        &claims,
        &args.key,
        args.alg,
        args.kid.clone(),
        kind.media_type(),
        Some("application/json"),
    )?;
    if let Some(parent) = args.out.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
        }
    }
    fs::write(&args.out, &token)
        .with_context(|| format!("failed to write token to {}", args.out.display()))?;

    println!(
        "Wrote {} JWS (alg={}, typ={}) to {}",
        kind.display_name(),
        args.alg,
        kind.media_type(),
        args.out.display()
    );
    Ok(())
}
