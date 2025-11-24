use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use clap::Args;
use serde_json::Value;

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

    /// Optional key identifier to embed in the JWS header
    #[arg(long)]
    pub kid: Option<String>,
}

pub fn run(args: SignArgs) -> Result<()> {
    let payload = fs::read_to_string(&args.payload)
        .with_context(|| format!("failed to read payload file {}", args.payload.display()))?;
    let payload_json: Value =
        serde_json::from_str(&payload).context("payload is not valid JSON")?;

    let token = sign_jws(&payload_json, &args.key, args.alg, args.kid)?;
    if let Some(parent) = args.out.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
        }
    }
    fs::write(&args.out, &token)
        .with_context(|| format!("failed to write token to {}", args.out.display()))?;

    println!("Wrote JWS to {}", args.out.display());
    Ok(())
}
