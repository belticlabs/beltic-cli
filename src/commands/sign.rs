use std::{fs, path::PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use console::style;
use serde_json::Value;

use crate::credential::{
    build_claims, detect_credential_kind, parse_credential_kind, validate_credential,
    ClaimsOptions, CredentialKind,
};
use crate::crypto::{parse_signature_alg, sign_jws, SignatureAlg};

use super::discovery::{find_credentials, find_private_keys};
use super::prompts::CommandPrompts;

#[derive(Args)]
pub struct SignArgs {
    /// Path to the private key (PEM). Auto-discovered if omitted.
    #[arg(long)]
    pub key: Option<PathBuf>,

    /// Algorithm to use for signing (default: EdDSA)
    #[arg(long, default_value = "EdDSA", value_parser = parse_signature_alg)]
    pub alg: SignatureAlg,

    /// JSON payload file to sign. Prompted if omitted.
    #[arg(long)]
    pub payload: Option<PathBuf>,

    /// Output file for the resulting JWS token. Defaults to {payload}.jwt
    #[arg(long)]
    pub out: Option<PathBuf>,

    /// Key identifier to embed in the JWS header (prompted if omitted)
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

    /// Disable interactive mode
    #[arg(long)]
    pub non_interactive: bool,
}

pub fn run(args: SignArgs) -> Result<()> {
    // Determine if we need interactive mode
    let needs_interactive =
        (args.key.is_none() || args.payload.is_none() || args.kid.is_none()) && !args.non_interactive;

    if needs_interactive {
        run_interactive(args)
    } else {
        run_non_interactive(args)
    }
}

fn run_interactive(mut args: SignArgs) -> Result<()> {
    let prompts = CommandPrompts::new();

    prompts.section_header("Beltic Credential Signer")?;

    // 1. Key selection (with auto-discovery)
    if args.key.is_none() {
        let private_keys = find_private_keys();
        if private_keys.is_empty() {
            prompts.warn("No private keys found. Generate one with: beltic keygen")?;
            return Err(anyhow!("No private keys available"));
        }

        args.key = Some(prompts.prompt_select_path("Select private key", &private_keys, true)?);
    }

    // 2. Payload selection (with auto-discovery)
    if args.payload.is_none() {
        let credentials = find_credentials();
        if credentials.is_empty() {
            prompts.warn("No credential files found.")?;
            let path = prompts.prompt_path("Enter payload path", None)?;
            args.payload = Some(path);
        } else {
            args.payload =
                Some(prompts.prompt_select_path("Select payload to sign", &credentials, true)?);
        }
    }

    // 3. Key identifier (kid)
    if args.kid.is_none() {
        // Suggest kid based on key filename
        let suggested_kid = args
            .key
            .as_ref()
            .and_then(|p| p.file_stem())
            .and_then(|s| s.to_str())
            .map(|s| s.trim_end_matches("-private"))
            .unwrap_or("my-key");

        args.kid = Some(prompts.prompt_string("Key identifier (kid)", Some(suggested_kid))?);
    }

    // 4. Output path (default: {payload}.jwt)
    if args.out.is_none() {
        let default_out = args
            .payload
            .as_ref()
            .map(|p| p.with_extension("jwt"))
            .unwrap_or_else(|| PathBuf::from("output.jwt"));

        args.out = Some(prompts.prompt_path("Output path", Some(&default_out))?);
    }

    // Continue with signing
    do_sign(&args, &prompts)
}

fn run_non_interactive(args: SignArgs) -> Result<()> {
    // Validate required args
    let key = args.key.as_ref().ok_or_else(|| {
        anyhow!("--key is required in non-interactive mode (or run without --non-interactive)")
    })?;
    let payload = args.payload.as_ref().ok_or_else(|| {
        anyhow!("--payload is required in non-interactive mode")
    })?;
    let kid = args.kid.as_ref().ok_or_else(|| {
        anyhow!("--kid is required in non-interactive mode")
    })?;

    // Default output path
    let out = args
        .out
        .clone()
        .unwrap_or_else(|| payload.with_extension("jwt"));

    let payload_content = fs::read_to_string(payload)
        .with_context(|| format!("failed to read payload file {}", payload.display()))?;
    let payload_json: Value =
        serde_json::from_str(&payload_content).context("payload is not valid JSON")?;

    let kind = if let Some(kind) = args.credential_type {
        kind
    } else {
        detect_credential_kind(&payload_json).ok_or_else(|| {
            anyhow!("unable to detect credential type; pass --credential-type explicitly")
        })?
    };

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
        key,
        args.alg,
        Some(kid.clone()),
        kind.media_type(),
        Some("application/json"),
    )?;

    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
        }
    }
    fs::write(&out, &token)
        .with_context(|| format!("failed to write token to {}", out.display()))?;

    println!(
        "Wrote {} JWS (alg={}, typ={}) to {}",
        kind.display_name(),
        args.alg,
        kind.media_type(),
        out.display()
    );
    Ok(())
}

fn do_sign(args: &SignArgs, prompts: &CommandPrompts) -> Result<()> {
    let key = args.key.as_ref().expect("key should be set");
    let payload_path = args.payload.as_ref().expect("payload should be set");
    let out = args.out.as_ref().expect("out should be set");
    let kid = args.kid.as_ref().expect("kid should be set");

    let payload_content = fs::read_to_string(payload_path)
        .with_context(|| format!("failed to read payload file {}", payload_path.display()))?;
    let payload_json: Value =
        serde_json::from_str(&payload_content).context("payload is not valid JSON")?;

    let kind = if let Some(kind) = args.credential_type {
        kind
    } else {
        detect_credential_kind(&payload_json).ok_or_else(|| {
            anyhow!("unable to detect credential type; pass --credential-type explicitly")
        })?
    };

    prompts.info(&format!("Detected credential type: {}", kind.display_name()))?;

    if !args.skip_schema {
        prompts.info("Validating credential schema...")?;
        let errors = validate_credential(kind, &payload_json)?;
        if !errors.is_empty() {
            let mut message = String::from("schema validation failed:\n");
            for err in errors {
                message.push_str(&format!("  - {err}\n"));
            }
            bail!(message);
        }
        prompts.info("Schema validation passed")?;
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

    prompts.info(&format!("Signing with {} using key: {}", args.alg, key.display()))?;

    let token = sign_jws(
        &claims,
        key,
        args.alg,
        Some(kid.clone()),
        kind.media_type(),
        Some("application/json"),
    )?;

    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
        }
    }
    fs::write(out, &token)
        .with_context(|| format!("failed to write token to {}", out.display()))?;

    println!();
    println!("{}", style("Signed successfully!").green().bold());
    println!();
    println!("  {} {}", style("Type:").dim(), kind.display_name());
    println!("  {} {}", style("Algorithm:").dim(), args.alg);
    println!("  {} {}", style("Key ID:").dim(), kid);
    println!("  {} {}", style("Output:").dim(), out.display());

    Ok(())
}
