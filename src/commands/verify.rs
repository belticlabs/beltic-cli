use std::{fs, path::PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use console::style;
use serde_json::Value;

use crate::credential::{
    credential_kind_from_typ, detect_credential_kind, parse_credential_kind, validate_credential,
    CredentialKind,
};
use crate::crypto::{verify_jws, VerifiedToken};

use super::discovery::{find_public_keys, find_tokens};
use super::prompts::CommandPrompts;

#[derive(Args)]
pub struct VerifyArgs {
    /// Path to the public key (PEM). Auto-discovered if omitted.
    #[arg(long)]
    pub key: Option<PathBuf>,

    /// Path to the JWS token or the token string itself. Auto-discovered if omitted.
    #[arg(long)]
    pub token: Option<String>,

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

    /// Disable interactive mode
    #[arg(long)]
    pub non_interactive: bool,
}

pub fn run(args: VerifyArgs) -> Result<()> {
    // Determine if we need interactive mode
    let needs_interactive =
        (args.key.is_none() || args.token.is_none()) && !args.non_interactive;

    if needs_interactive {
        run_interactive(args)
    } else {
        run_non_interactive(args)
    }
}

fn run_interactive(mut args: VerifyArgs) -> Result<()> {
    let prompts = CommandPrompts::new();

    prompts.section_header("Beltic Token Verifier")?;

    // 1. Token selection (with auto-discovery)
    if args.token.is_none() {
        let tokens = find_tokens();
        if tokens.is_empty() {
            prompts.warn("No token files (.jwt, .jws) found.")?;
            let path = prompts.prompt_path("Enter token path", None)?;
            args.token = Some(path.display().to_string());
        } else {
            let selected = prompts.prompt_select_path("Select token to verify", &tokens, true)?;
            args.token = Some(selected.display().to_string());
        }
    }

    // 2. Public key selection (with auto-discovery)
    if args.key.is_none() {
        let public_keys = find_public_keys();
        if public_keys.is_empty() {
            prompts.warn("No public keys found.")?;
            let path = prompts.prompt_path("Enter public key path", None)?;
            args.key = Some(path);
        } else {
            args.key = Some(prompts.prompt_select_path("Select public key", &public_keys, true)?);
        }
    }

    // Continue with verification
    do_verify(&args, &prompts)
}

fn run_non_interactive(args: VerifyArgs) -> Result<()> {
    // Auto-discover token if not provided
    let token_input = if let Some(t) = args.token.as_ref() {
        t.clone()
    } else {
        let tokens = find_tokens();
        if tokens.is_empty() {
            bail!("No token files (.jwt) found.");
        }
        eprintln!("[info] Using auto-discovered token: {}", tokens[0].display());
        tokens[0].display().to_string()
    };

    // Auto-discover public key if not provided
    let key = if let Some(k) = args.key.as_ref() {
        k.clone()
    } else {
        let keys = find_public_keys();
        if keys.is_empty() {
            bail!("No public keys found.");
        }
        eprintln!("[info] Using auto-discovered key: {}", keys[0].display());
        keys[0].clone()
    };

    let token = load_token(&token_input)?;

    match verify_jws(token.trim(), &key) {
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

fn do_verify(args: &VerifyArgs, prompts: &CommandPrompts) -> Result<()> {
    let key = args.key.as_ref().expect("key should be set");
    let token_input = args.token.as_ref().expect("token should be set");

    prompts.info(&format!("Loading token from: {}", token_input))?;
    let token = load_token(token_input)?;

    prompts.info(&format!("Verifying with key: {}", key.display()))?;

    match verify_jws(token.trim(), key) {
        Ok(verified) => {
            println!();
            println!("{}", style("Verification successful!").green().bold());

            if let Err(err) = validate_verified_interactive(verified, args, prompts) {
                println!();
                println!("{}", style("Validation failed:").red().bold());
                println!("  {}", err);
                std::process::exit(1);
            }
            Ok(())
        }
        Err(err) => {
            println!();
            println!("{}", style("Verification failed:").red().bold());
            println!("  {}", err);
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

fn validate_verified_interactive(
    verified: VerifiedToken,
    args: &VerifyArgs,
    prompts: &CommandPrompts,
) -> Result<()> {
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
        prompts.info("Validating credential schema...")?;
        let errors = validate_credential(kind, vc)?;
        if !errors.is_empty() {
            let mut message = String::from("schema validation failed:\n");
            for err in errors {
                message.push_str(&format!("  - {err}\n"));
            }
            bail!(message);
        }
        prompts.info("Schema validation passed")?;
    }

    println!();
    println!("  {} {}", style("Type:").dim(), kind.display_name());
    println!("  {} {}", style("Algorithm:").dim(), verified.alg);
    println!(
        "  {} {}",
        style("Key ID:").dim(),
        verified.header.kid.as_deref().unwrap_or("<none>")
    );
    println!("  {} {}", style("Issuer:").dim(), iss);
    println!("  {} {}", style("Subject:").dim(), sub);
    println!("  {} {}", style("JTI:").dim(), jti);

    println!();
    println!("{}", style("Credential payload:").cyan().bold());
    let pretty = serde_json::to_string_pretty(vc)?;
    println!("{pretty}");

    Ok(())
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
