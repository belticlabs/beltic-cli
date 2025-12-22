//! Key Directory Management for Web Bot Auth
//!
//! Generate and serve HTTP Message Signatures key directories.

use std::{fs, path::PathBuf, time::SystemTime};

/// Directory signature validity duration in seconds.
/// This value is used for both the signature `expires` parameter and Cache-Control max-age
/// to ensure cached responses always have valid signatures.
const DIRECTORY_SIGNATURE_LIFETIME_SECS: u64 = 300; // 5 minutes

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::{Args, Subcommand};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use pkcs8::{DecodePrivateKey, DecodePublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[derive(Args)]
pub struct DirectoryArgs {
    #[command(subcommand)]
    pub command: DirectoryCommand,
}

#[derive(Subcommand)]
pub enum DirectoryCommand {
    /// Generate a key directory JSON from public keys
    Generate(GenerateArgs),

    /// Compute the JWK thumbprint for a public key
    Thumbprint(ThumbprintArgs),
}

#[derive(Args)]
pub struct GenerateArgs {
    /// Path to Ed25519 public key (PEM)
    #[arg(long)]
    pub public_key: Vec<PathBuf>,

    /// Output file for the key directory JSON
    #[arg(long)]
    pub out: PathBuf,

    /// URL to the agent's credential JWT (optional)
    #[arg(long)]
    pub credential_url: Option<String>,

    /// Agent metadata JSON (e.g., '{"kybTierRequired":"tier_0","overallSafetyRating":"low_risk","agentName":"my-agent"}')
    #[arg(long)]
    pub agent_metadata: Option<String>,

    /// Also output with signature headers (requires private key)
    #[arg(long)]
    pub sign: bool,

    /// Private key for signing the directory response
    #[arg(long)]
    pub private_key: Option<PathBuf>,

    /// Authority (host) for signature
    #[arg(long)]
    pub authority: Option<String>,
}

#[derive(Args)]
pub struct ThumbprintArgs {
    /// Path to Ed25519 public key (PEM)
    #[arg(long)]
    pub public_key: PathBuf,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyDirectory {
    keys: Vec<JwkKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_credential_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_metadata: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize)]
pub struct JwkKey {
    kty: String,
    crv: String,
    x: String,
}

pub fn run(args: DirectoryArgs) -> Result<()> {
    match args.command {
        DirectoryCommand::Generate(gen_args) => run_generate(gen_args),
        DirectoryCommand::Thumbprint(thumb_args) => run_thumbprint(thumb_args),
    }
}

fn run_generate(args: GenerateArgs) -> Result<()> {
    if args.public_key.is_empty() {
        bail!("at least one --public-key is required");
    }

    if args.sign && args.private_key.is_none() {
        bail!("--private-key is required when using --sign");
    }

    let mut keys: Vec<JwkKey> = Vec::new();

    for key_path in &args.public_key {
        let pem = fs::read_to_string(key_path)
            .with_context(|| format!("failed to read public key {}", key_path.display()))?;

        let verifying_key = VerifyingKey::from_public_key_pem(&pem).with_context(|| {
            format!(
                "failed to parse Ed25519 public key from {}",
                key_path.display()
            )
        })?;

        let public_bytes = verifying_key.to_bytes();
        let x = URL_SAFE_NO_PAD.encode(public_bytes);

        keys.push(JwkKey {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            x,
        });
    }

    // Parse agent metadata if provided
    let agent_metadata: Option<serde_json::Value> = args
        .agent_metadata
        .as_ref()
        .map(|m| serde_json::from_str(m))
        .transpose()
        .context("failed to parse --agent-metadata as JSON")?;

    let directory = KeyDirectory {
        keys,
        agent_credential_url: args.credential_url.clone(),
        agent_metadata,
    };
    let directory_json = serde_json::to_string_pretty(&directory)?;

    // Write directory
    if let Some(parent) = args.out.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
        }
    }
    fs::write(&args.out, &directory_json)
        .with_context(|| format!("failed to write directory to {}", args.out.display()))?;

    println!("Wrote key directory to {}", args.out.display());

    // Output thumbprints
    for (i, key) in directory.keys.iter().enumerate() {
        let thumbprint = compute_key_thumbprint(&key.x)?;
        println!("  Key {}: thumbprint = {}", i + 1, thumbprint);
    }

    // Output credential URL if provided
    if let Some(ref cred_url) = args.credential_url {
        println!("  Credential URL: {}", cred_url);
    }

    // Output agent metadata if provided
    if let Some(ref metadata) = directory.agent_metadata {
        println!("  Agent Metadata: {}", serde_json::to_string(metadata)?);
    }

    // Sign if requested
    if args.sign {
        let private_key_path = args
            .private_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("--private-key is required when using --sign"))?;
        let authority = args
            .authority
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("--authority is required when using --sign"))?;

        let pem = Zeroizing::new(fs::read_to_string(private_key_path).with_context(|| {
            format!("failed to read private key {}", private_key_path.display())
        })?);
        let signing_key =
            SigningKey::from_pkcs8_pem(&pem).context("failed to parse Ed25519 private key")?;
        let verifying_key = signing_key.verifying_key();
        let thumbprint = compute_jwk_thumbprint(&verifying_key)?;

        // Timestamps
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .context("system time error")?
            .as_secs();
        let created = now;
        let expires = now + DIRECTORY_SIGNATURE_LIFETIME_SECS;

        // Generate nonce
        let mut nonce_bytes = [0u8; 32];
        getrandom::getrandom(&mut nonce_bytes).context("failed to generate nonce")?;
        let nonce = URL_SAFE_NO_PAD.encode(nonce_bytes);

        // Build signature params
        let signature_params = format!(
            "(\"@authority\");alg=\"ed25519\";keyid=\"{}\";nonce=\"{}\";tag=\"http-message-signatures-directory\";created={};expires={}",
            thumbprint, nonce, created, expires
        );

        // Build signature base
        let signature_base = format!(
            "\"@authority\": {}\n\"@signature-params\": {}",
            authority, signature_params
        );

        // Sign
        let signature = signing_key.sign(signature_base.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        println!("\nSigned response headers:");
        println!("Content-Type: application/http-message-signatures-directory+json");
        println!("Signature: sig1=:{}:", signature_b64);
        println!("Signature-Input: sig1={}", signature_params);
        println!("Cache-Control: max-age={}", DIRECTORY_SIGNATURE_LIFETIME_SECS);
    }

    Ok(())
}

fn run_thumbprint(args: ThumbprintArgs) -> Result<()> {
    let pem = fs::read_to_string(&args.public_key)
        .with_context(|| format!("failed to read public key {}", args.public_key.display()))?;

    let verifying_key = VerifyingKey::from_public_key_pem(&pem).with_context(|| {
        format!(
            "failed to parse Ed25519 public key from {}",
            args.public_key.display()
        )
    })?;

    let thumbprint = compute_jwk_thumbprint(&verifying_key)?;

    println!("{}", thumbprint);

    Ok(())
}

/// Compute JWK thumbprint for an Ed25519 public key per RFC 7638.
fn compute_jwk_thumbprint(verifying_key: &VerifyingKey) -> Result<String> {
    let public_bytes = verifying_key.to_bytes();
    let x = URL_SAFE_NO_PAD.encode(public_bytes);
    compute_key_thumbprint(&x)
}

/// Compute thumbprint from base64url-encoded x coordinate.
fn compute_key_thumbprint(x: &str) -> Result<String> {
    // Canonical JWK (keys in lexicographic order)
    let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#, x);

    // SHA-256 hash
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let hash = hasher.finalize();

    Ok(URL_SAFE_NO_PAD.encode(hash))
}
