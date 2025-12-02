//! Extract credential ID from a credential JSON or JWT file.

use std::{fs, path::PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::Args;
use serde_json::Value;

#[derive(Args)]
pub struct CredentialIdArgs {
    /// Path to the credential file (JSON or JWT)
    #[arg()]
    pub file: PathBuf,
}

pub fn run(args: CredentialIdArgs) -> Result<()> {
    let path = &args.file;

    if !path.exists() {
        return Err(anyhow!("File not found: {}", path.display()));
    }

    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read file: {}", path.display()))?;

    let credential_id = if is_jwt(&content) {
        extract_from_jwt(&content)?
    } else {
        extract_from_json(&content)?
    };

    println!("{}", credential_id);
    Ok(())
}

fn is_jwt(content: &str) -> bool {
    let trimmed = content.trim();
    // JWT has 3 parts separated by dots
    trimmed.split('.').count() == 3 && !trimmed.contains('{')
}

fn extract_from_json(content: &str) -> Result<String> {
    let json: Value = serde_json::from_str(content)
        .context("Invalid JSON")?;

    // Try credentialId first (agent credentials)
    if let Some(id) = json.get("credentialId").and_then(|v| v.as_str()) {
        return Ok(id.to_string());
    }

    // Try developerCredentialId (developer credentials)
    if let Some(id) = json.get("developerCredentialId").and_then(|v| v.as_str()) {
        // Skip nil UUID
        if id != "00000000-0000-0000-0000-000000000000" {
            return Ok(id.to_string());
        }
    }

    Err(anyhow!("No credentialId found in JSON"))
}

fn extract_from_jwt(content: &str) -> Result<String> {
    let parts: Vec<&str> = content.trim().split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow!("Invalid JWT format"));
    }

    // Decode the payload (second part)
    let payload_b64 = parts[1];

    // Handle URL-safe base64
    let payload_bytes = base64_url_decode(payload_b64)
        .context("Failed to decode JWT payload")?;

    let payload: Value = serde_json::from_slice(&payload_bytes)
        .context("Failed to parse JWT payload")?;

    // Try jti claim (standard JWT claim for credential ID)
    if let Some(jti) = payload.get("jti").and_then(|v| v.as_str()) {
        return Ok(jti.to_string());
    }

    // Try vc.credentialId (embedded credential)
    if let Some(vc) = payload.get("vc") {
        if let Some(id) = vc.get("credentialId").and_then(|v| v.as_str()) {
            return Ok(id.to_string());
        }
    }

    Err(anyhow!("No credentialId found in JWT"))
}

fn base64_url_decode(input: &str) -> Result<Vec<u8>> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    // Add padding if needed
    let padded = match input.len() % 4 {
        2 => format!("{}==", input),
        3 => format!("{}=", input),
        _ => input.to_string(),
    };

    URL_SAFE_NO_PAD.decode(padded.trim_end_matches('='))
        .or_else(|_| {
            // Try standard base64 as fallback
            use base64::engine::general_purpose::STANDARD;
            STANDARD.decode(&padded)
        })
        .context("Base64 decode failed")
}
