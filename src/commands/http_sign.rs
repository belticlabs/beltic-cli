//! HTTP Request Signing (Web Bot Auth)
//!
//! Signs HTTP requests per RFC 9421 for Web Bot Auth compatibility.

use std::{collections::HashMap, fs, path::PathBuf, time::SystemTime};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::Args;
use ed25519_dalek::{Signer, SigningKey};
use pkcs8::DecodePrivateKey;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[derive(Args)]
pub struct HttpSignArgs {
    /// HTTP method (GET, POST, etc.)
    #[arg(long)]
    pub method: String,

    /// Target URL
    #[arg(long)]
    pub url: String,

    /// Path to the private key (PEM, Ed25519 only)
    #[arg(long)]
    pub key: PathBuf,

    /// URL to the agent's key directory
    #[arg(long)]
    pub key_directory: String,

    /// Additional headers to include in signature (format: "Name: Value")
    #[arg(long)]
    pub header: Vec<String>,

    /// Components to sign (default: @authority, signature-agent)
    #[arg(long)]
    pub component: Vec<String>,

    /// Request body (for Content-Digest)
    #[arg(long)]
    pub body: Option<String>,

    /// Path to request body file
    #[arg(long)]
    pub body_file: Option<PathBuf>,

    /// Signature validity in seconds (default: 60)
    #[arg(long, default_value = "60")]
    pub expires_in: u64,

    /// Output format: headers (default) or curl
    #[arg(long, default_value = "headers")]
    pub format: OutputFormat,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Headers,
    Curl,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "headers" => Ok(OutputFormat::Headers),
            "curl" => Ok(OutputFormat::Curl),
            _ => Err(format!("invalid format '{}': use 'headers' or 'curl'", s)),
        }
    }
}

pub fn run(args: HttpSignArgs) -> Result<()> {
    // Validate key directory URL
    if !args.key_directory.starts_with("https://") {
        bail!("key-directory must be an HTTPS URL");
    }
    if !args.key_directory.ends_with("/.well-known/http-message-signatures-directory") {
        eprintln!(
            "Warning: key-directory should end with /.well-known/http-message-signatures-directory"
        );
    }

    // Load private key
    let pem = Zeroizing::new(
        fs::read_to_string(&args.key)
            .with_context(|| format!("failed to read key file {}", args.key.display()))?,
    );
    let signing_key =
        SigningKey::from_pkcs8_pem(&pem).context("failed to parse Ed25519 private key")?;

    // Compute JWK thumbprint
    let verifying_key = signing_key.verifying_key();
    let thumbprint = compute_jwk_thumbprint(&verifying_key)?;

    // Parse URL
    let parsed_url = url::Url::parse(&args.url).context("invalid URL")?;
    let authority = parsed_url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL must have a host"))?;
    let authority = if let Some(port) = parsed_url.port() {
        format!("{}:{}", authority, port)
    } else {
        authority.to_string()
    };
    let path = parsed_url.path();
    let query = parsed_url.query().map(|q| format!("?{}", q)).unwrap_or_default();

    // Parse additional headers
    let mut headers: HashMap<String, String> = HashMap::new();
    for h in &args.header {
        let parts: Vec<&str> = h.splitn(2, ':').collect();
        if parts.len() != 2 {
            bail!("invalid header format '{}': use 'Name: Value'", h);
        }
        headers.insert(parts[0].trim().to_lowercase(), parts[1].trim().to_string());
    }

    // Handle body and Content-Digest
    let body = if let Some(body_path) = &args.body_file {
        Some(fs::read_to_string(body_path).with_context(|| {
            format!("failed to read body file {}", body_path.display())
        })?)
    } else {
        args.body.clone()
    };

    if let Some(ref body_content) = body {
        let digest = compute_content_digest(body_content.as_bytes());
        headers.insert("content-digest".to_string(), digest);
    }

    // Determine components to sign
    let mut components: Vec<String> = if args.component.is_empty() {
        vec![
            "@method".to_string(),
            "@authority".to_string(),
            "@path".to_string(),
            "signature-agent".to_string(),
        ]
    } else {
        args.component.clone()
    };

    // Ensure required components
    if !components.contains(&"@authority".to_string()) {
        components.insert(0, "@authority".to_string());
    }
    if !components.contains(&"signature-agent".to_string()) {
        components.push("signature-agent".to_string());
    }
    if body.is_some() && !components.contains(&"content-digest".to_string()) {
        components.push("content-digest".to_string());
    }

    // Timestamps
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("system time error")?
        .as_secs();
    let created = now;
    let expires = now + args.expires_in;

    // Generate nonce
    let mut nonce_bytes = [0u8; 32];
    getrandom::getrandom(&mut nonce_bytes).context("failed to generate nonce")?;
    let nonce = URL_SAFE_NO_PAD.encode(nonce_bytes);

    // Build signature params
    let component_list = components.iter().map(|c| format!("\"{}\"", c)).collect::<Vec<_>>().join(" ");
    let signature_params = format!(
        "({});alg=\"ed25519\";keyid=\"{}\";created={};expires={};nonce=\"{}\";tag=\"web-bot-auth\"",
        component_list, thumbprint, created, expires, nonce
    );

    // Build signature base
    let mut signature_base_lines: Vec<String> = Vec::new();
    for component in &components {
        let value = match component.as_str() {
            "@method" => args.method.to_uppercase(),
            "@authority" => authority.clone(),
            "@scheme" => parsed_url.scheme().to_string(),
            "@path" => path.to_string(),
            "@query" => if query.is_empty() { "?".to_string() } else { query.clone() },
            "@target-uri" => args.url.clone(),
            "@request-target" => format!("{} {}{}", args.method.to_lowercase(), path, query),
            "signature-agent" => format!("\"{}\"", args.key_directory),
            _ => {
                // It's a header
                headers.get(component).cloned().ok_or_else(|| {
                    anyhow::anyhow!("component '{}' not found in headers", component)
                })?
            }
        };
        signature_base_lines.push(format!("\"{}\": {}", component, value));
    }
    signature_base_lines.push(format!("\"@signature-params\": {}", signature_params));
    let signature_base = signature_base_lines.join("\n");

    // Sign
    let signature = signing_key.sign(signature_base.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    // Output
    let signature_agent_header = format!("\"{}\"", args.key_directory);
    let signature_input_header = format!("sig1={}", signature_params);
    let signature_header = format!("sig1=:{}:", signature_b64);

    match args.format {
        OutputFormat::Headers => {
            println!("Signature-Agent: {}", signature_agent_header);
            println!("Signature-Input: {}", signature_input_header);
            println!("Signature: {}", signature_header);
            if let Some(digest) = headers.get("content-digest") {
                println!("Content-Digest: {}", digest);
            }
        }
        OutputFormat::Curl => {
            let mut curl_cmd = format!(
                "curl -X {} '{}' \\\n  -H 'Signature-Agent: {}' \\\n  -H 'Signature-Input: {}' \\\n  -H 'Signature: {}'",
                args.method.to_uppercase(),
                args.url,
                signature_agent_header,
                signature_input_header,
                signature_header
            );
            if let Some(digest) = headers.get("content-digest") {
                curl_cmd.push_str(&format!(" \\\n  -H 'Content-Digest: {}'", digest));
            }
            for (name, value) in &headers {
                if name != "content-digest" {
                    curl_cmd.push_str(&format!(" \\\n  -H '{}: {}'", name, value));
                }
            }
            if let Some(ref body_content) = body {
                curl_cmd.push_str(&format!(" \\\n  -d '{}'", body_content.replace('\'', "'\\''")));
            }
            println!("{}", curl_cmd);
        }
    }

    eprintln!("\nKey ID (JWK thumbprint): {}", thumbprint);
    eprintln!("Signature valid for {} seconds (expires at {})", args.expires_in, expires);

    Ok(())
}

/// Compute JWK thumbprint for an Ed25519 public key per RFC 7638.
fn compute_jwk_thumbprint(verifying_key: &ed25519_dalek::VerifyingKey) -> Result<String> {
    // Get raw public key bytes (32 bytes)
    let public_bytes = verifying_key.to_bytes();
    let x = URL_SAFE_NO_PAD.encode(public_bytes);

    // Canonical JWK (keys in lexicographic order)
    let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#, x);

    // SHA-256 hash
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let hash = hasher.finalize();

    Ok(URL_SAFE_NO_PAD.encode(hash))
}

/// Compute Content-Digest header value.
fn compute_content_digest(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    let hash = hasher.finalize();
    format!("sha-256=:{}:", URL_SAFE_NO_PAD.encode(hash))
}


