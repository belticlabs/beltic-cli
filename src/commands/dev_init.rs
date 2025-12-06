//! Developer credential initialization command
//!
//! Creates a self-attested DeveloperCredential for use with agent credentials.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{anyhow, Context, Result};
use chrono::{Duration, Utc};
use clap::Args;
use console::style;
use serde_json::{json, Value};
use uuid::Uuid;

use super::discovery::find_public_keys;
use super::prompts::CommandPrompts;

/// Git-based auto-detection results
#[derive(Debug, Default)]
struct GitDefaults {
    name: Option<String>,
    email: Option<String>,
    website: Option<String>,
}

/// Detect defaults from git config
fn detect_git_defaults() -> GitDefaults {
    let mut defaults = GitDefaults::default();

    // Get user.name from git config
    if let Ok(output) = Command::new("git")
        .args(["config", "--get", "user.name"])
        .output()
    {
        if output.status.success() {
            let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !name.is_empty() {
                defaults.name = Some(name);
            }
        }
    }

    // Get user.email from git config
    if let Ok(output) = Command::new("git")
        .args(["config", "--get", "user.email"])
        .output()
    {
        if output.status.success() {
            let email = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !email.is_empty() {
                defaults.email = Some(email.clone());
                // Try to derive website from email domain
                if defaults.website.is_none() {
                    if let Some(domain) = email.split('@').nth(1) {
                        // Skip common email providers
                        if ![
                            "gmail.com",
                            "yahoo.com",
                            "hotmail.com",
                            "outlook.com",
                            "icloud.com",
                            "protonmail.com",
                        ]
                        .contains(&domain)
                        {
                            defaults.website = Some(format!("https://{}", domain));
                        }
                    }
                }
            }
        }
    }

    // Try to get website from remote origin
    if defaults.website.is_none() {
        if let Ok(output) = Command::new("git")
            .args(["remote", "get-url", "origin"])
            .output()
        {
            if output.status.success() {
                let remote = String::from_utf8_lossy(&output.stdout).trim().to_string();
                // Parse GitHub/GitLab URLs
                if let Some(url) = parse_git_remote_to_website(&remote) {
                    defaults.website = Some(url);
                }
            }
        }
    }

    defaults
}

/// Parse git remote URL to website URL
fn parse_git_remote_to_website(remote: &str) -> Option<String> {
    // Handle SSH URLs: git@github.com:user/repo.git
    if remote.starts_with("git@github.com:") {
        let path = remote
            .strip_prefix("git@github.com:")?
            .strip_suffix(".git")
            .unwrap_or(remote.strip_prefix("git@github.com:")?);
        let user = path.split('/').next()?;
        return Some(format!("https://github.com/{}", user));
    }

    // Handle HTTPS URLs: https://github.com/user/repo.git
    if remote.starts_with("https://github.com/") {
        let path = remote
            .strip_prefix("https://github.com/")?
            .strip_suffix(".git")
            .unwrap_or(remote.strip_prefix("https://github.com/")?);
        let user = path.split('/').next()?;
        return Some(format!("https://github.com/{}", user));
    }

    // Handle GitLab
    if remote.contains("gitlab.com") {
        if remote.starts_with("git@gitlab.com:") {
            let path = remote
                .strip_prefix("git@gitlab.com:")?
                .strip_suffix(".git")
                .unwrap_or(remote.strip_prefix("git@gitlab.com:")?);
            let user = path.split('/').next()?;
            return Some(format!("https://gitlab.com/{}", user));
        }
        if remote.starts_with("https://gitlab.com/") {
            let path = remote
                .strip_prefix("https://gitlab.com/")?
                .strip_suffix(".git")
                .unwrap_or(remote.strip_prefix("https://gitlab.com/")?);
            let user = path.split('/').next()?;
            return Some(format!("https://gitlab.com/{}", user));
        }
    }

    None
}

/// Entity types for developer credentials
const ENTITY_TYPES: &[(&str, &str)] = &[
    ("individual", "Individual developer"),
    ("corporation", "Corporation"),
    (
        "limited_liability_company",
        "Limited Liability Company (LLC)",
    ),
    ("sole_proprietorship", "Sole Proprietorship"),
    ("partnership", "Partnership"),
    ("nonprofit", "Nonprofit Organization"),
    ("government_agency", "Government Agency"),
];

/// Common country codes
const COMMON_COUNTRIES: &[(&str, &str)] = &[
    ("US", "United States"),
    ("GB", "United Kingdom"),
    ("DE", "Germany"),
    ("FR", "France"),
    ("CA", "Canada"),
    ("AU", "Australia"),
    ("JP", "Japan"),
    ("IN", "India"),
    ("SG", "Singapore"),
    ("OTHER", "Other (enter code)"),
];

#[derive(Args)]
pub struct DevInitArgs {
    /// Output path for the developer credential (default: ./developer-credential.json)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Legal name of the developer or organization
    #[arg(long)]
    pub name: Option<String>,

    /// Entity type (individual, corporation, llc, etc.)
    #[arg(long)]
    pub entity_type: Option<String>,

    /// Country code (ISO 3166-1 alpha-2, e.g., US, GB, DE)
    #[arg(long)]
    pub country: Option<String>,

    /// Website URL
    #[arg(long)]
    pub website: Option<String>,

    /// Business email address
    #[arg(long)]
    pub email: Option<String>,

    /// Path to public key (PEM) to embed in credential
    #[arg(long)]
    pub public_key: Option<PathBuf>,

    /// Overwrite existing credential file
    #[arg(short, long)]
    pub force: bool,

    /// Disable interactive mode
    #[arg(long)]
    pub non_interactive: bool,
}

pub fn run(args: DevInitArgs) -> Result<()> {
    if args.non_interactive {
        run_non_interactive(args)
    } else {
        run_interactive(args)
    }
}

fn run_interactive(mut args: DevInitArgs) -> Result<()> {
    let prompts = CommandPrompts::new();

    prompts.section_header("Beltic Developer Credential Generator")?;
    prompts.info("Create a self-attested developer credential for agent signing.")?;
    prompts.info("This credential identifies you as the developer of AI agents.")?;

    // Detect git defaults for suggestions
    let git_defaults = detect_git_defaults();

    // 1. Legal name
    if args.name.is_none() {
        args.name = Some(prompts.prompt_string(
            "Legal name (person or organization)",
            git_defaults.name.as_deref(),
        )?);
    }

    // 2. Entity type
    if args.entity_type.is_none() {
        let options: Vec<&str> = ENTITY_TYPES.iter().map(|(_, label)| *label).collect();
        let idx = prompts.prompt_select("Entity type", &options, 0)?;
        args.entity_type = Some(ENTITY_TYPES[idx].0.to_string());
    }

    // 3. Country
    if args.country.is_none() {
        let options: Vec<&str> = COMMON_COUNTRIES.iter().map(|(_, label)| *label).collect();
        let idx = prompts.prompt_select("Country", &options, 0)?;

        if COMMON_COUNTRIES[idx].0 == "OTHER" {
            args.country = Some(
                prompts
                    .prompt_string("Enter ISO 3166-1 alpha-2 country code (e.g., NL)", None)?
                    .to_uppercase(),
            );
        } else {
            args.country = Some(COMMON_COUNTRIES[idx].0.to_string());
        }
    }

    // 4. Website
    if args.website.is_none() {
        let default_website = git_defaults.website.as_deref().unwrap_or("https://");
        args.website = Some(prompts.prompt_string("Website URL", Some(default_website))?);
    }

    // 5. Email
    if args.email.is_none() {
        args.email = Some(prompts.prompt_string("Business email", git_defaults.email.as_deref())?);
    }

    // 6. Public key (optional)
    if args.public_key.is_none() {
        let public_keys = find_public_keys();
        if !public_keys.is_empty() {
            if prompts.prompt_confirm("Embed a public key in the credential?", true)? {
                args.public_key =
                    Some(prompts.prompt_select_path("Select public key", &public_keys, true)?);
            }
        }
    }

    // 7. Output path
    if args.output.is_none() {
        args.output = Some(prompts.prompt_path(
            "Output path",
            Some(&PathBuf::from("developer-credential.json")),
        )?);
    }

    // Generate and save
    let output_path = args.output.as_ref().ok_or_else(|| {
        anyhow!("output path is required; rerun without --non-interactive to provide one")
    })?;

    // Check for existing file
    if output_path.exists() && !args.force {
        if !prompts.prompt_confirm(
            &format!("{} exists. Overwrite?", output_path.display()),
            false,
        )? {
            prompts.warn("Aborted.")?;
            return Ok(());
        }
    }

    let credential = generate_developer_credential(&args)?;
    let json_str = serde_json::to_string_pretty(&credential)?;
    fs::write(output_path, &json_str)?;

    prompts.success(&format!(
        "Developer credential saved to {}",
        output_path.display()
    ))?;
    prompts.info("")?;
    prompts.info(&format!(
        "Credential ID: {}",
        style(credential["credentialId"].as_str().unwrap_or("")).cyan()
    ))?;
    prompts.info(&format!(
        "Valid until: {}",
        credential["expirationDate"].as_str().unwrap_or("")
    ))?;
    prompts.info("")?;
    prompts.info("Next steps:")?;
    prompts.info("  1. Generate a keypair if you haven't: beltic keygen")?;
    prompts.info(&format!(
        "  2. Sign the credential: beltic sign --payload {}",
        output_path.display()
    ))?;
    prompts
        .info("  3. Use the credential ID in agent manifests: beltic init --developer-id <id>")?;

    Ok(())
}

fn run_non_interactive(mut args: DevInitArgs) -> Result<()> {
    // Apply git defaults for missing fields
    let git_defaults = detect_git_defaults();

    if args.name.is_none() {
        if let Some(name) = git_defaults.name {
            eprintln!("[info] Using git user.name: {}", name);
            args.name = Some(name);
        }
    }

    if args.email.is_none() {
        if let Some(email) = git_defaults.email {
            eprintln!("[info] Using git user.email: {}", email);
            args.email = Some(email);
        }
    }

    if args.website.is_none() {
        if let Some(website) = git_defaults.website {
            eprintln!("[info] Using derived website: {}", website);
            args.website = Some(website);
        }
    }

    // Validate required fields after applying defaults
    if args.name.is_none() {
        anyhow::bail!("--name is required (not found in git config)");
    }
    if args.email.is_none() {
        anyhow::bail!("--email is required (not found in git config)");
    }
    if args.website.is_none() {
        anyhow::bail!("--website is required (could not derive from git remote)");
    }

    let output_path = args
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from("developer-credential.json"));

    // Check for existing file
    if output_path.exists() && !args.force {
        anyhow::bail!(
            "{} already exists. Use --force to overwrite.",
            output_path.display()
        );
    }

    let credential = generate_developer_credential(&args)?;
    let json_str = serde_json::to_string_pretty(&credential)?;
    fs::write(&output_path, &json_str)?;

    println!("Developer credential saved to {}", output_path.display());
    println!(
        "Credential ID: {}",
        credential["credentialId"].as_str().unwrap_or("")
    );

    Ok(())
}

fn generate_developer_credential(args: &DevInitArgs) -> Result<Value> {
    let now = Utc::now();
    let expiry = now + Duration::days(90); // 90-day validity for self-attested

    let credential_id = Uuid::new_v4();
    let name = args.name.as_deref().unwrap_or("Developer");
    let entity_type = args.entity_type.as_deref().unwrap_or("individual");
    let country = args.country.as_deref().unwrap_or("US");
    let website = args.website.as_deref().unwrap_or("https://example.com");
    let email = args.email.as_deref().unwrap_or("developer@example.com");

    // Determine business registration status based on entity type
    let registration_status = if entity_type == "individual" {
        "not_applicable"
    } else {
        "active_good_standing"
    };

    // Extract domain from website for DID
    let domain = website
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("example.com");

    // Build public key object if provided
    let public_key = if let Some(key_path) = &args.public_key {
        let pem_content = fs::read_to_string(key_path)
            .with_context(|| format!("Failed to read public key: {}", key_path.display()))?;

        // Detect key type from PEM
        let key_type = if pem_content.contains("ED25519") {
            "Ed25519VerificationKey2020"
        } else if pem_content.contains("EC") || pem_content.contains("P-256") {
            "JsonWebKey2020"
        } else {
            "Ed25519VerificationKey2020" // Default
        };

        json!({
            "type": key_type,
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "placeholder_base64url_public_key"
            }
        })
    } else {
        json!({
            "type": "Ed25519VerificationKey2020",
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "placeholder_base64url_public_key"
            }
        })
    };

    let credential = json!({
        "schemaVersion": "1.0",
        "legalName": name,
        "entityType": entity_type,
        "incorporationJurisdiction": {
            "country": country
        },
        "businessRegistrationStatus": registration_status,
        "website": website,
        "businessEmail": email,
        "taxIdExists": false,
        "kybTier": "tier_0_unverified",
        "sanctionsScreeningStatus": "not_screened",
        "overallRiskRating": "not_assessed",
        "credentialId": credential_id.to_string(),
        "issuanceDate": now.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        "expirationDate": expiry.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        "issuerDid": "did:web:self",
        "verificationMethod": "did:web:self#key-1",
        "credentialStatus": "active",
        "revocationListUrl": format!("https://{}/revocation", domain),
        "lastUpdatedDate": now.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        "subjectDid": format!("did:web:{}", domain),
        "publicKey": public_key,
        "proof": {
            "type": "Ed25519Signature2020",
            "created": now.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            "verificationMethod": "did:web:self#key-1",
            "proofPurpose": "assertionMethod",
            "proofValue": "placeholder_will_be_replaced_when_signed"
        },
        "assuranceMetadata": {
            "globalAssuranceLevel": "self_attested",
            "fieldAssurances": {
                "legalName": {
                    "assuranceLevel": "self_attested"
                },
                "website": {
                    "assuranceLevel": "self_attested"
                }
            }
        }
    });

    Ok(credential)
}
