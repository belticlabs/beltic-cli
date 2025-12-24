//! API Key management commands
//!
//! Usage: beltic api-key [create|list|revoke]

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use console::style;
use serde::{Deserialize, Serialize};

use crate::config::{load_config, load_credentials};

use super::prompts::CommandPrompts;

#[derive(Args)]
pub struct ApiKeyArgs {
    #[command(subcommand)]
    pub command: ApiKeyCommand,
}

#[derive(Subcommand)]
pub enum ApiKeyCommand {
    /// Create a new API key
    Create(CreateApiKeyArgs),
    /// List API keys (requires authentication)
    List,
    /// Revoke an API key (requires authentication)
    Revoke(RevokeApiKeyArgs),
}

#[derive(Args)]
pub struct CreateApiKeyArgs {
    /// Developer ID to create the key for
    #[arg(long)]
    pub developer_id: Option<String>,

    /// Name for the API key
    #[arg(long)]
    pub name: Option<String>,

    /// Description for the API key
    #[arg(long)]
    pub description: Option<String>,

    /// Custom API URL
    #[arg(long)]
    pub api_url: Option<String>,

    /// Disable interactive mode
    #[arg(long)]
    pub non_interactive: bool,
}

#[derive(Args)]
pub struct RevokeApiKeyArgs {
    /// API key ID to revoke
    #[arg(long)]
    pub key_id: Option<String>,

    /// Custom API URL
    #[arg(long)]
    pub api_url: Option<String>,

    /// Disable interactive mode
    #[arg(long)]
    pub non_interactive: bool,
}

/// Response from POST /v1/api-keys
#[derive(Debug, Deserialize)]
struct CreateApiKeyResponse {
    data: ApiKeyData,
    meta: ApiKeyMeta,
}

#[derive(Debug, Deserialize)]
struct ApiKeyData {
    #[allow(dead_code)]
    id: String,
    #[serde(rename = "type")]
    _type: String,
    attributes: ApiKeyAttributes,
}

#[derive(Debug, Deserialize, Serialize)]
struct ApiKeyAttributes {
    key_id: String,
    key_prefix: String,
    name: String,
    description: Option<String>,
    status: String,
    created_at: String,
}

#[derive(Debug, Deserialize)]
struct ApiKeyMeta {
    secret: String,
}

pub fn run(args: ApiKeyArgs) -> Result<()> {
    match args.command {
        ApiKeyCommand::Create(args) => run_create(args),
        ApiKeyCommand::List => run_list(),
        ApiKeyCommand::Revoke(args) => run_revoke(args),
    }
}

fn run_create(args: CreateApiKeyArgs) -> Result<()> {
    let prompts = CommandPrompts::new();

    prompts.section_header("Create API Key")?;

    println!();
    println!(
        "{}",
        style("API keys should be created in the KYA web console.").yellow().bold()
    );
    println!();
    println!("To create an API key:");
    println!("  1. Log into the web console: https://console.beltic.app (or http://localhost:3001 for local)");
    println!("  2. Go to Settings -> API Keys");
    println!("  3. Click 'Create API Key'");
    println!("  4. Copy the secret (it's only shown once!)");
    println!();
    
    // Still allow CLI creation if user is authenticated
    let access_token = load_credentials()?;
    if access_token.is_none() {
        anyhow::bail!("You need to be authenticated to create API keys. Either:\n  1. Create your first key in the web console (recommended), or\n  2. Login first: beltic auth login");
    }

    let prompts = CommandPrompts::new();
    prompts.section_header("Create API Key via CLI")?;
    prompts.warn("Note: It's recommended to create API keys in the web console for better security.")?;
    println!();

    // Load config
    let config = load_config().unwrap_or_default();
    let api_url = args
        .api_url
        .as_ref()
        .unwrap_or(&config.api_url)
        .trim_end_matches('/')
        .to_string();

    // Get name
    let name = if let Some(n) = args.name {
        n
    } else if args.non_interactive {
        anyhow::bail!("--name is required in non-interactive mode");
    } else {
        prompts.prompt_string("API key name", Some("CLI Key"))?
    };

    // Get description
    let description = args.description;

    // Build request
    prompts.info("Creating API key...")?;

    let request_body = serde_json::json!({
        "data": {
            "type": "api-keys",
            "attributes": {
                "name": name,
                "description": description,
                "permissions": []
            }
        }
    });

    let access_token =
        access_token.context("Not logged in. Run 'beltic auth login' first.")?;

    let client = reqwest::blocking::Client::new();
    let response = client
        .post(format!("{}/v1/api-keys", api_url))
        .header("Authorization", format!("Bearer {}", access_token))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&request_body)
        .send()
        .context("failed to connect to KYA platform API")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().unwrap_or_default();

        if status.as_u16() == 404 {
            anyhow::bail!("Developer not found. Make sure the developer ID is correct.");
        }

        anyhow::bail!("API key creation failed with status {}: {}", status, body);
    }

    let result: CreateApiKeyResponse = response
        .json()
        .context("failed to parse API key response")?;

    // Print success with the secret
    println!();
    println!("{}", style("API key created successfully!").green().bold());
    println!();
    println!("  {} {}", style("Key ID:").dim(), result.data.attributes.key_id);
    println!("  {} {}", style("Name:").dim(), result.data.attributes.name);
    if let Some(desc) = &result.data.attributes.description {
        println!("  {} {}", style("Description:").dim(), desc);
    }
    println!();
    println!("{}", style("IMPORTANT: Save this secret now - it will not be shown again!").yellow().bold());
    println!();
    println!("  {} {}", style("Secret:").dim().bold(), style(&result.meta.secret).cyan().bold());
    println!();
    println!("{}", style("Next steps:").cyan().bold());
    println!("  1. Save the secret in a secure location");
    println!("  2. Use the key in your applications for API access");
    println!();

    Ok(())
}

fn run_list() -> Result<()> {
    anyhow::bail!("List command not yet implemented. Use the API directly.");
}

fn run_revoke(args: RevokeApiKeyArgs) -> Result<()> {
    // Load credentials to authenticate
    let access_token =
        load_credentials()?.context("Not logged in. Run 'beltic auth login' first.")?;

    let config = load_config().unwrap_or_default();
    let api_url = args
        .api_url
        .as_ref()
        .unwrap_or(&config.api_url)
        .trim_end_matches('/')
        .to_string();

    let key_id = args.key_id.context("--key-id is required")?;

    let client = reqwest::blocking::Client::new();
    let response = client
        .post(format!("{}/v1/api-keys/{}/revoke", api_url, key_id))
        .header("Authorization", format!("Bearer {}", access_token))
        .header("Accept", "application/json")
        .send()
        .context("failed to connect to KYA platform API")?;

    if !response.status().is_success() {
        let status = response.status();
        anyhow::bail!("Revocation failed with status {}", status);
    }

    println!("{}", style("API key revoked successfully").green().bold());
    Ok(())
}




