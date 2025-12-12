//! Login command - authenticate with the Beltic platform
//!
//! Usage: beltic login [--api-url <url>]

use anyhow::{Context, Result};
use clap::Args;
use console::style;
use dialoguer::{theme::ColorfulTheme, Password};
use serde::Deserialize;

use crate::config::{load_config, save_config, save_credentials};

use super::prompts::CommandPrompts;

#[derive(Args)]
pub struct LoginArgs {
    /// Custom API URL (default: https://api.beltic.dev)
    #[arg(long)]
    pub api_url: Option<String>,

    /// API key (if not provided, will prompt interactively)
    #[arg(long)]
    pub api_key: Option<String>,

    /// Disable interactive mode
    #[arg(long)]
    pub non_interactive: bool,
}

/// Response from GET /v1/developers/me
#[derive(Debug, Deserialize)]
struct DeveloperMeResponse {
    data: DeveloperData,
}

#[derive(Debug, Deserialize)]
struct DeveloperData {
    id: String,
    attributes: DeveloperAttributes,
}

#[derive(Debug, Deserialize)]
struct DeveloperAttributes {
    legal_name: Option<String>,
    kyb_tier: Option<String>,
    verification_status: Option<String>,
}

pub fn run(args: LoginArgs) -> Result<()> {
    let prompts = CommandPrompts::new();

    prompts.section_header("Beltic Login")?;

    // Load existing config
    let mut config = load_config().unwrap_or_default();

    // Determine API URL
    let api_url = args
        .api_url
        .as_ref()
        .unwrap_or(&config.api_url)
        .trim_end_matches('/')
        .to_string();

    // Get API key (prompt or from args/env)
    let api_key = if let Some(key) = args.api_key {
        key
    } else if args.non_interactive {
        anyhow::bail!("API key required in non-interactive mode. Use --api-key or set BELTIC_API_KEY");
    } else {
        prompts.info("Enter your API key from the Beltic Console")?;
        prompts.info("(https://console.beltic.dev/settings)")?;
        println!();

        Password::with_theme(&ColorfulTheme::default())
            .with_prompt("API Key")
            .interact()
            .context("failed to read API key")?
    };

    // Validate the API key by calling /v1/developers/me
    prompts.info("Validating API key...")?;

    let client = reqwest::blocking::Client::new();
    let response = client
        .get(format!("{}/v1/developers/me", api_url))
        .header("X-Api-Key", &api_key)
        .header("Accept", "application/json")
        .send()
        .context("failed to connect to Beltic API")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().unwrap_or_default();

        if status.as_u16() == 401 || status.as_u16() == 403 {
            anyhow::bail!("Invalid API key. Please check your key and try again.");
        }

        anyhow::bail!(
            "API request failed with status {}: {}",
            status,
            body
        );
    }

    let developer: DeveloperMeResponse = response
        .json()
        .context("failed to parse developer response")?;

    // Save credentials
    save_credentials(&api_key).context("failed to save credentials")?;

    // Update and save config
    config.api_url = api_url;
    config.current_developer_id = Some(developer.data.id.clone());
    save_config(&config).context("failed to save config")?;

    // Print success
    println!();
    println!(
        "{}",
        style("Login successful!").green().bold()
    );
    println!();
    println!(
        "  {} {}",
        style("Developer ID:").dim(),
        developer.data.id
    );

    if let Some(name) = &developer.data.attributes.legal_name {
        println!("  {} {}", style("Name:").dim(), name);
    }

    if let Some(tier) = &developer.data.attributes.kyb_tier {
        println!("  {} {}", style("KYB Tier:").dim(), tier);
    }

    if let Some(status) = &developer.data.attributes.verification_status {
        let status_styled = match status.as_str() {
            "verified" => style(status).green(),
            "pending" => style(status).yellow(),
            _ => style(status).dim(),
        };
        println!("  {} {}", style("Status:").dim(), status_styled);
    }

    println!();
    println!("{}", style("Next steps:").cyan().bold());
    println!("  Check your identity:  beltic whoami");
    println!("  Create an agent:      beltic agents create");

    Ok(())
}
