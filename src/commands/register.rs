//! Register command - create a new developer account
//!
//! Usage: beltic register [options]

use anyhow::{Context, Result};
use clap::Args;
use console::style;
use serde::{Deserialize, Serialize};

use crate::config::{load_config, save_config};

use super::prompts::CommandPrompts;

#[derive(Args)]
pub struct RegisterArgs {
    /// Legal name of the developer or organization
    #[arg(long)]
    pub name: Option<String>,

    /// Entity type (individual|corporation|limited_liability_company|sole_proprietorship|partnership|nonprofit|government_agency)
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

    /// Custom Console URL (default: https://console.beltic.app)
    #[arg(long)]
    pub api_url: Option<String>,

    /// Disable interactive mode
    #[arg(long)]
    pub non_interactive: bool,
}

/// Response from POST /api/developers
#[derive(Debug, Deserialize)]
struct CreateDeveloperResponse {
    data: DeveloperData,
}

#[derive(Debug, Deserialize, Serialize)]
struct DeveloperData {
    id: String,
    #[serde(rename = "type")]
    _type: String,
    attributes: DeveloperAttributes,
}

#[derive(Debug, Deserialize, Serialize)]
struct DeveloperAttributes {
    legal_name: Option<String>,
    entity_type: Option<String>,
    business_email: Option<String>,
    website: Option<String>,
    verification_status: Option<String>,
}

pub fn run(args: RegisterArgs) -> Result<()> {
    let prompts = CommandPrompts::new();

    prompts.section_header("KYA Platform - Developer Registration")?;

    // Load existing config
    let mut config = load_config().unwrap_or_default();

    // Determine API URL
    let api_url = args
        .api_url
        .as_ref()
        .unwrap_or(&config.api_url)
        .trim_end_matches('/')
        .to_string();

    // Collect required fields
    let name = if let Some(n) = args.name {
        n
    } else if args.non_interactive {
        anyhow::bail!("--name is required in non-interactive mode");
    } else {
        prompts.prompt_string("Legal name (individual or organization)", None)?
    };

    let entity_type = if let Some(et) = args.entity_type {
        et
    } else if args.non_interactive {
        anyhow::bail!("--entity-type is required in non-interactive mode");
    } else {
        let options = vec![
            "individual",
            "corporation",
            "limited_liability_company",
            "sole_proprietorship",
            "partnership",
            "nonprofit",
            "government_agency",
        ];
        let idx = prompts.prompt_select("Entity type", &options, 0)?;
        options[idx].to_string()
    };

    let country = if let Some(c) = args.country {
        c
    } else if args.non_interactive {
        anyhow::bail!("--country is required in non-interactive mode");
    } else {
        prompts.prompt_string("Country code (ISO 3166-1 alpha-2, e.g., US, GB, DE)", Some("US"))?
    };

    let website = if let Some(w) = args.website {
        w
    } else if args.non_interactive {
        anyhow::bail!("--website is required in non-interactive mode");
    } else {
        prompts.prompt_string("Website URL", None)?
    };

    let email = if let Some(e) = args.email {
        e
    } else if args.non_interactive {
        anyhow::bail!("--email is required in non-interactive mode");
    } else {
        prompts.prompt_string("Business email address", None)?
    };

    // Build request
    prompts.info("Creating developer account...")?;

    let request_body = serde_json::json!({
        "data": {
            "type": "developers",
            "attributes": {
                "legal_name": name,
                "entity_type": entity_type,
                "incorporation_jurisdiction": country,
                "website": website,
                "business_email": email,
                "tax_id_exists": false, // Default, can be updated later
            }
        }
    });

    let client = reqwest::blocking::Client::new();
    let response = client
        .post(format!("{}/api/developers", api_url))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&request_body)
        .send()
        .context("failed to connect to console API")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().unwrap_or_default();

        if status.as_u16() == 409 {
            anyhow::bail!("Developer with this email already exists. Use 'beltic auth login' if you already have an account.");
        }

        anyhow::bail!("Registration failed with status {}: {}", status, body);
    }

    let developer: CreateDeveloperResponse = response
        .json()
        .context("failed to parse developer response")?;

    // Update and save config
    config.api_url = api_url.clone();
    config.current_developer_id = Some(developer.data.id.clone());
    save_config(&config).context("failed to save config")?;

    // Print success
    println!();
    println!("{}", style("Registration successful!").green().bold());
    println!();
    println!("  {} {}", style("Developer ID:").dim(), developer.data.id);

    if let Some(name) = &developer.data.attributes.legal_name {
        println!("  {} {}", style("Name:").dim(), name);
    }

    if let Some(email) = &developer.data.attributes.business_email {
        println!("  {} {}", style("Email:").dim(), email);
    }

    println!();
    println!("{}", style("Next steps:").cyan().bold());
    println!("  1. Login to your account:  beltic auth login");
    println!("  2. Check your identity:    beltic whoami");
    println!();

    Ok(())
}




