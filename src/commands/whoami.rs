//! Whoami command - display current authenticated developer info
//!
//! Usage: beltic whoami [--json]

use anyhow::{Context, Result};
use clap::Args;
use console::style;
use serde::{Deserialize, Serialize};

use crate::config::{load_config, load_credentials};

#[derive(Args)]
pub struct WhoamiArgs {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

/// Response from GET /v1/developers/me
#[derive(Debug, Deserialize, Serialize)]
struct DeveloperMeResponse {
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
    kyb_tier: Option<String>,
    verification_status: Option<String>,
    default_org: Option<String>,
    created_at: Option<String>,
}

pub fn run(args: WhoamiArgs) -> Result<()> {
    // Load credentials
    let api_key = load_credentials()?
        .context("Not logged in. Run 'beltic login' first.")?;

    // Load config
    let config = load_config().unwrap_or_default();

    // Call API
    let client = reqwest::blocking::Client::new();
    let response = client
        .get(format!("{}/v1/developers/me", config.api_url.trim_end_matches('/')))
        .header("X-Api-Key", &api_key)
        .header("Accept", "application/json")
        .send()
        .context("failed to connect to Beltic API")?;

    if !response.status().is_success() {
        let status = response.status();

        if status.as_u16() == 401 || status.as_u16() == 403 {
            anyhow::bail!(
                "Session expired or invalid. Run 'beltic login' to re-authenticate."
            );
        }

        anyhow::bail!("API request failed with status {}", status);
    }

    let developer: DeveloperMeResponse = response
        .json()
        .context("failed to parse developer response")?;

    if args.json {
        // Output raw JSON
        println!("{}", serde_json::to_string_pretty(&developer.data)?);
        return Ok(());
    }

    // Pretty print
    println!();
    println!("{}", style("Current Developer").cyan().bold());
    println!("{}", style("-".repeat(40)).dim());
    println!();

    println!(
        "  {} {}",
        style("Developer ID:").dim(),
        developer.data.id
    );

    if let Some(name) = &developer.data.attributes.legal_name {
        println!("  {} {}", style("Legal Name:").dim(), name);
    }

    if let Some(tier) = &developer.data.attributes.kyb_tier {
        let tier_styled = match tier.as_str() {
            "tier_3" => style(format!("{} (Full)", tier)).green(),
            "tier_2" => style(format!("{} (Enhanced)", tier)).cyan(),
            "tier_1" => style(format!("{} (Basic)", tier)).yellow(),
            "tier_0" => style(format!("{} (Unverified)", tier)).dim(),
            _ => style(tier.clone()).dim(),
        };
        println!("  {} {}", style("KYB Tier:").dim(), tier_styled);
    }

    if let Some(status) = &developer.data.attributes.verification_status {
        let status_styled = match status.as_str() {
            "verified" | "approved" => style("Verified").green(),
            "pending" => style("Pending").yellow(),
            "rejected" => style("Rejected").red(),
            _ => style(status.as_str()).dim(),
        };
        println!("  {} {}", style("Verified:").dim(), status_styled);
    }

    if let Some(org) = &developer.data.attributes.default_org {
        println!("  {} {}", style("Organization:").dim(), org);
    }

    if let Some(created) = &developer.data.attributes.created_at {
        println!("  {} {}", style("Created:").dim(), created);
    }

    println!();

    Ok(())
}
