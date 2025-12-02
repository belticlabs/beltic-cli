use anyhow::Result;
use clap::Parser;
use uuid::Uuid;

use crate::manifest::{init_manifest, InitOptions};

#[derive(Parser, Debug)]
pub struct InitArgs {
    /// Output path for the manifest (default: ./agent-manifest.json or ./agent-credential.json)
    #[arg(short, long)]
    output: Option<String>,

    /// Path to .beltic.yaml configuration file
    #[arg(short, long)]
    config: Option<String>,

    /// Include file patterns (can be specified multiple times)
    #[arg(short, long)]
    include: Vec<String>,

    /// Exclude file patterns (can be specified multiple times)
    #[arg(short = 'x', long)]
    exclude: Vec<String>,

    /// Deployment type (standalone, monorepo, embedded, plugin, serverless)
    #[arg(short = 't', long)]
    r#type: Option<String>,

    /// Developer credential ID (UUID)
    #[arg(short, long)]
    developer_id: Option<String>,

    /// Overwrite existing manifest
    #[arg(short, long)]
    force: bool,

    /// Disable interactive mode (non-interactive by default is false, so interactive is default)
    #[arg(long = "non-interactive")]
    non_interactive: bool,

    /// Skip validation of generated manifest
    #[arg(long = "no-validate")]
    no_validate: bool,

    /// Generate schema-compliant AgentCredential instead of AgentManifest
    /// Use this to create a credential ready for signing
    #[arg(long)]
    credential: bool,

    /// Issuer DID for self-signed credentials (auto-generated if not provided)
    #[arg(long)]
    issuer_did: Option<String>,
}

pub fn run(args: InitArgs) -> Result<()> {
    // Parse developer ID if provided
    let developer_id = if let Some(id_str) = args.developer_id {
        Some(
            Uuid::parse_str(&id_str)
                .map_err(|e| anyhow::anyhow!("Invalid developer ID UUID: {}", e))?,
        )
    } else {
        None
    };

    // Validate deployment type if provided
    if let Some(ref dtype) = args.r#type {
        let valid_types = ["standalone", "monorepo", "embedded", "plugin", "serverless"];
        if !valid_types.contains(&dtype.as_str()) {
            anyhow::bail!(
                "Invalid deployment type '{}'. Must be one of: {}",
                dtype,
                valid_types.join(", ")
            );
        }
    }

    let options = InitOptions {
        output_path: args.output,
        config_path: args.config,
        include_patterns: if args.include.is_empty() {
            None
        } else {
            Some(args.include)
        },
        exclude_patterns: if args.exclude.is_empty() {
            None
        } else {
            Some(args.exclude)
        },
        deployment_type: args.r#type,
        developer_id,
        force: args.force,
        interactive: !args.non_interactive,  // Interactive by default
        validate: !args.no_validate,         // Validate by default
        credential: args.credential,         // Schema-compliant credential output
        issuer_did: args.issuer_did,
    };

    init_manifest(&options)
}