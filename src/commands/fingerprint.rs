use anyhow::Result;
use clap::Parser;

use crate::manifest::{update_fingerprint, verify_fingerprint};

#[derive(Parser, Debug)]
pub struct FingerprintArgs {
    /// Path to agent manifest (default: ./agent-manifest.json)
    #[arg(short, long)]
    manifest: Option<String>,

    /// Path to .beltic.yaml configuration file (auto-detected if not specified)
    #[arg(short, long)]
    config: Option<String>,

    /// Include dependency fingerprints
    #[arg(short, long)]
    deps: bool,

    /// Verify fingerprint without updating
    #[arg(short, long)]
    verify: bool,
}

pub fn run(args: FingerprintArgs) -> Result<()> {
    if args.verify {
        return verify_fingerprint(args.manifest.as_deref());
    }

    update_fingerprint(args.manifest.as_deref())
}
