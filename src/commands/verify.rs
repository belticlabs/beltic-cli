use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use clap::Args;

use crate::crypto::verify_jws;

#[derive(Args)]
pub struct VerifyArgs {
    /// Path to the public key (PEM)
    #[arg(long)]
    pub key: PathBuf,

    /// File containing the JWS token to verify
    #[arg(long)]
    pub token: PathBuf,
}

pub fn run(args: VerifyArgs) -> Result<()> {
    let token = fs::read_to_string(&args.token)
        .with_context(|| format!("failed to read token file {}", args.token.display()))?;

    match verify_jws(token.trim(), &args.key) {
        Ok(verified) => {
            println!("VALID");
            let pretty = serde_json::to_string_pretty(&verified.payload)?;
            println!("{pretty}");
            Ok(())
        }
        Err(err) => {
            eprintln!("INVALID: {err}");
            std::process::exit(1);
        }
    }
}
