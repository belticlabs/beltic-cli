use std::{fs, io::Write, path::PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use anyhow::{Context, Result};
use clap::Args;
use console::style;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use p256::ecdsa::SigningKey as P256SigningKey;
use pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rand_core::OsRng;
use zeroize::Zeroizing;

use crate::crypto::{parse_signature_alg, SignatureAlg};

use super::discovery::{ensure_beltic_dir, ensure_private_keys_gitignored};
use super::prompts::{
    default_private_key_path, default_public_key_path, generate_key_name, CommandPrompts,
};

#[derive(Args)]
pub struct KeygenArgs {
    /// Algorithm to generate (default: EdDSA, interactive if omitted)
    #[arg(long, value_parser = parse_signature_alg)]
    pub alg: Option<SignatureAlg>,

    /// Path to write the private key (PEM). Defaults to ./.beltic/{name}-private.pem
    #[arg(long)]
    pub out: Option<PathBuf>,

    /// Path to write the public key (PEM). Defaults to ./.beltic/{name}-public.pem
    #[arg(long = "pub")]
    pub pub_out: Option<PathBuf>,

    /// Custom name for the keypair (default: {alg}-{date})
    #[arg(long)]
    pub name: Option<String>,

    /// Disable interactive mode (use defaults without prompting)
    #[arg(long)]
    pub non_interactive: bool,
}

pub fn run(args: KeygenArgs) -> Result<()> {
    // Determine if we need interactive mode
    let needs_interactive = args.out.is_none() && !args.non_interactive;

    if needs_interactive {
        run_interactive(args)
    } else {
        run_non_interactive(args)
    }
}

fn run_interactive(args: KeygenArgs) -> Result<()> {
    let prompts = CommandPrompts::new();

    prompts.section_header("Beltic Key Generator")?;

    // 1. Algorithm selection
    let alg = if let Some(alg) = args.alg {
        alg
    } else {
        prompts.prompt_algorithm(Some(SignatureAlg::EdDsa))?
    };

    // 2. Key name (default: algorithm-date)
    let default_name = generate_key_name(alg);
    let name = if let Some(name) = args.name {
        name
    } else {
        prompts.prompt_string("Key name", Some(&default_name))?
    };

    // 3. Generate paths
    let private_path = args.out.unwrap_or_else(|| default_private_key_path(&name));
    let public_path = args
        .pub_out
        .unwrap_or_else(|| default_public_key_path(&name));

    // 4. Check for existing files
    if private_path.exists() || public_path.exists() {
        let overwrite = prompts.prompt_confirm(
            &format!(
                "Key files already exist. Overwrite?\n  {}\n  {}",
                private_path.display(),
                public_path.display()
            ),
            false,
        )?;

        if !overwrite {
            prompts.warn("Aborted.")?;
            return Ok(());
        }
    }

    // 5. Ensure .beltic directory exists
    if private_path.starts_with(".beltic") || public_path.starts_with(".beltic") {
        ensure_beltic_dir()?;
    }

    // 6. Generate and write keys
    let (private_pem, public_pem) = generate_keypair(alg)?;

    write_private_key(&private_path, private_pem.as_bytes())?;
    write_file(&public_path, public_pem.as_bytes())
        .with_context(|| format!("failed to write public key to {}", public_path.display()))?;

    // 7. Auto-add to .gitignore
    let gitignore_updated = ensure_private_keys_gitignored()?;

    // 8. Print success message
    println!();
    println!(
        "{}",
        style("Key pair generated successfully!").green().bold()
    );
    println!();
    println!("  {} {}", style("Algorithm:").dim(), alg);
    println!(
        "  {} {}",
        style("Private key:").dim(),
        private_path.display()
    );
    println!("  {} {}", style("Public key:").dim(), public_path.display());

    if gitignore_updated {
        println!();
        println!(
            "{}",
            style("Added .beltic/*-private.pem to .gitignore").dim()
        );
    }

    println!();
    println!("{}", style("Next steps:").cyan().bold());
    println!(
        "  Sign a credential:  beltic sign --payload credential.json --key {}",
        private_path.display()
    );
    println!(
        "  Verify a token:     beltic verify --token token.jwt --key {}",
        public_path.display()
    );

    Ok(())
}

fn run_non_interactive(args: KeygenArgs) -> Result<()> {
    let alg = args.alg.unwrap_or(SignatureAlg::EdDsa);

    // Generate default name if not provided
    let name = args.name.unwrap_or_else(|| generate_key_name(alg));

    // Use provided paths or defaults
    let private_path = args.out.unwrap_or_else(|| default_private_key_path(&name));
    let public_path = args
        .pub_out
        .unwrap_or_else(|| default_public_key_path(&name));

    // Ensure .beltic directory exists
    if private_path.starts_with(".beltic") || public_path.starts_with(".beltic") {
        ensure_beltic_dir()?;
    }

    // Generate and write keys
    let (private_pem, public_pem) = generate_keypair(alg)?;

    write_private_key(&private_path, private_pem.as_bytes())?;
    write_file(&public_path, public_pem.as_bytes())
        .with_context(|| format!("failed to write public key to {}", public_path.display()))?;

    // Auto-add to .gitignore
    let _ = ensure_private_keys_gitignored();

    println!(
        "Generated {} keypair\n  private: {}\n  public: {}",
        alg,
        private_path.display(),
        public_path.display()
    );

    Ok(())
}

fn generate_keypair(alg: SignatureAlg) -> Result<(Zeroizing<String>, String)> {
    match alg {
        SignatureAlg::Es256 => {
            let signing_key = P256SigningKey::random(&mut OsRng);
            let verifying_key = signing_key.verifying_key();
            let private_pem = Zeroizing::new(
                signing_key
                    .to_pkcs8_pem(LineEnding::LF)
                    .context("failed to encode ES256 private key to PKCS#8 PEM")?
                    .to_string(),
            );
            let public_pem = verifying_key
                .to_public_key_pem(LineEnding::LF)
                .context("failed to encode ES256 public key to PEM")?;

            Ok((private_pem, public_pem))
        }
        SignatureAlg::EdDsa => {
            let signing_key = Ed25519SigningKey::generate(&mut OsRng);
            let verifying_key = signing_key.verifying_key();
            let private_pem = Zeroizing::new(
                signing_key
                    .to_pkcs8_pem(LineEnding::LF)
                    .context("failed to encode Ed25519 private key to PKCS#8 PEM")?
                    .to_string(),
            );
            let public_pem = verifying_key
                .to_public_key_pem(LineEnding::LF)
                .context("failed to encode Ed25519 public key to PEM")?;

            Ok((private_pem, public_pem))
        }
    }
}

fn write_file(path: &PathBuf, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
        }
    }

    fs::write(path, contents).map_err(Into::into)
}

/// Write private key with restricted permissions (0o600 on Unix)
fn write_private_key(path: &PathBuf, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
        }
    }

    #[cfg(unix)]
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600) // Owner read/write only
            .open(path)
            .with_context(|| format!("failed to create private key file {}", path.display()))?;
        file.write_all(contents)
            .with_context(|| format!("failed to write private key to {}", path.display()))?;
        return Ok(());
    }

    #[cfg(not(unix))]
    {
        fs::write(path, contents)
            .with_context(|| format!("failed to write private key to {}", path.display()))?;
        Ok(())
    }
}
