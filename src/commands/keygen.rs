use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use clap::Args;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use p256::ecdsa::SigningKey as P256SigningKey;
use pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rand_core::OsRng;
use zeroize::Zeroizing;

use crate::crypto::{parse_signature_alg, SignatureAlg};

#[derive(Args)]
pub struct KeygenArgs {
    /// Algorithm to generate (default: EdDSA)
    #[arg(long, default_value = "EdDSA", value_parser = parse_signature_alg)]
    pub alg: SignatureAlg,

    /// Path to write the private key (PEM)
    #[arg(long)]
    pub out: PathBuf,

    /// Path to write the public key (PEM)
    #[arg(long = "pub")]
    pub pub_out: PathBuf,
}

pub fn run(args: KeygenArgs) -> Result<()> {
    let (private_pem, public_pem) = generate_keypair(args.alg)?;

    write_file(&args.out, private_pem.as_bytes())
        .with_context(|| format!("failed to write private key to {}", args.out.display()))?;
    write_file(&args.pub_out, public_pem.as_bytes())
        .with_context(|| format!("failed to write public key to {}", args.pub_out.display()))?;

    println!(
        "Generated {} keypair\n  private: {}\n  public: {}",
        args.alg,
        args.out.display(),
        args.pub_out.display()
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
