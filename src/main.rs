use anyhow::Result;
use beltic::commands::{
    self, fingerprint::FingerprintArgs, init::InitArgs, keygen::KeygenArgs, sign::SignArgs,
    verify::VerifyArgs,
};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "beltic",
    version,
    about = "Beltic CLI for signing and verifying credentials"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize a new agent manifest
    Init(InitArgs),
    /// Update the code fingerprint in an existing manifest
    Fingerprint(FingerprintArgs),
    /// Generate a new keypair
    Keygen(KeygenArgs),
    /// Sign a JSON payload into a JWS token
    Sign(SignArgs),
    /// Verify a JWS token and print its payload
    Verify(VerifyArgs),
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Init(args) => commands::init::run(args)?,
        Command::Fingerprint(args) => commands::fingerprint::run(args)?,
        Command::Keygen(args) => commands::keygen::run(args)?,
        Command::Sign(args) => commands::sign::run(args)?,
        Command::Verify(args) => commands::verify::run(args)?,
    };

    Ok(())
}
