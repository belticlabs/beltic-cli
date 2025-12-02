use anyhow::Result;
use beltic::commands::{
    self, credential_id::CredentialIdArgs, dev_init::DevInitArgs, directory::DirectoryArgs,
    fingerprint::FingerprintArgs, http_sign::HttpSignArgs, init::InitArgs, keygen::KeygenArgs,
    schema::SchemaArgs, sign::SignArgs, verify::VerifyArgs,
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
    /// Initialize a new agent manifest or credential
    Init(InitArgs),
    /// Create a self-attested developer credential
    DevInit(DevInitArgs),
    /// Update the code fingerprint in an existing manifest
    Fingerprint(FingerprintArgs),
    /// Generate a new keypair
    Keygen(KeygenArgs),
    /// Sign a JSON payload into a JWS token
    Sign(SignArgs),
    /// Verify a JWS token and print its payload
    Verify(VerifyArgs),
    /// Sign an HTTP request (Web Bot Auth)
    HttpSign(HttpSignArgs),
    /// Manage HTTP Message Signatures key directories
    Directory(DirectoryArgs),
    /// Extract credential ID from a credential JSON or JWT file
    CredentialId(CredentialIdArgs),
    /// Manage schema caching and updates
    Schema(SchemaArgs),
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Init(args) => commands::init::run(args)?,
        Command::DevInit(args) => commands::dev_init::run(args)?,
        Command::Fingerprint(args) => commands::fingerprint::run(args)?,
        Command::Keygen(args) => commands::keygen::run(args)?,
        Command::Sign(args) => commands::sign::run(args)?,
        Command::Verify(args) => commands::verify::run(args)?,
        Command::HttpSign(args) => commands::http_sign::run(args)?,
        Command::Directory(args) => commands::directory::run(args)?,
        Command::CredentialId(args) => commands::credential_id::run(args)?,
        Command::Schema(args) => commands::schema::run(args)?,
    };

    Ok(())
}
