//! Schema management commands
//!
//! Provides CLI commands for managing schema caching and updates.

use anyhow::Result;
use clap::{Args, Subcommand};
use console::style;

use crate::schema::{self, SchemaType};

#[derive(Args)]
pub struct SchemaArgs {
    #[command(subcommand)]
    pub command: SchemaCommand,
}

#[derive(Subcommand)]
pub enum SchemaCommand {
    /// Show schema cache status
    Status,
    /// Refresh schemas from GitHub
    Refresh {
        /// Refresh only agent schema
        #[arg(long)]
        agent: bool,
        /// Refresh only developer schema
        #[arg(long)]
        developer: bool,
    },
    /// Clear schema cache
    Clear,
}

pub fn run(args: SchemaArgs) -> Result<()> {
    match args.command {
        SchemaCommand::Status => run_status(),
        SchemaCommand::Refresh { agent, developer } => run_refresh(agent, developer),
        SchemaCommand::Clear => run_clear(),
    }
}

fn run_status() -> Result<()> {
    println!("{}", style("Schema Cache Status").cyan().bold());
    println!();

    print_cache_status("Agent", SchemaType::Agent);
    print_cache_status("Developer", SchemaType::Developer);

    Ok(())
}

fn print_cache_status(name: &str, schema_type: SchemaType) {
    match schema::cache_status(schema_type) {
        Some(status) => {
            println!("  {}:", style(name).bold());
            println!("    Path: {}", status.path.display());
            if status.exists {
                let age_str = format_duration(status.age);
                let valid_icon = if status.valid {
                    style("✓").green()
                } else {
                    style("⚠").yellow()
                };
                println!("    Status: {} Cached ({})", valid_icon, age_str);
                if !status.valid {
                    println!(
                        "    {}",
                        style("  Cache expired, will refresh on next use").dim()
                    );
                }
            } else {
                println!("    Status: {} Not cached", style("○").dim());
            }
        }
        None => {
            println!("  {}:", style(name).bold());
            println!(
                "    Status: {} Unable to determine cache location",
                style("?").yellow()
            );
        }
    }
    println!();
}

fn format_duration(duration: Option<std::time::Duration>) -> String {
    match duration {
        Some(d) => {
            let secs = d.as_secs();
            if secs < 60 {
                format!("{}s ago", secs)
            } else if secs < 3600 {
                format!("{}m ago", secs / 60)
            } else if secs < 86400 {
                format!("{}h ago", secs / 3600)
            } else {
                format!("{}d ago", secs / 86400)
            }
        }
        None => "unknown".to_string(),
    }
}

fn run_refresh(agent_only: bool, developer_only: bool) -> Result<()> {
    let refresh_both = !agent_only && !developer_only;

    if refresh_both || agent_only {
        print!("Refreshing agent schema... ");
        match schema::refresh_schema(SchemaType::Agent) {
            Ok(_) => println!("{}", style("done").green()),
            Err(e) => println!("{} ({})", style("failed").red(), e),
        }
    }

    if refresh_both || developer_only {
        print!("Refreshing developer schema... ");
        match schema::refresh_schema(SchemaType::Developer) {
            Ok(_) => println!("{}", style("done").green()),
            Err(e) => println!("{} ({})", style("failed").red(), e),
        }
    }

    Ok(())
}

fn run_clear() -> Result<()> {
    print!("Clearing schema cache... ");
    match schema::clear_cache() {
        Ok(_) => {
            println!("{}", style("done").green());
            println!();
            println!("{}", style("Schemas will be re-fetched on next use.").dim());
        }
        Err(e) => {
            println!("{} ({})", style("failed").red(), e);
        }
    }

    Ok(())
}
