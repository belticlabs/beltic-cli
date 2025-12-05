use anyhow::{Context, Result};
use clap::Args;
use console::style;
use std::path::PathBuf;

use crate::manifest::schema::AgentManifest;
use crate::sandbox::{extract_policy, SandboxMonitor, SandboxReport};

#[derive(Args)]
pub struct SandboxArgs {
    /// Path to agent manifest
    #[arg(short, long, default_value = "./agent-manifest.json")]
    pub manifest: PathBuf,

    /// Command to run the agent (e.g., "node index.js", "python agent.py")
    #[arg(short, long)]
    pub command: String,

    /// Output path for sandbox report
    #[arg(short, long, default_value = "./sandbox-report.json")]
    pub output: PathBuf,

    /// Timeout in seconds (optional)
    #[arg(short, long)]
    pub timeout: Option<u64>,

    /// Show detailed policy information
    #[arg(long)]
    pub show_policy: bool,
}

pub fn run(args: SandboxArgs) -> Result<()> {
    // Load manifest
    let manifest_content = std::fs::read_to_string(&args.manifest)
        .with_context(|| format!("failed to read manifest at {}", args.manifest.display()))?;
    let manifest: AgentManifest =
        serde_json::from_str(&manifest_content).context("failed to parse manifest JSON")?;

    // Extract policy from manifest
    let policy = extract_policy(&manifest)?;

    eprintln!("[info] Testing agent: {} v{}", manifest.agent_name, manifest.agent_version);
    eprintln!("[info] Policy: {} tools, {} file paths, {} prohibited domains",
              policy.tools.len(),
              policy.filesystem.allowed_read_paths.len(),
              policy.network.prohibited_domains.len());

    if args.show_policy {
        print_detailed_policy(&policy);
    }

    // Run agent and monitor
    let mut monitor = SandboxMonitor::new(policy.clone());
    let exit_code = monitor.run_agent(&args.command, args.timeout)?;

    // Generate compliance report
    let violations = monitor.get_violations().to_vec();
    let observations = monitor.get_observations().to_vec();
    let report = SandboxReport::new(policy, violations, observations, exit_code);

    report.save(&args.output)?;
    report.print_summary();

    println!("\nWrote sandbox report to {}", args.output.display());

    if report.summary.compliant {
        println!("{}", style("Agent is compliant with declared policies").green().bold());
        Ok(())
    } else {
        println!("{}", style("Agent has policy violations").red().bold());
        std::process::exit(1);
    }
}

fn print_detailed_policy(policy: &crate::sandbox::SandboxPolicy) {
    println!();
    println!("{}", style("Security Policy").bold().cyan());
    println!("{}", style("-".repeat(40)).dim());

    println!("\nFilesystem:");
    println!("  Allowed paths ({})", policy.filesystem.allowed_read_paths.len());
    for (i, path) in policy.filesystem.allowed_read_paths.iter().take(5).enumerate() {
        println!("    {}", style(path).dim());
        if i == 4 && policy.filesystem.allowed_read_paths.len() > 5 {
            println!("    {} more...", policy.filesystem.allowed_read_paths.len() - 5);
            break;
        }
    }

    println!("\nNetwork:");
    println!("  Allowed domains:");
    for domain in &policy.network.allowed_domains {
        println!("    {}", style(domain).dim());
    }
    
    if !policy.network.prohibited_domains.is_empty() {
        println!("  Prohibited domains:");
        for domain in &policy.network.prohibited_domains {
            println!("    {}", style(domain).red());
        }
    }

    if !policy.network.external_api_allowed {
        println!("  {}", style("(external APIs blocked)").dim());
    }
    
    if !policy.tools.is_empty() {
        println!("\nTools ({}):", policy.tools.len());
        for tool in &policy.tools {
            println!("  {} - {}", tool.tool_name, style(&tool.risk_category).dim());
        }
    }

    println!("\nData handling:");
    println!("  Categories: {}", policy.data_restrictions.allowed_data_categories.join(", "));
    println!("  PII detection: {}", if policy.data_restrictions.pii_detection_required { "enabled" } else { "disabled" });
    println!("  Retention: {}", policy.data_restrictions.max_retention_period);

    if !policy.use_cases.prohibited.is_empty() {
        println!("\nProhibited use cases:");
        for (i, use_case) in policy.use_cases.prohibited.iter().enumerate() {
            if i < 3 {
                println!("  {}", style(use_case).yellow());
            } else if i == 3 {
                println!("  {} more...", policy.use_cases.prohibited.len() - 3);
                break;
            }
        }
    }
    println!();
}
