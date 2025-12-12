use super::monitor::{Observation, Severity, Violation};
use super::policy::SandboxPolicy;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Complete sandbox execution report
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxReport {
    /// Summary information
    pub summary: ReportSummary,

    /// Policy that was enforced
    pub policy: SandboxPolicy,

    /// Detected violations
    pub violations: Vec<Violation>,

    /// General observations
    pub observations: Vec<Observation>,

    /// Risk assessment
    pub risk_assessment: RiskAssessment,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportSummary {
    pub agent_name: String,
    pub agent_version: String,
    pub exit_code: i32,
    pub compliant: bool,
    pub total_violations: usize,
    pub total_observations: usize,
    pub timestamp: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskAssessment {
    pub risk_level: RiskLevel,
    pub risk_score: u8, // 0-100
    pub critical_violations: usize,
    pub high_violations: usize,
    pub medium_violations: usize,
    pub low_violations: usize,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl SandboxReport {
    pub fn new(
        policy: SandboxPolicy,
        violations: Vec<Violation>,
        observations: Vec<Observation>,
        exit_code: i32,
    ) -> Self {
        let risk_assessment = Self::calculate_risk(&violations);
        let compliant = violations.is_empty() && exit_code == 0;

        let summary = ReportSummary {
            agent_name: policy.agent_name.clone(),
            agent_version: policy.agent_version.clone(),
            exit_code,
            compliant,
            total_violations: violations.len(),
            total_observations: observations.len(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        Self {
            summary,
            policy,
            violations,
            observations,
            risk_assessment,
        }
    }

    /// Calculate risk assessment from violations
    fn calculate_risk(violations: &[Violation]) -> RiskAssessment {
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;

        for violation in violations {
            match violation.severity {
                Severity::Critical => critical += 1,
                Severity::High => high += 1,
                Severity::Medium => medium += 1,
                Severity::Low => low += 1,
            }
        }

        // Calculate risk score (0-100)
        let risk_score = (critical * 25 + high * 15 + medium * 8 + low * 3).min(100) as u8;

        // Determine overall risk level
        let risk_level = match risk_score {
            0..=20 => RiskLevel::Low,
            21..=50 => RiskLevel::Medium,
            51..=80 => RiskLevel::High,
            _ => RiskLevel::Critical,
        };

        // Generate recommendations
        let mut recommendations = Vec::new();

        if critical > 0 {
            recommendations.push(
                "CRITICAL: Do not deploy this agent. Address all critical violations immediately."
                    .to_string(),
            );
        }

        if high > 0 {
            recommendations
                .push("Review and fix all high-severity violations before deployment.".to_string());
        }

        if medium > 0 {
            recommendations.push(
                "Consider addressing medium-severity violations to improve security posture."
                    .to_string(),
            );
        }

        if violations.is_empty() {
            recommendations.push(
                "No violations detected. Agent appears to comply with declared policies."
                    .to_string(),
            );
            recommendations.push(
                "Consider running additional test scenarios to validate behavior.".to_string(),
            );
        }

        RiskAssessment {
            risk_level,
            risk_score,
            critical_violations: critical,
            high_violations: high,
            medium_violations: medium,
            low_violations: low,
            recommendations,
        }
    }

    /// Save report to JSON file
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(&self)?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Print summary to terminal
    pub fn print_summary(&self) {
        use console::style;

        println!();
        println!("Sandbox Report");
        println!("{}", "-".repeat(40));

        // Status
        let status_msg = if self.summary.compliant {
            style("COMPLIANT").green().bold()
        } else {
            style("NON-COMPLIANT").red().bold()
        };
        println!("Status: {}", status_msg);
        println!("Exit code: {}", self.summary.exit_code);

        // Risk assessment
        if !self.summary.compliant {
            let risk_msg = match self.risk_assessment.risk_level {
                RiskLevel::Low => style("LOW").green(),
                RiskLevel::Medium => style("MEDIUM").yellow(),
                RiskLevel::High => style("HIGH").yellow().bold(),
                RiskLevel::Critical => style("CRITICAL").red().bold(),
            };
            println!("Risk level: {}", risk_msg);
            println!("Risk score: {}/100", self.risk_assessment.risk_score);
        }
        println!();

        // Violations
        if !self.violations.is_empty() {
            println!("Violations ({}):", self.violations.len());
            for violation in &self.violations {
                let severity_label = match violation.severity {
                    Severity::Critical => style("CRITICAL").red().bold(),
                    Severity::High => style("HIGH").red(),
                    Severity::Medium => style("MEDIUM").yellow(),
                    Severity::Low => style("LOW").dim(),
                };
                println!("  [{}] {:?}", severity_label, violation.violation_type);
                println!("    {}", style(&violation.description).dim());
                if !violation.details.is_empty() {
                    println!("    {}", violation.details);
                }
            }
            println!();
        }

        // Summary stats
        println!("{}:", style("Summary").dim());
        println!("  Violations: {}", self.summary.total_violations);
        println!("  Observations: {}", self.summary.total_observations);
        println!("  Tools declared: {}", self.policy.tools.len());
        println!(
            "  Allowed domains: {}",
            self.policy.network.allowed_domains.len()
        );
        println!(
            "  Prohibited domains: {}",
            self.policy.network.prohibited_domains.len()
        );
    }
}
