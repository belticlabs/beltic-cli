use super::policy::SandboxPolicy;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Monitors agent execution and tracks policy violations
pub struct SandboxMonitor {
    policy: SandboxPolicy,
    violations: Vec<Violation>,
    observations: Vec<Observation>,
}

/// Represents a policy violation detected during agent execution
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Violation {
    pub timestamp: String,
    pub violation_type: ViolationType,
    pub severity: Severity,
    pub description: String,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationType {
    FileAccessDenied,
    NetworkAccessDenied,
    UnauthorizedTool,
    DataPolicyViolation,
    HumanOversightRequired,
    ProhibitedUseCase,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Represents an observation about agent behavior (not necessarily a violation)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Observation {
    pub timestamp: String,
    pub observation_type: String,
    pub description: String,
}

impl SandboxMonitor {
    pub fn new(policy: SandboxPolicy) -> Self {
        Self {
            policy,
            violations: Vec::new(),
            observations: Vec::new(),
        }
    }

    /// Run the agent command and monitor its execution
    pub fn run_agent(&mut self, command: &str, timeout_secs: Option<u64>) -> Result<i32> {
        eprintln!("[info] Executing: {}", command);

        let start_time = Instant::now();

        // Parse command string into program and arguments
        let parts: Vec<&str> = command.split_whitespace().collect();
        if parts.is_empty() {
            bail!("Empty command provided");
        }

        let program = parts[0];
        let args = &parts[1..];

        // Spawn agent process with output capture
        let mut child = Command::new(program)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("Failed to execute command: {}", command))?;

        // Capture stdout in real-time
        let stdout = child.stdout.take().context("Failed to capture stdout")?;
        let stderr = child.stderr.take().context("Failed to capture stderr")?;

        // Read and analyze output
        let stdout_reader = BufReader::new(stdout);
        let stderr_reader = BufReader::new(stderr);

        // Monitor stdout
        for line in stdout_reader.lines() {
            if let Ok(line) = line {
                println!("  {}", line);
                self.analyze_output(&line);
            }
        }

        // Monitor stderr
        for line in stderr_reader.lines() {
            if let Ok(line) = line {
                eprintln!("  {}", line);
                self.analyze_output(&line);
            }
        }

        // Wait for process to complete (with optional timeout)
        let exit_code = if let Some(timeout) = timeout_secs {
            self.wait_with_timeout(&mut child, Duration::from_secs(timeout))?
        } else {
            let status = child.wait().context("Failed to wait for agent process")?;
            status.code().unwrap_or(-1)
        };

        let duration = start_time.elapsed();
        eprintln!(
            "[info] Completed in {:.2}s (exit code: {})",
            duration.as_secs_f64(),
            exit_code
        );

        Ok(exit_code)
    }

    fn analyze_output(&mut self, line: &str) {
        let line_lower = line.to_lowercase();
        let timestamp = chrono::Utc::now().to_rfc3339();

        // Look for file access errors (ENOENT, EACCES, etc.)
        if line_lower.contains("enoent") || line_lower.contains("eacces") {
            self.add_observation(Observation {
                timestamp: timestamp.clone(),
                observation_type: "file_access_error".to_string(),
                description: format!("File access error detected: {}", line),
            });
        }

        // Network failures
        if line_lower.contains("econnrefused")
            || line_lower.contains("etimedout")
            || line_lower.contains("dns lookup failed")
        {
            self.add_observation(Observation {
                timestamp: timestamp.clone(),
                observation_type: "network_error".to_string(),
                description: format!("Network error detected: {}", line),
            });
        }

        // Check for API calls to non-allowed domains
        if line_lower.contains("http://") || line_lower.contains("https://") {
            self.check_network_access(line, &timestamp);
        }

        // Check for PII patterns if PII detection is required
        if self.policy.data_restrictions.pii_detection_required {
            self.check_pii_exposure(line, &timestamp);
        }

        // Check for prohibited keywords
        let prohibited_list = self.policy.use_cases.prohibited.clone();
        for prohibited in prohibited_list {
            if line_lower.contains(&prohibited.to_lowercase()) {
                self.add_violation(Violation {
                    timestamp: timestamp.clone(),
                    violation_type: ViolationType::ProhibitedUseCase,
                    severity: Severity::High,
                    description: "Potential prohibited use case detected".to_string(),
                    details: format!("Output contains prohibited keyword: {}", prohibited),
                });
            }
        }
    }

    fn check_network_access(&mut self, line: &str, timestamp: &str) {
        let url_pattern = regex::Regex::new(r"https?://([a-zA-Z0-9.-]+)").unwrap();

        for capture in url_pattern.captures_iter(line) {
            if let Some(domain_match) = capture.get(1) {
                let domain = domain_match.as_str();

                // 1. Check if domain is prohibited (High Severity)
                let is_prohibited = self
                    .policy
                    .network
                    .prohibited_domains
                    .iter()
                    .any(|prohibited| domain.contains(prohibited) || prohibited.contains(domain));

                if is_prohibited {
                    self.add_violation(Violation {
                        timestamp: timestamp.to_string(),
                        violation_type: ViolationType::NetworkAccessDenied,
                        severity: Severity::High,
                        description: "Network access to prohibited domain".to_string(),
                        details: format!("Attempted access to: {}", domain),
                    });
                    continue;
                }

                // 2. Check if domain is allowed (or external API allowed)
                let is_allowed = self
                    .policy
                    .network
                    .allowed_domains
                    .iter()
                    .any(|allowed| domain.ends_with(allowed) || allowed.ends_with(domain));

                if !is_allowed && !self.policy.network.external_api_allowed {
                    self.add_violation(Violation {
                        timestamp: timestamp.to_string(),
                        violation_type: ViolationType::NetworkAccessDenied,
                        severity: Severity::Medium,
                        description: "Network access to non-allowed domain".to_string(),
                        details: format!("Attempted access to: {}", domain),
                    });
                } else {
                    self.add_observation(Observation {
                        timestamp: timestamp.to_string(),
                        observation_type: "network_access".to_string(),
                        description: format!("Network access to: {}", domain),
                    });
                }
            }
        }
    }

    fn check_pii_exposure(&mut self, line: &str, timestamp: &str) {
        // Basic PII detection - email, SSN, credit card patterns
        let email_pattern =
            regex::Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap();
        let ssn_pattern = regex::Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap();
        let cc_pattern = regex::Regex::new(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b").unwrap();

        if email_pattern.is_match(line) || ssn_pattern.is_match(line) || cc_pattern.is_match(line) {
            self.add_violation(Violation {
                timestamp: timestamp.to_string(),
                violation_type: ViolationType::DataPolicyViolation,
                severity: Severity::High,
                description: "Potential PII detected in output".to_string(),
                details: "Output may contain email, SSN, or credit card number".to_string(),
            });
        }
    }

    fn wait_with_timeout(&self, child: &mut std::process::Child, timeout: Duration) -> Result<i32> {
        let start = Instant::now();

        loop {
            match child.try_wait()? {
                Some(status) => return Ok(status.code().unwrap_or(-1)),
                None => {
                    if start.elapsed() > timeout {
                        child.kill()?;
                        bail!("Agent execution timed out after {}s", timeout.as_secs());
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }

    fn add_violation(&mut self, violation: Violation) {
        self.violations.push(violation);
    }

    fn add_observation(&mut self, observation: Observation) {
        self.observations.push(observation);
    }

    pub fn get_violations(&self) -> &[Violation] {
        &self.violations
    }

    pub fn get_observations(&self) -> &[Observation] {
        &self.observations
    }

    pub fn get_policy(&self) -> &SandboxPolicy {
        &self.policy
    }
}
