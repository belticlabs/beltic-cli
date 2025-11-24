use crate::manifest::schema::*;

/// Provides default templates and values for agent manifest fields
pub struct ManifestTemplates;

impl ManifestTemplates {
    /// Get a professional agent description based on name and type
    pub fn generate_description(name: &str, architecture: &ArchitectureType) -> String {
        match architecture {
            ArchitectureType::SingleAgent => {
                format!("{} is an AI assistant that provides intelligent responses and assistance to users.", name)
            }
            ArchitectureType::Rag => {
                format!("{} is a retrieval-augmented generation (RAG) agent that combines document search with AI responses to provide accurate, context-aware assistance.", name)
            }
            ArchitectureType::ToolUsing => {
                format!("{} is a tool-using AI agent capable of executing various functions to help users accomplish tasks effectively.", name)
            }
            ArchitectureType::MultiAgent => {
                format!("{} is a multi-agent system that coordinates multiple specialized AI agents to solve complex problems collaboratively.", name)
            }
            ArchitectureType::AgenticWorkflow => {
                format!("{} is an agentic workflow system that orchestrates AI-driven processes to automate and optimize complex workflows.", name)
            }
            ArchitectureType::FineTuned => {
                format!("{} is a fine-tuned AI model specialized for domain-specific tasks with enhanced performance in its area of expertise.", name)
            }
            ArchitectureType::Hybrid => {
                format!("{} is a hybrid AI system combining multiple architectures to deliver comprehensive and versatile assistance.", name)
            }
        }
    }

    /// Get default deployment environment based on deployment type
    pub fn default_deployment_environment(deployment_type: &DeploymentType) -> String {
        match deployment_type {
            DeploymentType::Standalone => "Local development environment, containerized for production deployment".to_string(),
            DeploymentType::Monorepo => "Monorepo deployment within shared infrastructure, isolated runtime".to_string(),
            DeploymentType::Embedded => "Embedded within host application, shared runtime environment".to_string(),
            DeploymentType::Plugin => "Plugin architecture with sandboxed execution environment".to_string(),
            DeploymentType::Serverless => "Serverless function deployment, auto-scaling infrastructure".to_string(),
        }
    }

    /// Get default incident response SLO based on risk level
    pub fn default_incident_response_slo(risk_level: &str) -> String {
        match risk_level {
            "production" | "high_risk" => "PT2H".to_string(), // 2 hours
            "beta" | "moderate_risk" => "PT4H".to_string(),   // 4 hours
            "alpha" | "low_risk" => "PT8H".to_string(),       // 8 hours
            _ => "PT24H".to_string(),                         // 24 hours
        }
    }

    /// Generate deprecation policy template
    pub fn deprecation_policy_template() -> String {
        "Minimum 30-day notice via email and API deprecation headers. \
         Migration guide provided with backwards compatibility for 90 days. \
         Sunset date communicated through all channels with automated reminders."
            .to_string()
    }

    /// Generate fail-safe behavior based on oversight mode
    pub fn failsafe_behavior_template(oversight_mode: &HumanOversightMode) -> String {
        match oversight_mode {
            HumanOversightMode::AutonomousLowRisk => {
                "On error or uncertainty, the agent returns a helpful error message and logs the incident. \
                 No automated retries for failed operations. \
                 Graceful degradation with user notification."
            }
            HumanOversightMode::HumanReviewPreAction => {
                "All actions require human approval before execution. \
                 On timeout or rejection, the agent cancels the operation and notifies the user. \
                 Failed approvals are logged for audit."
            }
            HumanOversightMode::HumanReviewPostAction => {
                "Actions are executed with post-execution review. \
                 Suspicious activities trigger immediate suspension pending review. \
                 All actions are reversible within the review window."
            }
            HumanOversightMode::HumanInitiatedOnly => {
                "Agent only responds to explicit human requests. \
                 No autonomous actions permitted. \
                 Session timeout after 30 minutes of inactivity."
            }
            HumanOversightMode::CustomHandover => {
                "Custom handover protocol based on confidence thresholds. \
                 Escalates to human operator when confidence < 80%. \
                 Maintains context for seamless handover."
            }
        }
        .to_string()
    }

    /// Generate monitoring coverage description
    pub fn monitoring_coverage_template(has_tools: bool) -> String {
        let base = "Real-time monitoring of API calls, response times, and error rates. \
                    Daily automated health checks and performance metrics. \
                    Alert thresholds: >1% error rate, >2s p95 latency.";

        if has_tools {
            format!("{} Tool usage tracked with detailed audit logs. \
                     Risk-based alerts for sensitive operations.", base)
        } else {
            base.to_string()
        }
    }

    /// Get default data encryption standards
    pub fn default_encryption_standards() -> Vec<String> {
        vec![
            "AES-256-GCM at rest".to_string(),
            "TLS 1.3 in transit".to_string(),
            "RSA-2048 for key exchange".to_string(),
        ]
    }

    /// Get default safety benchmark names
    pub fn default_benchmark_names() -> SafetyBenchmarks {
        SafetyBenchmarks {
            harmful_content: "HELM-Toxicity-v1".to_string(),
            prompt_injection: "PINT-Benchmark-v2".to_string(),
            tool_abuse: "ToolSafety-Eval-v1".to_string(),
            pii_leakage: "PIIGuard-Benchmark-v1".to_string(),
        }
    }

    /// Get model provider options
    pub fn model_providers() -> Vec<(&'static str, &'static str)> {
        vec![
            ("Anthropic", "Claude"),
            ("OpenAI", "GPT"),
            ("Google", "Gemini"),
            ("Meta", "Llama"),
            ("Mistral", "Mistral"),
            ("Cohere", "Command"),
            ("Custom", "Custom Model"),
        ]
    }

    /// Get model families for a provider
    pub fn model_families(provider: &str) -> Vec<String> {
        match provider {
            "Anthropic" => vec![
                "Claude-3.5 Sonnet".to_string(),
                "Claude-3 Opus".to_string(),
                "Claude-3 Sonnet".to_string(),
                "Claude-3 Haiku".to_string(),
            ],
            "OpenAI" => vec![
                "GPT-4 Turbo".to_string(),
                "GPT-4".to_string(),
                "GPT-3.5 Turbo".to_string(),
                "GPT-4o".to_string(),
            ],
            "Google" => vec![
                "Gemini Pro".to_string(),
                "Gemini Ultra".to_string(),
                "Gemini Nano".to_string(),
            ],
            "Meta" => vec![
                "Llama 3 70B".to_string(),
                "Llama 3 8B".to_string(),
                "Code Llama".to_string(),
            ],
            _ => vec!["Custom Model".to_string()],
        }
    }

    /// Get default context window for model family
    pub fn default_context_window(model_family: &str) -> u32 {
        if model_family.contains("Claude-3") {
            200000
        } else if model_family.contains("GPT-4") && model_family.contains("Turbo") {
            128000
        } else if model_family.contains("GPT-4") {
            32000
        } else if model_family.contains("Gemini") {
            1000000
        } else if model_family.contains("Llama") {
            8192
        } else {
            4096
        }
    }

    /// Generate approved use cases based on agent type
    pub fn default_approved_use_cases(architecture: &ArchitectureType) -> Vec<String> {
        match architecture {
            ArchitectureType::SingleAgent => vec![
                "General Q&A and information retrieval".to_string(),
                "Text generation and summarization".to_string(),
                "Basic task assistance".to_string(),
            ],
            ArchitectureType::Rag => vec![
                "Document-based question answering".to_string(),
                "Knowledge base queries".to_string(),
                "Research assistance with citations".to_string(),
            ],
            ArchitectureType::ToolUsing => vec![
                "Task automation with tool execution".to_string(),
                "Data analysis and processing".to_string(),
                "Integration with external systems".to_string(),
            ],
            _ => vec![
                "Domain-specific assistance".to_string(),
                "Authorized use cases only".to_string(),
            ],
        }
    }

    /// Generate prohibited use cases (common for all)
    pub fn default_prohibited_use_cases() -> Vec<String> {
        vec![
            "Medical diagnosis or treatment advice".to_string(),
            "Legal advice or representation".to_string(),
            "Financial investment recommendations".to_string(),
            "Generation of harmful or illegal content".to_string(),
            "Impersonation or deception".to_string(),
        ]
    }

    /// Get compliance certification options
    pub fn compliance_options() -> Vec<(&'static str, ComplianceCert)> {
        vec![
            ("SOC 2 Type I", ComplianceCert::Soc2Type1),
            ("SOC 2 Type II", ComplianceCert::Soc2Type2),
            ("ISO 27001", ComplianceCert::Iso27001),
            ("HIPAA", ComplianceCert::Hipaa),
            ("PCI DSS", ComplianceCert::PciDss),
            ("FedRAMP", ComplianceCert::Fedramp),
            ("GDPR", ComplianceCert::Gdpr),
            ("CCPA", ComplianceCert::Ccpa),
        ]
    }
}

pub struct SafetyBenchmarks {
    pub harmful_content: String,
    pub prompt_injection: String,
    pub tool_abuse: String,
    pub pii_leakage: String,
}

impl Default for SafetyBenchmarks {
    fn default() -> Self {
        ManifestTemplates::default_benchmark_names()
    }
}

/// Generate a complete manifest with sensible defaults (no TODOs)
pub fn generate_complete_defaults(
    name: String,
    version: String,
    architecture: ArchitectureType,
    deployment_type: DeploymentType,
) -> AgentManifest {
    let description = ManifestTemplates::generate_description(&name, &architecture);
    let deployment_env = ManifestTemplates::default_deployment_environment(&deployment_type);
    let oversight_mode = match &architecture {
        ArchitectureType::ToolUsing | ArchitectureType::MultiAgent => {
            HumanOversightMode::HumanReviewPostAction
        }
        _ => HumanOversightMode::AutonomousLowRisk,
    };

    let mut manifest = AgentManifest::new_with_defaults();

    // Replace all TODOs with actual values
    manifest.agent_name = name;
    manifest.agent_version = version.clone();
    manifest.agent_description = description;
    manifest.architecture_type = architecture.clone();
    manifest.deployment_environment = deployment_env;

    // Set model defaults
    manifest.primary_model_provider = "Anthropic".to_string();
    manifest.primary_model_family = "Claude-3.5 Sonnet".to_string();
    manifest.model_context_window = 200000;

    // Set operational fields
    manifest.incident_response_contact = "security@example.com".to_string(); // Will be replaced in interactive mode
    manifest.incident_response_slo = ManifestTemplates::default_incident_response_slo(&version);
    manifest.deprecation_policy = ManifestTemplates::deprecation_policy_template();
    manifest.human_oversight_mode = oversight_mode.clone();
    manifest.fail_safe_behavior = ManifestTemplates::failsafe_behavior_template(&oversight_mode);
    manifest.monitoring_coverage = ManifestTemplates::monitoring_coverage_template(false);

    // Set data handling
    manifest.data_encryption_standards = ManifestTemplates::default_encryption_standards();
    manifest.pii_detection_enabled = true;
    manifest.pii_redaction_capability = PiiRedactionCapability::Basic;

    // Set use cases
    manifest.approved_use_cases = Some(ManifestTemplates::default_approved_use_cases(&architecture));
    manifest.prohibited_use_cases = Some(ManifestTemplates::default_prohibited_use_cases());

    manifest
}