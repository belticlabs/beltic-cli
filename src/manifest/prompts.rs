use anyhow::Result;
use console::{style, Term};
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Select};
use regex::Regex;
use uuid::Uuid;

use crate::manifest::schema::*;
use crate::manifest::templates::ManifestTemplates;

pub struct InteractivePrompts {
    theme: ColorfulTheme,
    term: Term,
}

impl InteractivePrompts {
    pub fn new() -> Self {
        Self {
            theme: ColorfulTheme::default(),
            term: Term::stdout(),
        }
    }

    /// Display a section header
    fn section_header(&self, icon: &str, title: &str) -> Result<()> {
        self.term.write_line("")?;
        self.term.write_line(&format!(
            "{} {}",
            style(icon).cyan().bold(),
            style(title).bold()
        ))?;
        self.term
            .write_line(&style("─".repeat(40)).dim().to_string())?;
        Ok(())
    }

    /// Prompt for agent identity fields
    pub fn prompt_identity(
        &self,
        defaults: Option<(&str, &str, &str)>,
    ) -> Result<(String, String, String, AgentStatus)> {
        self.section_header("📋", "Agent Identity")?;

        let name = Input::<String>::with_theme(&self.theme)
            .with_prompt("Agent name")
            .default(defaults.map(|d| d.0).unwrap_or("my-agent").to_string())
            .validate_with(|input: &String| -> Result<(), &str> {
                if input.len() < 2 || input.len() > 200 {
                    Err("Name must be 2-200 characters")
                } else {
                    Ok(())
                }
            })
            .interact_text()?;

        let version = Input::<String>::with_theme(&self.theme)
            .with_prompt("Version")
            .default(defaults.map(|d| d.1).unwrap_or("0.1.0").to_string())
            .validate_with(|input: &String| -> Result<(), &str> {
                let re = Regex::new(r"^\d+\.\d+\.\d+").unwrap();
                if re.is_match(input) {
                    Ok(())
                } else {
                    Err("Version must be in semantic format (e.g., 1.0.0)")
                }
            })
            .interact_text()?;

        let description = Input::<String>::with_theme(&self.theme)
            .with_prompt("Description (50-1000 chars)")
            .default(
                defaults
                    .map(|d| d.2.to_string())
                    .unwrap_or_else(|| format!("{} agent for intelligent assistance", &name)),
            )
            .validate_with(|input: &String| -> Result<(), &str> {
                if input.len() < 50 {
                    Err("Description must be at least 50 characters")
                } else if input.len() > 1000 {
                    Err("Description must be less than 1000 characters")
                } else {
                    Ok(())
                }
            })
            .interact_text()?;

        let status_options = vec![
            ("Production", AgentStatus::Production),
            ("Beta", AgentStatus::Beta),
            ("Alpha", AgentStatus::Alpha),
            ("Internal", AgentStatus::Internal),
        ];

        let status_idx = Select::with_theme(&self.theme)
            .with_prompt("Current status")
            .items(&status_options.iter().map(|o| o.0).collect::<Vec<_>>())
            .default(1) // Default to Beta
            .interact()?;

        Ok((
            name,
            version,
            description,
            status_options[status_idx].1.clone(),
        ))
    }

    /// Prompt for technical profile
    pub fn prompt_technical_profile(&self) -> Result<TechnicalProfile> {
        self.section_header("🤖", "Technical Profile")?;

        let providers = ManifestTemplates::model_providers();
        let provider_idx = Select::with_theme(&self.theme)
            .with_prompt("Model provider")
            .items(&providers.iter().map(|p| p.0).collect::<Vec<_>>())
            .default(0) // Default to Anthropic
            .interact()?;

        let provider = providers[provider_idx].0.to_string();

        let families = ManifestTemplates::model_families(&provider);
        let family_idx = Select::with_theme(&self.theme)
            .with_prompt("Model family")
            .items(&families)
            .default(0)
            .interact()?;

        let family = families[family_idx].clone();
        let default_context = ManifestTemplates::default_context_window(&family);

        let context_window = Input::<u32>::with_theme(&self.theme)
            .with_prompt("Context window (tokens)")
            .default(default_context)
            .interact_text()?;

        let deployment_env = Input::<String>::with_theme(&self.theme)
            .with_prompt("Deployment environment")
            .default("AWS us-west-2, containerized deployment".to_string())
            .interact_text()?;

        // Architecture type
        let arch_options = vec![
            ("Single Agent", ArchitectureType::SingleAgent),
            ("RAG (Retrieval-Augmented)", ArchitectureType::Rag),
            ("Tool-Using Agent", ArchitectureType::ToolUsing),
            ("Multi-Agent System", ArchitectureType::MultiAgent),
            ("Agentic Workflow", ArchitectureType::AgenticWorkflow),
            ("Fine-Tuned Model", ArchitectureType::FineTuned),
            ("Hybrid System", ArchitectureType::Hybrid),
        ];

        let arch_idx = Select::with_theme(&self.theme)
            .with_prompt("Architecture type")
            .items(&arch_options.iter().map(|a| a.0).collect::<Vec<_>>())
            .default(0)
            .interact()?;

        let architecture = arch_options[arch_idx].1.clone();

        // Modalities
        let modality_options = vec![
            ("Text", Modality::Text, true),
            ("Image", Modality::Image, false),
            ("Audio", Modality::Audio, false),
            ("Video", Modality::Video, false),
            ("Code", Modality::Code, false),
            ("Structured Data", Modality::StructuredData, false),
        ];

        let mut modalities = vec![Modality::Text]; // Always include text
        for (name, modality, default) in modality_options.iter().skip(1) {
            if Confirm::with_theme(&self.theme)
                .with_prompt(format!("Support {} modality?", name))
                .default(*default)
                .interact()?
            {
                modalities.push(modality.clone());
            }
        }

        // Language capabilities
        let languages = Input::<String>::with_theme(&self.theme)
            .with_prompt("Language capabilities (comma-separated ISO codes, e.g., en,es,fr)")
            .default("en".to_string())
            .interact_text()?;

        let language_capabilities: Vec<String> =
            languages.split(',').map(|s| s.trim().to_string()).collect();

        Ok(TechnicalProfile {
            primary_model_provider: provider,
            primary_model_family: family,
            model_context_window: context_window,
            deployment_environment: deployment_env,
            architecture_type: architecture,
            modality_support: modalities,
            language_capabilities,
        })
    }

    /// Prompt for tools configuration
    pub fn prompt_tools(&self) -> Result<Option<Vec<Tool>>> {
        self.section_header("🔧", "Tools & Actions")?;

        let has_tools = Confirm::with_theme(&self.theme)
            .with_prompt("Does your agent use tools?")
            .default(false)
            .interact()?;

        if !has_tools {
            return Ok(None);
        }

        let tool_count = Input::<usize>::with_theme(&self.theme)
            .with_prompt("How many tools?")
            .default(1)
            .validate_with(|input: &usize| -> Result<(), &str> {
                if *input == 0 {
                    Err("Must have at least 1 tool if using tools")
                } else if *input > 20 {
                    Err("Too many tools (max 20)")
                } else {
                    Ok(())
                }
            })
            .interact_text()?;

        let mut tools = Vec::new();

        for i in 1..=tool_count {
            self.term
                .write_line(&format!("\n{}:", style(format!("Tool {}", i)).yellow()))?;

            let tool_id = Input::<String>::with_theme(&self.theme)
                .with_prompt("  Tool ID")
                .default(format!("tool_{}", i))
                .interact_text()?;

            let tool_name = Input::<String>::with_theme(&self.theme)
                .with_prompt("  Name")
                .interact_text()?;

            let tool_description = Input::<String>::with_theme(&self.theme)
                .with_prompt("  Description (10-1000 chars)")
                .validate_with(|input: &String| -> Result<(), &str> {
                    if input.len() < 10 || input.len() > 1000 {
                        Err("Description must be 10-1000 characters")
                    } else {
                        Ok(())
                    }
                })
                .interact_text()?;

            let risk_categories = vec![
                ("Data", RiskCategory::Data),
                ("Compute", RiskCategory::Compute),
                ("Financial", RiskCategory::Financial),
                ("External", RiskCategory::External),
            ];

            let risk_idx = Select::with_theme(&self.theme)
                .with_prompt("  Risk category")
                .items(&risk_categories.iter().map(|r| r.0).collect::<Vec<_>>())
                .interact()?;

            let risk_category = risk_categories[risk_idx].1.clone();

            let risk_subcategory = self.prompt_risk_subcategory(&risk_category)?;

            let requires_auth = Confirm::with_theme(&self.theme)
                .with_prompt("  Requires authentication?")
                .default(true)
                .interact()?;

            let requires_human_approval = Confirm::with_theme(&self.theme)
                .with_prompt("  Requires human approval?")
                .default(false)
                .interact()?;

            let mitigations = if requires_human_approval || risk_category == RiskCategory::Financial
            {
                Some(
                    Input::<String>::with_theme(&self.theme)
                        .with_prompt("  Mitigations (optional)")
                        .allow_empty(true)
                        .interact_text()?,
                )
                .filter(|s| !s.is_empty())
            } else {
                None
            };

            tools.push(Tool {
                tool_id,
                tool_name,
                tool_description,
                risk_category,
                risk_subcategory,
                requires_auth,
                requires_human_approval,
                mitigations,
            });
        }

        Ok(Some(tools))
    }

    fn prompt_risk_subcategory(&self, category: &RiskCategory) -> Result<String> {
        let subcategories = match category {
            RiskCategory::Data => vec![
                "data_read_internal",
                "data_read_external",
                "data_write_internal",
                "data_write_external",
                "data_delete",
                "data_export",
            ],
            RiskCategory::Compute => vec![
                "compute_code_execution",
                "compute_query_generation",
                "compute_api_call",
                "compute_transformation",
                "compute_analysis",
            ],
            RiskCategory::Financial => vec![
                "financial_read",
                "financial_transaction",
                "financial_account_access",
                "financial_payment_initiation",
            ],
            RiskCategory::External => vec![
                "external_internet_access",
                "external_email",
                "external_notification",
                "external_authentication",
                "external_file_access",
            ],
        };

        let idx = Select::with_theme(&self.theme)
            .with_prompt("  Risk subcategory")
            .items(&subcategories)
            .interact()?;

        Ok(subcategories[idx].to_string())
    }

    /// Prompt for data handling and privacy
    pub fn prompt_data_handling(&self) -> Result<DataHandling> {
        self.section_header("🔐", "Data Handling & Privacy")?;

        let data_categories = vec![
            ("None", DataCategory::None, false),
            ("PII (Personal Info)", DataCategory::Pii, false),
            ("PHI (Health Info)", DataCategory::Phi, false),
            ("Financial", DataCategory::Financial, false),
            ("Biometric", DataCategory::Biometric, false),
            ("Behavioral", DataCategory::Behavioral, false),
            ("Authentication", DataCategory::Authentication, false),
            ("Proprietary", DataCategory::Proprietary, false),
            ("Government ID", DataCategory::GovernmentId, false),
            ("Children's Data", DataCategory::ChildrenData, false),
        ];

        let mut selected_categories = vec![];

        self.term.write_line(
            "Select all data categories processed (space to toggle, enter to confirm):",
        )?;

        for (name, category, _) in &data_categories {
            if Confirm::with_theme(&self.theme)
                .with_prompt(format!("  Process {}?", name))
                .default(false)
                .interact()?
            {
                selected_categories.push(category.clone());
            }
        }

        if selected_categories.is_empty() {
            selected_categories.push(DataCategory::None);
        }

        let retention_options = vec![
            ("7 days", "P7D"),
            ("30 days", "P30D"),
            ("90 days", "P90D"),
            ("1 year", "P365D"),
            ("No retention", "P0D"),
            ("Custom", "custom"),
        ];

        let retention_idx = Select::with_theme(&self.theme)
            .with_prompt("Data retention period")
            .items(&retention_options.iter().map(|r| r.0).collect::<Vec<_>>())
            .default(1) // Default to 30 days
            .interact()?;

        let retention_period = if retention_options[retention_idx].1 == "custom" {
            Input::<String>::with_theme(&self.theme)
                .with_prompt("Enter ISO 8601 duration (e.g., P30D)")
                .interact_text()?
        } else {
            retention_options[retention_idx].1.to_string()
        };

        let training_usage_options = vec![
            ("Never", TrainingDataUsage::Never),
            ("Anonymized Only", TrainingDataUsage::AnonymizedOnly),
            ("Aggregated Only", TrainingDataUsage::AggregatedOnly),
            (
                "With Explicit Consent",
                TrainingDataUsage::WithExplicitConsent,
            ),
            ("Opt-Out Available", TrainingDataUsage::OptOutAvailable),
            ("Not Applicable", TrainingDataUsage::NotApplicable),
        ];

        let training_idx = Select::with_theme(&self.theme)
            .with_prompt("Training data usage")
            .items(
                &training_usage_options
                    .iter()
                    .map(|t| t.0)
                    .collect::<Vec<_>>(),
            )
            .default(0) // Default to Never
            .interact()?;

        let has_pii = selected_categories.contains(&DataCategory::Pii)
            || selected_categories.contains(&DataCategory::Phi)
            || selected_categories.contains(&DataCategory::GovernmentId);

        let pii_detection = if has_pii {
            Confirm::with_theme(&self.theme)
                .with_prompt("Enable PII detection?")
                .default(true)
                .interact()?
        } else {
            false
        };

        let pii_redaction = if has_pii {
            let redaction_options = vec![
                ("None", PiiRedactionCapability::None),
                ("Basic", PiiRedactionCapability::Basic),
                ("Advanced", PiiRedactionCapability::Advanced),
                ("Context-Aware", PiiRedactionCapability::ContextAware),
            ];

            let redaction_idx = Select::with_theme(&self.theme)
                .with_prompt("PII redaction capability")
                .items(&redaction_options.iter().map(|r| r.0).collect::<Vec<_>>())
                .default(1) // Default to Basic
                .interact()?;

            redaction_options[redaction_idx].1.clone()
        } else {
            PiiRedactionCapability::None
        };

        Ok(DataHandling {
            data_categories_processed: selected_categories,
            data_retention_max_period: retention_period,
            training_data_usage: training_usage_options[training_idx].1.clone(),
            pii_detection_enabled: pii_detection,
            pii_redaction_capability: pii_redaction,
            data_encryption_standards: ManifestTemplates::default_encryption_standards(),
        })
    }

    /// Prompt for operations and lifecycle
    pub fn prompt_operations(&self) -> Result<Operations> {
        self.section_header("⚙️", "Operations & Lifecycle")?;

        let contact = Input::<String>::with_theme(&self.theme)
            .with_prompt("Incident response contact email")
            .validate_with(|input: &String| -> Result<(), &str> {
                if input.contains('@') && input.contains('.') {
                    Ok(())
                } else {
                    Err("Please enter a valid email address")
                }
            })
            .interact_text()?;

        let slo_options = vec![
            ("2 hours", "PT2H"),
            ("4 hours", "PT4H"),
            ("8 hours", "PT8H"),
            ("24 hours", "PT24H"),
            ("72 hours", "PT72H"),
        ];

        let slo_idx = Select::with_theme(&self.theme)
            .with_prompt("Incident response SLO")
            .items(&slo_options.iter().map(|s| s.0).collect::<Vec<_>>())
            .default(1) // Default to 4 hours
            .interact()?;

        let update_cadence_options = vec![
            ("Continuous", UpdateCadence::Continuous),
            ("Weekly", UpdateCadence::Weekly),
            ("Biweekly", UpdateCadence::Biweekly),
            ("Monthly", UpdateCadence::Monthly),
            ("Quarterly", UpdateCadence::Quarterly),
            ("As Needed", UpdateCadence::AsNeeded),
            ("No Updates", UpdateCadence::NoUpdates),
        ];

        let update_idx = Select::with_theme(&self.theme)
            .with_prompt("Update cadence")
            .items(
                &update_cadence_options
                    .iter()
                    .map(|u| u.0)
                    .collect::<Vec<_>>(),
            )
            .default(5) // Default to As Needed
            .interact()?;

        let oversight_options = vec![
            (
                "Autonomous (Low Risk)",
                HumanOversightMode::AutonomousLowRisk,
            ),
            (
                "Human Review Pre-Action",
                HumanOversightMode::HumanReviewPreAction,
            ),
            (
                "Human Review Post-Action",
                HumanOversightMode::HumanReviewPostAction,
            ),
            (
                "Human Initiated Only",
                HumanOversightMode::HumanInitiatedOnly,
            ),
            ("Custom Handover", HumanOversightMode::CustomHandover),
        ];

        let oversight_idx = Select::with_theme(&self.theme)
            .with_prompt("Human oversight mode")
            .items(&oversight_options.iter().map(|o| o.0).collect::<Vec<_>>())
            .default(0) // Default to Autonomous
            .interact()?;

        let oversight_mode = oversight_options[oversight_idx].1.clone();

        // Use templates for complex fields
        let deprecation_policy = ManifestTemplates::deprecation_policy_template();
        let fail_safe_behavior = ManifestTemplates::failsafe_behavior_template(&oversight_mode);
        let monitoring_coverage = ManifestTemplates::monitoring_coverage_template(false);

        Ok(Operations {
            incident_response_contact: contact,
            incident_response_slo: slo_options[slo_idx].1.to_string(),
            deprecation_policy,
            update_cadence: update_cadence_options[update_idx].1.clone(),
            human_oversight_mode: oversight_mode,
            fail_safe_behavior,
            monitoring_coverage,
        })
    }

    /// Prompt for developer credential ID
    pub fn prompt_developer_id(&self) -> Result<Option<Uuid>> {
        self.section_header("👤", "Developer Credentials")?;

        let has_id = Confirm::with_theme(&self.theme)
            .with_prompt("Do you have a developer credential ID from Beltic?")
            .default(false)
            .interact()?;

        if has_id {
            let id_str = Input::<String>::with_theme(&self.theme)
                .with_prompt("Developer credential ID (UUID)")
                .validate_with(|input: &String| -> Result<(), &str> {
                    match Uuid::parse_str(input) {
                        Ok(_) => Ok(()),
                        Err(_) => Err("Invalid UUID format"),
                    }
                })
                .interact_text()?;

            Ok(Some(Uuid::parse_str(&id_str)?))
        } else {
            self.term.write_line(
                &style(
                    "ℹ You'll need to obtain a developer credential ID from the Beltic platform",
                )
                .yellow()
                .to_string(),
            )?;
            Ok(None)
        }
    }

    /// Display validation results
    pub fn display_validation(&self, missing_count: usize, warnings: Vec<String>) -> Result<()> {
        self.section_header("📊", "Validation Results")?;

        if missing_count == 0 {
            self.term.write_line(&format!(
                "{} All required fields present",
                style("✅").green()
            ))?;
            self.term
                .write_line(&format!("{} Schema validation passed", style("✅").green()))?;
        } else {
            self.term.write_line(&format!(
                "{} {} required fields need attention",
                style("⚠").yellow(),
                missing_count
            ))?;
        }

        for warning in warnings {
            self.term
                .write_line(&format!("{} {}", style("ℹ").blue(), warning))?;
        }

        Ok(())
    }
}

// Helper structs for organizing prompts
pub struct TechnicalProfile {
    pub primary_model_provider: String,
    pub primary_model_family: String,
    pub model_context_window: u32,
    pub deployment_environment: String,
    pub architecture_type: ArchitectureType,
    pub modality_support: Vec<Modality>,
    pub language_capabilities: Vec<String>,
}

pub struct DataHandling {
    pub data_categories_processed: Vec<DataCategory>,
    pub data_retention_max_period: String,
    pub training_data_usage: TrainingDataUsage,
    pub pii_detection_enabled: bool,
    pub pii_redaction_capability: PiiRedactionCapability,
    pub data_encryption_standards: Vec<String>,
}

pub struct Operations {
    pub incident_response_contact: String,
    pub incident_response_slo: String,
    pub deprecation_policy: String,
    pub update_cadence: UpdateCadence,
    pub human_oversight_mode: HumanOversightMode,
    pub fail_safe_behavior: String,
    pub monitoring_coverage: String,
}
