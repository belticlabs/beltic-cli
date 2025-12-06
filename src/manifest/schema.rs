use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Agent manifest structure based on Beltic specification v1
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentManifest {
    // Manifest metadata
    pub manifest_schema_version: String,
    pub manifest_revision: String,

    // Core fingerprint (required)
    pub system_config_fingerprint: String,

    // Extended fingerprint metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint_metadata: Option<FingerprintMetadata>,

    // Agent Identity & Provenance
    pub agent_id: Uuid,
    pub agent_name: String,
    pub agent_version: String,
    pub agent_description: String,
    pub first_release_date: String, // ISO date format
    pub current_status: AgentStatus,
    pub developer_credential_id: Uuid,
    pub developer_credential_verified: bool,

    // Technical Profile
    pub primary_model_provider: String,
    pub primary_model_family: String,
    pub model_context_window: u32,
    pub modality_support: Vec<Modality>,
    pub language_capabilities: Vec<String>, // ISO 639-1 codes
    pub architecture_type: ArchitectureType,
    pub system_config_last_updated: String, // ISO date
    pub deployment_environment: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compliance_certifications: Option<Vec<ComplianceCert>>,
    pub data_location_profile: DataLocationProfile,

    // Tools & Actions (conditional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools_list: Option<Vec<Tool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools_last_audited: Option<String>, // ISO date

    // Data Handling & Privacy
    pub data_categories_processed: Vec<DataCategory>,
    pub data_retention_max_period: String, // ISO 8601 duration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_retention_by_category: Option<HashMap<String, String>>,
    pub training_data_usage: TrainingDataUsage,
    pub pii_detection_enabled: bool,
    pub pii_redaction_capability: PiiRedactionCapability,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pii_redaction_pipeline: Option<String>,
    pub data_encryption_standards: Vec<String>,

    // Operations & Lifecycle
    pub incident_response_contact: String,
    pub incident_response_slo: String, // ISO 8601 duration
    pub deprecation_policy: String,
    pub update_cadence: UpdateCadence,
    pub human_oversight_mode: HumanOversightMode,
    pub fail_safe_behavior: String,
    pub monitoring_coverage: String,

    // Risk Summary & Assurance (some fields will be set later)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_use_cases: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prohibited_use_cases: Option<Vec<String>>,
    pub age_restrictions: AgeRestriction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regulatory_approvals: Option<Vec<String>>,
    pub kyb_tier_required: KybTier,

    // Optional deployment context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment_context: Option<DeploymentContext>,

    // Auto-detection metadata (not part of final spec, but useful during init)
    #[serde(rename = "_metadata", skip_serializing_if = "Option::is_none")]
    pub metadata: Option<GenerationMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FingerprintMetadata {
    pub algorithm: String,
    pub timestamp: DateTime<Utc>,
    pub scope: FingerprintScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dependencies: Option<Dependencies>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FingerprintScope {
    #[serde(rename = "type")]
    pub scope_type: String, // full|scoped|custom
    pub paths: PathConfiguration,
    pub files_processed: usize,
    pub total_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PathConfiguration {
    pub included: Vec<String>,
    pub excluded: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Dependencies {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal: Option<Vec<InternalDep>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external: Option<Vec<ExternalDep>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InternalDep {
    pub path: String,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalDep {
    pub name: String,
    pub version: String,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataLocationProfile {
    pub storage_regions: Vec<String>, // ISO 3166-1 alpha-2 codes
    pub processing_regions: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_regions: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tool {
    pub tool_id: String,
    pub tool_name: String,
    pub tool_description: String,
    pub risk_category: RiskCategory,
    pub risk_subcategory: String,
    pub requires_auth: bool,
    pub requires_human_approval: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitigations: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentContext {
    #[serde(rename = "type")]
    pub deployment_type: DeploymentType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_application: Option<HostApplication>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<RuntimeInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository_structure: Option<RepositoryStructure>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostApplication {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeInfo {
    pub platform: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepositoryStructure {
    pub root: String,
    pub agent_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerationMetadata {
    pub generated_by: String,
    pub generated_at: DateTime<Utc>,
    pub auto_detected: HashMap<String, String>,
}

// Enums for various fields

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    Production,
    Beta,
    Alpha,
    Internal,
    Deprecated,
    Retired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Modality {
    Text,
    Image,
    Audio,
    Video,
    Code,
    StructuredData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchitectureType {
    SingleAgent,
    Rag,
    ToolUsing,
    MultiAgent,
    AgenticWorkflow,
    FineTuned,
    Hybrid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceCert {
    Soc2Type1,
    Soc2Type2,
    Iso27001,
    Hipaa,
    PciDss,
    Fedramp,
    Gdpr,
    Ccpa,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DataCategory {
    None,
    Pii,
    Phi,
    Financial,
    Biometric,
    Behavioral,
    Authentication,
    Proprietary,
    GovernmentId,
    ChildrenData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrainingDataUsage {
    Never,
    AnonymizedOnly,
    AggregatedOnly,
    WithExplicitConsent,
    OptOutAvailable,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PiiRedactionCapability {
    None,
    Basic,
    Advanced,
    ContextAware,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateCadence {
    Continuous,
    Weekly,
    Biweekly,
    Monthly,
    Quarterly,
    AsNeeded,
    NoUpdates,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanOversightMode {
    AutonomousLowRisk,
    HumanReviewPreAction,
    HumanReviewPostAction,
    HumanInitiatedOnly,
    CustomHandover,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AgeRestriction {
    None,
    #[serde(rename = "13+")]
    ThirteenPlus,
    #[serde(rename = "16+")]
    SixteenPlus,
    #[serde(rename = "18+")]
    EighteenPlus,
    #[serde(rename = "21+")]
    TwentyOnePlus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KybTier {
    Tier0,
    Tier1,
    Tier2,
    Tier3,
    Tier4,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RiskCategory {
    Data,
    Compute,
    Financial,
    External,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentType {
    Standalone,
    Monorepo,
    Embedded,
    Plugin,
    Serverless,
}

impl AgentManifest {
    /// Create a new manifest with default/placeholder values
    pub fn new_with_defaults() -> Self {
        Self {
            manifest_schema_version: "1.0".to_string(),
            manifest_revision: "1.0.0".to_string(),
            system_config_fingerprint: "TODO: Will be generated".to_string(),
            fingerprint_metadata: None,
            agent_id: Uuid::new_v4(),
            agent_name: "TODO: Agent name".to_string(),
            agent_version: "0.1.0".to_string(),
            agent_description:
                "TODO: Describe your agent's purpose and capabilities (50-1000 chars)".to_string(),
            first_release_date: chrono::Utc::now().format("%Y-%m-%d").to_string(),
            current_status: AgentStatus::Alpha,
            developer_credential_id: Uuid::nil(), // Placeholder, needs to be obtained from Beltic
            developer_credential_verified: false,
            primary_model_provider: "TODO: e.g., Anthropic, OpenAI, Google".to_string(),
            primary_model_family: "TODO: e.g., Claude-3 Opus, GPT-4 Turbo".to_string(),
            model_context_window: 200000,
            modality_support: vec![Modality::Text],
            language_capabilities: vec!["en".to_string()],
            architecture_type: ArchitectureType::SingleAgent,
            system_config_last_updated: chrono::Utc::now().format("%Y-%m-%d").to_string(),
            deployment_environment: "TODO: e.g., AWS us-east-1, local development".to_string(),
            compliance_certifications: None,
            data_location_profile: DataLocationProfile {
                storage_regions: vec!["US".to_string()],
                processing_regions: vec!["US".to_string()],
                backup_regions: None,
                notes: None,
            },
            tools_list: None,
            tools_last_audited: None,
            data_categories_processed: vec![DataCategory::None],
            data_retention_max_period: "P30D".to_string(), // 30 days default
            data_retention_by_category: None,
            training_data_usage: TrainingDataUsage::Never,
            pii_detection_enabled: false,
            pii_redaction_capability: PiiRedactionCapability::None,
            pii_redaction_pipeline: None,
            data_encryption_standards: vec!["TLS 1.3 in transit".to_string()],
            incident_response_contact: "TODO: security@example.com".to_string(),
            incident_response_slo: "PT4H".to_string(), // 4 hours default
            deprecation_policy: "TODO: Describe notice periods and migration support".to_string(),
            update_cadence: UpdateCadence::AsNeeded,
            human_oversight_mode: HumanOversightMode::AutonomousLowRisk,
            fail_safe_behavior:
                "TODO: Describe what triggers fail-safe, actions taken, and alerting".to_string(),
            monitoring_coverage: "TODO: Describe telemetry, review frequency, and alerts"
                .to_string(),
            approved_use_cases: None,
            prohibited_use_cases: None,
            age_restrictions: AgeRestriction::ThirteenPlus,
            regulatory_approvals: None,
            kyb_tier_required: KybTier::Tier0,
            deployment_context: None,
            metadata: None,
        }
    }
}
