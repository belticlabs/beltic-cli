//! AgentCredential structure matching the beltic-spec schema exactly.
//!
//! This is the schema-compliant credential that gets signed as a JWS.
//! It differs from AgentManifest which is the internal configuration format.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// AgentCredential v1 - matches schema at beltic-spec/schemas/agent/v1/agent-credential-v1.schema.json
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCredential {
    /// Optional JSON Schema reference
    #[serde(rename = "$schema", skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,

    /// Schema version - must be "1.0"
    pub schema_version: String,

    // === Agent Identity ===
    pub agent_id: Uuid,
    pub agent_name: String,
    pub agent_version: String,
    pub agent_description: String,
    pub first_release_date: String, // ISO date YYYY-MM-DD
    pub current_status: AgentStatus,
    pub developer_credential_id: Uuid,
    pub developer_credential_verified: bool,

    // === Technical Profile ===
    pub primary_model_provider: ModelProvider,
    pub primary_model_family: ModelFamily,
    pub model_context_window: u32,
    pub modality_support: Vec<Modality>,
    pub language_capabilities: Vec<String>, // ISO 639-1 codes like "en"
    pub architecture_type: ArchitectureType,
    pub system_config_fingerprint: String, // 64 hex chars, no prefix
    pub system_config_last_updated: String, // ISO date
    pub deployment_environment: DeploymentEnvironment,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub compliance_certifications: Option<Vec<ComplianceCert>>,

    pub data_location_profile: DataLocationProfile,

    // === Tools ===
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools_list: Option<Vec<Tool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools_last_audited: Option<String>,

    // === Data Handling ===
    pub data_categories_processed: Vec<DataCategory>,
    pub data_retention_max_period: String, // ISO 8601 duration like "P30D"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_retention_by_category: Option<std::collections::HashMap<String, String>>,
    pub training_data_usage: TrainingDataUsage,
    pub pii_detection_enabled: bool,
    pub pii_redaction_capability: PiiRedactionCapability,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pii_redaction_pipeline: Option<String>,
    pub data_encryption_standards: Vec<EncryptionStandard>,

    // === Safety Metrics - Harmful Content ===
    pub harmful_content_refusal_score: f32,
    pub harmful_content_benchmark_name: String,
    pub harmful_content_benchmark_version: String,
    pub harmful_content_evaluation_date: String,
    pub harmful_content_assurance_source: AssuranceSource,

    // === Safety Metrics - Prompt Injection ===
    pub prompt_injection_robustness_score: f32,
    pub prompt_injection_benchmark_name: String,
    pub prompt_injection_benchmark_version: String,
    pub prompt_injection_evaluation_date: String,
    pub prompt_injection_assurance_source: AssuranceSource,

    // === Safety Metrics - Tool Abuse (optional) ===
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_abuse_robustness_score: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_abuse_benchmark_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_abuse_benchmark_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_abuse_evaluation_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_abuse_assurance_source: Option<AssuranceSource>,

    // === Safety Metrics - PII Leakage ===
    pub pii_leakage_robustness_score: f32,
    pub pii_leakage_benchmark_name: String,
    pub pii_leakage_benchmark_version: String,
    pub pii_leakage_evaluation_date: String,
    pub pii_leakage_assurance_source: AssuranceSource,

    // === Operations ===
    pub incident_response_contact: String, // email
    #[serde(rename = "incidentResponseSLO")]
    pub incident_response_slo: String, // ISO 8601 duration
    pub deprecation_policy: String,
    pub update_cadence: UpdateCadence,
    pub human_oversight_mode: HumanOversightMode,
    pub fail_safe_behavior: String,
    pub monitoring_coverage: String,

    // === Risk & Compliance ===
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_use_cases: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prohibited_use_cases: Option<Vec<String>>,
    pub age_restrictions: AgeRestriction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regulatory_approvals: Option<Vec<String>>,
    pub kyb_tier_required: KybTier,

    // === Credential Metadata ===
    pub credential_issuance_date: String, // RFC3339
    pub credential_expiration_date: String, // RFC3339
    pub overall_safety_rating: SafetyRating,
    pub verification_level: VerificationLevel,
    pub credential_id: Uuid,
    pub issuer_did: String,
    pub verification_method: String, // DID#keyId format
    pub credential_status: CredentialStatus,
    pub revocation_list_url: String,
    pub proof: Proof,

    // === Optional HTTP Signing ===
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_signing_key_jwk_thumbprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_directory_url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_security_audit_date: Option<String>,
}

// === Enums matching schema exactly ===

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
pub enum ModelProvider {
    Anthropic,
    Openai,
    Google,
    Meta,
    Mistral,
    Cohere,
    Amazon,
    Microsoft,
    Huggingface,
    SelfHosted,
    Other,
}

impl ModelProvider {
    pub fn from_display_name(name: &str) -> Self {
        match name.to_lowercase().as_str() {
            "anthropic" | "claude" => ModelProvider::Anthropic,
            "openai" | "gpt" => ModelProvider::Openai,
            "google" | "gemini" => ModelProvider::Google,
            "meta" | "llama" => ModelProvider::Meta,
            "mistral" => ModelProvider::Mistral,
            "cohere" | "command" => ModelProvider::Cohere,
            "amazon" | "aws" | "bedrock" => ModelProvider::Amazon,
            "microsoft" | "azure" => ModelProvider::Microsoft,
            "huggingface" | "hf" => ModelProvider::Huggingface,
            "self_hosted" | "local" | "ollama" => ModelProvider::SelfHosted,
            _ => ModelProvider::Other,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ModelFamily {
    #[serde(rename = "claude-3-opus")]
    Claude3Opus,
    #[serde(rename = "claude-3-sonnet")]
    Claude3Sonnet,
    #[serde(rename = "claude-3-haiku")]
    Claude3Haiku,
    #[serde(rename = "claude-3.5-sonnet")]
    Claude35Sonnet,
    #[serde(rename = "claude-4")]
    Claude4,
    #[serde(rename = "gpt-4")]
    Gpt4,
    #[serde(rename = "gpt-4-turbo")]
    Gpt4Turbo,
    #[serde(rename = "gpt-4o")]
    Gpt4o,
    #[serde(rename = "gpt-4o-mini")]
    Gpt4oMini,
    #[serde(rename = "gemini-pro")]
    GeminiPro,
    #[serde(rename = "gemini-ultra")]
    GeminiUltra,
    #[serde(rename = "gemini-1.5")]
    Gemini15,
    #[serde(rename = "llama-3")]
    Llama3,
    #[serde(rename = "llama-3.1")]
    Llama31,
    #[serde(rename = "mistral-large")]
    MistralLarge,
    #[serde(rename = "mistral-medium")]
    MistralMedium,
    #[serde(rename = "command-r")]
    CommandR,
    #[serde(rename = "command-r-plus")]
    CommandRPlus,
    #[serde(rename = "other")]
    Other,
}

impl ModelFamily {
    pub fn from_display_name(name: &str) -> Self {
        let lower = name.to_lowercase();
        if lower.contains("claude-3.5") || lower.contains("claude 3.5") || lower.contains("sonnet 3.5") {
            ModelFamily::Claude35Sonnet
        } else if lower.contains("claude-4") || lower.contains("claude 4") || lower.contains("sonnet 4") {
            ModelFamily::Claude4
        } else if lower.contains("claude-3") && lower.contains("opus") {
            ModelFamily::Claude3Opus
        } else if lower.contains("claude-3") && lower.contains("sonnet") {
            ModelFamily::Claude3Sonnet
        } else if lower.contains("claude-3") && lower.contains("haiku") {
            ModelFamily::Claude3Haiku
        } else if lower.contains("gpt-4o-mini") {
            ModelFamily::Gpt4oMini
        } else if lower.contains("gpt-4o") {
            ModelFamily::Gpt4o
        } else if lower.contains("gpt-4") && lower.contains("turbo") {
            ModelFamily::Gpt4Turbo
        } else if lower.contains("gpt-4") {
            ModelFamily::Gpt4
        } else if lower.contains("gemini") && lower.contains("1.5") {
            ModelFamily::Gemini15
        } else if lower.contains("gemini") && lower.contains("ultra") {
            ModelFamily::GeminiUltra
        } else if lower.contains("gemini") {
            ModelFamily::GeminiPro
        } else if lower.contains("llama") && lower.contains("3.1") {
            ModelFamily::Llama31
        } else if lower.contains("llama") && lower.contains("3") {
            ModelFamily::Llama3
        } else if lower.contains("mistral") && lower.contains("large") {
            ModelFamily::MistralLarge
        } else if lower.contains("mistral") {
            ModelFamily::MistralMedium
        } else if lower.contains("command-r-plus") || lower.contains("command r plus") {
            ModelFamily::CommandRPlus
        } else if lower.contains("command") {
            ModelFamily::CommandR
        } else {
            ModelFamily::Other
        }
    }

    pub fn default_context_window(&self) -> u32 {
        match self {
            ModelFamily::Claude3Opus | ModelFamily::Claude3Sonnet | ModelFamily::Claude3Haiku => 200000,
            ModelFamily::Claude35Sonnet | ModelFamily::Claude4 => 200000,
            ModelFamily::Gpt4 => 32000,
            ModelFamily::Gpt4Turbo | ModelFamily::Gpt4o | ModelFamily::Gpt4oMini => 128000,
            ModelFamily::GeminiPro | ModelFamily::GeminiUltra | ModelFamily::Gemini15 => 1000000,
            ModelFamily::Llama3 | ModelFamily::Llama31 => 128000,
            ModelFamily::MistralLarge | ModelFamily::MistralMedium => 32000,
            ModelFamily::CommandR | ModelFamily::CommandRPlus => 128000,
            ModelFamily::Other => 8192,
        }
    }
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
#[serde(rename_all = "camelCase")]
pub struct DeploymentEnvironment {
    #[serde(rename = "type")]
    pub environment_type: DeploymentEnvType,
    pub cloud_provider: CloudProvider,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compliance_notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentEnvType {
    CloudManaged,
    CloudSelfManaged,
    OnPremises,
    Hybrid,
    Edge,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CloudProvider {
    Aws,
    Gcp,
    Azure,
    Oracle,
    Ibm,
    Alibaba,
    Other,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceCert {
    #[serde(rename = "soc2_type1")]
    Soc2Type1,
    #[serde(rename = "soc2_type2")]
    Soc2Type2,
    #[serde(rename = "iso27001")]
    Iso27001,
    #[serde(rename = "iso27017")]
    Iso27017,
    #[serde(rename = "iso27018")]
    Iso27018,
    #[serde(rename = "hipaa")]
    Hipaa,
    #[serde(rename = "pci_dss")]
    PciDss,
    #[serde(rename = "fedramp")]
    Fedramp,
    #[serde(rename = "gdpr_compliant")]
    GdprCompliant,
    #[serde(rename = "ccpa_compliant")]
    CcpaCompliant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataLocationProfile {
    pub storage_regions: Vec<String>,
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
    pub risk_subcategory: RiskSubcategory,
    pub requires_auth: bool,
    pub requires_human_approval: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitigations: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RiskCategory {
    Data,
    Compute,
    Financial,
    External,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RiskSubcategory {
    DataReadInternal,
    DataReadExternal,
    DataWriteInternal,
    DataWriteExternal,
    DataDelete,
    DataExport,
    ComputeCodeExecution,
    ComputeQueryGeneration,
    ComputeApiCall,
    ComputeTransformation,
    ComputeAnalysis,
    FinancialRead,
    FinancialTransaction,
    FinancialAccountAccess,
    FinancialPaymentInitiation,
    ExternalInternetAccess,
    ExternalEmail,
    ExternalNotification,
    ExternalAuthentication,
    ExternalFileAccess,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TrainingDataUsage {
    Never,
    AnonymizedOnly,
    AggregatedOnly,
    WithExplicitConsent,
    OptOutAvailable,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PiiRedactionCapability {
    None,
    Basic,
    Advanced,
    ContextAware,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EncryptionStandard {
    #[serde(rename = "AES-128-at-rest")]
    Aes128AtRest,
    #[serde(rename = "AES-256-at-rest")]
    Aes256AtRest,
    #[serde(rename = "AES-128-GCM")]
    Aes128Gcm,
    #[serde(rename = "AES-256-GCM")]
    Aes256Gcm,
    #[serde(rename = "TLS-1.2-in-transit")]
    Tls12InTransit,
    #[serde(rename = "TLS-1.3-in-transit")]
    Tls13InTransit,
    #[serde(rename = "ChaCha20-Poly1305")]
    ChaCha20Poly1305,
    #[serde(rename = "RSA-2048")]
    Rsa2048,
    #[serde(rename = "RSA-4096")]
    Rsa4096,
    #[serde(rename = "ECDHE")]
    Ecdhe,
    #[serde(rename = "other")]
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceSource {
    #[serde(rename = "self")]
    SelfAttested,
    Beltic,
    ThirdParty,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HumanOversightMode {
    AutonomousLowRisk,
    HumanReviewPreAction,
    HumanReviewPostAction,
    HumanInitiatedOnly,
    CustomHandover,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AgeRestriction {
    #[serde(rename = "none")]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KybTier {
    #[serde(rename = "tier_0")]
    Tier0,
    #[serde(rename = "tier_1")]
    Tier1,
    #[serde(rename = "tier_2")]
    Tier2,
    #[serde(rename = "tier_3")]
    Tier3,
    #[serde(rename = "tier_4")]
    Tier4,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SafetyRating {
    MinimalRisk,
    LowRisk,
    ModerateRisk,
    HighRisk,
    EvaluationPending,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum VerificationLevel {
    SelfAttested,
    BelticVerified,
    ThirdPartyVerified,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatus {
    Active,
    Suspended,
    Revoked,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Proof {
    #[serde(rename = "type")]
    pub proof_type: ProofType,
    pub created: String, // RFC3339
    pub verification_method: String,
    pub proof_purpose: ProofPurpose,
    pub proof_value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProofType {
    Ed25519Signature2020,
    JsonWebSignature2020,
    EcdsaSecp256k1Signature2019,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum ProofPurpose {
    AssertionMethod,
    Authentication,
    KeyAgreement,
}

impl AgentCredential {
    /// Create a new credential with self-signing defaults
    pub fn new_with_defaults(
        agent_name: String,
        agent_version: String,
        fingerprint: String,
        issuer_did: String,
    ) -> Self {
        let now = Utc::now();
        let credential_id = Uuid::new_v4();
        let today = now.format("%Y-%m-%d").to_string();
        let issuance = now.to_rfc3339();
        let expiration = (now + chrono::Duration::days(90)).to_rfc3339();

        // Strip sha256: prefix if present (schema expects just hex hash)
        let clean_fingerprint = fingerprint
            .strip_prefix("sha256:")
            .unwrap_or(&fingerprint)
            .to_string();

        Self {
            schema: Some("https://schema.beltic.com/agent/v1/agent-credential-v1.schema.json".to_string()),
            schema_version: "1.0".to_string(),
            agent_id: Uuid::new_v4(),
            agent_name: agent_name.clone(),
            agent_version,
            agent_description: format!(
                "{} is an AI agent that provides intelligent assistance to users. \
                This credential attests to its identity and capabilities.",
                agent_name
            ),
            first_release_date: today.clone(),
            current_status: AgentStatus::Alpha,
            developer_credential_id: Uuid::nil(),
            developer_credential_verified: false,
            primary_model_provider: ModelProvider::Anthropic,
            primary_model_family: ModelFamily::Claude35Sonnet,
            model_context_window: 200000,
            modality_support: vec![Modality::Text],
            language_capabilities: vec!["en".to_string()],
            architecture_type: ArchitectureType::SingleAgent,
            system_config_fingerprint: clean_fingerprint,
            system_config_last_updated: today.clone(),
            deployment_environment: DeploymentEnvironment {
                environment_type: DeploymentEnvType::CloudManaged,
                cloud_provider: CloudProvider::None,
                primary_region: Some("US".to_string()),
                compliance_notes: None,
            },
            // Must have at least one item per schema - default to GDPR for general privacy
            compliance_certifications: Some(vec![ComplianceCert::GdprCompliant]),
            data_location_profile: DataLocationProfile {
                storage_regions: vec!["US".to_string()],
                processing_regions: vec!["US".to_string()],
                backup_regions: None,
                notes: None,
            },
            tools_list: None,
            tools_last_audited: None,
            data_categories_processed: vec![DataCategory::None],
            data_retention_max_period: "P30D".to_string(),
            data_retention_by_category: None,
            training_data_usage: TrainingDataUsage::Never,
            pii_detection_enabled: false,
            pii_redaction_capability: PiiRedactionCapability::None,
            pii_redaction_pipeline: None,
            data_encryption_standards: vec![EncryptionStandard::Tls13InTransit],
            // Self-attested safety metrics (score 0 = not evaluated)
            harmful_content_refusal_score: 0.0,
            harmful_content_benchmark_name: "self-evaluation".to_string(),
            harmful_content_benchmark_version: "0.0.0".to_string(),
            harmful_content_evaluation_date: today.clone(),
            harmful_content_assurance_source: AssuranceSource::SelfAttested,
            prompt_injection_robustness_score: 0.0,
            prompt_injection_benchmark_name: "self-evaluation".to_string(),
            prompt_injection_benchmark_version: "0.0.0".to_string(),
            prompt_injection_evaluation_date: today.clone(),
            prompt_injection_assurance_source: AssuranceSource::SelfAttested,
            tool_abuse_robustness_score: None,
            tool_abuse_benchmark_name: None,
            tool_abuse_benchmark_version: None,
            tool_abuse_evaluation_date: None,
            tool_abuse_assurance_source: None,
            pii_leakage_robustness_score: 0.0,
            pii_leakage_benchmark_name: "self-evaluation".to_string(),
            pii_leakage_benchmark_version: "0.0.0".to_string(),
            pii_leakage_evaluation_date: today.clone(),
            pii_leakage_assurance_source: AssuranceSource::SelfAttested,
            incident_response_contact: "security@example.com".to_string(),
            incident_response_slo: "PT4H".to_string(),
            deprecation_policy: "Minimum 30-day notice via email. Migration guide provided.".to_string(),
            update_cadence: UpdateCadence::AsNeeded,
            human_oversight_mode: HumanOversightMode::AutonomousLowRisk,
            fail_safe_behavior: "On error, returns helpful message and logs incident. No automated retries.".to_string(),
            // Must be at least 50 characters per schema
            monitoring_coverage: "Real-time monitoring enabled with logging, error tracking, and basic alerting.".to_string(),
            approved_use_cases: None,
            prohibited_use_cases: None,
            age_restrictions: AgeRestriction::None,
            regulatory_approvals: None,
            kyb_tier_required: KybTier::Tier0,
            credential_issuance_date: issuance,
            credential_expiration_date: expiration,
            overall_safety_rating: SafetyRating::EvaluationPending,
            verification_level: VerificationLevel::SelfAttested,
            credential_id,
            issuer_did: issuer_did.clone(),
            verification_method: format!("{}#key-1", issuer_did),
            credential_status: CredentialStatus::Active,
            revocation_list_url: "https://example.com/.well-known/revocation".to_string(),
            proof: Proof {
                proof_type: ProofType::Ed25519Signature2020,
                created: now.to_rfc3339(),
                verification_method: format!("{}#key-1", issuer_did),
                proof_purpose: ProofPurpose::AssertionMethod,
                // Placeholder meets 40+ char minimum, will be replaced by signing
                proof_value: "placeholder-proof-value-will-be-replaced-by-jws-signature".to_string(),
                challenge: None,
                domain: None,
            },
            http_signing_key_jwk_thumbprint: None,
            key_directory_url: None,
            last_security_audit_date: None,
        }
    }
}
