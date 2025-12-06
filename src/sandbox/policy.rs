use crate::manifest::schema::{AgentManifest, DataCategory, RiskCategory};
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Security policy extracted from agent manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxPolicy {
    /// Agent identity
    pub agent_name: String,
    pub agent_version: String,

    /// Filesystem access policy
    pub filesystem: FilesystemPolicy,

    /// Network access policy
    pub network: NetworkPolicy,

    /// Tools and capabilities
    pub tools: Vec<ToolPolicy>,

    /// Data handling restrictions
    pub data_restrictions: DataRestrictions,

    /// Human oversight requirements
    pub human_oversight_required: bool,

    /// Approved and prohibited use cases
    pub use_cases: UseCasePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FilesystemPolicy {
    /// Paths that can be read (from fingerprint scope)
    pub allowed_read_paths: Vec<String>,

    /// Paths explicitly excluded
    pub blocked_paths: Vec<String>,

    /// Root directory for the agent
    pub root_directory: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPolicy {
    /// Allowed API domains (extracted from model providers + tools)
    pub allowed_domains: Vec<String>,

    /// Prohibited domains (blacklist)
    pub prohibited_domains: Vec<String>,

    /// Whether external API access is permitted
    pub external_api_allowed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolPolicy {
    pub tool_id: String,
    pub tool_name: String,
    pub risk_category: String,
    pub requires_auth: bool,
    pub requires_human_approval: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataRestrictions {
    /// Data categories that can be processed
    pub allowed_data_categories: Vec<String>,

    /// Whether PII detection must be enabled
    pub pii_detection_required: bool,

    /// Maximum data retention period
    pub max_retention_period: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UseCasePolicy {
    pub approved: Vec<String>,
    pub prohibited: Vec<String>,
}

/// Extract sandbox policy from agent manifest
pub fn extract_policy(manifest: &AgentManifest) -> Result<SandboxPolicy> {
    // Extract filesystem policy from fingerprint metadata
    let filesystem = extract_filesystem_policy(manifest);

    // Extract network policy from model provider and tools
    let network = extract_network_policy(manifest);

    // Extract tool policies
    let tools = extract_tool_policies(manifest);

    // Extract data restrictions
    let data_restrictions = extract_data_restrictions(manifest);

    // Determine if human oversight is required
    let human_oversight_required = matches!(
        manifest.human_oversight_mode,
        crate::manifest::schema::HumanOversightMode::HumanReviewPreAction
            | crate::manifest::schema::HumanOversightMode::HumanInitiatedOnly
    );

    // Extract use cases
    let use_cases = UseCasePolicy {
        approved: manifest.approved_use_cases.clone().unwrap_or_default(),
        prohibited: manifest.prohibited_use_cases.clone().unwrap_or_default(),
    };

    Ok(SandboxPolicy {
        agent_name: manifest.agent_name.clone(),
        agent_version: manifest.agent_version.clone(),
        filesystem,
        network,
        tools,
        data_restrictions,
        human_oversight_required,
        use_cases,
    })
}

fn extract_filesystem_policy(manifest: &AgentManifest) -> FilesystemPolicy {
    let mut allowed_read_paths = Vec::new();
    let mut blocked_paths = Vec::new();
    let mut root_directory = None;

    if let Some(ref fp_metadata) = manifest.fingerprint_metadata {
        allowed_read_paths = fp_metadata.scope.paths.included.clone();
        blocked_paths = fp_metadata.scope.paths.excluded.clone();
        root_directory = fp_metadata.scope.paths.root.clone();
    }

    // Default to some reasonable paths if nothing specified
    if allowed_read_paths.is_empty() {
        allowed_read_paths = vec![
            "./data/**".to_string(),
            "./config/**".to_string(),
            "./src/**".to_string(),
        ];
    }

    // Always block sensitive system paths
    blocked_paths.extend(vec![
        "/etc/**".to_string(),
        "/sys/**".to_string(),
        "/proc/**".to_string(),
        "**/.env".to_string(),
        "**/.git/**".to_string(),
        "**/node_modules/**".to_string(),
    ]);

    FilesystemPolicy {
        allowed_read_paths,
        blocked_paths,
        root_directory,
    }
}

fn extract_network_policy(manifest: &AgentManifest) -> NetworkPolicy {
    let mut allowed_domains = Vec::new();

    // Add primary model provider domains
    match manifest.primary_model_provider.to_lowercase().as_str() {
        provider if provider.contains("anthropic") => {
            allowed_domains.push("api.anthropic.com".to_string());
        }
        provider if provider.contains("openai") => {
            allowed_domains.push("api.openai.com".to_string());
        }
        provider if provider.contains("google") => {
            allowed_domains.push("generativelanguage.googleapis.com".to_string());
        }
        _ => {}
    }

    // Check if tools indicate external API usage
    let has_external_tools = manifest
        .tools_list
        .as_ref()
        .map(|tools| {
            tools.iter().any(|t| {
                matches!(t.risk_category, RiskCategory::External)
                    || t.tool_description.to_lowercase().contains("api")
                    || t.tool_description.to_lowercase().contains("http")
            })
        })
        .unwrap_or(false);

    // Build prohibited domains list (common malicious/suspicious patterns)
    let prohibited_domains = vec![
        "pastebin.com".to_string(),
        "hastebin.com".to_string(),
        "ix.io".to_string(),
        "0x0.st".to_string(),
        // Add more as needed
    ];

    NetworkPolicy {
        allowed_domains,
        prohibited_domains,
        external_api_allowed: has_external_tools,
    }
}

fn extract_tool_policies(manifest: &AgentManifest) -> Vec<ToolPolicy> {
    manifest
        .tools_list
        .as_ref()
        .map(|tools| {
            tools
                .iter()
                .map(|t| ToolPolicy {
                    tool_id: t.tool_id.clone(),
                    tool_name: t.tool_name.clone(),
                    risk_category: format!("{:?}", t.risk_category),
                    requires_auth: t.requires_auth,
                    requires_human_approval: t.requires_human_approval,
                })
                .collect()
        })
        .unwrap_or_default()
}

fn extract_data_restrictions(manifest: &AgentManifest) -> DataRestrictions {
    let allowed_data_categories: Vec<String> = manifest
        .data_categories_processed
        .iter()
        .map(|cat| format!("{:?}", cat))
        .collect();

    let pii_detection_required = manifest
        .data_categories_processed
        .iter()
        .any(|cat| matches!(cat, DataCategory::Pii | DataCategory::Phi));

    DataRestrictions {
        allowed_data_categories,
        pii_detection_required,
        max_retention_period: manifest.data_retention_max_period.clone(),
    }
}
