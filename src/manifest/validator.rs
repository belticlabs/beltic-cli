use anyhow::{anyhow, Result};
use regex::Regex;
use serde_json::Value;
use uuid::Uuid;

use crate::manifest::schema::AgentManifest;

/// Validation result with errors and warnings
#[derive(Debug, Default)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub missing_fields: Vec<String>,
}

impl ValidationResult {
    pub fn new() -> Self {
        Self {
            is_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            missing_fields: Vec::new(),
        }
    }

    pub fn add_error(&mut self, error: String) {
        self.errors.push(error);
        self.is_valid = false;
    }

    pub fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }

    pub fn add_missing_field(&mut self, field: String) {
        self.missing_fields.push(field);
        self.is_valid = false;
    }
}

/// Validate an agent manifest against Beltic v1 schema
pub fn validate_manifest(manifest: &AgentManifest) -> ValidationResult {
    let mut result = ValidationResult::new();

    // Check for placeholder values (TODOs)
    check_no_todos(manifest, &mut result);

    // Validate required fields
    validate_required_fields(manifest, &mut result);

    // Validate field formats
    validate_field_formats(manifest, &mut result);

    // Validate business logic
    validate_business_logic(manifest, &mut result);

    // Check safety metrics
    validate_safety_metrics(manifest, &mut result);

    result
}

/// Check that no TODO placeholders remain
fn check_no_todos(manifest: &AgentManifest, result: &mut ValidationResult) {
    let json_str = serde_json::to_string(manifest).unwrap_or_default();

    if json_str.contains("TODO") {
        result.add_error("Manifest contains TODO placeholders that must be replaced".to_string());
    }

    // Check specific fields that commonly have TODOs
    if manifest.agent_name.starts_with("TODO") || manifest.agent_name == "my-agent" {
        result.add_error("Agent name must be set to a meaningful value".to_string());
    }

    if manifest.agent_description.starts_with("TODO") || manifest.agent_description.len() < 50 {
        result.add_error(
            "Agent description must be at least 50 characters and not a placeholder".to_string(),
        );
    }

    if manifest.incident_response_contact.starts_with("TODO")
        || manifest.incident_response_contact == "security@example.com"
    {
        result.add_error(
            "Incident response contact must be a valid email address for your organization"
                .to_string(),
        );
    }

    if manifest.developer_credential_id == Uuid::nil() {
        result.add_warning("Developer credential ID is not set. You'll need to obtain this from the Beltic platform".to_string());
    }
}

/// Validate all required fields are present and non-empty
fn validate_required_fields(manifest: &AgentManifest, result: &mut ValidationResult) {
    // Identity fields
    if manifest.agent_name.is_empty() {
        result.add_missing_field("agentName".to_string());
    }
    if manifest.agent_version.is_empty() {
        result.add_missing_field("agentVersion".to_string());
    }
    if manifest.agent_description.is_empty() {
        result.add_missing_field("agentDescription".to_string());
    }
    if manifest.first_release_date.is_empty() {
        result.add_missing_field("firstReleaseDate".to_string());
    }

    // Technical fields
    if manifest.primary_model_provider.is_empty() {
        result.add_missing_field("primaryModelProvider".to_string());
    }
    if manifest.primary_model_family.is_empty() {
        result.add_missing_field("primaryModelFamily".to_string());
    }
    if manifest.deployment_environment.is_empty() {
        result.add_missing_field("deploymentEnvironment".to_string());
    }
    if manifest.system_config_fingerprint.is_empty() {
        result.add_missing_field("systemConfigFingerprint".to_string());
    }

    // Data handling
    if manifest.data_categories_processed.is_empty() {
        result.add_missing_field("dataCategoriesProcessed".to_string());
    }
    if manifest.data_retention_max_period.is_empty() {
        result.add_missing_field("dataRetentionMaxPeriod".to_string());
    }
    if manifest.data_encryption_standards.is_empty() {
        result.add_missing_field("dataEncryptionStandards".to_string());
    }

    // Operations
    if manifest.incident_response_contact.is_empty() {
        result.add_missing_field("incidentResponseContact".to_string());
    }
    if manifest.incident_response_slo.is_empty() {
        result.add_missing_field("incidentResponseSLO".to_string());
    }
    if manifest.deprecation_policy.is_empty() {
        result.add_missing_field("deprecationPolicy".to_string());
    }
    if manifest.fail_safe_behavior.is_empty() {
        result.add_missing_field("failSafeBehavior".to_string());
    }
    if manifest.monitoring_coverage.is_empty() {
        result.add_missing_field("monitoringCoverage".to_string());
    }

    // Data location
    if manifest.data_location_profile.storage_regions.is_empty() {
        result.add_missing_field("dataLocationProfile.storageRegions".to_string());
    }
    if manifest.data_location_profile.processing_regions.is_empty() {
        result.add_missing_field("dataLocationProfile.processingRegions".to_string());
    }

    // Modalities and languages
    if manifest.modality_support.is_empty() {
        result.add_missing_field("modalitySupport".to_string());
    }
    if manifest.language_capabilities.is_empty() {
        result.add_missing_field("languageCapabilities".to_string());
    }

    // Conditional tool fields
    if let Some(tools) = &manifest.tools_list {
        if !tools.is_empty() && manifest.tools_last_audited.is_none() {
            result.add_missing_field("toolsLastAudited".to_string());
        }
    }
}

/// Validate field formats
fn validate_field_formats(manifest: &AgentManifest, result: &mut ValidationResult) {
    // Validate semantic version
    let version_regex = Regex::new(r"^\d+\.\d+\.\d+(-[\w\.]+)?(\+[\w\.]+)?$").unwrap();
    if !version_regex.is_match(&manifest.agent_version) {
        result.add_error(format!(
            "Invalid version format: {}. Must be semantic version (e.g., 1.0.0)",
            manifest.agent_version
        ));
    }

    // Validate email
    if !manifest.incident_response_contact.contains('@')
        || !manifest.incident_response_contact.contains('.')
    {
        result.add_error(format!(
            "Invalid email address: {}",
            manifest.incident_response_contact
        ));
    }

    // Validate ISO date
    let date_regex = Regex::new(r"^\d{4}-\d{2}-\d{2}$").unwrap();
    if !date_regex.is_match(&manifest.first_release_date) {
        result.add_error(format!(
            "Invalid date format: {}. Must be ISO date (YYYY-MM-DD)",
            manifest.first_release_date
        ));
    }
    if !date_regex.is_match(&manifest.system_config_last_updated) {
        result.add_error(format!(
            "Invalid date format for systemConfigLastUpdated: {}",
            manifest.system_config_last_updated
        ));
    }

    // Validate ISO duration
    let duration_regex = Regex::new(r"^P(T?\d+[YMDHMS])+$").unwrap();
    if !duration_regex.is_match(&manifest.data_retention_max_period) {
        result.add_error(format!(
            "Invalid ISO duration: {}. Must be ISO 8601 (e.g., P30D, PT4H)",
            manifest.data_retention_max_period
        ));
    }
    if !duration_regex.is_match(&manifest.incident_response_slo) {
        result.add_error(format!(
            "Invalid ISO duration for SLO: {}",
            manifest.incident_response_slo
        ));
    }

    // Validate fingerprint (64 hex chars)
    if manifest.system_config_fingerprint != "TODO: Will be generated" {
        let fingerprint = manifest.system_config_fingerprint.replace("sha256:", "");
        if fingerprint.len() != 64 || !fingerprint.chars().all(|c| c.is_ascii_hexdigit()) {
            result.add_error(format!(
                "Invalid fingerprint format. Must be 64 hex characters"
            ));
        }
    }

    // Validate language codes (ISO 639-1)
    for lang in &manifest.language_capabilities {
        if lang.len() != 2 {
            result.add_warning(format!(
                "Language code '{}' should be ISO 639-1 (2 letters)",
                lang
            ));
        }
    }

    // Validate region codes (ISO 3166-1 alpha-2)
    for region in &manifest.data_location_profile.storage_regions {
        if region.len() != 2 || !region.chars().all(|c| c.is_ascii_uppercase()) {
            result.add_warning(format!(
                "Region code '{}' should be ISO 3166-1 alpha-2 (e.g., US, CA)",
                region
            ));
        }
    }

    // Validate field lengths
    if manifest.agent_name.len() < 2 || manifest.agent_name.len() > 200 {
        result.add_error(format!(
            "Agent name must be 2-200 characters (current: {})",
            manifest.agent_name.len()
        ));
    }

    if manifest.agent_description.len() < 50 || manifest.agent_description.len() > 1000 {
        result.add_error(format!(
            "Agent description must be 50-1000 characters (current: {})",
            manifest.agent_description.len()
        ));
    }

    if manifest.fail_safe_behavior.len() < 50 || manifest.fail_safe_behavior.len() > 800 {
        result.add_error(format!(
            "Fail-safe behavior must be 50-800 characters (current: {})",
            manifest.fail_safe_behavior.len()
        ));
    }

    if manifest.monitoring_coverage.len() < 50 || manifest.monitoring_coverage.len() > 800 {
        result.add_error(format!(
            "Monitoring coverage must be 50-800 characters (current: {})",
            manifest.monitoring_coverage.len()
        ));
    }
}

/// Validate business logic and consistency
fn validate_business_logic(manifest: &AgentManifest, result: &mut ValidationResult) {
    // Check tools consistency
    if let Some(tools) = &manifest.tools_list {
        if tools.is_empty() && manifest.tools_last_audited.is_some() {
            result.add_warning("toolsLastAudited is set but no tools are defined".to_string());
        }

        for tool in tools {
            if tool.tool_description.len() < 10 || tool.tool_description.len() > 1000 {
                result.add_error(format!(
                    "Tool '{}' description must be 10-1000 characters",
                    tool.tool_name
                ));
            }

            if tool.risk_category == crate::manifest::schema::RiskCategory::Financial
                && !tool.requires_auth
            {
                result.add_warning(format!(
                    "Financial tool '{}' should require authentication",
                    tool.tool_name
                ));
            }
        }
    }

    // Check data handling consistency
    use crate::manifest::schema::{DataCategory, PiiRedactionCapability};

    let has_sensitive_data = manifest.data_categories_processed.iter().any(|c| {
        matches!(
            c,
            DataCategory::Pii
                | DataCategory::Phi
                | DataCategory::Financial
                | DataCategory::GovernmentId
                | DataCategory::ChildrenData
        )
    });

    if has_sensitive_data {
        if !manifest.pii_detection_enabled {
            result.add_warning(
                "PII detection should be enabled when processing sensitive data".to_string(),
            );
        }

        if matches!(
            manifest.pii_redaction_capability,
            PiiRedactionCapability::None
        ) {
            result.add_warning(
                "PII redaction capability should be enabled when processing sensitive data"
                    .to_string(),
            );
        }

        // Should have proper encryption
        let has_encryption = manifest
            .data_encryption_standards
            .iter()
            .any(|s| s.contains("AES") || s.contains("TLS"));
        if !has_encryption {
            result.add_error(
                "Must specify encryption standards when processing sensitive data".to_string(),
            );
        }
    }

    // Check model context window is reasonable
    if manifest.model_context_window == 0 {
        result.add_error("Model context window must be greater than 0".to_string());
    } else if manifest.model_context_window > 2_000_000 {
        result.add_warning(format!(
            "Unusually large context window: {}",
            manifest.model_context_window
        ));
    }

    // Check age restrictions with data categories
    if manifest
        .data_categories_processed
        .contains(&DataCategory::ChildrenData)
    {
        use crate::manifest::schema::AgeRestriction;
        if matches!(manifest.age_restrictions, AgeRestriction::None) {
            result.add_error(
                "Age restrictions must be set when processing children's data".to_string(),
            );
        }
    }
}

/// Validate safety metrics (will be set by Beltic, but check structure)
fn validate_safety_metrics(_manifest: &AgentManifest, result: &mut ValidationResult) {
    // For now, just add a note that safety metrics will be evaluated
    result
        .add_warning("Safety metrics will be evaluated and set by the Beltic platform".to_string());
}

/// Check if a string contains a valid UUID
pub fn is_valid_uuid(s: &str) -> bool {
    Uuid::parse_str(s).is_ok()
}

/// Validate JSON against expected structure
pub fn validate_json_structure(json: &Value) -> Result<()> {
    let obj = json
        .as_object()
        .ok_or_else(|| anyhow!("Manifest must be a JSON object"))?;

    // Check for required top-level fields
    let required_fields = vec![
        "manifestSchemaVersion",
        "agentId",
        "agentName",
        "agentVersion",
        "agentDescription",
        "currentStatus",
    ];

    for field in required_fields {
        if !obj.contains_key(field) {
            anyhow::bail!("Missing required field: {}", field);
        }
    }

    Ok(())
}

/// Get a summary of validation results
pub fn format_validation_summary(result: &ValidationResult) -> String {
    let mut summary = String::new();

    if result.is_valid {
        summary.push_str("✅ Manifest validation passed\n");
    } else {
        summary.push_str("❌ Manifest validation failed\n");
    }

    if !result.missing_fields.is_empty() {
        summary.push_str(&format!(
            "\nMissing {} required fields:\n",
            result.missing_fields.len()
        ));
        for field in &result.missing_fields {
            summary.push_str(&format!("  • {}\n", field));
        }
    }

    if !result.errors.is_empty() {
        summary.push_str(&format!("\nFound {} errors:\n", result.errors.len()));
        for error in &result.errors {
            summary.push_str(&format!("  • {}\n", error));
        }
    }

    if !result.warnings.is_empty() {
        summary.push_str(&format!("\nFound {} warnings:\n", result.warnings.len()));
        for warning in &result.warnings {
            summary.push_str(&format!("  • {}\n", warning));
        }
    }

    summary
}
