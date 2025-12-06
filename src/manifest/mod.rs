pub mod config;
pub mod credential;
pub mod detector;
pub mod fingerprint;
pub mod prompts;
pub mod schema;
pub mod templates;
pub mod validator;

use anyhow::Result;
use chrono::Utc;
use std::fs;
use std::path::Path;
use uuid::Uuid;

use crate::manifest::config::BelticConfig;
use crate::manifest::credential::{
    AgentCredential, AgentStatus as CredAgentStatus, ArchitectureType as CredArchType,
    ComplianceCert, DataCategory as CredDataCategory, Modality as CredModality,
};
use crate::manifest::detector::detect_project_info;
use crate::manifest::fingerprint::{generate_fingerprint, FingerprintOptions};
use crate::manifest::schema::{
    AgentManifest, AgentStatus, ArchitectureType, DataCategory, GenerationMetadata, Modality,
};

/// Options for manifest initialization
#[derive(Debug, Clone)]
pub struct InitOptions {
    pub output_path: Option<String>,
    pub config_path: Option<String>,
    pub include_patterns: Option<Vec<String>>,
    pub exclude_patterns: Option<Vec<String>>,
    pub deployment_type: Option<String>,
    pub developer_id: Option<Uuid>,
    pub force: bool,
    pub interactive: bool,
    pub validate: bool,
    /// Output schema-compliant AgentCredential instead of AgentManifest
    pub credential: bool,
    /// Issuer DID for self-signed credentials
    pub issuer_did: Option<String>,
}

impl Default for InitOptions {
    fn default() -> Self {
        Self {
            output_path: None,
            config_path: None,
            include_patterns: None,
            exclude_patterns: None,
            deployment_type: None,
            developer_id: None,
            force: false,
            interactive: true, // Default to interactive mode
            validate: true,    // Default to validating
            credential: false, // Default to manifest output
            issuer_did: None,
        }
    }
}

/// Initialize a new agent manifest or credential
pub fn init_manifest(options: &InitOptions) -> Result<()> {
    // Route to credential generation if --credential flag is set
    if options.credential {
        return init_credential(options);
    }

    // Use enhanced version if interactive mode is enabled (default)
    if options.interactive {
        init_manifest_interactive(options)
    } else {
        init_manifest_noninteractive(options)
    }
}

/// Initialize manifest with interactive prompts
fn init_manifest_interactive(options: &InitOptions) -> Result<()> {
    use crate::manifest::prompts::InteractivePrompts;
    use crate::manifest::templates::ManifestTemplates;
    use crate::manifest::validator::validate_manifest;
    use console::style;

    let base_dir = std::env::current_dir()?;
    let output_path = options
        .output_path
        .as_ref()
        .map(|p| Path::new(p).to_path_buf())
        .unwrap_or_else(|| base_dir.join("agent-manifest.json"));

    // Check if manifest already exists
    if output_path.exists() && !options.force {
        anyhow::bail!(
            "Manifest already exists at {}. Use --force to overwrite.",
            output_path.display()
        );
    }

    println!(
        "{}",
        style("🚀 Beltic Agent Manifest Generator").bold().cyan()
    );

    // Auto-detect project information first
    let detection_results = detect_project_info(&base_dir)?;

    // Initialize interactive prompts
    let prompts = InteractivePrompts::new();

    // 1. Agent Identity
    let defaults = (
        detection_results
            .project_name
            .as_deref()
            .unwrap_or("my-agent"),
        detection_results
            .project_version
            .as_deref()
            .unwrap_or("0.1.0"),
        detection_results
            .project_description
            .as_deref()
            .unwrap_or(""),
    );
    let (name, version, description, status) = prompts.prompt_identity(Some(defaults))?;

    // 2. Technical Profile
    let technical_profile = prompts.prompt_technical_profile()?;

    // 3. Tools
    let tools = prompts.prompt_tools()?;

    // 4. Data Handling
    let data_handling = prompts.prompt_data_handling()?;

    // 5. Operations
    let operations = prompts.prompt_operations()?;

    // 6. Developer ID
    let developer_id = if options.developer_id.is_some() {
        options.developer_id
    } else {
        prompts.prompt_developer_id()?
    };

    // Generate fingerprint
    println!("\n✓ Generating codebase fingerprint...");
    let config = load_or_create_config(&base_dir, options)?;
    let fingerprint_options = if let Some(ref includes) = options.include_patterns {
        FingerprintOptions {
            include_patterns: includes.clone(),
            exclude_patterns: options.exclude_patterns.clone().unwrap_or_default(),
            root_path: base_dir.clone(),
            include_dependencies: true,
            respect_gitignore: true,
        }
    } else {
        FingerprintOptions::from_path_config(&config.agent.paths, base_dir.clone())
    };

    let fingerprint_result = generate_fingerprint(&fingerprint_options)?;
    println!(
        "✓ Generated fingerprint: {} ({} files)",
        style(&fingerprint_result.hash).green(),
        fingerprint_result.file_count
    );

    // Build manifest
    let mut manifest = AgentManifest::new_with_defaults();

    // Apply identity
    manifest.agent_name = name;
    manifest.agent_version = version;
    manifest.agent_description = description;
    manifest.current_status = status;
    manifest.first_release_date = detection_results
        .first_release_date
        .unwrap_or_else(|| chrono::Utc::now().format("%Y-%m-%d").to_string());

    // Apply technical profile
    manifest.primary_model_provider = technical_profile.primary_model_provider;
    manifest.primary_model_family = technical_profile.primary_model_family;
    manifest.model_context_window = technical_profile.model_context_window;
    manifest.deployment_environment = technical_profile.deployment_environment;
    manifest.architecture_type = technical_profile.architecture_type;
    manifest.modality_support = technical_profile.modality_support;
    manifest.language_capabilities = technical_profile.language_capabilities;

    // Apply tools
    manifest.tools_list = tools.clone();
    if tools.is_some() {
        manifest.tools_last_audited = Some(chrono::Utc::now().format("%Y-%m-%d").to_string());
    }

    // Apply data handling
    manifest.data_categories_processed = data_handling.data_categories_processed;
    manifest.data_retention_max_period = data_handling.data_retention_max_period;
    manifest.training_data_usage = data_handling.training_data_usage;
    manifest.pii_detection_enabled = data_handling.pii_detection_enabled;
    manifest.pii_redaction_capability = data_handling.pii_redaction_capability;
    manifest.data_encryption_standards = data_handling.data_encryption_standards;

    // Apply operations
    manifest.incident_response_contact = operations.incident_response_contact;
    manifest.incident_response_slo = operations.incident_response_slo;
    manifest.deprecation_policy = operations.deprecation_policy;
    manifest.update_cadence = operations.update_cadence;
    manifest.human_oversight_mode = operations.human_oversight_mode;
    manifest.fail_safe_behavior = operations.fail_safe_behavior;
    manifest.monitoring_coverage = operations.monitoring_coverage;

    // Apply defaults for remaining fields
    manifest.system_config_fingerprint = fingerprint_result.hash;
    manifest.fingerprint_metadata = Some(fingerprint_result.metadata);
    manifest.system_config_last_updated = chrono::Utc::now().format("%Y-%m-%d").to_string();

    // Data location profile
    manifest.data_location_profile.storage_regions = vec!["US".to_string()];
    manifest.data_location_profile.processing_regions = vec!["US".to_string()];

    // Developer credential
    manifest.developer_credential_id = developer_id.unwrap_or_else(Uuid::nil);
    manifest.developer_credential_verified = false;

    // Use cases
    manifest.approved_use_cases = Some(ManifestTemplates::default_approved_use_cases(
        &manifest.architecture_type,
    ));
    manifest.prohibited_use_cases = Some(ManifestTemplates::default_prohibited_use_cases());

    // Apply deployment context if detected
    if detection_results.deployment_context.is_some() {
        manifest.deployment_context = detection_results.deployment_context;
    }

    // Metadata
    manifest.metadata = Some(GenerationMetadata {
        generated_by: format!("beltic v{}", env!("CARGO_PKG_VERSION")),
        generated_at: Utc::now(),
        auto_detected: detection_results.detection_sources,
    });

    // Validate before writing
    if options.validate {
        let validation_result = validate_manifest(&manifest);
        let warnings = validation_result.warnings.clone();
        let missing_count = validation_result.missing_fields.len();

        if !validation_result.is_valid && missing_count > 0 {
            prompts.display_validation(missing_count, warnings)?;
            anyhow::bail!("Manifest validation failed. Please fix errors and try again.");
        } else {
            prompts.display_validation(0, warnings)?;
        }
    }

    // Write manifest
    let json = serde_json::to_string_pretty(&manifest)?;
    fs::write(&output_path, json)?;

    println!("\n✓ Created {}", style(output_path.display()).green());

    // Write .beltic.yaml if it doesn't exist
    let beltic_yaml_path = base_dir.join(".beltic.yaml");
    if !beltic_yaml_path.exists() {
        config.save_to_file(&beltic_yaml_path)?;
        println!("✓ Created {}", style(beltic_yaml_path.display()).green());
    }

    Ok(())
}

/// Initialize manifest without prompts (non-interactive mode)
fn init_manifest_noninteractive(options: &InitOptions) -> Result<()> {
    use crate::manifest::schema::DeploymentType;
    use crate::manifest::templates::generate_complete_defaults;
    use crate::manifest::validator::validate_manifest;

    let base_dir = std::env::current_dir()?;
    let output_path = options
        .output_path
        .as_ref()
        .map(|p| Path::new(p).to_path_buf())
        .unwrap_or_else(|| base_dir.join("agent-manifest.json"));

    // Check if manifest already exists
    if output_path.exists() && !options.force {
        anyhow::bail!(
            "Manifest already exists at {}. Use --force to overwrite.",
            output_path.display()
        );
    }

    println!("✓ Initializing agent manifest (non-interactive)...");

    // Load or create config
    let config = if let Some(config_path) = &options.config_path {
        let path = Path::new(config_path);
        if path.exists() {
            println!("✓ Found config file: {}", config_path);
            BelticConfig::from_file(path)?
        } else {
            anyhow::bail!("Config file not found: {}", config_path);
        }
    } else if let Some(config) = BelticConfig::find_and_load(&base_dir)? {
        println!("✓ Found .beltic.yaml configuration");
        config
    } else {
        // Create default config based on deployment type
        let deployment_type = options.deployment_type.as_deref().unwrap_or("standalone");
        match deployment_type {
            "monorepo" => {
                let agent_path = base_dir
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("agent");
                BelticConfig::default_monorepo(agent_path)
            }
            "plugin" => BelticConfig::default_plugin(),
            "serverless" => BelticConfig::default_serverless(),
            _ => BelticConfig::default_standalone(),
        }
    };

    // Auto-detect project information
    println!("✓ Detecting project information...");
    let detection_results = detect_project_info(&base_dir)?;

    // Get name and version with defaults (no TODOs)
    let name = detection_results.project_name.clone().unwrap_or_else(|| {
        base_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("agent")
            .to_string()
    });

    let version = detection_results
        .project_version
        .clone()
        .unwrap_or_else(|| "0.1.0".to_string());

    println!("✓ Using agent name: {}", name);
    println!("✓ Using version: {}", version);

    // Determine deployment type
    let deployment_type = match options.deployment_type.as_deref() {
        Some("monorepo") => DeploymentType::Monorepo,
        Some("plugin") => DeploymentType::Plugin,
        Some("serverless") => DeploymentType::Serverless,
        Some("embedded") => DeploymentType::Embedded,
        _ => detection_results
            .deployment_type
            .unwrap_or(DeploymentType::Standalone),
    };

    // Determine architecture type
    let architecture = detection_results
        .architecture_type
        .unwrap_or(crate::manifest::schema::ArchitectureType::SingleAgent);

    // Generate fingerprint
    println!("✓ Generating codebase fingerprint...");
    let fingerprint_options = if let Some(ref includes) = options.include_patterns {
        FingerprintOptions {
            include_patterns: includes.clone(),
            exclude_patterns: options.exclude_patterns.clone().unwrap_or_default(),
            root_path: base_dir.clone(),
            include_dependencies: true,
            respect_gitignore: true,
        }
    } else {
        FingerprintOptions::from_path_config(&config.agent.paths, base_dir.clone())
    };

    let fingerprint_result = generate_fingerprint(&fingerprint_options)?;
    println!(
        "✓ Generated fingerprint ({} files, {})",
        fingerprint_result.file_count, fingerprint_result.hash
    );

    // Create manifest with complete defaults (no TODOs)
    let mut manifest = generate_complete_defaults(name, version, architecture, deployment_type);

    // Apply fingerprint
    manifest.system_config_fingerprint = fingerprint_result.hash.clone();
    manifest.fingerprint_metadata = Some(fingerprint_result.metadata);
    manifest.system_config_last_updated = chrono::Utc::now().format("%Y-%m-%d").to_string();

    // Apply detected/provided values
    if let Some(desc) = detection_results.project_description {
        if desc.len() >= 50 && desc.len() <= 1000 {
            manifest.agent_description = desc;
        }
    }

    if let Some(date) = detection_results.first_release_date {
        manifest.first_release_date = date;
    } else {
        manifest.first_release_date = chrono::Utc::now().format("%Y-%m-%d").to_string();
    }

    // Apply deployment context
    if detection_results.deployment_context.is_some() {
        manifest.deployment_context = detection_results.deployment_context;
    }

    // Apply detected capabilities
    if !detection_results.modality_support.is_empty() {
        manifest.modality_support = detection_results.modality_support;
    }
    if !detection_results.language_capabilities.is_empty() {
        manifest.language_capabilities = detection_results.language_capabilities;
    }
    if !detection_results.data_categories.is_empty() {
        manifest.data_categories_processed = detection_results.data_categories;
    } else {
        // Default to none if not detected
        manifest.data_categories_processed = vec![crate::manifest::schema::DataCategory::None];
    }

    // Apply developer ID if provided
    if let Some(dev_id) = options.developer_id {
        manifest.developer_credential_id = dev_id;
        manifest.developer_credential_verified = false;
    }

    // Generate metadata
    manifest.metadata = Some(GenerationMetadata {
        generated_by: format!("beltic v{}", env!("CARGO_PKG_VERSION")),
        generated_at: Utc::now(),
        auto_detected: detection_results.detection_sources,
    });

    // Validate if requested
    if options.validate {
        let validation_result = validate_manifest(&manifest);
        if !validation_result.is_valid {
            println!("\n⚠ Validation warnings:");
            for warning in &validation_result.warnings {
                println!("  • {}", warning);
            }
            for error in &validation_result.errors {
                println!("  ✗ {}", error);
            }
        }
    }

    // Write manifest
    let json = serde_json::to_string_pretty(&manifest)?;
    fs::write(&output_path, json)?;

    println!("✓ Created {}", output_path.display());

    // Write .beltic.yaml if it doesn't exist
    let beltic_yaml_path = base_dir.join(".beltic.yaml");
    if !beltic_yaml_path.exists() {
        config.save_to_file(&beltic_yaml_path)?;
        println!("✓ Created {}", beltic_yaml_path.display());
    }

    println!("\nNext steps:");
    println!("1. Review {} and adjust as needed", output_path.display());
    if manifest.developer_credential_id == Uuid::nil() {
        println!("2. Obtain developer credential ID from Beltic platform");
    }
    println!("3. Run 'beltic fingerprint' after code changes");
    println!("4. Sign manifest with 'beltic sign'");

    Ok(())
}

/// Helper function to load or create config
fn load_or_create_config(base_dir: &Path, options: &InitOptions) -> Result<BelticConfig> {
    if let Some(config_path) = &options.config_path {
        let path = Path::new(config_path);
        if path.exists() {
            BelticConfig::from_file(path)
        } else {
            anyhow::bail!("Config file not found: {}", config_path);
        }
    } else if let Some(config) = BelticConfig::find_and_load(base_dir)? {
        Ok(config)
    } else {
        // Create default config based on deployment type
        let deployment_type = options.deployment_type.as_deref().unwrap_or("standalone");
        Ok(match deployment_type {
            "monorepo" => {
                let agent_path = base_dir
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("agent");
                BelticConfig::default_monorepo(agent_path)
            }
            "plugin" => BelticConfig::default_plugin(),
            "serverless" => BelticConfig::default_serverless(),
            _ => BelticConfig::default_standalone(),
        })
    }
}

/// Update fingerprint in existing manifest
pub fn update_fingerprint(manifest_path: Option<&str>) -> Result<()> {
    let base_dir = std::env::current_dir()?;
    let default_path = base_dir.join("agent-manifest.json");
    let manifest_path = manifest_path.map(Path::new).unwrap_or(&default_path);

    if !manifest_path.exists() {
        anyhow::bail!("Manifest not found at {}", manifest_path.display());
    }

    // Read existing manifest
    let content = fs::read_to_string(&manifest_path)?;
    let mut manifest: serde_json::Value = serde_json::from_str(&content)?;

    // Get current fingerprint
    let current_fingerprint = manifest
        .get("systemConfigFingerprint")
        .and_then(|f| f.as_str())
        .map(|s| s.to_string());

    println!("✓ Current fingerprint: {:?}", current_fingerprint);

    // Generate new fingerprint
    println!("✓ Generating new fingerprint...");

    // Try to load config
    let config =
        BelticConfig::find_and_load(&base_dir)?.unwrap_or_else(BelticConfig::default_standalone);

    let fingerprint_options =
        FingerprintOptions::from_path_config(&config.agent.paths, base_dir.clone());

    let fingerprint_result = generate_fingerprint(&fingerprint_options)?;

    // Update manifest
    if let Some(obj) = manifest.as_object_mut() {
        obj.insert(
            "systemConfigFingerprint".to_string(),
            serde_json::json!(fingerprint_result.hash),
        );
        obj.insert(
            "fingerprintMetadata".to_string(),
            serde_json::to_value(fingerprint_result.metadata)?,
        );
        obj.insert(
            "systemConfigLastUpdated".to_string(),
            serde_json::json!(Utc::now().format("%Y-%m-%d").to_string()),
        );
    }

    // Write updated manifest
    let updated = serde_json::to_string_pretty(&manifest)?;
    fs::write(&manifest_path, updated)?;

    println!("✓ New fingerprint: {}", fingerprint_result.hash);
    println!("✓ Updated {}", manifest_path.display());

    if current_fingerprint.as_deref() != Some(&fingerprint_result.hash) {
        println!("\nNote: Remember to increment agentVersion if behavior changed");
    }

    Ok(())
}

/// Verify fingerprint without updating the manifest
pub fn verify_fingerprint(manifest_path: Option<&str>) -> Result<()> {
    use console::style;

    let base_dir = std::env::current_dir()?;
    let default_path = base_dir.join("agent-manifest.json");
    let manifest_path = manifest_path.map(Path::new).unwrap_or(&default_path);

    if !manifest_path.exists() {
        anyhow::bail!("Manifest not found at {}", manifest_path.display());
    }

    // Read existing manifest
    let content = fs::read_to_string(&manifest_path)?;
    let manifest: serde_json::Value = serde_json::from_str(&content)?;

    // Get stored fingerprint
    let stored_fingerprint = manifest
        .get("systemConfigFingerprint")
        .and_then(|f| f.as_str())
        .ok_or_else(|| anyhow::anyhow!("No fingerprint found in manifest"))?;

    println!(
        "📋 Stored fingerprint: {}",
        style(stored_fingerprint).cyan()
    );

    // Generate new fingerprint
    println!("🔍 Generating current fingerprint...");

    // Try to load config
    let config =
        BelticConfig::find_and_load(&base_dir)?.unwrap_or_else(BelticConfig::default_standalone);

    let fingerprint_options =
        FingerprintOptions::from_path_config(&config.agent.paths, base_dir.clone());

    let fingerprint_result = generate_fingerprint(&fingerprint_options)?;

    println!(
        "📋 Current fingerprint:  {}",
        style(&fingerprint_result.hash).cyan()
    );
    println!("📊 Files processed: {}", fingerprint_result.file_count);

    // Compare fingerprints
    if stored_fingerprint == fingerprint_result.hash {
        println!(
            "\n{}",
            style("✓ VERIFIED: Fingerprints match!").green().bold()
        );
        println!("  The codebase has not changed since the manifest was created.");
    } else {
        println!(
            "\n{}",
            style("✗ MISMATCH: Fingerprints differ!").red().bold()
        );
        println!("  The codebase has changed since the manifest was created.");
        println!("\n{}", style("Recommendations:").yellow());
        println!("  1. Review what has changed");
        println!("  2. Run 'beltic fingerprint' to update the manifest");
        println!("  3. Consider incrementing the agent version if behavior changed");

        // Exit with error code
        anyhow::bail!("Fingerprint verification failed");
    }

    Ok(())
}

// === Credential Generation Functions ===

/// Initialize a schema-compliant agent credential (non-interactive)
pub fn init_credential(options: &InitOptions) -> Result<()> {
    let base_dir = std::env::current_dir()?;
    let output_path = options
        .output_path
        .as_ref()
        .map(|p| Path::new(p).to_path_buf())
        .unwrap_or_else(|| base_dir.join("agent-credential.json"));

    // Check if credential already exists
    if output_path.exists() && !options.force {
        anyhow::bail!(
            "Credential already exists at {}. Use --force to overwrite.",
            output_path.display()
        );
    }

    println!("Initializing agent credential...");

    // Load or create config
    let config = if let Some(config_path) = &options.config_path {
        let path = Path::new(config_path);
        if path.exists() {
            println!("  Found config file: {}", config_path);
            BelticConfig::from_file(path)?
        } else {
            anyhow::bail!("Config file not found: {}", config_path);
        }
    } else if let Some(config) = BelticConfig::find_and_load(&base_dir)? {
        println!("  Found .beltic.yaml configuration");
        config
    } else {
        BelticConfig::default_standalone()
    };

    // Auto-detect project information
    println!("  Detecting project information...");
    let detection_results = detect_project_info(&base_dir)?;

    let name = detection_results.project_name.clone().unwrap_or_else(|| {
        base_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("agent")
            .to_string()
    });

    let version = detection_results
        .project_version
        .clone()
        .unwrap_or_else(|| "0.1.0".to_string());

    println!("  Agent name: {}", name);
    println!("  Version: {}", version);

    // Generate fingerprint
    println!("  Generating codebase fingerprint...");
    let fingerprint_options = if let Some(ref includes) = options.include_patterns {
        FingerprintOptions {
            include_patterns: includes.clone(),
            exclude_patterns: options.exclude_patterns.clone().unwrap_or_default(),
            root_path: base_dir.clone(),
            include_dependencies: true,
            respect_gitignore: true,
        }
    } else {
        FingerprintOptions::from_path_config(&config.agent.paths, base_dir.clone())
    };

    let fingerprint_result = generate_fingerprint(&fingerprint_options)?;
    println!(
        "  Fingerprint: {} ({} files)",
        fingerprint_result.hash, fingerprint_result.file_count
    );

    // Determine issuer DID
    let issuer_did = options.issuer_did.clone().unwrap_or_else(|| {
        format!(
            "did:web:self.{}.local",
            name.to_lowercase().replace(' ', "-")
        )
    });

    // Create credential with defaults
    let mut credential = AgentCredential::new_with_defaults(
        name.clone(),
        version,
        fingerprint_result.hash,
        issuer_did,
    );

    // Apply detected values
    if let Some(desc) = detection_results.project_description {
        if desc.len() >= 50 && desc.len() <= 1000 {
            credential.agent_description = desc;
        }
    }

    if let Some(date) = detection_results.first_release_date {
        credential.first_release_date = date;
    }

    // Convert architecture type
    if let Some(arch) = detection_results.architecture_type {
        credential.architecture_type = convert_architecture_type(&arch);
    }

    // Convert modalities
    if !detection_results.modality_support.is_empty() {
        credential.modality_support = detection_results
            .modality_support
            .iter()
            .map(convert_modality)
            .collect();
    }

    // Convert data categories and update compliance certs accordingly
    if !detection_results.data_categories.is_empty() {
        let converted_categories: Vec<CredDataCategory> = detection_results
            .data_categories
            .iter()
            .map(convert_data_category)
            .collect();

        // Update compliance certifications based on data categories
        // Schema requires specific certs for certain data types
        let mut certs = vec![ComplianceCert::GdprCompliant];

        // PHI data requires HIPAA
        if converted_categories.contains(&CredDataCategory::Phi) {
            certs.push(ComplianceCert::Hipaa);
        }

        // Financial data requires PCI-DSS or SOC2 Type 2
        if converted_categories.contains(&CredDataCategory::Financial) {
            certs.push(ComplianceCert::PciDss);
        }

        // PII data with SOC2 Type 1 for general attestation
        if converted_categories.contains(&CredDataCategory::Pii) {
            certs.push(ComplianceCert::Soc2Type1);
        }

        // Deduplicate
        certs.sort_by(|a, b| format!("{:?}", a).cmp(&format!("{:?}", b)));
        certs.dedup();

        credential.compliance_certifications = Some(certs);
        credential.data_categories_processed = converted_categories;
    }

    // Set language capabilities
    if !detection_results.language_capabilities.is_empty() {
        credential.language_capabilities = detection_results.language_capabilities;
    }

    // Apply developer ID if provided
    if let Some(dev_id) = options.developer_id {
        credential.developer_credential_id = dev_id;
    }

    // Write credential
    let json = serde_json::to_string_pretty(&credential)?;
    fs::write(&output_path, json)?;

    println!("\nCreated {}", output_path.display());
    println!("\nNext steps:");
    if credential.developer_credential_id == Uuid::nil() {
        println!("1. Obtain developer credential from Beltic or create self-signed");
        println!("2. Run: beltic init --developer-id <credential-id>");
    }
    println!(
        "3. Sign credential: beltic sign --payload {}",
        output_path.display()
    );

    // Write .beltic.yaml if it doesn't exist
    let beltic_yaml_path = base_dir.join(".beltic.yaml");
    if !beltic_yaml_path.exists() {
        config.save_to_file(&beltic_yaml_path)?;
        println!("Created {}", beltic_yaml_path.display());
    }

    Ok(())
}

// === Type conversion helpers ===

fn convert_architecture_type(arch: &ArchitectureType) -> CredArchType {
    match arch {
        ArchitectureType::SingleAgent => CredArchType::SingleAgent,
        ArchitectureType::MultiAgent => CredArchType::MultiAgent,
        ArchitectureType::Rag => CredArchType::Rag,
        ArchitectureType::ToolUsing => CredArchType::ToolUsing,
        ArchitectureType::AgenticWorkflow => CredArchType::AgenticWorkflow,
        ArchitectureType::FineTuned => CredArchType::FineTuned,
        ArchitectureType::Hybrid => CredArchType::Hybrid,
    }
}

fn convert_modality(modality: &Modality) -> CredModality {
    match modality {
        Modality::Text => CredModality::Text,
        Modality::Image => CredModality::Image,
        Modality::Audio => CredModality::Audio,
        Modality::Video => CredModality::Video,
        Modality::Code => CredModality::Text, // Map Code to Text
        Modality::StructuredData => CredModality::Text, // Map StructuredData to Text
    }
}

fn convert_data_category(cat: &DataCategory) -> CredDataCategory {
    match cat {
        DataCategory::Pii => CredDataCategory::Pii,
        DataCategory::Phi => CredDataCategory::Phi,
        DataCategory::Financial => CredDataCategory::Financial,
        DataCategory::Biometric => CredDataCategory::Biometric,
        DataCategory::Behavioral => CredDataCategory::Behavioral,
        DataCategory::Authentication => CredDataCategory::Authentication,
        DataCategory::Proprietary => CredDataCategory::Proprietary,
        DataCategory::GovernmentId => CredDataCategory::GovernmentId,
        DataCategory::ChildrenData => CredDataCategory::ChildrenData,
        DataCategory::None => CredDataCategory::None,
    }
}

#[allow(dead_code)]
fn convert_agent_status(status: &AgentStatus) -> CredAgentStatus {
    match status {
        AgentStatus::Alpha => CredAgentStatus::Alpha,
        AgentStatus::Beta => CredAgentStatus::Beta,
        AgentStatus::Production => CredAgentStatus::Production,
        AgentStatus::Deprecated => CredAgentStatus::Deprecated,
        AgentStatus::Retired => CredAgentStatus::Retired,
        AgentStatus::Internal => CredAgentStatus::Alpha, // Map Internal to Alpha
    }
}
