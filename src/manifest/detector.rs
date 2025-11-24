use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::manifest::schema::{
    AgentStatus, ArchitectureType, DataCategory, DeploymentContext, DeploymentType,
    Modality, RepositoryStructure,
};

/// Auto-detection results
#[derive(Debug, Default)]
pub struct DetectionResults {
    pub project_name: Option<String>,
    pub project_version: Option<String>,
    pub project_description: Option<String>,
    pub first_release_date: Option<String>,
    pub git_remote: Option<String>,
    pub primary_language: Option<String>,
    pub architecture_type: Option<ArchitectureType>,
    pub deployment_type: Option<DeploymentType>,
    pub modality_support: Vec<Modality>,
    pub language_capabilities: Vec<String>,
    pub data_categories: Vec<DataCategory>,
    pub deployment_context: Option<DeploymentContext>,
    pub detection_sources: HashMap<String, String>,
}

/// Detect project information from various sources
pub fn detect_project_info(base_dir: &Path) -> Result<DetectionResults> {
    let mut results = DetectionResults::default();

    // Try different detection strategies
    detect_from_cargo_toml(base_dir, &mut results);
    detect_from_package_json(base_dir, &mut results);
    detect_from_git(base_dir, &mut results);
    detect_from_readme(base_dir, &mut results);
    detect_architecture_patterns(base_dir, &mut results);
    detect_deployment_type(base_dir, &mut results);
    detect_language_support(base_dir, &mut results);
    detect_modalities(base_dir, &mut results);

    // Fallback for project name
    if results.project_name.is_none() {
        results.project_name = base_dir
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.to_string());
        results
            .detection_sources
            .insert("project_name".to_string(), "directory name".to_string());
    }

    // Default version if not found
    if results.project_version.is_none() {
        results.project_version = Some("0.1.0".to_string());
        results
            .detection_sources
            .insert("project_version".to_string(), "default".to_string());
    }

    Ok(results)
}

/// Detect from Cargo.toml
fn detect_from_cargo_toml(base_dir: &Path, results: &mut DetectionResults) {
    let cargo_path = base_dir.join("Cargo.toml");
    if !cargo_path.exists() {
        return;
    }

    if let Ok(content) = fs::read_to_string(&cargo_path) {
        if let Ok(cargo_toml) = content.parse::<toml::Value>() {
            // Project name
            if let Some(name) = cargo_toml
                .get("package")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
            {
                results.project_name = Some(name.to_string());
                results
                    .detection_sources
                    .insert("project_name".to_string(), "Cargo.toml".to_string());
            }

            // Version
            if let Some(version) = cargo_toml
                .get("package")
                .and_then(|p| p.get("version"))
                .and_then(|v| v.as_str())
            {
                results.project_version = Some(version.to_string());
                results
                    .detection_sources
                    .insert("project_version".to_string(), "Cargo.toml".to_string());
            }

            // Description
            if let Some(desc) = cargo_toml
                .get("package")
                .and_then(|p| p.get("description"))
                .and_then(|d| d.as_str())
            {
                results.project_description = Some(desc.to_string());
                results
                    .detection_sources
                    .insert("project_description".to_string(), "Cargo.toml".to_string());
            }

            // Check for workspace (monorepo indicator)
            if cargo_toml.get("workspace").is_some() {
                results.deployment_type = Some(DeploymentType::Monorepo);
            }

            results.primary_language = Some("Rust".to_string());
        }
    }
}

/// Detect from package.json
fn detect_from_package_json(base_dir: &Path, results: &mut DetectionResults) {
    let package_path = base_dir.join("package.json");
    if !package_path.exists() {
        return;
    }

    if let Ok(content) = fs::read_to_string(&package_path) {
        if let Ok(package_json) = serde_json::from_str::<serde_json::Value>(&content) {
            // Project name
            if results.project_name.is_none() {
                if let Some(name) = package_json.get("name").and_then(|n| n.as_str()) {
                    results.project_name = Some(name.to_string());
                    results
                        .detection_sources
                        .insert("project_name".to_string(), "package.json".to_string());
                }
            }

            // Version
            if results.project_version.is_none() {
                if let Some(version) = package_json.get("version").and_then(|v| v.as_str()) {
                    results.project_version = Some(version.to_string());
                    results
                        .detection_sources
                        .insert("project_version".to_string(), "package.json".to_string());
                }
            }

            // Description
            if results.project_description.is_none() {
                if let Some(desc) = package_json.get("description").and_then(|d| d.as_str()) {
                    results.project_description = Some(desc.to_string());
                    results
                        .detection_sources
                        .insert("project_description".to_string(), "package.json".to_string());
                }
            }

            // Check for workspaces (monorepo)
            if package_json.get("workspaces").is_some() {
                results.deployment_type = Some(DeploymentType::Monorepo);
            }

            // Check dependencies for AI/ML libraries
            if let Some(deps) = package_json.get("dependencies") {
                detect_from_npm_deps(deps, results);
            }

            if results.primary_language.is_none() {
                results.primary_language = Some("JavaScript/TypeScript".to_string());
            }
        }
    }
}

/// Detect architecture from NPM dependencies
fn detect_from_npm_deps(deps: &serde_json::Value, results: &mut DetectionResults) {
    if let Some(deps_obj) = deps.as_object() {
        let dep_names: Vec<String> = deps_obj.keys().cloned().collect();

        // Check for AI/ML libraries
        if dep_names.iter().any(|d| {
            d.contains("openai")
                || d.contains("langchain")
                || d.contains("anthropic")
                || d.contains("@google-cloud/aiplatform")
        }) {
            if dep_names.iter().any(|d| d.contains("langchain")) {
                results.architecture_type = Some(ArchitectureType::Rag);
            } else {
                results.architecture_type = Some(ArchitectureType::ToolUsing);
            }
        }

        // Check for image processing libraries
        if dep_names
            .iter()
            .any(|d| d.contains("sharp") || d.contains("jimp") || d.contains("canvas"))
        {
            results.modality_support.push(Modality::Image);
        }

        // Check for audio libraries
        if dep_names
            .iter()
            .any(|d| d.contains("audio") || d.contains("wav") || d.contains("mp3"))
        {
            results.modality_support.push(Modality::Audio);
        }
    }
}

/// Detect from Git
fn detect_from_git(base_dir: &Path, results: &mut DetectionResults) {
    // Check if it's a git repo
    if !base_dir.join(".git").exists() {
        return;
    }

    // Get remote URL
    if let Ok(output) = Command::new("git")
        .current_dir(base_dir)
        .args(&["remote", "get-url", "origin"])
        .output()
    {
        if output.status.success() {
            let remote = String::from_utf8_lossy(&output.stdout).trim().to_string();
            results.git_remote = Some(remote.clone());
            results
                .detection_sources
                .insert("git_remote".to_string(), "git remote".to_string());

            // Detect if it's a GitHub/GitLab repo
            if remote.contains("github.com") || remote.contains("gitlab.com") {
                if let Some(context) = &mut results.deployment_context {
                    if let Some(repo_struct) = &mut context.repository_structure {
                        repo_struct.root = remote;
                    }
                } else {
                    results.deployment_context = Some(DeploymentContext {
                        deployment_type: results
                            .deployment_type
                            .clone()
                            .unwrap_or(DeploymentType::Standalone),
                        host_application: None,
                        runtime: None,
                        repository_structure: Some(RepositoryStructure {
                            root: remote,
                            agent_path: ".".to_string(),
                        }),
                    });
                }
            }
        }
    }

    // Get first commit date
    if results.first_release_date.is_none() {
        if let Ok(output) = Command::new("git")
            .current_dir(base_dir)
            .args(&["log", "--reverse", "--format=%ad", "--date=short", "-1"])
            .output()
        {
            if output.status.success() {
                let date = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !date.is_empty() {
                    results.first_release_date = Some(date);
                    results
                        .detection_sources
                        .insert("first_release_date".to_string(), "git log".to_string());
                }
            }
        }
    }
}

/// Detect from README
fn detect_from_readme(base_dir: &Path, results: &mut DetectionResults) {
    let readme_names = ["README.md", "README.MD", "readme.md", "README.txt", "README"];

    for name in &readme_names {
        let readme_path = base_dir.join(name);
        if readme_path.exists() {
            if let Ok(content) = fs::read_to_string(&readme_path) {
                // Extract description from first paragraph if not already set
                if results.project_description.is_none() {
                    // Look for first non-header paragraph
                    let lines: Vec<&str> = content.lines().collect();
                    let mut description = String::new();
                    let mut found_content = false;

                    for line in lines {
                        let trimmed = line.trim();
                        // Skip headers and empty lines
                        if trimmed.starts_with('#') || trimmed.is_empty() {
                            if found_content {
                                break; // End of first paragraph
                            }
                            continue;
                        }
                        found_content = true;
                        if !description.is_empty() {
                            description.push(' ');
                        }
                        description.push_str(trimmed);
                        if description.len() >= 200 {
                            break;
                        }
                    }

                    if !description.is_empty() {
                        // Truncate to fit spec limits (50-1000 chars)
                        if description.len() > 1000 {
                            description.truncate(997);
                            description.push_str("...");
                        }
                        results.project_description = Some(description);
                        results
                            .detection_sources
                            .insert("project_description".to_string(), name.to_string());
                    }
                }

                // Look for keywords indicating architecture/capabilities
                let content_lower = content.to_lowercase();
                if content_lower.contains("rag") || content_lower.contains("retrieval") {
                    results.architecture_type = Some(ArchitectureType::Rag);
                }
                if content_lower.contains("multi-agent") || content_lower.contains("multi agent") {
                    results.architecture_type = Some(ArchitectureType::MultiAgent);
                }
                if content_lower.contains("plugin") || content_lower.contains("extension") {
                    results.deployment_type = Some(DeploymentType::Plugin);
                }
                if content_lower.contains("serverless") || content_lower.contains("lambda") {
                    results.deployment_type = Some(DeploymentType::Serverless);
                }
            }
            break;
        }
    }
}

/// Detect architecture patterns from code
fn detect_architecture_patterns(base_dir: &Path, results: &mut DetectionResults) {
    // Look for common patterns in code files
    let patterns = [
        ("**/*.ts", "typescript"),
        ("**/*.js", "javascript"),
        ("**/*.py", "python"),
        ("**/*.rs", "rust"),
        ("**/*.go", "go"),
        ("**/*.java", "java"),
    ];

    for (pattern, _lang) in patterns {
        if let Ok(paths) = glob::glob(&base_dir.join(pattern).to_string_lossy()) {
            for path in paths.flatten() {
                if let Ok(content) = fs::read_to_string(&path) {
                    // Check for tool usage patterns
                    if content.contains("function_call")
                        || content.contains("tool_call")
                        || content.contains("tools:")
                    {
                        results.architecture_type = Some(ArchitectureType::ToolUsing);
                    }

                    // Check for RAG patterns
                    if content.contains("vector_store")
                        || content.contains("embedding")
                        || content.contains("similarity_search")
                    {
                        results.architecture_type = Some(ArchitectureType::Rag);
                    }

                    // Check for data categories
                    if content.contains("email") || content.contains("phone") {
                        if !results.data_categories.contains(&DataCategory::Pii) {
                            results.data_categories.push(DataCategory::Pii);
                        }
                    }
                    if content.contains("credit_card") || content.contains("payment") {
                        if !results.data_categories.contains(&DataCategory::Financial) {
                            results.data_categories.push(DataCategory::Financial);
                        }
                    }
                }
            }
        }
    }
}

/// Detect deployment type
fn detect_deployment_type(base_dir: &Path, results: &mut DetectionResults) {
    // Already detected? Skip
    if results.deployment_type.is_some() {
        return;
    }

    // Check for serverless configs
    if base_dir.join("serverless.yml").exists()
        || base_dir.join("serverless.yaml").exists()
        || base_dir.join("serverless.json").exists()
    {
        results.deployment_type = Some(DeploymentType::Serverless);
        return;
    }

    // Check for plugin/extension manifests
    if base_dir.join("plugin.json").exists()
        || base_dir.join("extension.json").exists()
        || base_dir.join("manifest.json").exists()
    {
        results.deployment_type = Some(DeploymentType::Plugin);
        return;
    }

    // Check for monorepo indicators
    if base_dir.join("lerna.json").exists()
        || base_dir.join("nx.json").exists()
        || base_dir.join("pnpm-workspace.yaml").exists()
    {
        results.deployment_type = Some(DeploymentType::Monorepo);
        return;
    }

    // Check if we're in a subdirectory of a monorepo
    if let Some(parent) = base_dir.parent() {
        if parent.join("package.json").exists() || parent.join("Cargo.toml").exists() {
            // We might be in a monorepo subdirectory
            results.deployment_type = Some(DeploymentType::Monorepo);
            return;
        }
    }

    // Default to standalone
    results.deployment_type = Some(DeploymentType::Standalone);
}

/// Detect language support
fn detect_language_support(base_dir: &Path, results: &mut DetectionResults) {
    // Look for i18n/localization files
    let i18n_dirs = ["i18n", "locales", "translations", "lang"];

    for dir_name in &i18n_dirs {
        let i18n_path = base_dir.join(dir_name);
        if i18n_path.exists() && i18n_path.is_dir() {
            if let Ok(entries) = fs::read_dir(&i18n_path) {
                for entry in entries.flatten() {
                    if let Some(name) = entry.file_name().to_str() {
                        // Extract language codes from filenames like en.json, de.yml, etc.
                        if let Some(lang_code) = name.split('.').next() {
                            if lang_code.len() == 2 {
                                // ISO 639-1 code
                                results.language_capabilities.push(lang_code.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    // Default to English if no languages detected
    if results.language_capabilities.is_empty() {
        results.language_capabilities.push("en".to_string());
    }
}

/// Detect supported modalities
fn detect_modalities(base_dir: &Path, results: &mut DetectionResults) {
    // Always support text
    if !results.modality_support.contains(&Modality::Text) {
        results.modality_support.push(Modality::Text);
    }

    // Look for code files → code modality
    if glob::glob(&base_dir.join("**/*.{ts,js,py,rs,go,java}").to_string_lossy())
        .ok()
        .and_then(|paths| paths.flatten().next())
        .is_some()
    {
        if !results.modality_support.contains(&Modality::Code) {
            results.modality_support.push(Modality::Code);
        }
    }

    // Look for structured data files
    if glob::glob(&base_dir.join("**/*.{json,yaml,yml,toml,csv}").to_string_lossy())
        .ok()
        .and_then(|paths| paths.flatten().next())
        .is_some()
    {
        if !results.modality_support.contains(&Modality::StructuredData) {
            results.modality_support.push(Modality::StructuredData);
        }
    }
}

/// Infer agent status from version
pub fn infer_status_from_version(version: &str) -> AgentStatus {
    let version_lower = version.to_lowercase();

    if version_lower.contains("alpha") || version_lower.starts_with("0.0") {
        AgentStatus::Alpha
    } else if version_lower.contains("beta") || version_lower.contains("rc") {
        AgentStatus::Beta
    } else if version_lower.starts_with("0.") {
        AgentStatus::Beta
    } else {
        AgentStatus::Production
    }
}