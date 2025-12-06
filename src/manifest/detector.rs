use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::manifest::schema::{
    AgentStatus, ArchitectureType, DataCategory, DeploymentContext, DeploymentType, Modality,
    RepositoryStructure,
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
    detect_from_pyproject_toml(base_dir, &mut results);
    detect_from_setup_py(base_dir, &mut results);
    detect_from_requirements_txt(base_dir, &mut results);
    detect_from_go_mod(base_dir, &mut results);
    detect_from_git(base_dir, &mut results);
    detect_from_readme(base_dir, &mut results);
    detect_architecture_patterns(base_dir, &mut results);
    detect_ai_frameworks(base_dir, &mut results);
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
                    results.detection_sources.insert(
                        "project_description".to_string(),
                        "package.json".to_string(),
                    );
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

/// Detect from pyproject.toml (Python)
fn detect_from_pyproject_toml(base_dir: &Path, results: &mut DetectionResults) {
    let pyproject_path = base_dir.join("pyproject.toml");
    if !pyproject_path.exists() {
        return;
    }

    if let Ok(content) = fs::read_to_string(&pyproject_path) {
        if let Ok(pyproject) = content.parse::<toml::Value>() {
            // Try [project] section first (PEP 621)
            if let Some(project) = pyproject.get("project") {
                // Project name
                if results.project_name.is_none() {
                    if let Some(name) = project.get("name").and_then(|n| n.as_str()) {
                        results.project_name = Some(name.to_string());
                        results
                            .detection_sources
                            .insert("project_name".to_string(), "pyproject.toml".to_string());
                    }
                }

                // Version
                if results.project_version.is_none() {
                    if let Some(version) = project.get("version").and_then(|v| v.as_str()) {
                        results.project_version = Some(version.to_string());
                        results
                            .detection_sources
                            .insert("project_version".to_string(), "pyproject.toml".to_string());
                    }
                }

                // Description
                if results.project_description.is_none() {
                    if let Some(desc) = project.get("description").and_then(|d| d.as_str()) {
                        results.project_description = Some(desc.to_string());
                        results.detection_sources.insert(
                            "project_description".to_string(),
                            "pyproject.toml".to_string(),
                        );
                    }
                }

                // Check dependencies for AI/ML libraries
                if let Some(deps) = project.get("dependencies").and_then(|d| d.as_array()) {
                    detect_from_python_deps(deps, results);
                }
            }

            // Try [tool.poetry] section (Poetry)
            if let Some(poetry) = pyproject.get("tool").and_then(|t| t.get("poetry")) {
                // Project name
                if results.project_name.is_none() {
                    if let Some(name) = poetry.get("name").and_then(|n| n.as_str()) {
                        results.project_name = Some(name.to_string());
                        results.detection_sources.insert(
                            "project_name".to_string(),
                            "pyproject.toml (poetry)".to_string(),
                        );
                    }
                }

                // Version
                if results.project_version.is_none() {
                    if let Some(version) = poetry.get("version").and_then(|v| v.as_str()) {
                        results.project_version = Some(version.to_string());
                        results.detection_sources.insert(
                            "project_version".to_string(),
                            "pyproject.toml (poetry)".to_string(),
                        );
                    }
                }

                // Description
                if results.project_description.is_none() {
                    if let Some(desc) = poetry.get("description").and_then(|d| d.as_str()) {
                        results.project_description = Some(desc.to_string());
                        results.detection_sources.insert(
                            "project_description".to_string(),
                            "pyproject.toml (poetry)".to_string(),
                        );
                    }
                }

                // Check dependencies
                if let Some(deps) = poetry.get("dependencies").and_then(|d| d.as_table()) {
                    let dep_names: Vec<String> = deps.keys().cloned().collect();
                    detect_ai_deps_from_names(&dep_names, results);
                }
            }

            if results.primary_language.is_none() {
                results.primary_language = Some("Python".to_string());
            }
        }
    }
}

/// Detect from setup.py (Python legacy)
fn detect_from_setup_py(base_dir: &Path, results: &mut DetectionResults) {
    let setup_path = base_dir.join("setup.py");
    if !setup_path.exists() {
        return;
    }

    if let Ok(content) = fs::read_to_string(&setup_path) {
        // Extract name from setup.py using simple regex-like matching
        if results.project_name.is_none() {
            if let Some(name) = extract_setup_py_field(&content, "name") {
                results.project_name = Some(name);
                results
                    .detection_sources
                    .insert("project_name".to_string(), "setup.py".to_string());
            }
        }

        // Extract version
        if results.project_version.is_none() {
            if let Some(version) = extract_setup_py_field(&content, "version") {
                results.project_version = Some(version);
                results
                    .detection_sources
                    .insert("project_version".to_string(), "setup.py".to_string());
            }
        }

        // Extract description
        if results.project_description.is_none() {
            if let Some(desc) = extract_setup_py_field(&content, "description") {
                results.project_description = Some(desc);
                results
                    .detection_sources
                    .insert("project_description".to_string(), "setup.py".to_string());
            }
        }

        // Check for AI/ML dependencies in install_requires
        let content_lower = content.to_lowercase();
        if content_lower.contains("langchain")
            || content_lower.contains("crewai")
            || content_lower.contains("autogen")
            || content_lower.contains("openai")
            || content_lower.contains("anthropic")
        {
            detect_ai_deps_from_content(&content, results);
        }

        if results.primary_language.is_none() {
            results.primary_language = Some("Python".to_string());
        }
    }
}

/// Extract a field value from setup.py
fn extract_setup_py_field(content: &str, field: &str) -> Option<String> {
    // Simple pattern matching for setup.py fields
    // Matches patterns like: name="myproject" or name='myproject'
    let pattern1 = format!(r#"{}=["']([^"']+)["']"#, field);
    let pattern2 = format!(r#"{}=['"]([^'"]+)['"]"#, field);

    if let Ok(re) = regex::Regex::new(&pattern1) {
        if let Some(caps) = re.captures(content) {
            if let Some(m) = caps.get(1) {
                return Some(m.as_str().to_string());
            }
        }
    }

    if let Ok(re) = regex::Regex::new(&pattern2) {
        if let Some(caps) = re.captures(content) {
            if let Some(m) = caps.get(1) {
                return Some(m.as_str().to_string());
            }
        }
    }

    None
}

/// Detect from requirements.txt (Python)
fn detect_from_requirements_txt(base_dir: &Path, results: &mut DetectionResults) {
    let requirements_path = base_dir.join("requirements.txt");
    if !requirements_path.exists() {
        return;
    }

    if let Ok(content) = fs::read_to_string(&requirements_path) {
        detect_ai_deps_from_content(&content, results);

        if results.primary_language.is_none() {
            results.primary_language = Some("Python".to_string());
        }
    }
}

/// Detect from Python dependencies array (PEP 621 format)
fn detect_from_python_deps(deps: &[toml::Value], results: &mut DetectionResults) {
    let dep_names: Vec<String> = deps
        .iter()
        .filter_map(|d| d.as_str())
        .map(|s| {
            // Extract package name from dependency string (e.g., "langchain>=0.1.0" -> "langchain")
            s.split(|c| c == '>' || c == '<' || c == '=' || c == '[' || c == ';')
                .next()
                .unwrap_or(s)
                .trim()
                .to_lowercase()
        })
        .collect();

    detect_ai_deps_from_names(&dep_names, results);
}

/// Detect from Go mod file
fn detect_from_go_mod(base_dir: &Path, results: &mut DetectionResults) {
    let go_mod_path = base_dir.join("go.mod");
    if !go_mod_path.exists() {
        return;
    }

    if let Ok(content) = fs::read_to_string(&go_mod_path) {
        // Extract module name
        if results.project_name.is_none() {
            for line in content.lines() {
                let line = line.trim();
                if line.starts_with("module ") {
                    let module = line.strip_prefix("module ").unwrap_or("").trim();
                    // Extract the last part of the module path as the project name
                    let name = module.rsplit('/').next().unwrap_or(module);
                    results.project_name = Some(name.to_string());
                    results
                        .detection_sources
                        .insert("project_name".to_string(), "go.mod".to_string());
                    break;
                }
            }
        }

        // Check for AI-related Go packages
        let content_lower = content.to_lowercase();
        if content_lower.contains("github.com/sashabaranov/go-openai")
            || content_lower.contains("github.com/anthropics/anthropic-sdk-go")
            || content_lower.contains("langchaingo")
        {
            if results.architecture_type.is_none() {
                results.architecture_type = Some(ArchitectureType::ToolUsing);
            }
            results
                .detection_sources
                .insert("architecture_type".to_string(), "go.mod".to_string());
        }

        if results.primary_language.is_none() {
            results.primary_language = Some("Go".to_string());
        }
    }
}

/// Detect AI framework patterns from dependency names
fn detect_ai_deps_from_names(dep_names: &[String], results: &mut DetectionResults) {
    let has_langchain = dep_names.iter().any(|d| d.contains("langchain"));
    let has_crewai = dep_names.iter().any(|d| d.contains("crewai"));
    let has_autogen = dep_names
        .iter()
        .any(|d| d.contains("autogen") || d.contains("pyautogen"));
    let has_openai = dep_names.iter().any(|d| d == "openai");
    let has_anthropic = dep_names.iter().any(|d| d == "anthropic");
    let has_llama_index = dep_names
        .iter()
        .any(|d| d.contains("llama-index") || d.contains("llama_index"));
    let has_transformers = dep_names.iter().any(|d| d == "transformers");
    let has_agents = dep_names.iter().any(|d| d.contains("agents"));

    // Determine architecture type based on frameworks
    if has_crewai || has_autogen {
        results.architecture_type = Some(ArchitectureType::MultiAgent);
        results.detection_sources.insert(
            "architecture_type".to_string(),
            "dependencies (multi-agent framework)".to_string(),
        );
    } else if has_langchain || has_llama_index {
        results.architecture_type = Some(ArchitectureType::Rag);
        results.detection_sources.insert(
            "architecture_type".to_string(),
            "dependencies (RAG framework)".to_string(),
        );
    } else if has_openai || has_anthropic || has_agents {
        results.architecture_type = Some(ArchitectureType::ToolUsing);
        results.detection_sources.insert(
            "architecture_type".to_string(),
            "dependencies (AI SDK)".to_string(),
        );
    } else if has_transformers {
        results.architecture_type = Some(ArchitectureType::FineTuned);
        results.detection_sources.insert(
            "architecture_type".to_string(),
            "dependencies (transformers)".to_string(),
        );
    }
}

/// Detect AI framework patterns from raw content (requirements.txt, setup.py)
fn detect_ai_deps_from_content(content: &str, results: &mut DetectionResults) {
    // Extract package names from lines
    let dep_names: Vec<String> = content
        .lines()
        .filter(|l| !l.trim().starts_with('#') && !l.trim().is_empty())
        .map(|l| {
            l.split(|c| c == '>' || c == '<' || c == '=' || c == '[' || c == ';')
                .next()
                .unwrap_or(l)
                .trim()
                .to_lowercase()
        })
        .collect();

    detect_ai_deps_from_names(&dep_names, results);
}

/// Detect AI frameworks from code patterns
fn detect_ai_frameworks(base_dir: &Path, results: &mut DetectionResults) {
    // If architecture already detected from dependencies, skip
    if results.architecture_type.is_some() {
        return;
    }

    // Check Python files for framework imports
    if let Ok(paths) = glob::glob(&base_dir.join("**/*.py").to_string_lossy()) {
        for path in paths.flatten().take(50) {
            // Limit to first 50 files
            if let Ok(content) = fs::read_to_string(&path) {
                // Check for framework imports
                if content.contains("from crewai") || content.contains("import crewai") {
                    results.architecture_type = Some(ArchitectureType::MultiAgent);
                    results.detection_sources.insert(
                        "architecture_type".to_string(),
                        "code (crewai import)".to_string(),
                    );
                    return;
                }
                if content.contains("from autogen") || content.contains("import autogen") {
                    results.architecture_type = Some(ArchitectureType::MultiAgent);
                    results.detection_sources.insert(
                        "architecture_type".to_string(),
                        "code (autogen import)".to_string(),
                    );
                    return;
                }
                if content.contains("from langchain") || content.contains("import langchain") {
                    results.architecture_type = Some(ArchitectureType::Rag);
                    results.detection_sources.insert(
                        "architecture_type".to_string(),
                        "code (langchain import)".to_string(),
                    );
                    return;
                }
                if content.contains("from llama_index") || content.contains("import llama_index") {
                    results.architecture_type = Some(ArchitectureType::Rag);
                    results.detection_sources.insert(
                        "architecture_type".to_string(),
                        "code (llama_index import)".to_string(),
                    );
                    return;
                }
                if content.contains("from openai") || content.contains("import openai") {
                    results.architecture_type = Some(ArchitectureType::ToolUsing);
                    results.detection_sources.insert(
                        "architecture_type".to_string(),
                        "code (openai import)".to_string(),
                    );
                    // Don't return, keep looking for more specific frameworks
                }
                if content.contains("from anthropic") || content.contains("import anthropic") {
                    results.architecture_type = Some(ArchitectureType::ToolUsing);
                    results.detection_sources.insert(
                        "architecture_type".to_string(),
                        "code (anthropic import)".to_string(),
                    );
                    // Don't return, keep looking for more specific frameworks
                }
            }
        }
    }

    // Check TypeScript/JavaScript files for framework imports
    if let Ok(paths) = glob::glob(&base_dir.join("**/*.{ts,js}").to_string_lossy()) {
        for path in paths.flatten().take(50) {
            if let Ok(content) = fs::read_to_string(&path) {
                if content.contains("@langchain") || content.contains("langchain") {
                    results.architecture_type = Some(ArchitectureType::Rag);
                    results.detection_sources.insert(
                        "architecture_type".to_string(),
                        "code (langchain import)".to_string(),
                    );
                    return;
                }
                if content.contains("@anthropic-ai/sdk") || content.contains("anthropic") {
                    if results.architecture_type.is_none() {
                        results.architecture_type = Some(ArchitectureType::ToolUsing);
                        results.detection_sources.insert(
                            "architecture_type".to_string(),
                            "code (anthropic import)".to_string(),
                        );
                    }
                }
                if content.contains("openai") {
                    if results.architecture_type.is_none() {
                        results.architecture_type = Some(ArchitectureType::ToolUsing);
                        results.detection_sources.insert(
                            "architecture_type".to_string(),
                            "code (openai import)".to_string(),
                        );
                    }
                }
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
    let readme_names = [
        "README.md",
        "README.MD",
        "readme.md",
        "README.txt",
        "README",
    ];

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
    if glob::glob(
        &base_dir
            .join("**/*.{ts,js,py,rs,go,java}")
            .to_string_lossy(),
    )
    .ok()
    .and_then(|paths| paths.flatten().next())
    .is_some()
    {
        if !results.modality_support.contains(&Modality::Code) {
            results.modality_support.push(Modality::Code);
        }
    }

    // Look for structured data files
    if glob::glob(
        &base_dir
            .join("**/*.{json,yaml,yml,toml,csv}")
            .to_string_lossy(),
    )
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
