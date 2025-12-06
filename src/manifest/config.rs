use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Beltic configuration file structure (.beltic.yaml)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BelticConfig {
    pub version: String,
    pub agent: AgentConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub paths: PathConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dependencies: Option<DependencyConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment: Option<DeploymentConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathConfig {
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentConfig {
    #[serde(rename = "type")]
    pub deployment_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_application: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

impl BelticConfig {
    /// Load config from a file path
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    /// Try to find and load .beltic.yaml in current or parent directories
    pub fn find_and_load(start_dir: &Path) -> Result<Option<Self>> {
        let mut current = start_dir.to_path_buf();

        loop {
            let config_path = current.join(".beltic.yaml");
            if config_path.exists() {
                return Ok(Some(Self::from_file(&config_path)?));
            }

            let config_path = current.join(".beltic.yml");
            if config_path.exists() {
                return Ok(Some(Self::from_file(&config_path)?));
            }

            if !current.pop() {
                break;
            }
        }

        Ok(None)
    }

    /// Create a default configuration for standalone agents
    pub fn default_standalone() -> Self {
        Self {
            version: "1.0".to_string(),
            agent: AgentConfig {
                paths: PathConfig {
                    include: vec![
                        "src/**".to_string(),
                        "lib/**".to_string(),
                        "Cargo.toml".to_string(),
                        "package.json".to_string(),
                        "*.md".to_string(),
                    ],
                    exclude: vec![
                        "**/*.test.*".to_string(),
                        "**/*.spec.*".to_string(),
                        "**/test/**".to_string(),
                        "**/tests/**".to_string(),
                        "**/node_modules/**".to_string(),
                        "**/target/**".to_string(),
                        "**/.git/**".to_string(),
                    ],
                },
                dependencies: None,
                deployment: Some(DeploymentConfig {
                    deployment_type: "standalone".to_string(),
                    host_application: None,
                    runtime: None,
                    location: None,
                }),
            },
        }
    }

    /// Create a configuration for monorepo agents
    pub fn default_monorepo(agent_path: &str) -> Self {
        Self {
            version: "1.0".to_string(),
            agent: AgentConfig {
                paths: PathConfig {
                    include: vec![
                        format!("{}/**", agent_path),
                        "shared/**".to_string(),
                        "common/**".to_string(),
                    ],
                    exclude: vec![
                        "**/*.test.*".to_string(),
                        "**/*.spec.*".to_string(),
                        "**/test/**".to_string(),
                        "**/tests/**".to_string(),
                        "**/node_modules/**".to_string(),
                        "**/target/**".to_string(),
                        "**/.git/**".to_string(),
                    ],
                },
                dependencies: Some(DependencyConfig {
                    internal: Some(vec!["../shared".to_string()]),
                    external: None,
                }),
                deployment: Some(DeploymentConfig {
                    deployment_type: "monorepo".to_string(),
                    host_application: None,
                    runtime: None,
                    location: Some(agent_path.to_string()),
                }),
            },
        }
    }

    /// Create a configuration for plugin/extension agents
    pub fn default_plugin() -> Self {
        Self {
            version: "1.0".to_string(),
            agent: AgentConfig {
                paths: PathConfig {
                    include: vec![
                        "src/plugin/**".to_string(),
                        "plugin.json".to_string(),
                        "manifest.json".to_string(),
                    ],
                    exclude: vec![
                        "**/*.test.*".to_string(),
                        "**/test/**".to_string(),
                        "**/node_modules/**".to_string(),
                    ],
                },
                dependencies: None,
                deployment: Some(DeploymentConfig {
                    deployment_type: "plugin".to_string(),
                    host_application: None,
                    runtime: None,
                    location: None,
                }),
            },
        }
    }

    /// Create a configuration for serverless functions
    pub fn default_serverless() -> Self {
        Self {
            version: "1.0".to_string(),
            agent: AgentConfig {
                paths: PathConfig {
                    include: vec![
                        "handler.*".to_string(),
                        "index.*".to_string(),
                        "serverless.yml".to_string(),
                        "serverless.yaml".to_string(),
                        "src/**".to_string(),
                    ],
                    exclude: vec![
                        "**/*.test.*".to_string(),
                        "**/test/**".to_string(),
                        "**/node_modules/**".to_string(),
                        "**/.serverless/**".to_string(),
                    ],
                },
                dependencies: None,
                deployment: Some(DeploymentConfig {
                    deployment_type: "serverless".to_string(),
                    host_application: None,
                    runtime: Some("nodejs18.x".to_string()),
                    location: None,
                }),
            },
        }
    }

    /// Save config to a file
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let yaml = serde_yaml::to_string(&self)?;
        fs::write(path, yaml)?;
        Ok(())
    }

    /// Generate an example config file with comments
    pub fn generate_example() -> String {
        r#"# Beltic Configuration File
# This file defines the boundaries and metadata for your agent

version: "1.0"

agent:
  # Define which files belong to this agent
  paths:
    include:
      - "src/agents/customer-service/**"
      - "shared/prompts/**"
      - "config/agent-config.yaml"
    exclude:
      - "**/*.test.ts"
      - "**/node_modules/**"
      - "**/dist/**"

  # Track dependencies that affect agent behavior (optional)
  dependencies:
    # Other modules in your repository
    internal:
      - "../shared-utils"
      - "../auth-module"
    # External packages (NPM, Cargo, etc.)
    external:
      - "openai@^3.0.0"
      - "langchain@^0.1.0"

  # Deployment context (optional)
  deployment:
    type: "monorepo"  # standalone|monorepo|embedded|plugin|serverless
    host_application: "main-platform"
    runtime: "node:18-alpine"
    location: "agents/customer-service"
"#
        .to_string()
    }
}

/// Resolve paths based on config
pub fn resolve_paths(config: &PathConfig, base_dir: &Path) -> (Vec<String>, Vec<String>) {
    let includes = config
        .include
        .iter()
        .map(|p| base_dir.join(p).to_string_lossy().to_string())
        .collect();

    let excludes = config.exclude.clone();

    (includes, excludes)
}
