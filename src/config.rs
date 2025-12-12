//! Configuration and credential management for Beltic CLI
//!
//! Stores configuration in ~/.beltic/config.yaml and credentials in ~/.beltic/credentials

use std::fs;
use std::io::Write;
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use anyhow::{Context, Result};
use directories::BaseDirs;
use serde::{Deserialize, Serialize};

const CONFIG_DIR: &str = ".beltic";
const CONFIG_FILE: &str = "config.yaml";
const CREDENTIALS_FILE: &str = "credentials";

/// Beltic CLI configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct BelticConfig {
    /// API URL (default: https://api.beltic.dev)
    #[serde(default = "default_api_url")]
    pub api_url: String,

    /// Current developer ID (set after login)
    pub current_developer_id: Option<String>,
}

impl Default for BelticConfig {
    fn default() -> Self {
        Self {
            api_url: default_api_url(),
            current_developer_id: None,
        }
    }
}

fn default_api_url() -> String {
    "https://api.beltic.dev".to_string()
}

/// Get the path to the beltic config directory (~/.beltic/)
pub fn config_dir() -> Result<PathBuf> {
    let base_dirs = BaseDirs::new().context("failed to determine home directory")?;
    Ok(base_dirs.home_dir().join(CONFIG_DIR))
}

/// Get the path to the config file (~/.beltic/config.yaml)
pub fn config_file_path() -> Result<PathBuf> {
    Ok(config_dir()?.join(CONFIG_FILE))
}

/// Get the path to the credentials file (~/.beltic/credentials)
pub fn credentials_file_path() -> Result<PathBuf> {
    Ok(config_dir()?.join(CREDENTIALS_FILE))
}

/// Ensure the config directory exists
pub fn ensure_config_dir() -> Result<PathBuf> {
    let dir = config_dir()?;
    if !dir.exists() {
        fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create config directory {}", dir.display()))?;
    }
    Ok(dir)
}

/// Load configuration from disk
pub fn load_config() -> Result<BelticConfig> {
    let path = config_file_path()?;
    if !path.exists() {
        return Ok(BelticConfig::default());
    }

    let contents =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;

    serde_yaml::from_str(&contents).with_context(|| format!("failed to parse {}", path.display()))
}

/// Save configuration to disk
pub fn save_config(config: &BelticConfig) -> Result<()> {
    ensure_config_dir()?;
    let path = config_file_path()?;

    let contents = serde_yaml::to_string(config).context("failed to serialize config")?;

    fs::write(&path, contents).with_context(|| format!("failed to write {}", path.display()))?;

    Ok(())
}

/// Save API key to credentials file with restricted permissions (0600)
pub fn save_credentials(api_key: &str) -> Result<()> {
    ensure_config_dir()?;
    let path = credentials_file_path()?;

    let contents = format!("BELTIC_API_KEY={}\n", api_key);

    #[cfg(unix)]
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600) // Owner read/write only
            .open(&path)
            .with_context(|| format!("failed to create credentials file {}", path.display()))?;
        file.write_all(contents.as_bytes())
            .with_context(|| format!("failed to write credentials to {}", path.display()))?;
        return Ok(());
    }

    #[cfg(not(unix))]
    {
        fs::write(&path, contents)
            .with_context(|| format!("failed to write credentials to {}", path.display()))?;
        Ok(())
    }
}

/// Load API key from credentials file
pub fn load_credentials() -> Result<Option<String>> {
    let path = credentials_file_path()?;
    if !path.exists() {
        return Ok(None);
    }

    let contents =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;

    // Parse simple KEY=VALUE format
    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with("BELTIC_API_KEY=") {
            let key = line.strip_prefix("BELTIC_API_KEY=").unwrap_or("");
            if !key.is_empty() {
                return Ok(Some(key.to_string()));
            }
        }
    }

    Ok(None)
}

/// Delete stored credentials
pub fn delete_credentials() -> Result<()> {
    let path = credentials_file_path()?;
    if path.exists() {
        fs::remove_file(&path)
            .with_context(|| format!("failed to delete {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_api_url() {
        let config = BelticConfig::default();
        assert_eq!(config.api_url, "https://api.beltic.dev");
    }
}
