//! Schema fetching and caching module
//!
//! This module provides functionality to fetch JSON schemas from the beltic-spec
//! repository and cache them locally for offline use.

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde_json::Value;

/// Base URL for the beltic-spec schemas on GitHub
const GITHUB_RAW_BASE: &str =
    "https://raw.githubusercontent.com/belticlabs/beltic-spec/main/schemas";

/// Cache TTL: 24 hours
const CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Schema type for fetching
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaType {
    Agent,
    Developer,
}

impl SchemaType {
    /// Returns the relative path within the schemas directory
    pub fn path(self) -> &'static str {
        match self {
            SchemaType::Agent => "agent/v1/agent-credential-v1.schema.json",
            SchemaType::Developer => "developer/v1/developer-credential-v1.schema.json",
        }
    }

    /// Returns the full URL for the schema
    pub fn url(self) -> String {
        format!("{}/{}", GITHUB_RAW_BASE, self.path())
    }

    /// Returns the cache file name
    pub fn cache_name(self) -> &'static str {
        match self {
            SchemaType::Agent => "agent-credential-v1.schema.json",
            SchemaType::Developer => "developer-credential-v1.schema.json",
        }
    }
}

/// Get the cache directory for beltic schemas
fn cache_dir() -> Option<PathBuf> {
    ProjectDirs::from("com", "beltic", "beltic-cli").map(|dirs| dirs.cache_dir().to_path_buf())
}

/// Check if cached schema is still valid (within TTL)
fn is_cache_valid(path: &PathBuf) -> bool {
    if !path.exists() {
        return false;
    }

    if let Ok(metadata) = fs::metadata(path) {
        if let Ok(modified) = metadata.modified() {
            if let Ok(elapsed) = SystemTime::now().duration_since(modified) {
                return elapsed < CACHE_TTL;
            }
        }
    }

    false
}

/// Read schema from cache
fn read_cached_schema(schema_type: SchemaType) -> Option<Value> {
    let cache_dir = cache_dir()?;
    let cache_path = cache_dir.join(schema_type.cache_name());

    if !is_cache_valid(&cache_path) {
        return None;
    }

    let content = fs::read_to_string(&cache_path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Write schema to cache
fn write_cached_schema(schema_type: SchemaType, schema: &Value) -> Result<()> {
    let cache_dir = cache_dir().context("could not determine cache directory")?;

    fs::create_dir_all(&cache_dir)
        .with_context(|| format!("failed to create cache directory: {}", cache_dir.display()))?;

    let cache_path = cache_dir.join(schema_type.cache_name());
    let content = serde_json::to_string_pretty(schema)?;

    fs::write(&cache_path, content)
        .with_context(|| format!("failed to write cache file: {}", cache_path.display()))?;

    Ok(())
}

/// Fetch schema from GitHub
fn fetch_schema_from_github(schema_type: SchemaType) -> Result<Value> {
    let url = schema_type.url();

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("failed to create HTTP client")?;

    let response = client
        .get(&url)
        .header("User-Agent", "beltic-cli")
        .send()
        .with_context(|| format!("failed to fetch schema from {}", url))?;

    if !response.status().is_success() {
        anyhow::bail!(
            "failed to fetch schema from {}: HTTP {}",
            url,
            response.status()
        );
    }

    let schema: Value = response
        .json()
        .with_context(|| format!("failed to parse schema from {}", url))?;

    Ok(schema)
}

/// Get schema, preferring cache but fetching from GitHub if needed
///
/// Strategy:
/// 1. Check local cache - if valid and within TTL, use it
/// 2. Try to fetch from GitHub
/// 3. If fetch fails but cache exists (even expired), use stale cache
/// 4. If no cache and fetch fails, use embedded schema as fallback
pub fn get_schema(schema_type: SchemaType) -> Result<Value> {
    // 1. Check valid cache
    if let Some(cached) = read_cached_schema(schema_type) {
        return Ok(cached);
    }

    // 2. Try to fetch from GitHub
    match fetch_schema_from_github(schema_type) {
        Ok(schema) => {
            // Cache for future use (ignore cache write errors)
            let _ = write_cached_schema(schema_type, &schema);
            Ok(schema)
        }
        Err(fetch_err) => {
            // 3. Try stale cache if available
            let cache_dir = cache_dir();
            if let Some(dir) = cache_dir {
                let cache_path = dir.join(schema_type.cache_name());
                if cache_path.exists() {
                    if let Ok(content) = fs::read_to_string(&cache_path) {
                        if let Ok(schema) = serde_json::from_str(&content) {
                            eprintln!(
                                "[warn] Using stale cached schema for {} (fetch failed: {})",
                                schema_type.cache_name(),
                                fetch_err
                            );
                            return Ok(schema);
                        }
                    }
                }
            }

            // 4. Fall back to embedded schema
            eprintln!(
                "[warn] Using embedded schema for {} (fetch failed: {})",
                schema_type.cache_name(),
                fetch_err
            );
            Ok(get_embedded_schema(schema_type))
        }
    }
}

/// Get the embedded (compile-time) schema as fallback
fn get_embedded_schema(schema_type: SchemaType) -> Value {
    match schema_type {
        SchemaType::Agent => serde_json::from_str(include_str!(
            "../schemas/agent/v1/agent-credential-v1.schema.json"
        ))
        .expect("embedded agent schema should parse"),
        SchemaType::Developer => serde_json::from_str(include_str!(
            "../schemas/developer/v1/developer-credential-v1.schema.json"
        ))
        .expect("embedded developer schema should parse"),
    }
}

/// Force refresh schema from GitHub, ignoring cache
pub fn refresh_schema(schema_type: SchemaType) -> Result<Value> {
    let schema = fetch_schema_from_github(schema_type)?;
    write_cached_schema(schema_type, &schema)?;
    Ok(schema)
}

/// Clear all cached schemas
pub fn clear_cache() -> Result<()> {
    let cache_dir = cache_dir().context("could not determine cache directory")?;
    if cache_dir.exists() {
        fs::remove_dir_all(&cache_dir)
            .with_context(|| format!("failed to remove cache directory: {}", cache_dir.display()))?;
    }
    Ok(())
}

/// Get cache status for a schema type
pub fn cache_status(schema_type: SchemaType) -> Option<CacheStatus> {
    let cache_dir = cache_dir()?;
    let cache_path = cache_dir.join(schema_type.cache_name());

    if !cache_path.exists() {
        return Some(CacheStatus {
            path: cache_path,
            exists: false,
            valid: false,
            age: None,
        });
    }

    let metadata = fs::metadata(&cache_path).ok()?;
    let modified = metadata.modified().ok()?;
    let age = SystemTime::now().duration_since(modified).ok()?;
    let valid = age < CACHE_TTL;

    Some(CacheStatus {
        path: cache_path,
        exists: true,
        valid,
        age: Some(age),
    })
}

/// Information about cached schema status
#[derive(Debug)]
pub struct CacheStatus {
    pub path: PathBuf,
    pub exists: bool,
    pub valid: bool,
    pub age: Option<Duration>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_type_url() {
        assert!(SchemaType::Agent.url().contains("agent-credential"));
        assert!(SchemaType::Developer.url().contains("developer-credential"));
    }

    #[test]
    fn test_embedded_schema_loads() {
        let agent_schema = get_embedded_schema(SchemaType::Agent);
        assert!(agent_schema.get("$schema").is_some());

        let developer_schema = get_embedded_schema(SchemaType::Developer);
        assert!(developer_schema.get("$schema").is_some());
    }
}
