//! Auto-discovery utilities for keys, tokens, and credentials
//!
//! This module provides functions to discover keys, tokens, and credentials
//! in standard locations, and manage the .beltic directory.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};

use super::prompts::beltic_dir;

/// Ensure the .beltic directory exists
pub fn ensure_beltic_dir() -> Result<PathBuf> {
    let dir = beltic_dir();
    if !dir.exists() {
        fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create directory {}", dir.display()))?;
    }
    Ok(dir)
}

/// Find private keys in standard locations
/// Searches: ./.beltic/, ./keys/, ./
pub fn find_private_keys() -> Vec<PathBuf> {
    let search_dirs = vec![beltic_dir(), PathBuf::from("keys"), PathBuf::from(".")];

    find_keys_in_dirs(&search_dirs, true)
}

/// Find public keys in standard locations
/// Searches: ./.beltic/, ./keys/, ./
pub fn find_public_keys() -> Vec<PathBuf> {
    let search_dirs = vec![beltic_dir(), PathBuf::from("keys"), PathBuf::from(".")];

    find_keys_in_dirs(&search_dirs, false)
}

fn find_keys_in_dirs(dirs: &[PathBuf], private: bool) -> Vec<PathBuf> {
    let mut keys = Vec::new();
    let suffix = if private { "private" } else { "public" };

    for dir in dirs {
        if !dir.exists() {
            continue;
        }

        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        // Match patterns like *-private.pem or *-public.pem
                        if name.ends_with(".pem") && name.contains(suffix) {
                            keys.push(path);
                        }
                    }
                }
            }
        }
    }

    // Sort by modification time (newest first)
    keys.sort_by(|a, b| {
        let a_time = fs::metadata(a).and_then(|m| m.modified()).ok();
        let b_time = fs::metadata(b).and_then(|m| m.modified()).ok();
        b_time.cmp(&a_time)
    });

    keys
}

/// Find JWS/JWT tokens in standard locations
/// Searches: ./, ./.beltic/
pub fn find_tokens() -> Vec<PathBuf> {
    let search_dirs = vec![PathBuf::from("."), beltic_dir()];

    let mut tokens = Vec::new();

    for dir in search_dirs {
        if !dir.exists() {
            continue;
        }

        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                        if ext == "jwt" || ext == "jws" {
                            tokens.push(path);
                        }
                    }
                }
            }
        }
    }

    // Sort by modification time (newest first)
    tokens.sort_by(|a, b| {
        let a_time = fs::metadata(a).and_then(|m| m.modified()).ok();
        let b_time = fs::metadata(b).and_then(|m| m.modified()).ok();
        b_time.cmp(&a_time)
    });

    tokens
}

/// Find credential JSON files in standard locations
/// Searches: ./, ./.beltic/
pub fn find_credentials() -> Vec<PathBuf> {
    let search_dirs = vec![PathBuf::from("."), beltic_dir()];

    let mut credentials = Vec::new();

    for dir in search_dirs {
        if !dir.exists() {
            continue;
        }

        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        // Match patterns like *credential*.json or agent-*.json
                        if name.ends_with(".json")
                            && (name.contains("credential")
                                || name.starts_with("agent-")
                                || name.starts_with("developer-"))
                        {
                            credentials.push(path);
                        }
                    }
                }
            }
        }
    }

    // Sort by modification time (newest first)
    credentials.sort_by(|a, b| {
        let a_time = fs::metadata(a).and_then(|m| m.modified()).ok();
        let b_time = fs::metadata(b).and_then(|m| m.modified()).ok();
        b_time.cmp(&a_time)
    });

    credentials
}

/// Add private keys pattern to .gitignore
/// Adds: .beltic/*-private.pem
pub fn add_to_gitignore(pattern: &str) -> Result<bool> {
    let gitignore_path = PathBuf::from(".gitignore");

    // Check if pattern already exists
    if gitignore_path.exists() {
        let file = File::open(&gitignore_path)?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            if let Ok(line) = line {
                if line.trim() == pattern {
                    // Pattern already exists
                    return Ok(false);
                }
            }
        }
    }

    // Append pattern to .gitignore
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&gitignore_path)?;

    // Add newline before if file doesn't end with one
    if gitignore_path.exists() {
        let contents = fs::read_to_string(&gitignore_path)?;
        if !contents.is_empty() && !contents.ends_with('\n') {
            writeln!(file)?;
        }
    }

    writeln!(file, "{}", pattern)?;
    Ok(true)
}

/// Ensure private keys are gitignored
/// Returns true if .gitignore was modified
pub fn ensure_private_keys_gitignored() -> Result<bool> {
    add_to_gitignore(".beltic/*-private.pem")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use tempfile::TempDir;

    #[test]
    fn test_ensure_beltic_dir() {
        let temp = TempDir::new().unwrap();
        env::set_current_dir(temp.path()).unwrap();

        let dir = ensure_beltic_dir().unwrap();
        assert!(dir.exists());
        assert_eq!(dir, PathBuf::from(".beltic"));
    }

    #[test]
    fn test_find_keys_empty() {
        let temp = TempDir::new().unwrap();
        env::set_current_dir(temp.path()).unwrap();

        let private_keys = find_private_keys();
        assert!(private_keys.is_empty());

        let public_keys = find_public_keys();
        assert!(public_keys.is_empty());
    }

    #[test]
    fn test_find_tokens_empty() {
        let temp = TempDir::new().unwrap();
        env::set_current_dir(temp.path()).unwrap();

        let tokens = find_tokens();
        assert!(tokens.is_empty());
    }
}
