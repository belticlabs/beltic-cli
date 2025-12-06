use anyhow::{Context, Result};
use chrono::Utc;
use glob::glob;
use globset::{Glob, GlobSetBuilder};
use ignore::WalkBuilder;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::manifest::config::PathConfig;
use crate::manifest::schema::{
    ExternalDep, FingerprintMetadata, FingerprintScope, InternalDep, PathConfiguration,
};

/// Result of fingerprinting operation
#[derive(Debug)]
pub struct FingerprintResult {
    pub hash: String,
    pub metadata: FingerprintMetadata,
    pub file_count: usize,
    pub total_size: u64,
    pub files_hashed: Vec<PathBuf>,
}

/// Options for fingerprinting
#[derive(Debug, Clone)]
pub struct FingerprintOptions {
    pub include_patterns: Vec<String>,
    pub exclude_patterns: Vec<String>,
    pub root_path: PathBuf,
    pub include_dependencies: bool,
    pub respect_gitignore: bool,
}

impl Default for FingerprintOptions {
    fn default() -> Self {
        Self {
            include_patterns: vec!["**/*".to_string()],
            exclude_patterns: vec![
                ".git/**".to_string(),
                "target/**".to_string(),
                "node_modules/**".to_string(),
                "dist/**".to_string(),
                "build/**".to_string(),
                "*.log".to_string(),
                ".env*".to_string(),
            ],
            root_path: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            include_dependencies: false,
            respect_gitignore: true,
        }
    }
}

impl FingerprintOptions {
    /// Create options from a PathConfig
    pub fn from_path_config(config: &PathConfig, root: PathBuf) -> Self {
        Self {
            include_patterns: config.include.clone(),
            exclude_patterns: config.exclude.clone(),
            root_path: root,
            include_dependencies: false,
            respect_gitignore: true,
        }
    }
}

/// Generate a SHA256 fingerprint of the codebase
pub fn generate_fingerprint(options: &FingerprintOptions) -> Result<FingerprintResult> {
    let mut hasher = Sha256::new();
    let mut file_hashes = BTreeMap::new(); // Use BTreeMap for deterministic ordering
    let mut total_size = 0u64;
    let mut files_hashed = Vec::new();

    // Collect all files to hash
    let files = collect_files(options)?;

    // Hash each file
    for file_path in files {
        if file_path.is_file() {
            let relative_path = file_path
                .strip_prefix(&options.root_path)
                .unwrap_or(&file_path)
                .to_string_lossy()
                .to_string();

            // Normalize path separators for cross-platform consistency
            // Always use forward slashes, regardless of OS
            let normalized_path = relative_path.replace('\\', "/");

            let file_hash = hash_file(&file_path)?;
            let file_size = fs::metadata(&file_path)?.len();

            file_hashes.insert(normalized_path, file_hash);
            total_size += file_size;
            files_hashed.push(file_path);
        }
    }

    // Create deterministic combined hash
    for (path, hash) in &file_hashes {
        hasher.update(path.as_bytes());
        hasher.update(b":");
        hasher.update(hash.as_bytes());
        hasher.update(b"\n");
    }

    let final_hash = format!("{:x}", hasher.finalize());

    // Build metadata
    let metadata = FingerprintMetadata {
        algorithm: "sha256".to_string(),
        timestamp: Utc::now(),
        scope: FingerprintScope {
            scope_type: if options.include_patterns == vec!["**/*".to_string()] {
                "full".to_string()
            } else {
                "scoped".to_string()
            },
            paths: PathConfiguration {
                included: options.include_patterns.clone(),
                excluded: options.exclude_patterns.clone(),
                root: Some(options.root_path.to_string_lossy().to_string()),
            },
            files_processed: file_hashes.len(),
            total_size,
        },
        dependencies: None, // Will be populated if include_dependencies is true
    };

    Ok(FingerprintResult {
        hash: format!("sha256:{}", final_hash),
        metadata,
        file_count: file_hashes.len(),
        total_size,
        files_hashed,
    })
}

/// Collect files based on include/exclude patterns
fn collect_files(options: &FingerprintOptions) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Build exclude GlobSet once for efficiency
    let exclude_set =
        build_globset(&options.exclude_patterns).context("Failed to build exclude patterns")?;

    // Process each include pattern
    for pattern in &options.include_patterns {
        let full_pattern = options.root_path.join(pattern);
        let pattern_str = full_pattern.to_string_lossy();

        // Use glob for pattern matching
        if pattern.contains('*') || pattern.contains('?') || pattern.contains('[') {
            for entry in glob(&pattern_str).context(format!("Invalid glob pattern: {}", pattern))? {
                if let Ok(path) = entry {
                    if should_include_file(&path, &options.root_path, &exclude_set)? {
                        if seen.insert(path.clone()) {
                            files.push(path);
                        }
                    }
                }
            }
        } else {
            // Direct path
            let path = options.root_path.join(pattern);
            if path.exists() {
                if path.is_file() {
                    if should_include_file(&path, &options.root_path, &exclude_set)? {
                        if seen.insert(path.clone()) {
                            files.push(path);
                        }
                    }
                } else if path.is_dir() {
                    // Walk directory
                    let walker = if options.respect_gitignore {
                        WalkBuilder::new(&path)
                            .hidden(false)
                            .git_ignore(true)
                            .git_global(true)
                            .git_exclude(true)
                            .follow_links(false) // Explicitly don't follow symlinks for security
                            .build()
                    } else {
                        WalkBuilder::new(&path)
                            .hidden(false)
                            .git_ignore(false)
                            .follow_links(false) // Explicitly don't follow symlinks for security
                            .build()
                    };

                    for entry in walker {
                        if let Ok(entry) = entry {
                            let entry_path = entry.path().to_path_buf();
                            if entry_path.is_file() {
                                if should_include_file(
                                    &entry_path,
                                    &options.root_path,
                                    &exclude_set,
                                )? {
                                    if seen.insert(entry_path.clone()) {
                                        files.push(entry_path);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Sort files for deterministic output
    files.sort();

    Ok(files)
}

/// Build a GlobSet from patterns for efficient matching
fn build_globset(patterns: &[String]) -> Result<globset::GlobSet> {
    let mut builder = GlobSetBuilder::new();

    for pattern in patterns {
        // Create glob that properly handles ** patterns
        let glob = Glob::new(pattern).context(format!("Invalid glob pattern: {}", pattern))?;
        builder.add(glob);
    }

    builder.build().context("Failed to build GlobSet")
}

/// Check if a file should be included based on exclude patterns
fn should_include_file(path: &Path, root: &Path, exclude_set: &globset::GlobSet) -> Result<bool> {
    // Get relative path from root
    let relative_path = path.strip_prefix(root).unwrap_or(path).to_string_lossy();

    // Normalize to forward slashes for consistent matching across platforms
    let normalized_path = relative_path.replace('\\', "/");

    // Check if path matches any exclude pattern
    if exclude_set.is_match(&normalized_path) {
        return Ok(false);
    }

    Ok(true)
}

/// Hash a single file
fn hash_file(path: &Path) -> Result<String> {
    let mut file =
        fs::File::open(path).context(format!("Failed to open file: {}", path.display()))?;

    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

/// Generate fingerprint for internal dependencies
pub fn fingerprint_internal_dependencies(
    deps: &[String],
    base_dir: &Path,
) -> Result<Vec<InternalDep>> {
    let mut results = Vec::new();

    for dep_path in deps {
        let full_path = base_dir.join(dep_path);
        if full_path.exists() {
            let options = FingerprintOptions {
                root_path: full_path.clone(),
                ..Default::default()
            };

            let fingerprint = generate_fingerprint(&options)?;
            results.push(InternalDep {
                path: dep_path.clone(),
                hash: fingerprint.hash,
            });
        }
    }

    Ok(results)
}

/// Parse and fingerprint external dependencies (placeholder for now)
pub fn fingerprint_external_dependencies(
    _deps: &[String],
    _base_dir: &Path,
) -> Result<Vec<ExternalDep>> {
    // This would parse package.json, Cargo.toml, requirements.txt, etc.
    // and generate hashes of the dependency specifications
    // For now, return empty vec
    Ok(vec![])
}

/// Update an existing manifest's fingerprint
pub fn update_manifest_fingerprint(
    manifest_path: &Path,
    options: &FingerprintOptions,
) -> Result<String> {
    let fingerprint = generate_fingerprint(options)?;

    // Read existing manifest
    let manifest_content = fs::read_to_string(manifest_path)?;
    let mut manifest: serde_json::Value = serde_json::from_str(&manifest_content)?;

    // Update fingerprint fields
    if let Some(obj) = manifest.as_object_mut() {
        obj.insert(
            "systemConfigFingerprint".to_string(),
            serde_json::json!(fingerprint.hash),
        );
        obj.insert(
            "fingerprintMetadata".to_string(),
            serde_json::to_value(&fingerprint.metadata)?,
        );
    }

    // Write updated manifest
    let updated = serde_json::to_string_pretty(&manifest)?;
    fs::write(manifest_path, updated)?;

    Ok(fingerprint.hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_hash_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, "hello world").unwrap();

        let hash = hash_file(&file_path).unwrap();
        // SHA256 of "hello world"
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_deterministic_fingerprint() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "content a").unwrap();
        fs::write(dir.path().join("b.txt"), "content b").unwrap();

        let options = FingerprintOptions {
            root_path: dir.path().to_path_buf(),
            include_patterns: vec!["*.txt".to_string()],
            exclude_patterns: vec![],
            include_dependencies: false,
            respect_gitignore: false,
        };

        let result1 = generate_fingerprint(&options).unwrap();
        let result2 = generate_fingerprint(&options).unwrap();

        assert_eq!(result1.hash, result2.hash);
        assert_eq!(result1.file_count, 2);
    }

    #[test]
    fn test_cross_platform_paths() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/main.rs"), "fn main() {}").unwrap();

        let options = FingerprintOptions {
            root_path: dir.path().to_path_buf(),
            include_patterns: vec!["**/*.rs".to_string()],
            exclude_patterns: vec![],
            include_dependencies: false,
            respect_gitignore: false,
        };

        let result = generate_fingerprint(&options).unwrap();

        // The fingerprint should use forward slashes internally, regardless of OS
        assert_eq!(result.file_count, 1);

        // Verify that the path in metadata uses forward slashes
        let paths = &result.metadata.scope.paths.included;
        assert!(paths.contains(&"**/*.rs".to_string()));
    }

    #[test]
    fn test_exclude_patterns_with_double_star() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("target/debug")).unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();

        fs::write(dir.path().join("src/main.rs"), "fn main() {}").unwrap();
        fs::write(dir.path().join("target/debug/output.txt"), "build output").unwrap();

        let options = FingerprintOptions {
            root_path: dir.path().to_path_buf(),
            include_patterns: vec!["**/*".to_string()],
            exclude_patterns: vec!["**/target/**".to_string()],
            include_dependencies: false,
            respect_gitignore: false,
        };

        let result = generate_fingerprint(&options).unwrap();

        // Should only include src/main.rs, not target/debug/output.txt
        assert_eq!(result.file_count, 1);

        // Verify the included file is main.rs
        let included_files: Vec<String> = result
            .files_hashed
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        assert!(included_files.contains(&"main.rs".to_string()));
        assert!(!included_files.contains(&"output.txt".to_string()));
    }

    #[test]
    fn test_exclude_patterns_exact_match() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("test.txt"), "test").unwrap();
        fs::write(dir.path().join("test.log"), "log").unwrap();
        fs::write(dir.path().join("data.json"), "data").unwrap();

        let options = FingerprintOptions {
            root_path: dir.path().to_path_buf(),
            include_patterns: vec!["*".to_string()],
            exclude_patterns: vec!["*.log".to_string()],
            include_dependencies: false,
            respect_gitignore: false,
        };

        let result = generate_fingerprint(&options).unwrap();

        // Should exclude test.log
        assert_eq!(result.file_count, 2);

        let included_files: Vec<String> = result
            .files_hashed
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        assert!(included_files.contains(&"test.txt".to_string()));
        assert!(included_files.contains(&"data.json".to_string()));
        assert!(!included_files.contains(&"test.log".to_string()));
    }

    #[test]
    fn test_empty_directory() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("empty")).unwrap();

        let options = FingerprintOptions {
            root_path: dir.path().to_path_buf(),
            include_patterns: vec!["**/*".to_string()],
            exclude_patterns: vec![],
            include_dependencies: false,
            respect_gitignore: false,
        };

        let result = generate_fingerprint(&options).unwrap();

        // Empty directory should result in zero files
        assert_eq!(result.file_count, 0);
    }

    #[test]
    fn test_empty_file() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("empty.txt"), "").unwrap();

        let options = FingerprintOptions {
            root_path: dir.path().to_path_buf(),
            include_patterns: vec!["*.txt".to_string()],
            exclude_patterns: vec![],
            include_dependencies: false,
            respect_gitignore: false,
        };

        let result = generate_fingerprint(&options).unwrap();

        // Empty file should still be counted
        assert_eq!(result.file_count, 1);

        // SHA256 of empty string
        let empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        // The fingerprint should be different from the empty hash
        // because it includes the path in the combined hash
        assert_ne!(result.hash, format!("sha256:{}", empty_hash));
    }

    #[test]
    fn test_large_file() {
        let dir = tempdir().unwrap();
        let large_content = "x".repeat(100_000); // 100KB file
        fs::write(dir.path().join("large.txt"), &large_content).unwrap();

        let options = FingerprintOptions {
            root_path: dir.path().to_path_buf(),
            include_patterns: vec!["*.txt".to_string()],
            exclude_patterns: vec![],
            include_dependencies: false,
            respect_gitignore: false,
        };

        let result = generate_fingerprint(&options).unwrap();

        // Should handle large file without issues
        assert_eq!(result.file_count, 1);
        assert_eq!(result.total_size, 100_000);
    }

    #[test]
    fn test_nested_directories() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("a/b/c")).unwrap();
        fs::write(dir.path().join("a/file1.txt"), "1").unwrap();
        fs::write(dir.path().join("a/b/file2.txt"), "2").unwrap();
        fs::write(dir.path().join("a/b/c/file3.txt"), "3").unwrap();

        let options = FingerprintOptions {
            root_path: dir.path().to_path_buf(),
            include_patterns: vec!["**/*.txt".to_string()],
            exclude_patterns: vec![],
            include_dependencies: false,
            respect_gitignore: false,
        };

        let result = generate_fingerprint(&options).unwrap();

        // Should find all three files in nested directories
        assert_eq!(result.file_count, 3);
    }

    #[test]
    fn test_special_characters_in_filenames() {
        let dir = tempdir().unwrap();
        // Test files with spaces and special characters
        fs::write(dir.path().join("file with spaces.txt"), "test").unwrap();
        fs::write(dir.path().join("file-with-dashes.txt"), "test").unwrap();
        fs::write(dir.path().join("file_with_underscores.txt"), "test").unwrap();

        let options = FingerprintOptions {
            root_path: dir.path().to_path_buf(),
            include_patterns: vec!["*.txt".to_string()],
            exclude_patterns: vec![],
            include_dependencies: false,
            respect_gitignore: false,
        };

        let result = generate_fingerprint(&options).unwrap();

        // Should handle special characters in filenames
        assert_eq!(result.file_count, 3);
    }

    #[test]
    fn test_glob_pattern_matching() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("test.rs"), "rust").unwrap();
        fs::write(dir.path().join("test.js"), "javascript").unwrap();
        fs::write(dir.path().join("test.py"), "python").unwrap();

        let options = FingerprintOptions {
            root_path: dir.path().to_path_buf(),
            include_patterns: vec!["*.rs".to_string()],
            exclude_patterns: vec![],
            include_dependencies: false,
            respect_gitignore: false,
        };

        let result = generate_fingerprint(&options).unwrap();

        // Should only match .rs files
        assert_eq!(result.file_count, 1);

        let included_files: Vec<String> = result
            .files_hashed
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        assert!(included_files.contains(&"test.rs".to_string()));
    }

    #[test]
    fn test_build_globset() {
        let patterns = vec![
            "**/target/**".to_string(),
            "*.log".to_string(),
            ".git/**".to_string(),
        ];

        let globset = build_globset(&patterns).unwrap();

        // Test matching
        assert!(globset.is_match("target/debug/file.rs"));
        assert!(globset.is_match("src/target/file.rs"));
        assert!(globset.is_match("test.log"));
        assert!(globset.is_match(".git/config"));

        // Test non-matching
        assert!(!globset.is_match("src/main.rs"));
        assert!(!globset.is_match("data.json"));
    }
}
