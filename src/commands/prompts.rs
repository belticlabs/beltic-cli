//! Shared interactive prompts for CLI commands
//!
//! This module provides reusable prompt utilities for keygen, sign, and verify commands.

use std::path::PathBuf;

use anyhow::Result;
use chrono::Local;
use console::{style, Term};
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Select};

use crate::crypto::SignatureAlg;

/// Interactive prompts for CLI commands
pub struct CommandPrompts {
    theme: ColorfulTheme,
    term: Term,
}

impl Default for CommandPrompts {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandPrompts {
    pub fn new() -> Self {
        Self {
            theme: ColorfulTheme::default(),
            term: Term::stdout(),
        }
    }

    /// Display a section header
    pub fn section_header(&self, title: &str) -> Result<()> {
        self.term.write_line("")?;
        self.term
            .write_line(&format!("{}", style(title).bold().cyan()))?;
        self.term
            .write_line(&style("-".repeat(40)).dim().to_string())?;
        Ok(())
    }

    /// Display a success message
    pub fn success(&self, message: &str) -> Result<()> {
        self.term
            .write_line(&format!("{} {}", style("").green(), message))?;
        Ok(())
    }

    /// Display an info message
    pub fn info(&self, message: &str) -> Result<()> {
        self.term.write_line(&format!("{}", style(message).dim()))?;
        Ok(())
    }

    /// Display a warning message
    pub fn warn(&self, message: &str) -> Result<()> {
        self.term
            .write_line(&format!("{}", style(message).yellow()))?;
        Ok(())
    }

    /// Prompt for algorithm selection
    pub fn prompt_algorithm(&self, default: Option<SignatureAlg>) -> Result<SignatureAlg> {
        let options = vec![
            ("EdDSA (Ed25519) - recommended", SignatureAlg::EdDsa),
            ("ES256 (P-256) - NIST compliant", SignatureAlg::Es256),
        ];

        let default_idx = match default.unwrap_or(SignatureAlg::EdDsa) {
            SignatureAlg::EdDsa => 0,
            SignatureAlg::Es256 => 1,
        };

        let idx = Select::with_theme(&self.theme)
            .with_prompt("Select algorithm")
            .items(&options.iter().map(|o| o.0).collect::<Vec<_>>())
            .default(default_idx)
            .interact()?;

        Ok(options[idx].1)
    }

    /// Prompt for a file path with optional default
    pub fn prompt_path(&self, prompt: &str, default: Option<&PathBuf>) -> Result<PathBuf> {
        let mut input = Input::<String>::with_theme(&self.theme).with_prompt(prompt);

        if let Some(path) = default {
            input = input.default(path.display().to_string());
        }

        let path_str = input.interact_text()?;
        Ok(PathBuf::from(path_str))
    }

    /// Prompt for a string with optional default
    pub fn prompt_string(&self, prompt: &str, default: Option<&str>) -> Result<String> {
        let mut input = Input::<String>::with_theme(&self.theme).with_prompt(prompt);

        if let Some(d) = default {
            input = input.default(d.to_string());
        }

        Ok(input.interact_text()?)
    }

    /// Prompt for confirmation
    pub fn prompt_confirm(&self, prompt: &str, default: bool) -> Result<bool> {
        Ok(Confirm::with_theme(&self.theme)
            .with_prompt(prompt)
            .default(default)
            .interact()?)
    }

    /// Prompt for selection from options
    pub fn prompt_select(&self, prompt: &str, options: &[&str], default: usize) -> Result<usize> {
        Ok(Select::with_theme(&self.theme)
            .with_prompt(prompt)
            .items(options)
            .default(default)
            .interact()?)
    }

    /// Prompt for selection from PathBuf options with "Enter path manually" option
    pub fn prompt_select_path(
        &self,
        prompt: &str,
        paths: &[PathBuf],
        allow_manual: bool,
    ) -> Result<PathBuf> {
        let mut options: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();

        if allow_manual {
            options.push("Enter path manually...".to_string());
        }

        let idx = Select::with_theme(&self.theme)
            .with_prompt(prompt)
            .items(&options)
            .default(0)
            .interact()?;

        if allow_manual && idx == options.len() - 1 {
            // User chose manual entry
            self.prompt_path("Enter path", None)
        } else {
            Ok(paths[idx].clone())
        }
    }
}

/// Get the default beltic directory (./.beltic/)
pub fn beltic_dir() -> PathBuf {
    PathBuf::from(".beltic")
}

/// Generate a timestamp-based key name
/// Format: {alg}-{YYYY-MM-DD}
/// Example: "eddsa-2024-11-26"
pub fn generate_key_name(alg: SignatureAlg) -> String {
    let date = Local::now().format("%Y-%m-%d");
    let alg_str = match alg {
        SignatureAlg::EdDsa => "eddsa",
        SignatureAlg::Es256 => "es256",
    };
    format!("{}-{}", alg_str, date)
}

/// Generate default private key path
pub fn default_private_key_path(name: &str) -> PathBuf {
    beltic_dir().join(format!("{}-private.pem", name))
}

/// Generate default public key path
pub fn default_public_key_path(name: &str) -> PathBuf {
    beltic_dir().join(format!("{}-public.pem", name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_beltic_dir() {
        assert_eq!(beltic_dir(), PathBuf::from(".beltic"));
    }

    #[test]
    fn test_generate_key_name() {
        let name = generate_key_name(SignatureAlg::EdDsa);
        assert!(name.starts_with("eddsa-"));
        assert!(name.len() == 16); // "eddsa-YYYY-MM-DD"

        let name = generate_key_name(SignatureAlg::Es256);
        assert!(name.starts_with("es256-"));
    }

    #[test]
    fn test_default_paths() {
        let name = "eddsa-2024-11-26";
        assert_eq!(
            default_private_key_path(name),
            PathBuf::from(".beltic/eddsa-2024-11-26-private.pem")
        );
        assert_eq!(
            default_public_key_path(name),
            PathBuf::from(".beltic/eddsa-2024-11-26-public.pem")
        );
    }
}
