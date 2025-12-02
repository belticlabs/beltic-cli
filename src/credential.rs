use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use jsonschema::{Draft, JSONSchema};
use serde_json::{Map, Value};
use std::sync::{Mutex, OnceLock};

use crate::schema::{self, SchemaType};

/// Media type for DeveloperCredential JWTs.
pub const DEVELOPER_TYP: &str = "application/beltic-developer+jwt";
/// Media type for AgentCredential JWTs.
pub const AGENT_TYP: &str = "application/beltic-agent+jwt";

/// Supported credential types for signing/verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    Agent,
    Developer,
}

impl CredentialKind {
    pub fn media_type(self) -> &'static str {
        match self {
            CredentialKind::Agent => AGENT_TYP,
            CredentialKind::Developer => DEVELOPER_TYP,
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            CredentialKind::Agent => "AgentCredential",
            CredentialKind::Developer => "DeveloperCredential",
        }
    }

    fn issuance_field(self) -> &'static str {
        match self {
            CredentialKind::Agent => "credentialIssuanceDate",
            CredentialKind::Developer => "issuanceDate",
        }
    }

    fn expiration_field(self) -> &'static str {
        match self {
            CredentialKind::Agent => "credentialExpirationDate",
            CredentialKind::Developer => "expirationDate",
        }
    }

    fn schema_type(self) -> SchemaType {
        match self {
            CredentialKind::Agent => SchemaType::Agent,
            CredentialKind::Developer => SchemaType::Developer,
        }
    }
}

// Use mutex-protected boxes for dynamic schema storage
static AGENT_SCHEMA: OnceLock<Mutex<Option<Value>>> = OnceLock::new();
static DEVELOPER_SCHEMA: OnceLock<Mutex<Option<Value>>> = OnceLock::new();

/// Parse a credential type string (for CLI value parsers).
pub fn parse_credential_kind(value: &str) -> Result<CredentialKind, String> {
    match value.to_ascii_lowercase().as_str() {
        "agent" | "agentcredential" => Ok(CredentialKind::Agent),
        "developer" | "developercredential" => Ok(CredentialKind::Developer),
        other => Err(format!(
            "Unknown credential type '{}'. Expected 'agent' or 'developer'.",
            other
        )),
    }
}

/// Map a typ/media type value to a credential kind.
pub fn credential_kind_from_typ(value: &str) -> Option<CredentialKind> {
    match value {
        AGENT_TYP => Some(CredentialKind::Agent),
        DEVELOPER_TYP => Some(CredentialKind::Developer),
        _ => None,
    }
}

/// Attempt to detect credential type from the JSON payload.
pub fn detect_credential_kind(value: &Value) -> Option<CredentialKind> {
    // $schema hint
    if let Some(schema) = value.get("$schema").and_then(|v| v.as_str()) {
        if schema.contains("/agent/") {
            return Some(CredentialKind::Agent);
        }
        if schema.contains("/developer/") {
            return Some(CredentialKind::Developer);
        }
    }

    // Field-based heuristics
    if value.get("agentName").is_some() && value.get("agentId").is_some() {
        return Some(CredentialKind::Agent);
    }
    if value.get("legalName").is_some() && value.get("subjectDid").is_some() {
        return Some(CredentialKind::Developer);
    }

    None
}

/// Validate the credential JSON against the schema.
/// Uses dynamic schema fetching with caching and embedded fallback.
pub fn validate_credential(kind: CredentialKind, value: &Value) -> Result<Vec<String>> {
    // Ensure schema is loaded
    let schema = ensure_schema_loaded(kind);

    // Compile the schema (we compile fresh each time to use latest fetched schema)
    let compiled = compile_schema(&schema);

    let mut errors = Vec::new();
    if let Err(iter) = compiled.validate(value) {
        for err in iter {
            let path = err.instance_path.to_string();
            let location = if path.is_empty() {
                "<root>"
            } else {
                path.as_str()
            };
            errors.push(format!("{location}: {err}"));
        }
    }

    Ok(errors)
}

/// Get or fetch the schema for a credential kind.
/// Uses dynamic fetching with caching and embedded fallback.
fn get_or_fetch_schema(kind: CredentialKind) -> Value {
    schema::get_schema(kind.schema_type()).unwrap_or_else(|_| {
        // Ultimate fallback: use embedded schema
        match kind {
            CredentialKind::Agent => serde_json::from_str(include_str!(
                "../schemas/agent/v1/agent-credential-v1.schema.json"
            ))
            .expect("embedded agent schema should parse"),
            CredentialKind::Developer => serde_json::from_str(include_str!(
                "../schemas/developer/v1/developer-credential-v1.schema.json"
            ))
            .expect("embedded developer schema should parse"),
        }
    })
}

fn ensure_schema_loaded(kind: CredentialKind) -> Value {
    let schema_lock = match kind {
        CredentialKind::Agent => AGENT_SCHEMA.get_or_init(|| Mutex::new(None)),
        CredentialKind::Developer => DEVELOPER_SCHEMA.get_or_init(|| Mutex::new(None)),
    };

    let mut guard = schema_lock.lock().unwrap();
    if guard.is_none() {
        *guard = Some(get_or_fetch_schema(kind));
    }
    guard.as_ref().unwrap().clone()
}

fn compile_schema(schema: &Value) -> JSONSchema {
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(schema)
        .expect("schema should compile")
}

/// Options for building JWT claims from a credential.
pub struct ClaimsOptions<'a> {
    pub issuer: Option<&'a str>,
    pub subject: Option<&'a str>,
    pub audience: &'a [String],
}

/// Build JWT claims following the Beltic signing profile.
pub fn build_claims(
    credential: &Value,
    kind: CredentialKind,
    options: ClaimsOptions<'_>,
) -> Result<Value> {
    let issuer = if let Some(override_issuer) = options.issuer {
        override_issuer.to_string()
    } else {
        extract_string(credential, "issuerDid")?
    };

    let subject = if let Some(subject) = options.subject {
        subject.to_string()
    } else if let Some(subject) = credential
        .get("subjectDid")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
    {
        subject
    } else if kind == CredentialKind::Agent {
        // For agent credentials, use a DID derived from agentId
        // Format: did:agent:{agentId}
        let agent_id = credential
            .get("agentId")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        format!("did:agent:{}", agent_id)
    } else {
        return Err(anyhow!(
            "subject DID is required (pass --subject or include subjectDid in the credential)"
        ));
    };

    let credential_id = extract_string(credential, "credentialId")?;
    let nbf = parse_rfc3339_seconds(credential, kind.issuance_field())?;
    let exp = parse_rfc3339_seconds(credential, kind.expiration_field())?;

    if exp <= nbf {
        return Err(anyhow!(
            "expiration must be greater than issuance ({} <= {})",
            exp,
            nbf
        ));
    }

    let mut claims = Map::new();
    claims.insert("iss".to_string(), Value::String(issuer));
    claims.insert("sub".to_string(), Value::String(subject));
    claims.insert("jti".to_string(), Value::String(credential_id));
    claims.insert("nbf".to_string(), Value::Number(nbf.into()));
    claims.insert("exp".to_string(), Value::Number(exp.into()));
    claims.insert("iat".to_string(), Value::Number(nbf.into()));
    claims.insert("vc".to_string(), credential.clone());

    if !options.audience.is_empty() {
        if options.audience.len() == 1 {
            claims.insert(
                "aud".to_string(),
                Value::String(options.audience[0].clone()),
            );
        } else {
            claims.insert(
                "aud".to_string(),
                Value::Array(
                    options
                        .audience
                        .iter()
                        .map(|a| Value::String(a.clone()))
                        .collect(),
                ),
            );
        }
    }

    Ok(Value::Object(claims))
}

fn extract_string(value: &Value, field: &str) -> Result<String> {
    value
        .get(field)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("missing or invalid '{}' field", field))
}

fn parse_rfc3339_seconds(value: &Value, field: &str) -> Result<i64> {
    let raw = extract_string(value, field)?;
    let parsed: DateTime<Utc> = DateTime::parse_from_rfc3339(raw.trim())
        .map_err(|e| anyhow!("invalid {} (expecting RFC3339 date-time): {}", field, e))?
        .with_timezone(&Utc);
    Ok(parsed.timestamp())
}
