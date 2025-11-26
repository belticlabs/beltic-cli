use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use jsonschema::{Draft, JSONSchema};
use serde_json::{Map, Value};
use std::sync::OnceLock;

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
}

static AGENT_SCHEMA: OnceLock<Value> = OnceLock::new();
static DEVELOPER_SCHEMA: OnceLock<Value> = OnceLock::new();
static AGENT_VALIDATOR: OnceLock<JSONSchema> = OnceLock::new();
static DEVELOPER_VALIDATOR: OnceLock<JSONSchema> = OnceLock::new();

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

/// Validate the credential JSON against the embedded schema.
pub fn validate_credential(kind: CredentialKind, value: &Value) -> Result<Vec<String>> {
    let compiled = validator(kind);

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

fn schema_value(kind: CredentialKind) -> &'static Value {
    match kind {
        CredentialKind::Agent => AGENT_SCHEMA.get_or_init(|| {
            serde_json::from_str(include_str!(
                "../schemas/agent/v1/agent-credential-v1.schema.json"
            ))
            .expect("embedded agent schema should parse")
        }),
        CredentialKind::Developer => DEVELOPER_SCHEMA.get_or_init(|| {
            serde_json::from_str(include_str!(
                "../schemas/developer/v1/developer-credential-v1.schema.json"
            ))
            .expect("embedded developer schema should parse")
        }),
    }
}

fn validator(kind: CredentialKind) -> &'static JSONSchema {
    match kind {
        CredentialKind::Agent => AGENT_VALIDATOR.get_or_init(|| compile_schema(schema_value(kind))),
        CredentialKind::Developer => {
            DEVELOPER_VALIDATOR.get_or_init(|| compile_schema(schema_value(kind)))
        }
    }
}

fn compile_schema(schema: &'static Value) -> JSONSchema {
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(schema)
        .expect("embedded schema should compile")
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
