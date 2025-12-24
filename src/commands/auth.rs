//! Authentication commands - OAuth login/logout with WorkOS
//!
//! Usage: beltic auth login
//!        beltic auth logout

use std::time::Duration;

use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use clap::{Args, Subcommand};
use console::style;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::config::{
    delete_credentials, load_config, load_credentials, save_config, save_credentials,
};

use super::prompts::CommandPrompts;

// WorkOS OAuth configuration
const WORKOS_CLIENT_ID: &str = "client_01KD6DX6TJ0SVR510DQ5WSTWTR";
const WORKOS_AUTHORIZE_URL: &str = "https://api.workos.com/user_management/authorize";
const CALLBACK_PORT: u16 = 8239;
const CALLBACK_PATH: &str = "/callback";
const CALLBACK_TIMEOUT_SECS: u64 = 300; // 5 minutes

#[derive(Args)]
pub struct AuthArgs {
    #[command(subcommand)]
    pub command: AuthCommand,
}

#[derive(Subcommand)]
pub enum AuthCommand {
    /// Login via browser OAuth
    Login(LoginArgs),
    /// Logout and clear stored credentials
    Logout,
}

#[derive(Args)]
pub struct LoginArgs {
    /// Custom API URL (for validating token after OAuth)
    #[arg(long)]
    pub api_url: Option<String>,

    /// Skip opening browser automatically (display URL instead)
    #[arg(long)]
    pub no_browser: bool,
}

/// PKCE code verifier and challenge
struct PkceChallenge {
    verifier: String,
    challenge: String,
}

/// OAuth token response from WorkOS
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

/// Response from GET /api/developers/me
#[derive(Debug, Deserialize)]
struct DeveloperMeResponse {
    data: DeveloperData,
}

#[derive(Debug, Deserialize)]
struct DeveloperData {
    id: String,
    attributes: DeveloperAttributes,
}

#[derive(Debug, Deserialize)]
struct DeveloperAttributes {
    legal_name: Option<String>,
    kyb_tier: Option<String>,
    verification_status: Option<String>,
}

const SUCCESS_HTML: &str = r#"<!DOCTYPE html>
<html>
<head>
    <title>Beltic CLI - Login Successful</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: #f5f5f5;
        }
        .container {
            text-align: center;
            padding: 40px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 { color: #22c55e; margin-bottom: 16px; }
        p { color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Login Successful</h1>
        <p>You can close this window and return to your terminal.</p>
    </div>
</body>
</html>"#;

const ERROR_HTML: &str = r#"<!DOCTYPE html>
<html>
<head>
    <title>Beltic CLI - Login Failed</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: #f5f5f5;
        }
        .container {
            text-align: center;
            padding: 40px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 { color: #ef4444; margin-bottom: 16px; }
        p { color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Login Failed</h1>
        <p>An error occurred during authentication. Please try again in your terminal.</p>
    </div>
</body>
</html>"#;

pub fn run(args: AuthArgs) -> Result<()> {
    match args.command {
        AuthCommand::Login(args) => run_login(args),
        AuthCommand::Logout => run_logout(),
    }
}

/// Generate PKCE code verifier and challenge
fn generate_pkce_challenge() -> PkceChallenge {
    // Generate 32 random bytes for the verifier
    let mut verifier_bytes = [0u8; 32];
    getrandom::getrandom(&mut verifier_bytes).expect("failed to generate random bytes");

    // Base64url encode the verifier (no padding)
    let verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);

    // SHA256 hash the verifier to create the challenge
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let challenge_bytes = hasher.finalize();

    // Base64url encode the challenge
    let challenge = URL_SAFE_NO_PAD.encode(challenge_bytes);

    PkceChallenge { verifier, challenge }
}

/// Build the OAuth authorization URL
fn build_authorize_url(pkce: &PkceChallenge) -> String {
    let redirect_uri = format!("http://localhost:{}{}", CALLBACK_PORT, CALLBACK_PATH);

    // Include provider=authkit to use AuthKit's hosted authentication UI
    // Also include state parameter for additional security
    let state = urlencoding::encode(&pkce.verifier[..16]); // Use first 16 chars of verifier as state
    
    format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&code_challenge={}&code_challenge_method=S256&scope=openid%20email%20profile&provider=authkit&state={}",
        WORKOS_AUTHORIZE_URL,
        WORKOS_CLIENT_ID,
        urlencoding::encode(&redirect_uri),
        pkce.challenge,
        state
    )
}

/// Extract the authorization code from a callback URL
fn extract_code_from_url(url: &str) -> Result<String> {
    // URL format: /callback?code=xxx or /callback?code=xxx&state=...
    let query_start = url.find('?').context("no query parameters in callback URL")?;
    let query = &url[query_start + 1..];

    for param in query.split('&') {
        if let Some(code) = param.strip_prefix("code=") {
            if !code.is_empty() {
                return Ok(code.to_string());
            }
        }
    }

    // Check for error parameter
    for param in query.split('&') {
        if let Some(error) = param.strip_prefix("error=") {
            let error_desc = query
                .split('&')
                .find_map(|p| p.strip_prefix("error_description="))
                .unwrap_or("Unknown error");
            anyhow::bail!("OAuth error: {} - {}", error, urlencoding::decode(error_desc)?);
        }
    }

    anyhow::bail!("no authorization code in callback URL")
}

/// Start the local callback server and wait for the OAuth callback
fn start_callback_server() -> Result<String> {
    let server = tiny_http::Server::http(format!("127.0.0.1:{}", CALLBACK_PORT))
        .map_err(|e| anyhow::anyhow!("failed to start callback server on port {}: {}", CALLBACK_PORT, e))?;

    // Wait for the callback request with timeout
    let request = server
        .recv_timeout(Duration::from_secs(CALLBACK_TIMEOUT_SECS))
        .context("callback server error")?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "login timed out after {} seconds. Please try again.",
                CALLBACK_TIMEOUT_SECS
            )
        })?;

    // Extract the code from the URL
    let url = request.url().to_string();
    let code_result = extract_code_from_url(&url);

    // Send response to browser
    let (html, status_code) = match &code_result {
        Ok(_) => (SUCCESS_HTML, 200),
        Err(_) => (ERROR_HTML, 400),
    };

    let response = tiny_http::Response::from_string(html)
        .with_status_code(status_code)
        .with_header(
            tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..])
                .unwrap(),
        );

    // Ignore response errors - user may have closed browser
    let _ = request.respond(response);

    code_result
}

/// Exchange the authorization code for an access token via the console API
/// The console proxies the token exchange (PKCE doesn't require client_secret)
fn exchange_code_for_token(code: &str, verifier: &str, api_url: &str) -> Result<TokenResponse> {
    let redirect_uri = format!("http://localhost:{}{}", CALLBACK_PORT, CALLBACK_PATH);
    let api_url_trimmed = api_url.trim_end_matches('/');
    let token_url = format!("{}/api/auth/token", api_url_trimmed);

    let client = reqwest::blocking::Client::new();
    
    // Send JSON to the console's token exchange endpoint
    let body = serde_json::json!({
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": redirect_uri,
        "client_id": WORKOS_CLIENT_ID,
    });
    
    let response = client
        .post(&token_url)
        .json(&body)
        .header("Accept", "application/json")
        .send()
        .with_context(|| format!("failed to exchange code for token - is the console running at {}?", api_url_trimmed))?;

    let status = response.status();
    let response_body = response.text().unwrap_or_default();

    if !status.is_success() {
        anyhow::bail!(
            "token exchange failed with status {}: {}",
            status,
            response_body
        );
    }

    let token_response: TokenResponse = serde_json::from_str(&response_body).context("failed to parse token response")?;
    
    Ok(token_response)
}

fn run_login(args: LoginArgs) -> Result<()> {
    let prompts = CommandPrompts::new();

    prompts.section_header("Beltic Login")?;
    println!();

    // Step 1: Generate PKCE challenge
    let pkce = generate_pkce_challenge();

    // Step 2: Build authorize URL
    let authorize_url = build_authorize_url(&pkce);

    // Step 3: Open browser or display URL
    prompts.info("Authenticating via browser...")?;
    println!();

    if args.no_browser {
        println!("Open this URL in your browser to authenticate:");
        println!();
        println!("  {}", style(&authorize_url).cyan().underlined());
        println!();
    } else {
        println!("Opening browser for authentication...");
        println!();
        println!("If the browser doesn't open automatically, visit:");
        println!("  {}", style(&authorize_url).cyan().underlined());
        println!();

        if let Err(e) = open::that(&authorize_url) {
            prompts.warn(&format!("Failed to open browser: {}. Please open the URL manually.", e))?;
        }
    }

    // Step 4: Get API URL (needed for token exchange)
    let config = load_config().unwrap_or_default();
    let api_url = args
        .api_url
        .as_ref()
        .unwrap_or(&config.api_url)
        .trim_end_matches('/')
        .to_string();

    // Step 5: Start callback server and wait for code
    prompts.info("Waiting for authorization (timeout: 5 minutes)...")?;
    let code = start_callback_server()?;

    // Step 6: Exchange code for token
    prompts.info("Exchanging authorization code...")?;
    let token_response = exchange_code_for_token(&code, &pkce.verifier, &api_url)?;

    // Step 7: Validate token by calling /api/developers/me

    prompts.info("Validating token...")?;

    let client = reqwest::blocking::Client::new();
    let auth_header = format!("Bearer {}", token_response.access_token);
    let me_url = format!("{}/api/developers/me", api_url);
    
    let response = client
        .get(&me_url)
        .header("Authorization", &auth_header)
        .header("Accept", "application/json")
        .send()
        .context("failed to connect to console API")?;

    let status = response.status();
    let body = response.text().unwrap_or_default();

    if !status.is_success() {
        if status.as_u16() == 401 || status.as_u16() == 403 {
            anyhow::bail!("Token validation failed. Your account may not be linked to the platform.");
        }

        anyhow::bail!("API request failed with status {}: {}", status, body);
    }

    let developer: DeveloperMeResponse = serde_json::from_str(&body)
        .context("failed to parse developer response")?;

    // Step 7: Save credentials
    save_credentials(&token_response.access_token).context("failed to save credentials")?;

    // Step 8: Update and save config
    let mut config = config;
    config.api_url = api_url;
    config.current_developer_id = Some(developer.data.id.clone());
    save_config(&config).context("failed to save config")?;

    // Print success
    println!();
    println!("{}", style("Login successful!").green().bold());
    println!();
    println!("  {} {}", style("Developer ID:").dim(), developer.data.id);

    if let Some(name) = &developer.data.attributes.legal_name {
        println!("  {} {}", style("Name:").dim(), name);
    }

    if let Some(tier) = &developer.data.attributes.kyb_tier {
        println!("  {} {}", style("KYB Tier:").dim(), tier);
    }

    if let Some(status) = &developer.data.attributes.verification_status {
        let status_styled = match status.as_str() {
            "verified" => style(status).green(),
            "pending" => style(status).yellow(),
            _ => style(status).dim(),
        };
        println!("  {} {}", style("Status:").dim(), status_styled);
    }

    println!();
    println!("{}", style("Next steps:").cyan().bold());
    println!("  Check your identity:  beltic whoami");
    println!("  Create an agent:      beltic init");

    Ok(())
}

fn run_logout() -> Result<()> {
    let prompts = CommandPrompts::new();

    prompts.section_header("Beltic Logout")?;
    println!();

    // Check if credentials exist
    if load_credentials()?.is_none() {
        prompts.warn("You are not currently logged in.")?;
        return Ok(());
    }

    // Delete credentials
    delete_credentials()?;

    // Clear developer ID from config
    let mut config = load_config().unwrap_or_default();
    config.current_developer_id = None;
    save_config(&config)?;

    println!("{}", style("Logged out successfully.").green().bold());
    println!();
    println!(
        "To log in again, run: {}",
        style("beltic auth login").cyan()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkce_challenge_generation() {
        let pkce = generate_pkce_challenge();

        // Verifier should be base64url encoded 32 bytes = 43 chars
        assert_eq!(pkce.verifier.len(), 43);

        // Challenge should be base64url encoded SHA256 = 43 chars
        assert_eq!(pkce.challenge.len(), 43);

        // Verifier and challenge should be different
        assert_ne!(pkce.verifier, pkce.challenge);
    }

    #[test]
    fn test_authorize_url_format() {
        let pkce = PkceChallenge {
            verifier: "test_verifier".to_string(),
            challenge: "test_challenge".to_string(),
        };

        let url = build_authorize_url(&pkce);

        assert!(url.starts_with(WORKOS_AUTHORIZE_URL));
        assert!(url.contains(&format!("client_id={}", WORKOS_CLIENT_ID)));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("code_challenge=test_challenge"));
        assert!(url.contains("code_challenge_method=S256"));
    }

    #[test]
    fn test_extract_code_from_url() {
        let url = "/callback?code=abc123";
        assert_eq!(extract_code_from_url(url).unwrap(), "abc123");

        let url_with_state = "/callback?code=xyz789&state=some_state";
        assert_eq!(extract_code_from_url(url_with_state).unwrap(), "xyz789");
    }

    #[test]
    fn test_extract_code_missing() {
        let url = "/callback?state=some_state";
        assert!(extract_code_from_url(url).is_err());
    }

    #[test]
    fn test_extract_code_error() {
        let url = "/callback?error=access_denied&error_description=User%20cancelled";
        let result = extract_code_from_url(url);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("access_denied"));
    }
}
