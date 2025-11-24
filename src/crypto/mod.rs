use std::{fmt, str::FromStr};

use anyhow::anyhow;
use jsonwebtoken::Algorithm;

pub mod signer;
pub mod verifier;

pub use signer::sign_jws;
pub use verifier::{verify_jws, VerifiedToken};

pub const BELTIC_JWT_TYP: &str = "application/beltic-agent+jwt";

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SignatureAlg {
    Es256,
    EdDsa,
}

impl SignatureAlg {
    pub fn as_jwt_alg(self) -> Algorithm {
        match self {
            SignatureAlg::Es256 => Algorithm::ES256,
            SignatureAlg::EdDsa => Algorithm::EdDSA,
        }
    }

    pub fn try_from_jwt_alg(alg: Algorithm) -> anyhow::Result<Self> {
        match alg {
            Algorithm::ES256 => Ok(SignatureAlg::Es256),
            Algorithm::EdDSA => Ok(SignatureAlg::EdDsa),
            other => Err(anyhow!("unsupported JWS alg: {:?}", other)),
        }
    }
}

impl fmt::Display for SignatureAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureAlg::Es256 => write!(f, "ES256"),
            SignatureAlg::EdDsa => write!(f, "EdDSA"),
        }
    }
}

impl FromStr for SignatureAlg {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "ES256" => Ok(SignatureAlg::Es256),
            "EDDSA" => Ok(SignatureAlg::EdDsa),
            _ => Err(format!(
                "unknown algorithm '{}', expected ES256 or EdDSA",
                s
            )),
        }
    }
}

pub fn parse_signature_alg(value: &str) -> Result<SignatureAlg, String> {
    value.parse()
}
