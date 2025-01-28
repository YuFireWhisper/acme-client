use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{base64::Base64, key_pair::KeyPair};

#[derive(Debug, Error)]
pub enum JwkError {
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("Failed to convert key: {0}")]
    KeyConversionError(String),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kty")]
pub enum Jwk {
    #[serde(rename = "RSA")]
    Rsa(RsaJwk),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RsaJwk {
    n: String,
    e: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alg: Option<String>,
}

impl RsaJwk {
    fn from_key_pair(key_pair: &KeyPair, kid: Option<String>) -> Result<Self, JwkError> {
        let rsa = key_pair
            .pub_key
            .rsa()
            .map_err(|e| JwkError::KeyConversionError(e.to_string()))?;

        let n = Base64::new(rsa.n().to_vec()).base64_url();
        let e = Base64::new(rsa.e().to_vec()).base64_url();
        let alg = Some(String::from("RS256"));

        Ok(RsaJwk { n, e, kid, alg })
    }
}

impl Jwk {
    pub fn new(key_pair: &KeyPair, kid: Option<String>) -> Result<Self, JwkError> {
        match key_pair.alg_name.as_str() {
            "RSA" => Ok(Jwk::Rsa(RsaJwk::from_key_pair(key_pair, kid)?)),
            alg => Err(JwkError::UnsupportedAlgorithm(alg.to_string())),
        }
    }

    pub fn kid(&self) -> Option<&str> {
        match self {
            Jwk::Rsa(jwk) => jwk.kid.as_deref(),
        }
    }

    pub fn algorithm(&self) -> Option<&str> {
        match self {
            Jwk::Rsa(jwk) => jwk.alg.as_deref(),
        }
    }
}
