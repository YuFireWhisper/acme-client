use crate::nonce::{NonceT, NonceError};
use serde::Serialize;
use serde_json::Value as JsonValue;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtectionError {
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Nonce error: {0}")]
    Nonce(#[from] NonceError),
}

type Result<T> = std::result::Result<T, ProtectionError>;

pub struct Protection<'a> {
    nonce: &'a dyn NonceT,
    alg: String,
    value: Option<JsonValue>,
}

#[derive(Debug, Serialize)]
pub struct ProtectedHeader {
    alg: String,
    nonce: String,
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
}

impl<'a> Protection<'a> {
    pub fn new(nonce: &'a dyn NonceT, alg: impl AsRef<str>) -> Self {
        let alg = match alg.as_ref().to_uppercase().as_str() {
            "RS256" | "RSA" => "RS256",
            "ES256" | "ECDSA" => "ES256",
            _ => "RS256",
        }
        .to_string();

        Self {
            nonce,
            alg,
            value: None,
        }
    }

    pub fn set_value<T: Serialize>(&mut self, value: T) -> Result<&mut Self> {
        self.value = Some(serde_json::to_value(value)?);
        Ok(self)
    }

    pub fn create_header(&self, url: impl Into<String>) -> Result<ProtectedHeader> {
        let nonce = self.nonce.get()?;
        let url = url.into();

        let (jwk, kid) = match &self.value {
            Some(value) if value.is_object() => (Some(value.clone()), None),
            Some(value) => (
                None,
                Some(
                    value
                        .as_str()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| value.to_string()),
                ),
            ),
            None => (None, None),
        };

        Ok(ProtectedHeader {
            alg: self.alg.clone(),
            nonce,
            url,
            jwk,
            kid,
        })
    }
}

impl std::fmt::Display for ProtectedHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        serde_json::to_string(self)
            .map_err(|_| std::fmt::Error)
            .and_then(|s| write!(f, "{}", s))
    }
}

#[cfg(test)]
mod tests {
    use crate::nonce::MockNonce;

    use super::*;
    use serde_json::json;

    #[test]
    fn test_alg_normalization() {
        let nonce = MockNonce::new("test-nonce");
        let cases = vec![
            ("rs256", "RS256"),
            ("RSA", "RS256"),
            ("es256", "ES256"),
            ("ECDSA", "ES256"),
            ("invalid", "RS256"),
        ];

        for (input, expected) in cases {
            let protection = Protection::new(&nonce, input);
            assert_eq!(protection.alg, expected);
        }
    }

    #[test]
    fn test_jwk_handling() -> Result<()> {
        let nonce = MockNonce::new("test-nonce");
        let jwk = json!({"kty": "EC", "crv": "P-256"});

        let mut protection = Protection::new(&nonce, "ES256");
        protection.set_value(&jwk)?;
        let header = protection.create_header("https://example.com")?;

        assert!(header.jwk.is_some());
        assert_eq!(header.jwk, Some(jwk));
        assert!(header.kid.is_none());
        Ok(())
    }

    #[test]
    fn test_kid_handling() -> Result<()> {
        let nonce = MockNonce::new("test-nonce");

        let mut protection = Protection::new(&nonce, "RS256");
        protection.set_value("key_id_123")?;
        let header = protection.create_header("https://example.com")?;
        assert_eq!(header.kid, Some("key_id_123".to_string()));
        assert!(header.jwk.is_none());

        let mut protection = Protection::new(&nonce, "RS256");
        protection.set_value(42)?;
        let header = protection.create_header("https://example.com")?;
        assert_eq!(header.kid, Some("42".to_string()));

        Ok(())
    }

    #[test]
    fn test_header_serialization() -> Result<()> {
        let nonce = MockNonce::new("test-nonce");
        let header = Protection::new(&nonce, "ES256").create_header("https://example.com")?;

        let json = header.to_string();
        assert!(json.contains("\"nonce\":\"test-nonce\""));
        assert!(json.contains("\"url\":\"https://example.com\""));
        assert!(json.contains("\"alg\":\"ES256\""));
        Ok(())
    }
}
