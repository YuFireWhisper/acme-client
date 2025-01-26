use crate::nonce::Nonce;
use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Debug)]
pub struct Protection {
    nonce: Nonce,
    alg: String,
    value: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ProtectedHeader {
    alg: String,
    nonce: String,
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
}

impl Protection {
    pub fn new(nonce: Nonce, alg: impl AsRef<str>) -> Self {
        let alg = match alg.as_ref().to_uppercase().as_str() {
            "RSA" | "RS256" => "RS256",
            "ECDSA" | "ES256" => "ES256",
            _ => "RS256",
        }
        .to_string();

        Self {
            nonce,
            alg,
            value: None,
        }
    }

    pub fn set_value(&mut self, value: impl Into<String>) -> &mut Self {
        self.value = Some(value.into());
        self
    }

    pub fn create_header(&self, url: impl Into<String>) -> Result<ProtectedHeader, Box<dyn Error>> {
        let nonce = self.nonce.get()?;
        let url = url.into();

        let (jwk, kid) = match &self.value {
            Some(value) => match serde_json::from_str(value) {
                Ok(jwk) => (Some(jwk), None),
                Err(_) => (None, Some(value.clone())),
            },
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

impl ToString for Protection {
    fn to_string(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_protection_flow() -> Result<(), Box<dyn Error>> {
        let nonce = Nonce::new("https://acme-v02.api.letsencrypt.org/acme/new-nonce");

        let mut protection = Protection::new(nonce, "RSA");
        let jwk = json!({
            "kty": "RSA",
            "n": "sample-n",
            "e": "sample-e"
        })
        .to_string();
        protection.set_value(jwk);

        let header = protection.create_header("https://example.com/register")?;
        assert!(header.jwk.is_some());
        assert!(header.kid.is_none());
        assert_eq!(header.alg, "RS256");

        protection.set_value("account-kid");
        let header = protection.create_header("https://example.com/order")?;
        assert!(header.jwk.is_none());
        assert!(header.kid.is_some());
        assert_eq!(header.kid.unwrap(), "account-kid");

        let nonce = Nonce::new("https://acme-v02.api.letsencrypt.org/acme/new-nonce");
        let protection = Protection::new(nonce, "ECDSA");
        assert_eq!(protection.alg, "ES256");

        Ok(())
    }
}
