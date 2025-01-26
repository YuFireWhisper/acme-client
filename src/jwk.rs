use serde::{Deserialize, Serialize};
use std::error::Error;

use crate::{base64::Base64, key_pair::KeyPair};

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

impl Jwk {
    pub fn new(key_pair: &KeyPair, kid: Option<String>) -> Result<Self, Box<dyn Error>> {
        match key_pair.alg_name.as_str() {
            "RSA" => {
                let rsa = key_pair.pub_key.rsa()?;

                let n = Base64::new(rsa.n().to_vec()?).base64_url();
                let e = Base64::new(rsa.e().to_vec()?).base64_url();

                let alg = match key_pair.alg_name.as_str() {
                    "RSA" => Some(String::from("RS256")),
                    _ => None,
                };

                Ok(Jwk::Rsa(RsaJwk { n, e, kid, alg }))
            }
            _ => Err("Unsupported algorithm".into()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{key_pair::KeyPair, storage::Storage};

    #[test]
    fn test_create_rsa_jwk() -> Result<(), Box<dyn Error>> {
        let storage = Storage::open("test_storage")?;
        let key_pair = KeyPair::new(storage, "RSA", Some(2048))?;

        let jwk = Jwk::new(&key_pair, Some("test-key-id".to_string()))?;

        let jwk_json = serde_json::to_string_pretty(&jwk)?;
        println!("JWK JSON:\n{}", jwk_json);

        if let Jwk::Rsa(rsa_jwk) = jwk {
            assert!(!rsa_jwk.n.is_empty());
            assert!(!rsa_jwk.e.is_empty());
            assert_eq!(rsa_jwk.kid.unwrap(), "test-key-id");
            assert_eq!(rsa_jwk.alg.unwrap(), "RS256");
        }

        Ok(())
    }
}
