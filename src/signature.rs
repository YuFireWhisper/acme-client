use crate::{base64::Base64, key_pair::KeyPair};
use openssl::hash::MessageDigest;
use openssl::sign::Signer;
use std::error::Error;

#[derive(Debug)]
pub enum SignatureError {
    SigningError(String),
    UnsupportedAlgorithm(String),
    SerializationError(serde_json::Error),
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SignatureError::UnsupportedAlgorithm(alg) => {
                write!(f, "Unsupported algorithm: {}", alg)
            }
            SignatureError::SigningError(msg) => write!(f, "Signing error: {}", msg),
            SignatureError::SerializationError(e) => write!(f, "Serialization error: {}", e),
        }
    }
}

impl From<serde_json::Error> for SignatureError {
    fn from(e: serde_json::Error) -> Self {
        SignatureError::SerializationError(e)
    }
}

impl Error for SignatureError {}

trait SignatureAlgorithmT {
    fn sign(&self, data: &[u8], key_pair: &KeyPair) -> Result<Vec<u8>, SignatureError>;
}

struct RSASignature;

impl SignatureAlgorithmT for RSASignature {
    fn sign(&self, data: &[u8], key_pair: &KeyPair) -> Result<Vec<u8>, SignatureError> {
        let mut signer = Signer::new(MessageDigest::sha256(), &key_pair.pri_key)
            .map_err(|e| SignatureError::SigningError(e.to_string()))?;

        signer
            .update(data)
            .map_err(|e| SignatureError::SigningError(e.to_string()))?;

        signer
            .sign_to_vec()
            .map_err(|e| SignatureError::SigningError(e.to_string()))
    }
}

struct SignatureAlgorithmFactory;

impl SignatureAlgorithmFactory {
    fn get_algorithm(alg_name: &str) -> Result<Box<dyn SignatureAlgorithmT>, SignatureError> {
        match alg_name.to_uppercase().as_str() {
            "RSA" => Ok(Box::new(RSASignature)),
            _ => Err(SignatureError::UnsupportedAlgorithm(alg_name.to_string())),
        }
    }
}

pub fn create_signature(
    header_b64: &Base64,
    payload_b64: &Base64,
    key_pair: &KeyPair,
) -> Result<Base64, SignatureError> {
    let signing_input = format!("{}.{}", header_b64.base64_url(), payload_b64.base64_url());
    let algorithm = SignatureAlgorithmFactory::get_algorithm(&key_pair.alg_name)?;

    let signature = algorithm.sign(signing_input.as_bytes(), key_pair)?;

    Ok(Base64::new(&signature))
}
