use crate::{base64::Base64, key_pair::KeyPair};
use openssl::hash::MessageDigest;
use openssl::sign::Signer;
use serde::Serialize;
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

pub fn create_signature<T: Serialize, U: Serialize>(
    header: &T,
    payload: &U,
    key_pair: &KeyPair,
) -> Result<String, SignatureError> {
    let header = serde_json::to_string(&header)?;
    let payload = serde_json::to_string(&payload)?;

    let header = Base64::new(header).base64_url();
    let payload = Base64::new(payload).base64_url();

    let signing_input = format!("{}.{}", header, payload);
    let algorithm = SignatureAlgorithmFactory::get_algorithm(&key_pair.alg_name)?;

    let signature = algorithm.sign(signing_input.as_bytes(), key_pair)?;
    let signature_b64 = Base64::new(String::from_utf8_lossy(&signature).to_string()).base64_url();

    Ok(format!("{}.{}.{}", header, payload, signature_b64))
}
