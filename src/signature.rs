use crate::{base64::Base64, key_pair::KeyPair, payload::Payload, protection::Protection};
use openssl::hash::MessageDigest;
use openssl::sign::Signer;
use std::error::Error;

#[derive(Debug)]
pub enum SignatureError {
    UnsupportedAlgorithm(String),
    SigningError(String),
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SignatureError::UnsupportedAlgorithm(alg) => {
                write!(f, "Unsupported algorithm: {}", alg)
            }
            SignatureError::SigningError(msg) => write!(f, "Signing error: {}", msg),
        }
    }
}

impl Error for SignatureError {}

trait SignatureAlgorithm {
    fn sign(&self, data: &[u8], key_pair: &KeyPair) -> Result<Vec<u8>, SignatureError>;
}

struct RSASignature;

impl SignatureAlgorithm for RSASignature {
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
    fn get_algorithm(alg_name: &str) -> Result<Box<dyn SignatureAlgorithm>, SignatureError> {
        match alg_name.to_uppercase().as_str() {
            "RSA" => Ok(Box::new(RSASignature)),
            _ => Err(SignatureError::UnsupportedAlgorithm(alg_name.to_string())),
        }
    }
}

pub fn create_signature(
    header: String,
    payload: String,
    key_pair: KeyPair,
) -> Result<String, SignatureError> {
    let protected = Base64::new(header).base64_url();
    let payload = Base64::new(payload).base64_url();
    let signing_input = format!("{}.{}", protected, payload);
    let algorithm = SignatureAlgorithmFactory::get_algorithm(&key_pair.alg_name)?;
    let signature = algorithm.sign(signing_input.as_bytes(), &key_pair)?;
    let signature_b64 = Base64::new(String::from_utf8_lossy(&signature).to_string()).base64_url();

    Ok(format!("{}.{}.{}", protected, payload, signature_b64))
}
