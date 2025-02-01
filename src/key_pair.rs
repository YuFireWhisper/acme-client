use openssl::{
    error::ErrorStack,
    pkey::{Id, PKey, Private, Public},
    rsa::Rsa,
    sha::sha256,
};
use thiserror::Error;

use crate::{
    base64::Base64,
    jwk::{Jwk, JwkError},
    storage::{Storage, StorageError},
};

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("OpenSSL error: {0}")]
    OpenSSL(#[from] ErrorStack),
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("Unsupported algorithm")]
    UnsupportedAlgorithm,
    #[error("JWK error")]
    KeyConversionFailed,
    #[error("Thumbprint error")]
    ThumbprintError,
    #[error("JWK error")]
    JwkError(#[from] JwkError),
}

type Result<T> = std::result::Result<T, KeyError>;

pub struct KeyPair {
    pub alg_name: String,
    pub pri_key: PKey<Private>,
    pub pub_key: PKey<Public>,
}

impl KeyPair {
    pub fn new(
        storage: &dyn Storage,
        alg_name: &str,
        bits: Option<u32>,
        path: Option<&str>,
    ) -> Result<Self> {
        let alg_name = Self::normalize_algorithm_name(alg_name)?;

        if path.is_none() {
            let pri_key = Self::generate_key(&alg_name, bits)?;
            let pub_key = Self::derive_public_key(&pri_key)?;

            return Ok(Self {
                alg_name,
                pri_key,
                pub_key,
            });
        }

        let path = path.unwrap();
        match storage.read_file(path) {
            Ok(pri_key_data) => {
                let pri_key = PKey::private_key_from_pem(&pri_key_data)?;
                let pub_key = Self::derive_public_key(&pri_key)?;
                return Ok(Self {
                    alg_name,
                    pri_key,
                    pub_key,
                });
            }
            Err(StorageError::NotFound(_)) => {}
            Err(e) => {
                return Err(KeyError::Storage(e));
            }
        }

        let pri_key = Self::generate_key(&alg_name, bits)?;
        let pub_key = Self::derive_public_key(&pri_key)?;

        storage.write_file(path, &pri_key.private_key_to_pem_pkcs8()?)?;

        Ok(Self {
            alg_name,
            pri_key,
            pub_key,
        })
    }

    fn normalize_algorithm_name(name: &str) -> Result<String> {
        match name.to_uppercase().as_str() {
            "RSA" => Ok("RSA".to_owned()),
            _ => Err(KeyError::UnsupportedAlgorithm),
        }
    }

    fn derive_public_key(pri_key: &PKey<Private>) -> Result<PKey<Public>> {
        match pri_key.id() {
            Id::RSA => {
                let rsa = pri_key.rsa()?;
                let pub_rsa =
                    Rsa::from_public_components(rsa.n().to_owned()?, rsa.e().to_owned()?)?;
                Ok(PKey::from_rsa(pub_rsa)?)
            }
            _ => Err(KeyError::UnsupportedAlgorithm),
        }
    }

    fn generate_key(alg_name: &str, bits: Option<u32>) -> Result<PKey<Private>> {
        match alg_name {
            "RSA" => {
                let rsa = Rsa::generate(bits.unwrap_or(2048))?;
                Ok(PKey::from_rsa(rsa)?)
            }
            _ => Err(KeyError::UnsupportedAlgorithm),
        }
    }

    pub fn thumbprint(&self) -> Result<String> {
        let jwk = Jwk::new(self, None)?;
        println!("{:?}", jwk.to_acme_json()?);
        let hash = sha256(jwk.to_acme_json()?.as_bytes());
        Ok(Base64::new(hash).base64_url())
    }

    pub fn from_pem(pri_key_pem: &[u8]) -> Result<Self> {
        let pri_key = PKey::private_key_from_pem(pri_key_pem)?;
        let pub_key = Self::derive_public_key(&pri_key)?;

        Ok(Self {
            alg_name: "RSA".to_owned(),
            pri_key,
            pub_key,
        })
    }

    pub fn from_file(storage: &dyn Storage, path: &str) -> Result<Self> {
        let pri_key_data = storage.read_file(path)?;
        Self::from_pem(&pri_key_data)
    }

    pub fn key_parameters(&self) -> Result<u32> {
        match self.pri_key.id() {
            Id::RSA => {
                let rsa = self.pri_key.rsa()?;
                Ok(rsa.size() * 8)
            }
            _ => Err(KeyError::UnsupportedAlgorithm),
        }
    }
}
