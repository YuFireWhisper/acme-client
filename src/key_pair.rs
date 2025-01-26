use openssl::{
    error::ErrorStack,
    pkey::{Id, PKey, Private, Public},
    rsa::Rsa,
};

use crate::storage::{Storage, StorageError};

#[derive(Debug)]
pub enum KeyError {
    OpenSsl(ErrorStack),
    Storage(StorageError),
    UnsupportedAlgorithm,
    KeyConversionFailed,
}

impl From<ErrorStack> for KeyError {
    fn from(error: ErrorStack) -> Self {
        KeyError::OpenSsl(error)
    }
}

impl From<StorageError> for KeyError {
    fn from(error: StorageError) -> Self {
        KeyError::Storage(error)
    }
}

pub struct KeyPair {
    pub alg_name: String,
    pub pri_key: PKey<Private>,
    pub pub_key: PKey<Public>,
}

impl KeyPair {
    const KEY_PAIR_DIR: &'static str = "key_pair";
    const PRIVATE_KEY_SUFFIX: &'static str = "/private_key";

    pub fn new<T: Storage>(storage: &T, alg_name: &str, bits: Option<u32>) -> Result<Self, KeyError> {
        let alg_name = Self::normalize_algorithm_name(alg_name)?;
        let key_path = format!(
            "{}/{}{}",
            Self::KEY_PAIR_DIR,
            &alg_name,
            Self::PRIVATE_KEY_SUFFIX
        );

        if let Some(pri_key_data) = storage.read_file(&key_path)? {
            let pri_key = PKey::private_key_from_pem(&pri_key_data)?;
            let pub_key = Self::derive_public_key(&pri_key)?;
            return Ok(Self {
                alg_name,
                pri_key,
                pub_key,
            });
        }

        let pri_key = Self::generate_key(&alg_name, bits)?;
        let pub_key = Self::derive_public_key(&pri_key)?;

        storage.write_file(&key_path, &pri_key.private_key_to_pem_pkcs8()?)?;

        Ok(Self {
            alg_name,
            pri_key,
            pub_key,
        })
    }

    fn normalize_algorithm_name(name: &str) -> Result<String, KeyError> {
        match name.to_uppercase().as_str() {
            "RSA" => Ok("RSA".to_owned()),
            _ => Err(KeyError::UnsupportedAlgorithm),
        }
    }

    fn derive_public_key(pri_key: &PKey<Private>) -> Result<PKey<Public>, KeyError> {
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

    fn generate_key(alg_name: &str, bits: Option<u32>) -> Result<PKey<Private>, KeyError> {
        match alg_name {
            "RSA" => {
                let rsa = Rsa::generate(bits.unwrap_or(2048))?;
                Ok(PKey::from_rsa(rsa)?)
            }
            _ => Err(KeyError::UnsupportedAlgorithm),
        }
    }
}

