use openssl::{
    error::ErrorStack,
    pkey::{Id, PKey, Private, Public},
    rsa::Rsa,
};
use std::{error::Error, str::FromStr};

use crate::storage::Storage;

pub enum KeyError {
    OpenSslError(openssl::error::ErrorStack),
    UnsupportedKeyType,
}

impl From<openssl::error::ErrorStack> for KeyError {
    fn from(error: openssl::error::ErrorStack) -> Self {
        KeyError::OpenSslError(error)
    }
}

type KeyResult<T> = Result<T, KeyError>;

pub struct KeyPair {
    pub alg_name: String,
    pub pri_key: PKey<Private>,
    pub pub_key: PKey<Public>,
}

impl KeyPair {
    const KEY_PAIR_DIR: &'static str = "key_pair";
    const PRIVATE_KEY_PATH: &'static str = "private_key";

    pub fn new(storage: Storage, alg_name: &str, bits: Option<u32>) -> KeyResult<Self> {
        let alg_name = Self::normalize_name(alg_name);
        if let Some(pri_key) =
            storage.read_file(Self::KEY_PAIR_DIR + "/" + &alg_name + Self::PRIVATE_KEY_PATH)?
        {
            return Ok(KeyPair {
                alg_name,
                pri_key: PKey::private_key_from_pem(&pri_key)?,
                pub_key: Self::public_key_from_private_pem(&pri_key)?,
            });
        }

        let pri_key = Self::generate(&alg_name, bits)?;
        let pub_key = Self::public_key_from_private_key(&pri_key)?;

        storage.write_file(
            Self::KEY_PAIR_DIR + "/" + &alg_name + Self::PRIVATE_KEY_PATH,
            &pri_key.private_key_to_pem_pkcs8()?,
        )?;

        Ok(KeyPair {
            alg_name,
            pri_key,
            pub_key,
        })
    }

    fn normalize_name(name: &str) -> String {
        match name.to_uppercase().as_str() {
            "RSA" | "RS256" | "RS384" | "RS512" => "RSA".to_string(),
        }
    }

    fn public_key_from_private_pem(pri_key: &Vec<u8>) -> Result<PKey<Public>, ErrorStack> {
        let pri_key = PKey::private_key_from_pem(pri_key)?;
        let pub_key = Self::public_key_from_private_key(&pri_key)?;
        Ok(pub_key)
    }

    fn public_key_from_private_key(pri_key: &PKey<Private>) -> Result<PKey<Public>, ErrorStack> {
        match pri_key.id() {
            Id::RSA => {
                let rsa = pri_key.rsa()?;
                return PKey::from_rsa(Rsa::from_public_components(
                    rsa.n().to_owned()?,
                    rsa.e().to_owned()?,
                )?);
            }
            _ => Err("Unsupported key type".into()),
        }
    }

    pub fn generate(alg_name: &str, bits: Option<u32>) -> Result<PKey<Private>, Box<dyn Error>> {
        let alg_name = Self::normalize_name(alg_name);

        match alg_name.as_str() {
            "RSA" => {
                let bits = bits.unwrap_or(2048);
                let rsa = Rsa::generate(bits)?;
                Ok(PKey::from_rsa(rsa)?)
            }
            _ => Err("Unsupported key type".into()),
        }
    }
}
