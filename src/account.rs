use std::{env, path::PathBuf, string::FromUtf8Error};

use reqwest::blocking::Client;
use serde_json::Value;
use thiserror::Error;

use crate::{
    directory::{Directory, DirectoryError},
    jwk::{Jwk, JwkError},
    key_pair::{KeyError, KeyPair},
    nonce::Nonce,
    payload::{NewAccountPayload, PayloadT},
    protection::{Protection, ProtectionError},
    signature::{create_signature, SignatureError},
    storage::{FileStorage, Storage, StorageError},
};

#[derive(Debug, Error)]
pub enum AccountError {
    #[error("Request error: {0}")]
    RequestError(#[from] reqwest::Error),
    #[error("Request header error: {0}")]
    RequestHeaderError(#[from] reqwest::header::ToStrError),
    #[error("Request failed: {status:?}, {headers:?}, {body:?}")]
    RequestErrorDetailed {
        status: reqwest::StatusCode,
        headers: reqwest::header::HeaderMap,
        body: String,
    },
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("UTF-8 error: {0}")]
    Utf8Error(#[from] FromUtf8Error),
    #[error("Storage error: {0}")]
    StorageError(#[from] StorageError),
    #[error("JWK error: {0}")]
    JwkError(#[from] JwkError),
    #[error("Protection error: {0}")]
    ProtectionError(#[from] ProtectionError),
    #[error("Signature error: {0}")]
    SignatureError(#[from] SignatureError),
    #[error("Key error: {0}")]
    KeyError(#[from] KeyError),
    #[error("Directory error: {0}")]
    DirectoryError(#[from] DirectoryError),
}

pub type Result<T> = std::result::Result<T, AccountError>;

pub struct Account {
    pub email: String,
    pub key_pair: KeyPair,
    pub dir: Directory,
    pub account_url: String,
    pub nonce: Nonce,
    pub storage: Box<dyn Storage>,
}

impl Account {
    const DEFAULT_KEY_ALG: &'static str = "RSA";
    const DEFAULT_KEY_BITS: u32 = 2048;
    const DEFAULT_DIR_URL: &'static str = "https://acme-v02.api.letsencrypt.org/directory";

    pub fn new(email: &str) -> Result<Self> {
        let builder = AccountBuilder::new(email);
        Self::from_builder(builder)
    }

    fn get_defalut_storage_path() -> PathBuf {
        let app_name = env!("CARGO_PKG_NAME");

        #[cfg(target_os = "linux")]
        {
            let base_dir = env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/var/lib"));

            base_dir.join(".local/share").join(app_name)
        }
    }

    fn from_builder(builder: AccountBuilder) -> Result<Self> {
        let storage = FileStorage::open(builder.storage_path)?;
        let account_url_path = format!("{}/account_url", builder.email);
        let account_key_pair_path = format!("{}/account_key_pair", builder.email);
        let dir_url_path = format!("{}/dir_url", builder.email);

        if let Ok(account_url) = storage.read_file(&account_url_path) {
            let account_url = String::from_utf8(account_url)?;
            let key_pair = KeyPair::from_file(&storage, &account_key_pair_path)?;
            let dir_data = storage.read_file(&dir_url_path)?;
            let dir = Directory::new(&storage, &String::from_utf8_lossy(&dir_data))?;
            let nonce = Nonce::new(&dir.new_nonce);

            return Ok(Account {
                email: builder.email,
                key_pair,
                dir,
                account_url,
                nonce,
                storage: Box::new(storage),
            });
        }

        let key_pair = KeyPair::new(&storage, &builder.key_pair_alg, Some(builder.key_pair_bits), Some(&account_key_pair_path))?;
        let dir = Directory::new(&storage, &builder.dir_url)?;
        let account_url = Account::create_account(&dir, &key_pair, &builder.email)?;
        storage.write_file(&account_url_path, account_url.as_bytes())?;
        let nonce = Nonce::new(&dir.new_nonce);
    
        Ok(Account {
            email: builder.email,
            key_pair,
            dir,
            account_url,
            nonce,
            storage: Box::new(storage),
        })
    }

    pub fn create_account(dir: &Directory, key_pair: &KeyPair, email: &str) -> Result<String> {
        let new_account_api = &dir.new_account;
        let nonce = Nonce::new(&dir.new_nonce);

        let jwk = Jwk::new(key_pair, None)?;
        let header = Protection::new(&nonce, &key_pair.alg_name)
            .set_value(jwk)?
            .create_header(new_account_api)?
            .to_base64()?;
        let payload = NewAccountPayload::new(email).to_base64()?;
        let signature = create_signature(&header, &payload, key_pair)?.base64_url();

        let jws = serde_json::to_string(&Value::Object({
            let mut map = serde_json::Map::new();
            map.insert("protected".to_string(), header.base64_url().into());
            map.insert("payload".to_string(), payload.base64_url().into());
            map.insert("signature".to_string(), signature.into());
            map
        }))?;

        let client = Client::new();
        let response = client
            .post(new_account_api)
            .header("Content-Type", "application/jose+json")
            .body(jws)
            .send()?;

        let status = response.status();
        if !status.is_success() {
            let headers = response.headers().clone();
            let body = response.text()?;
            return Err(AccountError::RequestErrorDetailed {
                status,
                headers,
                body,
            });
        }

        let account_url = response
            .headers()
            .get("Location")
            .ok_or_else(|| AccountError::RequestErrorDetailed {
                status: response.status(),
                headers: response.headers().clone(),
                body: "Location header not found".to_string(),
            })?
            .to_str()?
            .to_string();

        Ok(account_url)
    }
}

pub struct AccountBuilder {
    email: String,
    key_pair_alg: String,
    key_pair_bits: u32,
    dir_url: String,
    storage_path: PathBuf,
}

impl AccountBuilder {
    pub fn new(email: &str) -> Self {
        AccountBuilder {
            email: email.to_string(),
            key_pair_alg: Account::DEFAULT_KEY_ALG.to_string(),
            key_pair_bits: Account::DEFAULT_KEY_BITS,
            dir_url: Account::DEFAULT_DIR_URL.to_string(),
            storage_path: Account::get_defalut_storage_path(),
        }
    } 

    pub fn key_pair_alg(mut self, key_pair_alg: &str) -> Self {
        self.key_pair_alg = key_pair_alg.to_string();
        self
    }

    pub fn key_pair_bits(mut self, key_pair_bits: u32) -> Self {
        self.key_pair_bits = key_pair_bits;
        self
    }

    pub fn dir_url(mut self, dir_url: &str) -> Self {
        self.dir_url = dir_url.to_string();
        self
    }

    pub fn storage_path(mut self, storage_path: &str) -> Self {
        self.storage_path = PathBuf::from(storage_path);
        self
    }

    pub fn build(self) -> Result<Account> {
        Account::from_builder(self)
    }
}
