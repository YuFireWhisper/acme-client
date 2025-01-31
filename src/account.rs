use std::string::FromUtf8Error;

use reqwest::blocking::Client;
use serde_json::Value;
use thiserror::Error;

use crate::{
    directory::Directory,
    jwk::{Jwk, JwkError},
    key_pair::KeyPair,
    nonce::Nonce,
    payload::{NewAccountPayload, PayloadT},
    protection::{Protection, ProtectionError},
    signature::{create_signature, SignatureError},
    storage::{Storage, StorageError},
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
}

pub type Result<T> = std::result::Result<T, AccountError>;

pub struct Account {
    pub email: String,
    pub account_url: String,
    pub key_pair: KeyPair,
    pub nonce: Nonce,
    pub dir: Directory,
    pub storage: Box<dyn Storage>,
    pub storage_path: String,
}

impl Account {
    const ACCOUNT_DIR: &'static str = "account";
    const ACCOUNT_URL: &'static str = "account_url";

    pub fn new<T: Storage + 'static>(
        storage: Box<T>,
        dir: Directory,
        key_pair: KeyPair,
        email: &str,
    ) -> Result<Self> {
        let account_url_path = Account::get_account_url_path(email);
        let account_url_path = account_url_path.as_str();

        let nonce = Nonce::new(&dir.new_nonce);

        if let Ok(account_url) = storage.read_file(account_url_path) {
            return Ok(Account {
                email: email.to_string(),
                account_url: String::from_utf8(account_url)?,
                key_pair,
                nonce,
                dir,
                storage,
                storage_path: Self::get_storage_path(email),
            });
        }

        let account_url = Account::create_account(&dir, &key_pair, email)?;
        storage.write_file(account_url_path, account_url.as_bytes())?;

        Ok(Account {
            email: email.to_string(),
            account_url,
            key_pair,
            nonce,
            dir,
            storage,
            storage_path: Self::get_storage_path(email),
        })
    }

    fn get_account_url_path(email: &str) -> String {
        let mut account_url_path = String::with_capacity(
            Self::ACCOUNT_DIR.len() + email.len() + Self::ACCOUNT_URL.len() + 2,
        );
        account_url_path.push_str(Self::ACCOUNT_DIR);
        account_url_path.push('/');
        account_url_path.push_str(email);
        account_url_path.push('/');
        account_url_path.push_str(Self::ACCOUNT_URL);

        account_url_path
    }

    fn get_storage_path(email: &str) -> String {
        let mut storage_path = String::with_capacity(
            1 + Self::ACCOUNT_DIR.len() + email.len() + Self::ACCOUNT_URL.len() + 2,
        );
        storage_path.push('/');
        storage_path.push_str(Self::ACCOUNT_DIR);
        storage_path.push('/');
        storage_path.push_str(email);
        storage_path.push('/');

        storage_path
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
