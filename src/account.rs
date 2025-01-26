use std::result;

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    directory::Directory,
    jwk::Jwk,
    key_pair::KeyPair,
    nonce::Nonce,
    protection::Protection,
    signature::create_signature,
    storage::{Storage, StorageError},
};

pub enum AccountError {
    StorageError(StorageError),
    RequestError(reqwest::Error),
    JsonError(serde_json::Error),
    UrlNotFound,
    Unknown,
}

impl From<StorageError> for AccountError {
    fn from(err: StorageError) -> Self {
        AccountError::StorageError(err)
    }
}

impl From<reqwest::Error> for AccountError {
    fn from(err: reqwest::Error) -> Self {
        AccountError::RequestError(err)
    }
}

impl From<serde_json::Error> for AccountError {
    fn from(err: serde_json::Error) -> Self {
        AccountError::JsonError(err)
    }
}

pub type AccountResult<T> = result::Result<T, AccountError>;

pub struct Account {
    email: String,
    account_url: String,
    key_pair: KeyPair,
    storage: Storage,
}

const ACCOUNT_DIR: String = "account".to_string();
const ACCOUNT_URL: String = "account_url".to_string();

impl Account {
    pub fn new(
        storage: Storage,
        dir: Directory,
        key_pair: KeyPair,
        email: &str,
    ) -> AccountResult<Self> {
        let account_url_store_path: &str = &ACCOUNT_DIR + "/" + email + "/" + &ACCOUNT_URL;

        if let Some(account_url) = storage.read_file(account_url_store_path)? {
            return Ok(Account {
                email: email.to_string(),
                account_url: String::from_utf8(account_url)?,
                key_pair,
                storage,
            });
        }

        let account_url = Account::create_account(dir, key_pair, email)?;
        storage.write_file(account_url_store_path, account_url.as_bytes())?;

        Ok(Account {
            email: email.to_string(),
            account_url,
            key_pair,
            storage,
        })
    }

    pub fn create_account(dir: Directory, key_pair: KeyPair, email: &str) -> AccountResult<String> {
        let new_account_api = &dir.new_account;
        let nonce = Nonce::new(&dir.new_nonce);

        let jwk = Jwk::new(&key_pair, None)?;
        let header = Protection::new(nonce, key_pair.alg_name).set_value(jwk);
        let payload = serde_json::to_string(&NewAccountRequest {
            terms_of_service_agreed: true,
            contact: vec![format!("mailto:{}", email)],
        })?;
        let signature = create_signature(header.to_string(), payload, key_pair);

        let jws = serde_json::to_string(&Value::Object({
            let mut map = serde_json::Map::new();
            map.insert("protected".to_string(), header.to_string().into());
            map.insert("payload".to_string(), payload.into());
            map.insert("signature".to_string(), signature.into());
            map
        }))?;

        let client = Client::new();
        let response = client
            .post(new_account_api)
            .header("Content-Type", "application/jose+json")
            .body(jws)
            .send()?;

        let new_account_response: NewAccountResponse = response.json()?;
        let account_url = new_account_response.orders;

        Ok(account_url)
    }
}

#[derive(Debug, Serialize)]
struct NewAccountRequest {
    terms_of_service_agreed: bool,
    contact: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct NewAccountResponse {
    status: String,
    contact: Vec<String>,
    orders: String,
    created_at: String,
}
