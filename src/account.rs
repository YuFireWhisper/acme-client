use std::result;

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::storage::{Storage, StorageError};

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
    url: String,
}

const ACCOUNT_URL_KEY: String = "account_url_".to_string();
const NEW_ACCOUNT_URL_KEY: String = "new_account_url".to_string();

impl Account {
    pub fn new(storage: &mut Storage, email: &str) -> AccountResult<Self> {
        if let Ok(Some(url)) = storage.read_str(&Self::acc_url_key_of(email)) {
            return Ok(Account { url });
        }

        let new_account = Self::create_account(storage, email)?;
        storage
            .write_str(&Self::acc_url_key_of(email), &new_account.orders)
            .map_err(AccountError::StorageError)?;

        Ok(Account {
            url: new_account.orders,
        })
    }

    fn create_account(storage: &mut Storage, email: &str) -> AccountResult<NewAccountResponse> {
        let new_account_url = storage
            .read_str(&NEW_ACCOUNT_URL_KEY)?
            .ok_or("url not found")?;

        let client = Client::new();
        let req = NewAccountRequest {
            terms_of_service_agreed: true,
            contact: vec![format!("mailto:{}", email)],
        };

        let resp = client
            .post(&new_account_url)
            .json(&req)
            .send()?
            .json::<NewAccountResponse>()?;

        Ok(resp)
    }

    pub fn acc_url_key_of(email: &str) -> String {
        ACCOUNT_URL_KEY + email
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
