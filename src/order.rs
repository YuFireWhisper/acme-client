use std::{result, str::FromStr};

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    account::Account,
    challenge::Challenge,
    jws::{Jws, JwsError},
    payload::{Identifier, NewOrderPayload},
    protection::{Protection, ProtectionError},
    signature::{create_signature, SignatureError},
    storage::StorageError,
};

#[derive(Debug, Error)]
pub enum OrderError {
    #[error("Protection error: {0}")]
    Protection(#[from] ProtectionError),
    #[error("Signature error: {0}")]
    Signature(#[from] SignatureError),
    #[error("Request error: {0}")]
    Request(#[from] reqwest::Error),
    #[error("JWS error: {0}")]
    Jws(#[from] JwsError),
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("Missing Location header")]
    MissingLocationHeader,
    #[error("Invalid Location header")]
    InvalidLocationHeader,
    #[error("Invalid status value")]
    InvalidStatus,
}

type Result<T> = result::Result<T, OrderError>;

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OrderStatus {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
}

impl FromStr for OrderStatus {
    type Err = OrderError;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "pending" => Ok(Self::Pending),
            "ready" => Ok(Self::Ready),
            "processing" => Ok(Self::Processing),
            "valid" => Ok(Self::Valid),
            "invalid" => Ok(Self::Invalid),
            _ => Err(OrderError::InvalidStatus),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Order {
    pub status: OrderStatus,
    pub expires: String,
    pub identifiers: Vec<Identifier>,
    pub authorizations: Vec<String>,
    pub finalize: String,
    #[serde(skip)]
    pub order_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    #[serde(skip)]
    pub challenges: Vec<Challenge>,
}

impl Order {
    pub fn new(account: &Account, domain: &str) -> Result<Self> {
        let order_storage_path = format!("{}{}", account.storage_path, domain);

        if let Ok(order_url_bytes) = account.storage.read_file(&order_storage_path) {
            if let Ok(order_url) = String::from_utf8(order_url_bytes) {
                if let Ok(order) = Self::get_order(&order_url) {
                    if order.status == OrderStatus::Valid {
                        return Ok(order);
                    }
                }
            }
        }

        let payload = NewOrderPayload::new(vec![domain]);
        let jws = Self::build_jws(account, payload)?;

        let response = Client::new()
            .post(&account.dir.new_order)
            .header("Content-Type", "application/jose+json")
            .body(jws.to_json()?)
            .send()?;

        let order_url = response
            .headers()
            .get("Location")
            .ok_or(OrderError::MissingLocationHeader)?
            .to_str()
            .map_err(|_| OrderError::InvalidLocationHeader)?
            .to_owned();

        account
            .storage
            .write_file(&order_storage_path, order_url.as_bytes())?;

        let mut order: Self = response.json()?;
        order.order_url = order_url;

        order.challenges = order
            .authorizations
            .iter()
            .filter_map(|auth_url| Challenge::from_url(auth_url).ok())
            .flatten()
            .collect();

        Ok(order)
    }

    fn get_order(order_url: &str) -> Result<Self> {
        let response = Client::new()
            .get(order_url)
            .header("Content-Type", "application/jose+json")
            .send()?;

        let mut order: Self = response.json()?;
        order.order_url = order_url.to_owned();

        Ok(order)
    }

    fn build_jws(account: &Account, payload: NewOrderPayload) -> Result<Jws> {
        let header = Protection::new(&account.nonce, &account.key_pair.alg_name)
            .set_value(&account.account_url)?
            .create_header(&account.dir.new_order)?;

        let signature = create_signature(&header, &payload, &account.key_pair)?;
        Jws::new(&header, &payload, &signature).map_err(Into::into)
    }
}
