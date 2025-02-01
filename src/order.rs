use std::{collections::HashMap, str::FromStr};

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    account::Account,
    base64::Base64,
    challenge::{Challenge, ChallengeError, ChallengeType},
    csr::CSR,
    jws::{Jws, JwsError},
    key_pair::{KeyError, KeyPair},
    payload::{FinalizeOrderPayload, Identifier, NewOrderPayload, PayloadT},
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
    #[error("Challenge error: {0}")]
    Challenge(#[from] ChallengeError),
    #[error("Missing Location header: {status:?}, {headers:?}, {body:?}")]
    MissingLocationHeader {
        status: reqwest::StatusCode,
        headers: reqwest::header::HeaderMap,
        body: String,
    },
    #[error("Invalid Location header")]
    InvalidLocationHeader,
    #[error("Invalid status value")]
    InvalidStatus,
    #[error("Account thumbprint calculation failed")]
    ThumbprintError,
    #[error("Serde JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Request header error: {0}")]
    RequestHeaderError(#[from] reqwest::header::ToStrError),
    #[error("Request failed: {status:?}, {headers:?}, {body:?}")]
    RequestErrorDetailed {
        status: reqwest::StatusCode,
        headers: reqwest::header::HeaderMap,
        body: String,
    },
    #[error("Key pair error: {0}")]
    KeyPair(#[from] KeyError),
    #[error("CSR error: {0}")]
    Csr(#[from] crate::csr::CsrError),
    #[error("OpenSSL ErrorStack error: {0}")]
    OpenSSL(#[from] openssl::error::ErrorStack),
    #[error("Order is not valid")]
    OrderNotValid,
    #[error("Order is not ready")]
    OrderNotReady,
}

type Result<T> = std::result::Result<T, OrderError>;

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
    pub challenges: HashMap<ChallengeType, Challenge>,
    #[serde(skip)]
    order_storage_path: String,
    #[serde(skip)]
    domain: String,
}

impl Order {
    pub fn new(account: &mut Account, domain: &str) -> Result<Self> {
        let order_storage_path = format!("{}/{}/order_url", &account.email, domain);

        if let Ok(order_url_bytes) = account.storage.read_file(&order_storage_path) {
            if let Ok(order_url) = String::from_utf8(order_url_bytes) {
                if let Ok(mut order) = Self::get_order(&order_url) {
                    if order.status != OrderStatus::Invalid {
                        order.fetch_challenges(account)?;
                        order.domain = domain.to_owned();
                        order.order_storage_path = order_storage_path;
                        order.order_url = order_url;
                        return Ok(order);
                    }
                }
            }
        }

        let payload = NewOrderPayload::new(vec![domain]).to_base64()?;
        let jws = Self::build_jws(account, &payload)?;

        let response = Client::new()
            .post(&account.dir.new_order)
            .header("Content-Type", "application/jose+json")
            .body(jws.to_json()?)
            .send()?;

        if !response.status().is_success() {
            return Err(OrderError::RequestErrorDetailed {
                status: response.status(),
                headers: response.headers().clone(),
                body: response.text()?,
            });
        }

        let order_url = response
            .headers()
            .get("Location")
            .ok_or_else(|| OrderError::MissingLocationHeader {
                status: response.status(),
                headers: response.headers().clone(),
                body: "Location header not found".to_string(),
            })?
            .to_str()?
            .to_string();

        account
            .storage
            .write_file(&order_storage_path, order_url.as_bytes())?;

        let mut order: Self = response.json()?;
        order.domain = domain.to_owned();
        order.order_storage_path = order_storage_path;
        order.order_url = order_url.clone();

        order.fetch_challenges(account)?;

        Ok(order)
    }

    pub fn get_challenge(&mut self, challenge_type: ChallengeType) -> Option<&mut Challenge> {
        self.challenges.get_mut(&challenge_type)
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

    fn fetch_challenges(&mut self, account: &Account) -> Result<()> {
        let thumbprint = account
            .key_pair
            .thumbprint()
            .map_err(|_| OrderError::ThumbprintError)?;

        self.challenges = self
            .authorizations
            .iter()
            .flat_map(
                |auth_url| match Challenge::fetch_challenges(auth_url, &thumbprint) {
                    Ok(challenges) => challenges.into_iter(),
                    Err(_) => Vec::new().into_iter(),
                },
            )
            .map(|c| (c.challenge_type.clone(), c))
            .collect();

        Ok(())
    }

    fn build_jws(account: &Account, payload_b64: &Base64) -> Result<Jws> {
        let header = Protection::new(&account.nonce, &account.key_pair.alg_name)
            .set_value(&account.account_url)?
            .create_header(&account.dir.new_order)?
            .to_base64()?;

        let signature = create_signature(&header, payload_b64, &account.key_pair)?;
        Jws::new(&header, payload_b64, &signature).map_err(Into::into)
    }

    pub fn finalize(&mut self, account: &Account) -> Result<&Self> {
        if self.status == OrderStatus::Valid {
            return Ok(self);
        }

        if self.status != OrderStatus::Ready {
            return Err(OrderError::OrderNotReady);
        }

        let cert_key_storage_path = format!("{}/{}/cert_key", &account.email, &self.domain);
        let cert_key_pair =
            KeyPair::new(&*account.storage, "RSA", None, Some(&cert_key_storage_path))?;

        let csr = Base64::new(
            CSR::new()?
                .set_san(&self.domain)
                .build(&cert_key_pair)?
                .to_der()?,
        );
        println!("CSR: {}", csr.base64_url());

        let header = Protection::new(&account.nonce, &account.key_pair.alg_name)
            .set_value(&account.account_url)?
            .create_header(&self.finalize)?
            .to_base64()?;
        let payload = FinalizeOrderPayload::new(&csr).to_base64()?;
        let signature = create_signature(&header, &payload, &account.key_pair)?;

        println!("Protected Header: {}", header.as_str());
        println!("Payload: {}", payload.as_str());
        println!("Account URL: {}", account.account_url);

        let jws = Jws::new(&header, &payload, &signature)?;

        println!("Finalize: {}", self.finalize);

        let response = Client::new()
            .post(&self.finalize)
            .header("Content-Type", "application/jose+json")
            .body(jws.to_json()?)
            .send()?;

        if !response.status().is_success() {
            return Err(OrderError::RequestErrorDetailed {
                status: response.status(),
                headers: response.headers().clone(),
                body: response.text()?,
            });
        }

        let response: OrderUpdateResponse = response.json()?;
        self.status = response.status;
        println!("Status: {:?}", self.status);
        self.certificate = response.certificate;

        Ok(self)
    }

    pub fn download_certificate(&self, account: &Account, path: &str) -> Result<()> {
        if self.certificate.is_none() || self.status != OrderStatus::Valid {
            return Err(OrderError::OrderNotValid);
        }

        let client = Client::new();
        let response = client.get(self.certificate.as_ref().unwrap()).send()?;

        if !response.status().is_success() {
            return Err(OrderError::RequestErrorDetailed {
                status: response.status(),
                headers: response.headers().clone(),
                body: response.text()?,
            });
        }

        let cert_bytes = response.bytes()?;
        account.storage.write_file(path, &cert_bytes)?;

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct OrderUpdateResponse {
    status: OrderStatus,
    certificate: Option<String>,
}
