use std::{
    collections::HashMap,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

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
    #[error("Cloudflare API error: {0}")]
    Cloudflare(String),
    #[error("No DNS challenge found")]
    NoDnsChallenge,
    #[error("Challenge not found")]
    ChallengeNotFound,
    #[error("DNS validation failed: {0}")]
    DnsValidation(String),
}

type Result<T> = std::result::Result<T, OrderError>;

const DNS_CHECK_INTERVAL: Duration = Duration::from_secs(5);
const DNS_CHECK_TIMEOUT: Duration = Duration::from_secs(120);

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

    pub fn finalize(&mut self, account: &Account) -> Result<&Self> {
        if self.status == OrderStatus::Valid {
            return Ok(self);
        }

        if self.status != OrderStatus::Ready {
            return Err(OrderError::OrderNotReady);
        }

        let cert_key_storage_path = format!("{}/{}/cert_key", &account.email, &self.domain);
        let cert_key_pair = KeyPair::new(
            &*account.storage,
            &account.key_pair.alg_name,
            Some(account.key_pair.key_parameters()?),
            Some(&cert_key_storage_path),
        )?;

        let csr = Base64::new(
            CSR::new()?
                .set_san(&self.domain)
                .build(&cert_key_pair)?
                .to_der()?,
        );

        let header = Protection::new(&account.nonce, &account.key_pair.alg_name)
            .set_value(&account.account_url)?
            .create_header(&self.finalize)?
            .to_base64()?;
        let payload = FinalizeOrderPayload::new(&csr).to_base64()?;
        let signature = create_signature(&header, &payload, &account.key_pair)?;

        let jws = Jws::new(&header, &payload, &signature)?;

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
        println!("Order status: {:?}", self.status);
        self.certificate = response.certificate;

        Ok(self)
    }

    pub fn download_certificate(&self, account: &Account) -> Result<()> {
        let cert_storage_path = format!("{}/{}/cert", &account.email, &self.domain);

        if self.status == OrderStatus::Processing {
            loop {
                let order = Self::get_order(&self.order_url)?;
                if order.status == OrderStatus::Valid {
                    break;
                }

                std::thread::sleep(Duration::from_secs(5));
            }
        }

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
        account
            .storage
            .write_file(&cert_storage_path, &cert_bytes)?;

        Ok(())
    }

    pub fn validate_challenge(
        mut self,
        account: &Account,
        challenge_type: ChallengeType,
    ) -> Result<Self> {
        let txt_value = {
            let challenge = self
                .challenges
                .get_mut(&challenge_type)
                .ok_or(OrderError::ChallengeNotFound)?;
 
            challenge.dns_txt_value()
        };

        if challenge_type == ChallengeType::Dns01 {
            let start_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let record_name = format!("_acme-challenge.{}", self.domain);

            loop {
                match self.check_dns_record(&record_name, &txt_value) {
                    Ok(true) => break,
                    Ok(false) => (),
                    Err(e) => return Err(e),
                }

                if SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    - start_time
                    > DNS_CHECK_TIMEOUT.as_secs()
                {
                    return Err(OrderError::DnsValidation(
                        "DNS record not updated within the time limit".to_string(),
                    ));
                }

                std::thread::sleep(DNS_CHECK_INTERVAL);
            }
        }

        {
            let challenge = self
                .challenges
                .get_mut(&challenge_type)
                .ok_or(OrderError::ChallengeNotFound)?;

            challenge.validate(account)?;
        }

        let response = Client::new()
            .get(&self.order_url)
            .header("Content-Type", "application/jose+json")
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
        println!("Order status: {:?}", self.status);

        Ok(self)
    }

    pub fn dns_provider(mut self, provider: DnsProvider, token: &str) -> Result<Self> {
        match provider {
            DnsProvider::Cloudflare => self.handle_cloudflare_dns(token)?,
        }
        Ok(self)
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

    fn check_dns_record(&self, record_name: &str, expected: &str) -> Result<bool> {
        let client = Client::new();
        let url = format!("https://dns.google/resolve?name={}&type=TXT", record_name);

        let response = client.get(&url).send()?;
        let json: serde_json::Value = serde_json::from_str(&response.text()?)?;

        let records = json["Answer"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|entry| entry["data"].as_str())
            .map(|s| s.trim_matches('"').to_string())
            .collect::<Vec<_>>();

        Ok(records.contains(&expected.to_string()))
    }

    fn handle_cloudflare_dns(&mut self, token: &str) -> Result<()> {
        let client = Client::new();
        let challenges: Vec<&Challenge> = self
            .challenges
            .values()
            .filter(|c| c.challenge_type == ChallengeType::Dns01)
            .collect();

        if challenges.is_empty() {
            return Err(OrderError::NoDnsChallenge);
        }

        let zone_id = self.get_cloudflare_zone_id(&client, token)?;

        for challenge in challenges {
            let record_name = format!("_acme-challenge.{}", self.domain);
            self.delete_existing_txt_records(&client, token, &zone_id, &record_name)?;
            let content = format!("\"{}\"", challenge.dns_txt_value());
            self.create_cloudflare_txt_record(&client, token, &zone_id, &record_name, &content)?;
        }

        Ok(())
    }

    fn delete_existing_txt_records(
        &self,
        client: &Client,
        token: &str,
        zone_id: &str,
        record_name: &str,
    ) -> Result<()> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records?type=TXT&name={}",
            zone_id, record_name
        );
        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()?;

        let list: CloudflareDnsListResponse = response.json()?;
        if !list.success {
            return Err(OrderError::Cloudflare(format_cloudflare_errors(
                list.errors,
            )));
        }

        for record in list.result {
            let delete_url = format!(
                "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
                zone_id, record.id
            );
            let del_response = client
                .delete(&delete_url)
                .header("Authorization", format!("Bearer {}", token))
                .send()?;

            let del_result: CloudflareDnsResponse = del_response.json()?;
            if !del_result.success {
                return Err(OrderError::Cloudflare(format_cloudflare_errors(
                    del_result.errors,
                )));
            }
        }

        Ok(())
    }

    fn get_cloudflare_zone_id(&self, client: &Client, token: &str) -> Result<String> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones?name={}",
            self.domain
        );
        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()?;

        let result: CloudflareZoneResponse = response.json()?;
        if !result.success {
            return Err(OrderError::Cloudflare(format_cloudflare_errors(
                result.errors,
            )));
        }

        result
            .result
            .first()
            .map(|z| z.id.clone())
            .ok_or_else(|| OrderError::Cloudflare("Zone not found".into()))
    }

    fn create_cloudflare_txt_record(
        &self,
        client: &Client,
        token: &str,
        zone_id: &str,
        name: &str,
        content: &str,
    ) -> Result<()> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
            zone_id
        );
        let record = CloudflareDnsRecord {
            record_type: "TXT".into(),
            name: name.into(),
            content: content.into(),
            ttl: 60,
        };

        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&record)
            .send()?;

        let result: CloudflareDnsResponse = response.json()?;
        if !result.success {
            return Err(OrderError::Cloudflare(format_cloudflare_errors(
                result.errors,
            )));
        }

        Ok(())
    }
}

fn format_cloudflare_errors(errors: Vec<CloudflareError>) -> String {
    errors
        .into_iter()
        .map(|e| format!("{}: {}", e.code, e.message))
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Debug, Deserialize)]
struct OrderUpdateResponse {
    status: OrderStatus,
    certificate: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum DnsProvider {
    Cloudflare,
}

#[derive(Debug, Serialize)]
struct CloudflareDnsRecord {
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    content: String,
    ttl: u32,
}

#[derive(Debug, Deserialize)]
struct CloudflareDnsListResponse {
    success: bool,
    result: Vec<CloudflareDnsRecordItem>,
    errors: Vec<CloudflareError>,
}

#[derive(Debug, Deserialize)]
struct CloudflareDnsRecordItem {
    id: String,
}

#[derive(Debug, Deserialize)]
struct CloudflareZoneResponse {
    success: bool,
    result: Vec<CloudflareZone>,
    errors: Vec<CloudflareError>,
}

#[derive(Debug, Deserialize)]
struct CloudflareZone {
    id: String,
}

#[derive(Debug, Deserialize)]
struct CloudflareDnsResponse {
    success: bool,
    errors: Vec<CloudflareError>,
}

#[derive(Debug, Deserialize)]
struct CloudflareError {
    code: u32,
    message: String,
}
