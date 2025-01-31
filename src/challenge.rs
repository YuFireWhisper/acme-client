use std::{collections::HashMap, sync::OnceLock};

use openssl::hash::{hash, MessageDigest};
use reqwest::blocking::Client;
use serde::Deserialize;
use thiserror::Error;

use crate::{
    account::Account,
    base64::Base64,
    jws::{Jws, JwsError},
    payload::{ChallengeValidationPayload, PayloadT},
    protection::{Protection, ProtectionError},
    signature::{create_signature, SignatureError},
};

#[derive(Debug, Error)]
pub enum ChallengeError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("JSON parsing failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("JWS error: {0}")]
    Jws(#[from] JwsError),
    #[error("Protection error: {0}")]
    Protection(#[from] ProtectionError),
    #[error("Signature error: {0}")]
    Signature(#[from] SignatureError),
    #[error("Unsupported challenge type: {0}")]
    UnsupportedType(String),
    #[error("Invalid challenge status: {0}")]
    InvalidStatus(String),
    #[error("Challenge in invalid state: {0:?}")]
    InvalidState(ChallengeStatus),
    #[error("Validation failed: {0}")]
    ValidationFailed(String),
    #[error("Authorization response parsing failed")]
    AuthorizationParseError,
}

type Result<T> = std::result::Result<T, ChallengeError>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ChallengeType {
    Http01,
    Dns01,
    TlsAlpn01,
}

impl ChallengeType {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "http-01" => Some(Self::Http01),
            "dns-01" => Some(Self::Dns01),
            "tls-alpn-01" => Some(Self::TlsAlpn01),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Http01 => "http-01",
            Self::Dns01 => "dns-01",
            Self::TlsAlpn01 => "tls-alpn-01",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeStatus {
    Pending,
    Valid,
    Invalid,
    Deactivated,
    Expired,
}

impl ChallengeStatus {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "pending" => Some(Self::Pending),
            "valid" => Some(Self::Valid),
            "invalid" => Some(Self::Invalid),
            "deactivated" => Some(Self::Deactivated),
            "expired" => Some(Self::Expired),
            _ => None,
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Valid | Self::Invalid | Self::Deactivated | Self::Expired
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::Deactivated => "deactivated",
            Self::Expired => "expired",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Challenge {
    pub challenge_type: ChallengeType,
    pub url: String,
    pub token: String,
    pub status: ChallengeStatus,
    pub validated: Option<String>,
    pub key_authorization: String,
}

#[derive(Deserialize)]
struct AuthorizationResponse {
    challenges: Vec<ChallengeResponse>,
}

#[derive(Deserialize)]
struct ChallengeResponse {
    r#type: String,
    url: String,
    status: String,
    token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    validated: Option<String>,
}

#[derive(Deserialize)]
struct ChallengeUpdateResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ApiError>,
}

#[derive(Deserialize)]
struct ApiError {
    #[serde(rename = "type")]
    error_type: String,
    detail: String,
}

static INSTRUCTIONS: OnceLock<HashMap<&'static str, Instructions>> = OnceLock::new();

struct Instructions {
    http01: String,
    dns01: String,
    tls_alpn01: String,
}

impl Challenge {
    pub fn fetch_challenges(auth_url: &str, thumbprint: &str) -> Result<Vec<Self>> {
        let response = Client::new()
            .get(auth_url)
            .header("Content-Type", "application/jose+json")
            .send()
            .map_err(ChallengeError::Request)?;

        if !response.status().is_success() {
            return Err(ChallengeError::Request(
                response.error_for_status().unwrap_err(),
            ));
        }

        let response_body = response.text().map_err(ChallengeError::Request)?;
        Self::parse_challenges(&response_body, thumbprint)
    }

    pub fn parse_challenges(json: &str, thumbprint: &str) -> Result<Vec<Self>> {
        let response: AuthorizationResponse =
            serde_json::from_str(json).map_err(ChallengeError::Json)?;

        let mut challenges = Vec::new();

        for resp in response.challenges {
            let challenge_type = ChallengeType::from_str(&resp.r#type)
                .ok_or_else(|| ChallengeError::UnsupportedType(resp.r#type.clone()))?;

            let status = ChallengeStatus::from_str(&resp.status)
                .ok_or_else(|| ChallengeError::InvalidStatus(resp.status.clone()))?;

            let key_authorization = format!("{}.{}", resp.token, thumbprint);

            challenges.push(Self {
                challenge_type,
                url: resp.url,
                token: resp.token,
                status,
                validated: resp.validated,
                key_authorization,
            });
        }

        Ok(challenges)
    }

    pub fn validate(&mut self, account: &mut Account) -> Result<()> {
        if self.status.is_terminal() {
            return Err(ChallengeError::InvalidState(self.status.clone()));
        }

        let payload = ChallengeValidationPayload::new().to_base64()?;
        let jws = self.build_jws(account, &payload)?;

        let response = Client::new()
            .post(&self.url)
            .header("Content-Type", "application/jose+json")
            .body(jws.to_json()?)
            .send()?;

        let status_code = response.status();
        let response_body = response.text()?;

        let update: ChallengeUpdateResponse = serde_json::from_str(&response_body)?;
        self.status = ChallengeStatus::from_str(&update.status)
            .ok_or_else(|| ChallengeError::InvalidStatus(update.status.clone()))?;

        if !status_code.is_success() {
            let error_detail = update
                .error
                .map(|e| format!("{}: {}", e.error_type, e.detail))
                .unwrap_or_else(|| "Unknown API error".to_string());
            return Err(ChallengeError::ValidationFailed(error_detail));
        }

        Ok(())
    }

    fn build_jws(&self, account: &Account, payload: &Base64) -> Result<Jws> {
        let header = Protection::new(&account.nonce, &account.key_pair.alg_name)
            .set_value(&account.account_url)?
            .create_header(&self.url)?
            .to_base64()?;

        let signature = create_signature(&header, payload, &account.key_pair)?;
        Jws::new(&header, payload, &signature).map_err(Into::into)
    }

    pub fn get_instructions(&self, lang: &str) -> String {
        let instructions = INSTRUCTIONS.get_or_init(init_instructions);
        let lang_instructions = instructions.get(lang).unwrap_or_else(|| {
            instructions
                .get("zh-tw")
                .expect("Default instructions not found")
        });

        match self.challenge_type {
            ChallengeType::Http01 => lang_instructions
                .http01
                .replace("{token}", &self.token)
                .replace("{key_auth}", &self.key_authorization),
            ChallengeType::Dns01 => {
                let dns_value = self.dns_txt_value();
                lang_instructions.dns01.replace("{dns_value}", &dns_value)
            }
            ChallengeType::TlsAlpn01 => lang_instructions
                .tls_alpn01
                .replace("{key_auth}", &self.key_authorization),
        }
    }

    pub fn dns_txt_value(&self) -> String {
        let digest = hash(MessageDigest::sha256(), self.key_authorization.as_bytes())
            .expect("SHA-256 hashing failed");
        Base64::new(digest).base64_url()
    }

    pub fn http_content(&self) -> Option<&str> {
        if self.challenge_type == ChallengeType::Http01 {
            Some(&self.key_authorization)
        } else {
            None
        }
    }
}

fn init_instructions() -> HashMap<&'static str, Instructions> {
    let mut m = HashMap::new();

    m.insert(
        "zh-tw",
        Instructions {
            http01: "HTTP-01 驗證步驟：\n\
                1. 建立文件路徑：/.well-known/acme-challenge/{token}\n\
                2. 文件內容：{key_auth}\n\
                3. 確保可通過 HTTP 訪問（非 HTTPS）\n\
                4. Content-Type 設為 text/plain"
                .to_string(),
            dns01: "DNS-01 驗證步驟：\n\
                1. 新增 TXT 記錄：\n\
                2. 主機名稱：_acme-challenge\n\
                3. 記錄值：{dns_value}\n\
                4. TTL 建議設為 300 秒\n\
                5. 等待 DNS 傳播"
                .to_string(),
            tls_alpn01: "TLS-ALPN-01 驗證步驟：\n\
                1. 配置 TLS 伺服器支援 ALPN\n\
                2. 使用協定：acme-tls/1\n\
                3. 證書包含驗證碼：{key_auth}\n\
                4. 確保 SNI 設定正確"
                .to_string(),
        },
    );

    m.insert(
        "en",
        Instructions {
            http01: "HTTP-01 Validation Steps:\n\
                1. Create file path: /.well-known/acme-challenge/{token}\n\
                2. File content: {key_auth}\n\
                3. Ensure accessible via HTTP (not HTTPS)\n\
                4. Set Content-Type to text/plain"
                .to_string(),
            dns01: "DNS-01 Validation Steps:\n\
                1. Add TXT record:\n\
                2. Hostname: _acme-challenge\n\
                3. Value: {dns_value}\n\
                4. Recommended TTL: 300\n\
                5. Wait for DNS propagation"
                .to_string(),
            tls_alpn01: "TLS-ALPN-01 Validation Steps:\n\
                1. Configure TLS server with ALPN\n\
                2. Use protocol: acme-tls/1\n\
                3. Certificate must include: {key_auth}\n\
                4. Ensure correct SNI setup"
                .to_string(),
        },
    );

    m
}
