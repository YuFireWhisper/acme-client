use openssl::hash::{hash, MessageDigest};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;

use crate::base64::Base64;

#[derive(Debug, Clone, PartialEq)]
pub enum ChallengeType {
    Http01,
    Dns01,
    TlsAlpn01,
}

impl ChallengeType {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "http-01" => Some(ChallengeType::Http01),
            "dns-01" => Some(ChallengeType::Dns01),
            "tls-alpn-01" => Some(ChallengeType::TlsAlpn01),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct Challenge {
    challenge_type: ChallengeType,
    token: String,
    url: String,
    status: String,
    validation_record: Option<Vec<ValidationRecord>>,
    key_authorization: String,
}

#[derive(Debug, Deserialize)]
struct ValidationRecord {
    url: String,
    hostname: String,
    port: String,
    addressed_used: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ChallengeResponse {
    #[serde(rename = "type")]
    challenge_type: String,
    url: String,
    status: String,
    token: String,
    #[serde(default)]
    validation_record: Option<Vec<ValidationRecord>>,
}

static INSTRUCTIONS: OnceLock<HashMap<&'static str, Instructions>> = OnceLock::new();

pub struct Instructions {
    http01: &'static str,
    dns01: &'static str,
    tls_alpn01: &'static str,
}

fn init_instructions() -> HashMap<&'static str, Instructions> {
    let mut m = HashMap::new();

    m.insert(
        "zh-tw",
        Instructions {
            http01: "HTTP-01 驗證說明:\n\
                1. 在您的 Web 服務器上創建以下路徑：/.well-known/acme-challenge/{}\n\
                2. 該文件應該包含以下內容：{}\n\
                3. 確保該路徑可以通過 HTTP 訪問（不要重定向到 HTTPS）\n\
                4. 文件應該返回 Content-Type: text/plain",
            dns01: "DNS-01 驗證說明:\n\
               1. 在您的 DNS 記錄中添加以下 TXT 記錄：\n\
               2. 記錄名稱：_acme-challenge\n\
               3. 記錄值：{}\n\
               4. TTL 建議設置為 120 秒或更短\n\
               5. 等待 DNS 記錄生效（可能需要幾分鐘到幾小時）",
            tls_alpn01: "TLS-ALPN-01 驗證說明:\n\
                    1. 在您的 Web 服務器上配置 TLS-ALPN-01 驗證\n\
                    2. 使用 acme-tls/1 協議\n\
                    3. 證書應包含以下驗證內容：{}\n\
                    4. 確保服務器正確響應 SNI 請求",
        },
    );

    m.insert(
        "en",
        Instructions {
            http01: "HTTP-01 Validation Instructions:\n\
                1. Create the following path on your web server: /.well-known/acme-challenge/{}\n\
                2. The file should contain the following content: {}\n\
                3. Ensure the path is accessible via HTTP (no HTTPS redirection)\n\
                4. The file should return Content-Type: text/plain",
            dns01: "DNS-01 Validation Instructions:\n\
               1. Add the following TXT record to your DNS:\n\
               2. Record name: _acme-challenge\n\
               3. Record value: {}\n\
               4. Recommended TTL: 120 seconds or less\n\
               5. Wait for DNS propagation (may take minutes to hours)",
            tls_alpn01: "TLS-ALPN-01 Validation Instructions:\n\
                    1. Configure TLS-ALPN-01 validation on your web server\n\
                    2. Use the acme-tls/1 protocol\n\
                    3. Certificate should include the following validation content: {}\n\
                    4. Ensure proper server response to SNI requests",
        },
    );

    m
}

impl Challenge {
    pub fn from_json(
        json: &str,
        account_key_thumbprint: &str,
    ) -> Result<Vec<Self>, serde_json::Error> {
        let challenges: Vec<ChallengeResponse> = serde_json::from_str(json)?;

        Ok(challenges
            .into_iter()
            .filter_map(|c| {
                let challenge_type = ChallengeType::from_str(&c.challenge_type)?;
                let key_authorization = format!("{}.{}", c.token, account_key_thumbprint);

                Some(Challenge {
                    challenge_type,
                    token: c.token,
                    url: c.url,
                    status: c.status,
                    validation_record: c.validation_record,
                    key_authorization,
                })
            })
            .collect())
    }

    pub fn get_validation_instructions(&self, lang: &str) -> String {
        let instructions = INSTRUCTIONS.get_or_init(init_instructions);
        let lang_instructions = instructions
            .get(lang)
            .unwrap_or(instructions.get("zh-tw").unwrap());

        match self.challenge_type {
            ChallengeType::Http01 => lang_instructions
                .http01
                .to_string()
                .replace("{}", &self.token)
                .replace("{}", &self.key_authorization),
            ChallengeType::Dns01 => {
                let dns_txt_value = self.get_dns_txt_value();
                lang_instructions
                    .dns01
                    .to_string()
                    .replace("{}", &dns_txt_value)
            }
            ChallengeType::TlsAlpn01 => lang_instructions
                .tls_alpn01
                .to_string()
                .replace("{}", &self.key_authorization),
        }
    }
    pub fn get_http_content(&self) -> Option<String> {
        if self.challenge_type == ChallengeType::Http01 {
            Some(self.key_authorization.clone())
        } else {
            None
        }
    }

    pub fn get_dns_txt_value(&self) -> String {
        let digest = hash(MessageDigest::sha256(), self.key_authorization.as_bytes())
            .expect("SHA-256 hashing failed");
        Base64::new(digest).base64_url()
    }

    pub fn get_verification_url(&self) -> &str {
        &self.url
    }

    pub fn get_status(&self) -> &str {
        &self.status
    }

    pub fn get_token(&self) -> &str {
        &self.token
    }

    pub fn get_type(&self) -> &ChallengeType {
        &self.challenge_type
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_creation() {
        let json = r#"[
            {
                "type": "http-01",
                "url": "https://example.com/challenge/1234",
                "status": "pending",
                "token": "abc123"
            }
        ]"#;

        let challenges = Challenge::from_json(json, "test-thumbprint").unwrap();
        assert_eq!(challenges.len(), 1);
        assert_eq!(challenges[0].get_type(), &ChallengeType::Http01);
        assert_eq!(challenges[0].get_token(), "abc123");
    }

    #[test]
    fn test_instructions_localization() {
        let json = r#"[
            {
                "type": "http-01",
                "url": "https://example.com/challenge/1234",
                "status": "pending",
                "token": "abc123"
            }
        ]"#;

        let challenges = Challenge::from_json(json, "test-thumbprint").unwrap();
        let challenge = &challenges[0];

        let zh_instructions = challenge.get_validation_instructions("zh-tw");
        let en_instructions = challenge.get_validation_instructions("en");

        assert!(zh_instructions.contains("驗證說明"));
        assert!(en_instructions.contains("Validation Instructions"));
    }
}
