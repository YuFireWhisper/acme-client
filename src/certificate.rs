use chrono::{DateTime, Utc};
use openssl::{asn1::Asn1Time, x509::X509};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CertificateError {
    #[error("Failed to parse certificate: {0}")]
    ParseError(#[from] openssl::error::ErrorStack),
    #[error("Certificate expired since {0}")]
    Expired(DateTime<Utc>),
    #[error("Invalid expiration timestamp")]
    InvalidTimestamp,
    #[error("Failed to parse expiration time: {0}")]
    ExpirationTimeParseError(String),
}

type Result<T> = std::result::Result<T, CertificateError>;

pub struct Certificate {
    cert: X509,
}

impl Certificate {
    pub fn new(pem: &str) -> Result<Self> {
        let cert = X509::from_pem(pem.as_bytes())?;
        Ok(Certificate { cert })
    }

    pub fn should_renew(&self, threshold_days: u32) -> Result<bool> {
        let not_after = self.cert.not_after();
        let now_ts = Utc::now().timestamp();
        let now_asn1 = Asn1Time::from_unix(now_ts)?;
        let diff = not_after.diff(now_asn1.as_ref())?;
        let remaining_seconds = diff.days as i64 * 86400 + diff.secs as i64;
        let threshold_seconds = threshold_days as i64 * 86400;
        Ok(remaining_seconds < threshold_seconds)
    }
}
