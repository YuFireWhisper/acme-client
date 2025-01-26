use reqwest::blocking::Client;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NonceError {
    #[error("Failed to make request: {0}")]
    RequestFailed(#[from] reqwest::Error),
    #[error("No Replay-Nonce header found in response")]
    NoNonceHeader,
    #[error("Invalid header value: {0}")]
    InvalidHeaderValue(#[from] reqwest::header::ToStrError),
}

pub trait NonceT {
    fn get(&self) -> Result<String, NonceError>;
}

#[derive(Debug)]
pub struct Nonce {
    client: Client,
    url: String,
}

impl Nonce {
    pub fn new(url: impl Into<String>) -> Self {
        Nonce {
            client: Client::new(),
            url: url.into(),
        }
    }
}

impl NonceT for Nonce {
    fn get(&self) -> Result<String, NonceError> {
        let response = self.client.head(&self.url).send()?;

        match response.headers().get("Replay-Nonce") {
            Some(nonce) => Ok(nonce.to_str()?.to_string()),
            None => Err(NonceError::NoNonceHeader),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MockNonce {
    value: String,
}

impl MockNonce {
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }
}

impl NonceT for MockNonce {
    fn get(&self) -> Result<String, NonceError> {
        Ok(self.value.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_nonce() {
        let nonce = MockNonce::new("test-nonce-123");
        assert_eq!(nonce.get().unwrap(), "test-nonce-123");
    }
}
