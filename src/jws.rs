use std::result;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    base64::{Base64, DecodeError},
    payload::PayloadT,
    protection::ProtectedHeader,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct Jws {
    header: String,
    payload: String,
    signature: String,
}

#[derive(Error, Debug)]
pub enum JwsError {
    #[error("Base64 decode error: {0}")]
    Base64DecodeError(#[from] DecodeError),
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

type Result<T> = result::Result<T, JwsError>;

impl Jws {
    pub fn new<T: PayloadT>(
        header: &ProtectedHeader,
        payload: &T,
        signature: &str,
    ) -> Result<Self> {
        let header_base64 = Base64::new(header.to_string());
        let payload_base64 = Base64::new(payload.to_json_string()?);
        let signature_base64 = Base64::from_encoded(signature)?;

        Ok(Jws {
            header: header_base64.as_str().to_string(),
            payload: payload_base64.as_str().to_string(),
            signature: signature_base64.as_str().to_string(),
        })
    }

    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }
}
