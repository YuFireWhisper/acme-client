use std::result;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::
    base64::{Base64, DecodeError}
;

#[derive(Serialize, Deserialize, Debug)]
pub struct Jws {
    #[serde(rename = "protected")]
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
    pub fn new(
        header_b64: &Base64,
        payload_b64: &Base64,
        signature_b64: &Base64,
    ) -> Result<Self> {
        Ok(Jws {
            header: header_b64.base64_url(),
            payload: payload_b64.base64_url(),
            signature: signature_b64.base64_url(),
        })
    }

    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }
}
