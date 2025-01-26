use serde::{Deserialize, Serialize};
use std::error::Error;

use crate::storage::Storage;

#[derive(Debug, Deserialize, Serialize)]
pub struct Directory {
    #[serde(rename = "newAccount")]
    pub new_account: String,
    #[serde(rename = "newNonce")]
    pub new_nonce: String,
    #[serde(rename = "newOrder")]
    pub new_order: String,
    #[serde(rename = "renewalInfo")]
    pub renewal_info: Option<String>,
    #[serde(rename = "revokeCert")]
    pub reovke_cert: String,
}

impl Directory {
    pub fn new(storage: &mut Storage, url: &str) -> Result<Self, Box<dyn Error>> {
        if let Some(data) = storage.read_file(url)? {
            return Ok(serde_json::from_slice(&data)?);
        }

        let client = reqwest::blocking::Client::new();
        let response = client.get(url).send()?;
        let directory: Directory = response.json()?;

        let serialized = serde_json::to_string(&directory)?.as_bytes();
        storage.write_file(url, serialized)?;

        Ok(directory)
    }
}
