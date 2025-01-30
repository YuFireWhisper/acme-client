use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DirectoryError {
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Request error: {0}")]
    Request(#[from] reqwest::Error),
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
}

type DirectoryResult<T> = std::result::Result<T, DirectoryError>;

use crate::{
    base64::Base64,
    storage::{Storage, StorageError},
};

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
    pub revoke_cert: String,
}

impl Directory {
    pub fn new<T: Storage>(storage: &T, url: &str) -> DirectoryResult<Self> {
        let storage_key = Base64::new(url.as_bytes()).base64_url();

        match storage.read_file(&storage_key) {
            Ok(data) => {
                return Ok(serde_json::from_slice(&data)?);
            }
            Err(StorageError::NotFound(_)) => {}
            Err(e) => {
                return Err(DirectoryError::Storage(e));
            }
        }

        let client = Client::new();
        let response = client.get(url).send()?;
        let directory: Directory = response.json()?;

        let serialized = serde_json::to_vec(&directory)?;
        storage.write_file(&storage_key, &serialized)?;

        Ok(directory)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{MemStorage, Storage};
    use mockito::Server;

    fn create_test_directory() -> Directory {
        Directory {
            new_account: "acc".into(),
            new_nonce: "nonce".into(),
            new_order: "order".into(),
            renewal_info: Some("renew".into()),
            revoke_cert: "revoke".into(),
        }
    }

    #[test]
    fn fetch_from_network_and_store() {
        let mut server = Server::new();
        let url = server.url();
        let storage_key = Base64::new(url.as_bytes()).base64_url();

        let dir = create_test_directory();
        let dir_json = serde_json::to_vec(&dir).unwrap();

        let mock = server
            .mock("GET", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(dir_json.clone())
            .create();

        let storage = MemStorage::new();
        let result = Directory::new(&storage, &url).unwrap();

        mock.assert();
        assert_eq!(result.new_account, dir.new_account);
        assert_eq!(storage.read_file(&storage_key).unwrap(), dir_json);
    }

    #[test]
    fn use_cached_data_when_available() {
        let mut server = Server::new();
        let url = server.url();
        let storage_key = Base64::new(url.as_bytes()).base64_url();

        let dir = create_test_directory();
        let dir_json = serde_json::to_vec(&dir).unwrap();

        let storage = MemStorage::new();
        storage.write_file(&storage_key, &dir_json).unwrap();

        let mock = server.mock("GET", "/").expect(0).create();

        let result = Directory::new(&storage, &url).unwrap();
        mock.assert();
        assert_eq!(result.new_account, dir.new_account);
    }

    #[test]
    fn handle_network_errors() {
        let mut server = Server::new();
        let url = server.url();

        let mock = server.mock("GET", "/").with_status(500).create();

        let storage = MemStorage::new();
        let result = Directory::new(&storage, &url);

        mock.assert();
        assert!(matches!(result, Err(DirectoryError::Request(_))));
    }

    #[test]
    fn handle_invalid_json() {
        let mut server = Server::new();
        let url = server.url();

        let mock = server
            .mock("GET", "/")
            .with_status(200)
            .with_body("invalid json")
            .create();

        let storage = MemStorage::new();
        let result = Directory::new(&storage, &url);

        mock.assert();
        assert!(matches!(result, Err(DirectoryError::Request(_))));
    }
}
