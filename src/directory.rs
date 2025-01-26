use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Debug)]
pub enum DirectoryError {
    JsonError(serde_json::Error),
    RequestError(reqwest::Error),
    StorageError(StorageError),
}

impl std::fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            DirectoryError::JsonError(err) => write!(f, "Json error: {}", err),
            DirectoryError::RequestError(err) => write!(f, "Request error: {}", err),
            DirectoryError::StorageError(err) => write!(f, "Storage error: {}", err),
        }
    }
}

impl From<serde_json::Error> for DirectoryError {
    fn from(err: serde_json::Error) -> Self {
        DirectoryError::JsonError(err)
    }
}

impl From<reqwest::Error> for DirectoryError {
    fn from(err: reqwest::Error) -> Self {
        DirectoryError::RequestError(err)
    }
}

impl From<StorageError> for DirectoryError {
    fn from(err: StorageError) -> Self {
        DirectoryError::StorageError(err)
    }
}

impl Error for DirectoryError {}

type DirectoryResult<T> = std::result::Result<T, DirectoryError>;

use crate::storage::{Storage, StorageError};

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
    pub fn new<T: Storage>(storage: &mut T, url: &str) -> DirectoryResult<Self> {
        if let Some(data) = storage.read_file(url)? {
            return Ok(serde_json::from_slice(&data)?);
        }

        let client = Client::new();
        let response = client.get(url).send()?;
        let directory: Directory = response.json()?;

        let serialized = serde_json::to_vec(&directory)?;
        storage.write_file(url, &serialized)?;

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

        let dir = create_test_directory();
        let dir_json = serde_json::to_vec(&dir).unwrap();

        let mock = server
            .mock("GET", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(dir_json.clone())
            .create();

        let mut storage = MemStorage::new();
        let result = Directory::new(&mut storage, &url).unwrap();

        mock.assert();
        assert_eq!(result.new_account, dir.new_account);
        assert_eq!(storage.read_file(&url).unwrap().unwrap(), dir_json);
    }

    #[test]
    fn use_cached_data_when_available() {
        let mut server = Server::new();
        let url = server.url();

        let dir = create_test_directory();
        let dir_json = serde_json::to_vec(&dir).unwrap();

        let mut storage = MemStorage::new();
        storage.write_file(&url, &dir_json).unwrap();

        let mock = server.mock("GET", "/").expect(0).create();

        let result = Directory::new(&mut storage, &url).unwrap();
        mock.assert();
        assert_eq!(result.new_account, dir.new_account);
    }

    #[test]
    fn handle_network_errors() {
        let mut server = Server::new();
        let url = server.url();

        let mock = server.mock("GET", "/").with_status(500).create();

        let mut storage = MemStorage::new();
        let result = Directory::new(&mut storage, &url);

        mock.assert();
        assert!(matches!(result, Err(DirectoryError::RequestError(_))));
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

        let mut storage = MemStorage::new();
        let result = Directory::new(&mut storage, &url);

        mock.assert();
        assert!(matches!(result, Err(DirectoryError::JsonError(_))));
    }
}
