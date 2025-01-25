use std::fs;

use serde::Deserialize;

static LETS_ENCRYPT_DIRECTORY_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";

#[derive(Debug, Deserialize)]
pub struct Directory {
    #[serde(rename = "newAccount")]
    new_account: String,
    #[serde(rename = "newNonce")]
    new_nonce: String,
    #[serde(rename = "newOrder")]
    new_order: String,
    #[serde(rename = "renewalInfo")]
    renewal_info: Option<String>,
    #[serde(rename = "revokeCert")]
    reovke_cert: String,
}

impl Directory { 
    async fn from_url(url: &str) -> Result<(), Box<dyn std::error::Error>> {
        let resp = reqwest::get(url).await?;
        let dir: Directory = resp.json().await?;

        Ok(dir)
    }
    
    async fn from_file(path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?; 
        let directory: Directory = serde_json::from_str(&content)?;
        
        Ok(directory)
    }
}
