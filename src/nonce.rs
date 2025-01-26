use reqwest::blocking::Client;
use std::error::Error;

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

    pub fn get(&self) -> Result<String, Box<dyn Error>> {
        let response = self.client.head(&self.url).send()?;

        match response.headers().get("Replay-Nonce") {
            Some(nonce) => Ok(nonce.to_str()?.to_string()),
            None => Err("No Replay-Nonce header found".into()),
        }
    }
}
