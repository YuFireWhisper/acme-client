use serde::{Deserialize, Serialize};
use std::error::Error;

pub trait PayloadT: Serialize + for<'de> Deserialize<'de> {
    fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    fn validate(&self) -> Result<(), Box<dyn Error>>;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountPayload {
    contact: Vec<String>,
    terms_of_service_agreed: bool,
}

impl AccountPayload {
    pub fn new(email: &str, terms_agreed: bool) -> Self {
        let contact = if email.contains("@") {
            vec![email.to_string()]
        } else {
            vec![format!("mailto:{}", email)]
        };

        AccountPayload {
            contact,
            terms_of_service_agreed: terms_agreed,
        }
    }
}

impl PayloadT for AccountPayload {
    fn validate(&self) -> Result<(), Box<dyn Error>> {
        if self.contact.is_empty() {
            return Err("Contact information is required".into());
        }
        if !self.terms_of_service_agreed {
            return Err("Terms of service must be agreed".into());
        }
        Ok(())
    }
}
