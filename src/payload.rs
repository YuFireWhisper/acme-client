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

#[derive(Debug, Serialize, Deserialize)]
pub struct Identifier {
    #[serde(rename = "type")]
    pub type_: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewOrderPayload {
    pub identifiers: Vec<Identifier>,
}

impl NewOrderPayload {
    pub fn new(domains: Vec<&str>) -> Self {
        let identifiers = domains
            .into_iter()
            .map(|domain| Identifier {
                type_: "dns".to_string(),
                value: domain.to_string(),
            })
            .collect();

        NewOrderPayload {
            identifiers,
        }
    }
}

impl PayloadT for NewOrderPayload {
    fn validate(&self) -> Result<(), Box<dyn Error>> {
        if self.identifiers.is_empty() {
            return Err("At least one identifier is required".into());
        }
        for identifier in &self.identifiers {
            if identifier.type_ != "dns" {
                return Err("Identifier type must be 'dns'".into());
            }
            if identifier.value.is_empty() {
                return Err("Identifier value cannot be empty".into());
            }
        }
        Ok(())
    }
}
