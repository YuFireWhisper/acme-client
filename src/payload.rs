use serde::{Deserialize, Serialize};
use std::error::Error;

pub trait Payload: Serialize + for<'de> Deserialize<'de> {
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

impl Payload for AccountPayload {
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
pub struct OrderPayload {
    order_id: String,
    products: Vec<OrderProduct>,
    total_amount: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OrderProduct {
    product_id: String,
    quantity: i32,
    price: f64,
}

impl OrderPayload {
    pub fn new(order_id: String, products: Vec<OrderProduct>) -> Self {
        let total_amount = products.iter().map(|p| p.price * p.quantity as f64).sum();

        OrderPayload {
            order_id,
            products,
            total_amount,
        }
    }
}

impl Payload for OrderPayload {
    fn validate(&self) -> Result<(), Box<dyn Error>> {
        if self.order_id.is_empty() {
            return Err("Order ID is required".into());
        }
        if self.products.is_empty() {
            return Err("Order must contain at least one product".into());
        }
        if self.total_amount <= 0.0 {
            return Err("Total amount must be greater than zero".into());
        }
        Ok(())
    }
}

pub fn process_payload<T: Payload>(payload: &T) -> Result<String, Box<dyn Error>> {
    payload.validate()?;
    Ok(payload.to_json_string()?)
}
