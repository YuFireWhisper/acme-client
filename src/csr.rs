use std::result;

use openssl::{
    hash::MessageDigest,
    stack::Stack,
    x509::{extension::SubjectAlternativeName, X509Req},
};
use thiserror::Error;

use crate::key_pair::KeyPair;

#[derive(Debug, Error)]
pub enum CsrError {
    #[error("Openssl error: {0}")]
    OpensslError(#[from] openssl::error::ErrorStack),
    #[error("No SAN entries")]
    NoSanEntries,
}

type Result<T> = result::Result<T, CsrError>;

pub struct CSR {
    san_entries: Vec<String>,
}

impl CSR {
    pub fn new() -> Result<Self> {
        Ok(CSR {
            san_entries: Vec::new(),
        })
    }

    pub fn set_san(mut self, dns_name: &str) -> Self {
        self.san_entries.push(dns_name.to_string());
        self
    }

    pub fn build(self, key_pair: &KeyPair) -> Result<X509Req> {
        let mut req_builder = X509Req::builder()?;

        if self.san_entries.is_empty() {
            return Err(CsrError::NoSanEntries);
        }

        let mut san_builder = SubjectAlternativeName::new();
        for entry in self.san_entries {
            san_builder.dns(&entry);
        }
        let san_extension = san_builder.build(&req_builder.x509v3_context(None))?;

        let mut stack = Stack::new()?;
        stack.push(san_extension)?;
        req_builder.add_extensions(&stack)?;

        req_builder.set_pubkey(&key_pair.pri_key)?;
        req_builder.sign(&key_pair.pri_key, MessageDigest::sha256())?;
        
        Ok(req_builder.build())
    }
}
