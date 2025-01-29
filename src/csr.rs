use std::result;

use openssl::{
    nid::Nid,
    x509::{X509Name, X509Req},
};
use thiserror::Error;

use crate::key_pair::KeyPair;

#[derive(Debug, Error)]
pub enum CsrError {
    #[error("Openssl error: {0}")]
    OpensslError(#[from] openssl::error::ErrorStack),
}

type Result<T> = result::Result<T, CsrError>;

pub struct CSR {
    common_name: String,
    organization: Option<String>,
    country: Option<String>,
    locality: Option<String>,
    state: Option<String>,
}

impl CSR {
    pub fn new(common_name: &str) -> Result<Self> {
        Ok(Self {
            common_name: common_name.to_string(),
            organization: None,
            country: None,
            locality: None,
            state: None,
        })
    }

    pub fn organization(mut self, organization: &str) -> Self {
        self.organization = Some(organization.to_string());
        self
    }

    pub fn country(mut self, country: &str) -> Self {
        self.country = Some(country.to_string());
        self
    }

    pub fn locality(mut self, locality: &str) -> Self {
        self.locality = Some(locality.to_string());
        self
    }

    pub fn state(mut self, state: &str) -> Self {
        self.state = Some(state.to_string());
        self
    }

    pub fn build(&self, key_pair: &KeyPair) -> Result<X509Req> {
        let mut name = X509Name::builder()?;

        name.append_entry_by_nid(Nid::COMMONNAME, &self.common_name)?;

        if let Some(org) = &self.organization {
            name.append_entry_by_nid(Nid::ORGANIZATIONNAME, org)?;
        }
        if let Some(country) = &self.country {
            name.append_entry_by_nid(Nid::COUNTRYNAME, country)?;
        }
        if let Some(locality) = &self.locality {
            name.append_entry_by_nid(Nid::LOCALITYNAME, locality)?;
        }
        if let Some(state) = &self.state {
            name.append_entry_by_nid(Nid::STATEORPROVINCENAME, state)?;
        }

        let name = name.build();

        let mut req = X509Req::builder()?;
        req.set_subject_name(&name)?;
        req.set_pubkey(&key_pair.pri_key)?;
        req.sign(&key_pair.pri_key, openssl::hash::MessageDigest::sha256())?;

        Ok(req.build())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{key_pair::KeyPair, storage::MemStorage};
    use openssl::nid::Nid;

    fn generate_test_keypair() -> KeyPair {
        KeyPair::new(&MemStorage::new(), "RSA", None).unwrap()
    }

    #[test]
    fn test_basic_csr_creation() {
        let key_pair = generate_test_keypair();
        let csr = CSR::new("example.com").unwrap().build(&key_pair).unwrap();

        let subject = csr.subject_name();
        let cn_entry = subject.entries_by_nid(Nid::COMMONNAME).next().unwrap();
        assert_eq!(
            cn_entry.data().as_utf8().unwrap().to_string(),
            "example.com"
        );

        let pub_key = key_pair.pub_key;
        assert!(csr.verify(&pub_key).unwrap());
    }

    #[test]
    fn test_full_csr_creation() {
        let key_pair = generate_test_keypair();
        let csr = CSR::new("example.com")
            .unwrap()
            .organization("ACME Corp")
            .country("US")
            .locality("San Francisco")
            .state("CA")
            .build(&key_pair)
            .unwrap();

        let subject = csr.subject_name();

        let verify_field = |nid, expected| {
            assert_eq!(
                subject
                    .entries_by_nid(nid)
                    .next()
                    .unwrap()
                    .data()
                    .as_utf8()
                    .unwrap()
                    .to_string(),
                expected
            );
        };

        verify_field(Nid::ORGANIZATIONNAME, "ACME Corp");
        verify_field(Nid::COUNTRYNAME, "US");
        verify_field(Nid::LOCALITYNAME, "San Francisco");
        verify_field(Nid::STATEORPROVINCENAME, "CA");

        let pub_key = key_pair.pub_key;
        assert!(csr.verify(&pub_key).unwrap());
    }

    #[test]
    fn test_optional_fields_omitted() {
        let key_pair = generate_test_keypair();
        let csr = CSR::new("example.com").unwrap().build(&key_pair).unwrap();

        let subject = csr.subject_name();

        assert!(subject
            .entries_by_nid(Nid::ORGANIZATIONNAME)
            .next()
            .is_none());
        assert!(subject.entries_by_nid(Nid::COUNTRYNAME).next().is_none());
        assert!(subject.entries_by_nid(Nid::LOCALITYNAME).next().is_none());
        assert!(subject
            .entries_by_nid(Nid::STATEORPROVINCENAME)
            .next()
            .is_none());
    }

    #[test]
    fn test_invalid_common_name() {
        let key_pair = generate_test_keypair();
        let result = CSR::new("").unwrap().build(&key_pair);

        assert!(result.is_err());
    }

    #[test]
    fn test_csr_signature_with_wrong_key() {
        let key_pair1 = generate_test_keypair();
        let key_pair2 = generate_test_keypair();

        let csr = CSR::new("example.com").unwrap().build(&key_pair1).unwrap();

        let wrong_pub_key = key_pair2.pub_key;
        assert!(!csr.verify(&wrong_pub_key).unwrap());
    }
}
