use serde_derive::{Deserialize, Serialize};
use thiserror::Error;

use crate::keys::PublicKey;
use crate::methods::{resolve_did_web, DidMethod};

#[derive(Error, Debug, PartialEq)]
pub enum DidResolveError {
    #[error("the provided did is not supported. Only did:web is supported")]
    DidNotSupported,
    #[error("a http error occured while trying to read the did")]
    HttpError(u16, String),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DidDoc {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<PublicKey>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub authentication: Vec<PublicKey>,
    #[serde(
        rename = "capabilityInvocation",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub capability_invocation: Vec<PublicKey>,
    #[serde(
        rename = "capabilityDelegation",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub capability_delegation: Vec<PublicKey>,
    #[serde(
        rename = "assertionMethod",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub assertion_method: Vec<PublicKey>,
}

pub struct Did {
    pub parts: Vec<String>,
    method: DidMethod,
}

impl Did {
    pub fn new(text: String) -> Self {
        let mut method = DidMethod::UNKOWN;
        let splitted_did: Vec<String> = text.split(":").map(|x| x.to_string()).collect();

        if splitted_did[0] == "did" && splitted_did[1] == "web" {
            method = DidMethod::WEB;
        }

        return Did {
            parts: splitted_did,
            method: method,
        };
    }

    pub fn resolve(&self) -> Result<DidDoc, DidResolveError> {
        match self.method {
            DidMethod::WEB => resolve_did_web(self),
            DidMethod::UNKOWN => Err(DidResolveError::DidNotSupported),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::did::DidResolveError;

    use super::Did;

    #[test]
    fn resolve() {
        let did_url = "did:web:gist.githubusercontent.com:bit-jniestroj:7fb3cce550db5a239b543035298429fe:raw:5e5540c6f67ffe30cca2dfc4bb950a68f412c406";

        let did = Did::new(did_url.to_string());

        did.resolve().unwrap();
    }

    #[test]
    fn resolve_did_jwk() {
        let did_url = "did:jwk:ansjdasd";

        let did = Did::new(did_url.to_string());

        let resolved = did.resolve();

        assert_eq!(resolved.is_err(), true);
        assert_eq!(resolved.err().unwrap(), DidResolveError::DidNotSupported);
    }

    #[test]
    fn resolve_did_wrong_url() {
        let did_url = "did:web:example.com";

        let did = Did::new(did_url.to_string());

        let resolved = did.resolve();

        assert_eq!(resolved.is_err(), true);
        assert_eq!(
            resolved.err().unwrap(),
            DidResolveError::HttpError(404, "HTTP status client error (404 Not Found) for url (https://example.com/.well-known/did.json)".to_string())
        );
    }
}
