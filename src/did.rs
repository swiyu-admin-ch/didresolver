// SPDX-License-Identifier: MIT
use std::sync::Arc;
use thiserror::Error;
use crate::methods::{resolve_did_tdw, resolve_did_web, DidMethod};
use didtoolbox::didtoolbox::DidDoc;

#[derive(Error, Debug, PartialEq)]
pub enum DidResolveError {
    #[error("the provided did is not supported. Only did:web and did:tdw are supported: {0}")]
    DidNotSupported(String),
    #[error("the supplied did log is invalid: {0}")]
    InvalidDidLog(String),
    #[error("a http error occurred while trying to read the did")]
    HttpError(u16, String),
}
pub struct Did {
    pub parts: Vec<String>,
    method: DidMethod,
}

impl Did {
    pub fn new(text: String) -> Self {
        let mut method = DidMethod::UNKNOWN;
        let splitted_did: Vec<String> = text.split(":").map(|x| x.to_string()).collect();

        if splitted_did[0] == "did" {
            method = match splitted_did[1].as_str() {
                "web" => DidMethod::WEB,
                "tdw" => DidMethod::TDW,
                _ => DidMethod::UNKNOWN,
            };
        }

        return Did {
            parts: splitted_did,
            method: method,
        };
    }

    pub fn resolve(&self, did_log_raw: String) -> Result<Arc<DidDoc>, DidResolveError> {
        let res = match self.method {
            DidMethod::WEB => resolve_did_web(self),
            DidMethod::TDW => resolve_did_tdw(self, did_log_raw),
            DidMethod::UNKNOWN => Err(DidResolveError::DidNotSupported(String::new())),
        };
        match res {
            Ok(doc) => Ok(Arc::new(doc)),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use crate::did::DidResolveError;
    use super::Did;
    use minify::json::minify;
    use rstest::{fixture, rstest};

    #[rstest]
    // CAUTION A did_url (param #2) MUST match the one residing in did_log_raw_filepath (param #1)
    #[case("test_data/did.jsonl", "did:tdw:E18kSmXiyfjSQfZgNdNnXi9JN7WADEfZycWvYXAu7VXAYso4CvifyEma7D3yhv7bmZ3cYHzgEQQTLq7rfuF7HjiY2fAi3:127.0.0.1%3A61646:123456789"
    )]
    fn resolve_did_tdw(#[case] did_log_raw_filepath: String, #[case] did_url: String) {
        let did = Did::new(did_url.to_string());

        let did_log_raw = minify(fs::read_to_string(Path::new(&did_log_raw_filepath)).unwrap().as_str());

        let did_doc = did.resolve(did_log_raw).unwrap();
        assert_eq!(did_doc.id, did_url);
    }

    #[test]
    fn resolve() {
        // did.json is available at https://gist.github.com/bit-jniestroj/7fb3cce550db5a239b543035298429fe
        let did_url = "did:web:gist.githubusercontent.com:bit-jniestroj:7fb3cce550db5a239b543035298429fe:raw:5e5540c6f67ffe30cca2dfc4bb950a68f412c406";

        let did = Did::new(did_url.to_string());

        did.resolve(String::new()).unwrap();
    }

    #[test]
    fn resolve_bbs() {
        // did.json is available at https://gist.github.com/bit-jniestroj/f23a80ba382f94fdb93436424f6e4e01
        let did_url = "did:web:gist.githubusercontent.com:bit-jniestroj:f23a80ba382f94fdb93436424f6e4e01:raw:d1bfa1f6c0bfee7687e9fc4ca6f86c2340c6b6f5";

        let did = Did::new(did_url.to_string());

        did.resolve(String::new()).unwrap();
    }

    #[test]
    fn resolve_did_jwk() {
        let did_url = "did:jwk:ansjdasd";

        let did = Did::new(did_url.to_string());

        // DID doc log is actually irrelevant for the test
        let resolved = did.resolve(String::new());

        assert_eq!(resolved.is_err(), true);
        assert_eq!(resolved.err().unwrap(), DidResolveError::DidNotSupported(String::new()));
    }

    #[test]
    fn resolve_did_wrong_url() {
        let did_url = "did:web:example.com";

        let did = Did::new(did_url.to_string());

        // DID doc log is actually irrelevant for the test
        let resolved = did.resolve(String::new());

        assert_eq!(resolved.is_err(), true);
        assert_eq!(
            resolved.err().unwrap(),
            DidResolveError::HttpError(404, "HTTP status client error (404 Not Found) for url (https://example.com/.well-known/did.json)".to_string())
        );
    }
}
