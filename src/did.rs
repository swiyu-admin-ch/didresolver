use std::fmt::{Display, Formatter};
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use didtoolbox::did_tdw::{TrustDidWeb};
use thiserror::Error;
use crate::methods::{resolve_did_tdw};
use didtoolbox::didtoolbox::DidDoc;
use ssi::dids::{DIDBuf as SSIDIDSBuf, DIDMethod as SSIDIDSDIDMethod};
use strum::{Display as EnumDisplay, AsRefStr as EnumAsRefStr, EnumString};

#[derive(Error, Debug, PartialEq)]
pub enum DidResolveError {
    #[error("the provided did is not supported. Only did:web and did:tdw are supported: {0}")]
    DidNotSupported(String),
    #[error("the supplied did log is invalid: {0}")]
    InvalidDidLog(String),
}

impl DidResolveError {
    /// Returns the error kind.
    pub fn kind(&self) -> DidResolveErrorKind {
        match self {
            Self::DidNotSupported(_) => DidResolveErrorKind::DidNotSupported,
            Self::InvalidDidLog(_) => DidResolveErrorKind::InvalidDidLog,
        }
    }
}

/// DidResolveError kind.
///
/// Each [`DidResolveError`] variant has a kind provided by the [`DidResolveErrorKind::kind`] method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DidResolveErrorKind {
    DidNotSupported,
    InvalidDidLog,
}

#[derive(Debug, PartialEq, Default, EnumDisplay, EnumAsRefStr)]
pub enum DidMethod {
    #[strum(to_string = "tdw", serialize = "tdw")]
    TDW,
    #[default]
    UNKNOWN,
}

#[derive(Debug, Default, PartialEq)]
// TODO This struct resembles the ssi::dids::DID, which is a way more advanced, so refactoring would be perhaps a good idea.
pub struct Did {
    pub parts: Vec<String>,
    method: DidMethod,
    method_id: String,
}

impl Did {
    pub fn new(text: String) -> Self {
        match Self::try_from(text.to_owned()) {
            Ok(did) => did,
            _ => {
                Did { // fallback
                    parts: text.split(":").map(|x| x.to_string()).collect(),
                    method: DidMethod::default(),
                    method_id: text.split(":").skip(2).map(|x| x.to_string()).collect(),
                }
            }
        }
    }

    pub fn resolve(&self, did_log_raw: String) -> Result<Arc<DidDoc>, DidResolveError> {
        let res = match self.method {
            DidMethod::TDW => resolve_did_tdw(self, did_log_raw),
            DidMethod::UNKNOWN => Err(DidResolveError::DidNotSupported(String::new())),
        };
        match res {
            Ok(doc) => Ok(Arc::new(doc)),
            Err(e) => Err(e),
        }
    }
}

/// This implementation reconstructs the original (textual) DID, regardless of its validity.
impl Display for Did {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.parts.join(":"))
    }
}

/// Implementation for a string denoting a did.
impl TryFrom<String> for Did {
    type Error = DidResolveError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match SSIDIDSBuf::try_from(value.to_owned()) {
            Ok(buf) => {
                if !buf.method_name().starts_with(TrustDidWeb::DID_METHOD_NAME) { // the single currently supported
                    return Err(DidResolveError::DidNotSupported(buf.method_name().to_owned()));
                };

                let method_specific_id = buf.method_specific_id().to_string();

                Ok(Did {
                    parts: buf.split(":").map(|x| x.to_string()).collect(),
                    method: DidMethod::TDW,
                    method_id: method_specific_id,
                })
            }
            Err(_e) => {
                //eprintln!("{_e}");
                Err(DidResolveError::DidNotSupported(value))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use crate::did::{DidMethod, DidResolveError, DidResolveErrorKind};
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

    #[rstest]
    // CAUTION A did_url (param #2) MUST match the one residing in did_log_raw_filepath (param #1)
    #[case("test_data/did.jsonl", "did:tdw:E18kSmXiyfjSQfZgNdNnXi9JN7WADEfZycWvYXAu7VXAYso4CvifyEma7D3yhv7bmZ3cYHzgEQQTLq7rfuF7HjiY2fAi3:127.0.0.1%3A61646:123456789"
    )]
    // TODO Remove the should_panic attribute as soon as the error handling is properly done in didtoolbox
    #[should_panic(expected = "Invalid did log. No entries found")]
    fn resolve_did_tdw_invalid_did_log(#[case] _did_log_raw_filepath: String, #[case] did_url: String) {
        let did = Did::new(did_url.to_string());

        match did.resolve(String::new()) {
            Err(e) => assert_eq!(e.kind(), DidResolveErrorKind::InvalidDidLog),
            _ => (),
        }
    }

    #[rstest]
    #[case("did:jwk:not_yet_supported")]
    #[case("did:web:not_yet_supported")]
    #[case("completely_irregular_did")]
    fn did_not_supported(#[case] did_url: String) {
        let did = Did::new(did_url.to_owned());

        assert!(did.parts.len() > 0); // assuming none of the "#[rstest]" cases is empty
        assert_eq!(did.to_string(), did_url); // assuming the Display trait is implemented accordingly for DID struct
        assert_eq!(did.method, DidMethod::default());
        assert!(did_url.ends_with(did.method_id.as_str()));
    }

    #[rstest]
    #[case("did:jwk:not_yet_supported")]
    #[case("did:web:not_yet_supported")]
    fn resolve_did_not_supported(#[case] did_url: String) {

        // Actual DID log is pretty irrelevant for the test, so empty string would suffice
        let resolved = Did::new(did_url).resolve(String::new());

        assert_eq!(resolved.is_err(), true);
        assert_eq!(resolved.err().unwrap(), DidResolveError::DidNotSupported(String::new()));
    }
}
