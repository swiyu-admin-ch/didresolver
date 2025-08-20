// SPDX-License-Identifier: MIT

use crate::methods::resolve_did_log;
use did_sidekicks::did_doc::DidDoc;
use did_tdw::did_tdw::TrustDidWebId;
use did_webvh::did_webvh::WebVerifiableHistoryId;
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use strum::{AsRefStr as EnumAsRefStr, Display as EnumDisplay};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum DidResolveError {
    #[error("the provided did is not supported. Only did:tdw are supported: {0}")]
    DidNotSupported(String),
    #[error("the supplied did is supported, but is malformed: {0}")]
    MalformedDid(String),
    #[error("the supplied did log is invalid: {0}")]
    InvalidDidLog(String),
}

impl DidResolveError {
    /// Returns the error kind.
    pub fn kind(&self) -> DidResolveErrorKind {
        match self {
            Self::DidNotSupported(_) => DidResolveErrorKind::DidNotSupported,
            Self::InvalidDidLog(_) => DidResolveErrorKind::InvalidDidLog,
            Self::MalformedDid(_) => DidResolveErrorKind::MalformedDid,
        }
    }
}

/// DidResolveError kind.
///
/// Each [`DidResolveError`] variant has a kind provided by the [`DidResolveErrorKind::kind`] method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DidResolveErrorKind {
    DidNotSupported,
    MalformedDid,
    InvalidDidLog,
}

#[derive(Debug, PartialEq, Default, EnumDisplay, EnumAsRefStr)]
pub enum DidMethod {
    #[strum(to_string = "tdw", serialize = "tdw")]
    TDW,
    #[strum(to_string = "webvh", serialize = "webvh")]
    WEBVH,
    #[default]
    UNKNOWN,
}

#[derive(Debug, Default, PartialEq)]
// This struct resembles the ssi::dids::DID, which is a way more advanced
pub struct Did {
    pub parts: Vec<String>,
    method: DidMethod,
    method_id: String,
}

impl Did {
    const DID: &'static str = "did";

    /// A UniFFI-compliant constructor.
    pub fn new(did_tdw: String) -> Result<Self, DidResolveError> {
        Self::try_from(did_tdw.to_owned())
    }

    /// Returns the url part from the supplied DID, if supported and not malformed.
    pub fn get_url(&self) -> Result<String, DidResolveError> {
        match self.method {
            DidMethod::TDW => match TrustDidWebId::parse_did_tdw(self.to_string()) {
                Ok(doc) => Ok(doc.get_url()),
                Err(e) => Err(DidResolveError::MalformedDid(e.to_string())),
            },
            DidMethod::WEBVH => match WebVerifiableHistoryId::parse_did_webvh(self.to_string()) {
                Ok(doc) => Ok(doc.get_url()),
                Err(e) => Err(DidResolveError::MalformedDid(e.to_string())),
            },
            DidMethod::UNKNOWN => Err(DidResolveError::DidNotSupported(String::new())),
        }
    }

    pub fn get_method(&self) -> &DidMethod {
        &self.method
    }

    pub fn resolve(&self, did_log_raw: String) -> Result<Arc<DidDoc>, DidResolveError> {
        resolve_did_log(self, did_log_raw)
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
        let did_split: Vec<&str> = value.splitn(4, ":").collect();
        if did_split.len() < 4 {
            return Err(DidResolveError::MalformedDid(value));
        };

        if did_split[0] != Self::DID {
            return Err(DidResolveError::DidNotSupported(value));
        }

        match did_split[1] {
            TrustDidWebId::DID_METHOD_NAME => {
                match TrustDidWebId::parse_did_tdw(value.to_owned()) {
                    Ok(buf) => {
                        let scid = buf.get_scid();
                        Ok(Did {
                            parts: did_split.into_iter().map(|v| v.to_string()).collect(),
                            method: DidMethod::TDW,
                            method_id: scid,
                        })
                    }
                    Err(_e) => Err(DidResolveError::MalformedDid(value)),
                }
            }
            WebVerifiableHistoryId::DID_METHOD_NAME => {
                match WebVerifiableHistoryId::parse_did_webvh(value.to_owned()) {
                    Ok(buf) => {
                        let scid = buf.get_scid();
                        Ok(Did {
                            parts: did_split.into_iter().map(|v| v.to_string()).collect(),
                            method: DidMethod::WEBVH,
                            method_id: scid,
                        })
                    }
                    Err(_e) => Err(DidResolveError::MalformedDid(value)),
                }
            }
            _ => Err(DidResolveError::DidNotSupported(value)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Did;
    use crate::did::DidResolveErrorKind;
    use did_sidekicks::did_doc::VerificationType;
    use rstest::{fixture, rstest};
    use std::fs;
    use std::path::Path;

    // For testing purposes only.
    struct HttpClient;
    impl HttpClient {
        /// May panic
        fn fetch_url(&self, url: String) -> String {
            match ureq::get(&url).call() {
                Ok(response) => match response.into_body().read_to_string() {
                    Ok(body) => body,
                    Err(e) => panic!("{e}"),
                },
                Err(e) => panic!("{e}"),
            }
        }
    }

    #[fixture]
    #[once]
    fn http_client() -> HttpClient {
        HttpClient {}
    }

    #[rstest]
    #[case(
        "did:tdw:QmRjT8JCbQkEffVBWSbQd8nbMVNfAxiXStLPmqkQUWcsfv:gist.githubusercontent.com:vst-bit:32b64cfac9075b2a3ab7301b772bcdef:raw:4775dd76799b35e99322bf738fafd6c10f421ed7"
    )]
    #[case(
        "did:tdw:QmRjT8JCbQkEffVBWSbQd8nbMVNfAxiXStLPmqkQUWcsfv:gist.githubusercontent.com:vst-bit:32b64cfac9075b2a3ab7301b772bcdef:raw:4775dd76799b35e99322bf738fafd6c10f421ed7"
    )]
    fn test_resolve_did_tdw(
        #[case] did_tdw: String,
        http_client: &HttpClient, // fixture
    ) -> Result<(), Box<dyn std::error::Error>> {
        let did = Did::new(did_tdw)?; // no error expected here

        let url = did.get_url();
        assert!(url.is_ok());
        let url = url.unwrap();
        assert!(!url.is_empty());

        let did_log_raw = http_client.fetch_url(url);
        assert!(!did_log_raw.is_empty());

        let res = did.resolve(did_log_raw);
        assert!(res.is_ok(), "ERROR: {:?}", res.err().unwrap());
        let did_doc = res.unwrap();

        // CAUTION Such assertions are not really possible when using GitHub gists as input
        //         assert_eq!(did_doc.get_id(), did.to_string()); // assuming the Display trait is implemented accordingly for DID struct
        //         assert!(did.to_string().contains(did_doc.get_id().as_str())); // assuming the Display trait is implemented accordingly for DID struct

        assert!(!did_doc.get_context().is_empty());
        assert!(!did_doc.get_verification_method().is_empty());
        did_doc.get_verification_method().iter().for_each(|method| {
            assert_eq!(method.verification_type, VerificationType::JsonWebKey2020);
            assert!(method.public_key_jwk.is_some());
        });
        assert!(!did_doc.get_authentication().is_empty());
        assert!(!did_doc.get_assertion_method().is_empty());

        Ok(())
    }

    #[rstest]
    // CAUTION A did_tdw (param #2) MUST match the one residing in did_log_raw_filepath (param #1)
    #[case(
        "test_data/did.jsonl",
        "did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    #[case(
        "test_data/did_without_controller.jsonl",
        "did:tdw:QmYD2gdyU1opYus5bJSoJr4c78mgctJnGHRsgqPv9NoLBh:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    fn test_resolve_did_tdw_from_file(
        #[case] did_log_raw_filepath: String,
        #[case] did_tdw: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let did = Did::new(did_tdw.to_string())?; // no error expected here

        let did_log_raw = fs::read_to_string(Path::new(&did_log_raw_filepath));
        assert!(did_log_raw.is_ok());
        let did_log_raw = did_log_raw.unwrap();

        let res = did.resolve(did_log_raw);
        assert!(res.is_ok(), "ERROR: {:?}", res.err().unwrap());
        let did_doc = res.unwrap();
        assert_eq!(did_doc.id, did_tdw);

        //assert_eq!(did_doc.get_id(), did.to_string()); // assuming the Display trait is implemented accordingly for DID struct
        assert!(did.to_string().contains(did_doc.get_id().as_str())); // assuming the Display trait is implemented accordingly for DID struct
        assert!(!did_doc.get_context().is_empty());
        assert!(!did_doc.get_verification_method().is_empty());
        assert!(!did_doc.get_authentication().is_empty());

        Ok(())
    }

    #[rstest]
    // CAUTION A did_tdw (param #2) MUST match the one residing in did_log_raw_filepath (param #1)
    #[case("test_data/did.jsonl", "did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    fn test_resolve_did_tdw_invalid_did_log_no_entries(
        #[case] _did_log_raw_filepath: String,
        #[case] did_tdw: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let did = Did::new(did_tdw.to_string())?; // no error expected here

        let res = did.resolve(String::new()); // empty string
        assert!(res.is_err(), "ERROR: {:?}", res.err().unwrap());
        assert_eq!(res.unwrap_err().kind(), DidResolveErrorKind::InvalidDidLog); // panic-safe unwrap call (see the previous line)

        Ok(())
    }

    #[rstest]
    // CAUTION A did_tdw (param #2) MUST match the one residing in did_log_raw_filepath (param #1)
    #[case(
        "test_data/non_incremented_version_did.jsonl",
        "did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    fn test_resolve_did_tdw_invalid_did_log_non_incremented_version(
        #[case] did_log_raw_filepath: String,
        #[case] did_tdw: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let did = Did::new(did_tdw.to_string())?; // no error expected here

        let did_log_raw = fs::read_to_string(Path::new(&did_log_raw_filepath));
        assert!(did_log_raw.is_ok());
        let did_log_raw = did_log_raw.unwrap();

        let res = did.resolve(did_log_raw); // panic-safe unwrap call (see above)
        assert!(res.is_err());
        let err = res.unwrap_err(); // panic-safe unwrap call (see the previous line)
        assert_eq!(err.kind(), DidResolveErrorKind::InvalidDidLog);
        assert!(err
            .to_string()
            .contains("Version numbers (`versionId`) must be in a sequence of positive consecutive integers"),
                "ERROR: {:?}", err);

        Ok(())
    }

    #[rstest]
    #[case("did:jwk:did_method_not_yet_supported:my_domain")]
    #[case("did:web:did_method_not_yet_supported:my_domain")]
    #[case("did:XYZ:did_method_does_not_exist_at_all:my_domain")]
    fn test_did_not_supported(#[case] did_tdw: String) {
        let did = Did::new(did_tdw.to_owned());

        assert!(did.is_err());
        assert_eq!(
            did.unwrap_err().kind(), // panic-safe unwrap call (see the previous line)
            DidResolveErrorKind::DidNotSupported
        );
    }

    #[rstest]
    #[case("did:tdw:QMySCID:domain")]
    #[case("did:tdw:QMySCID:domain:path")]
    #[case("did:tdw:Q24hsDDvpZHmUyNwXWgy36jhB6SFMLT2Aq7HWmZSk6XyZaM7qJNPNYthtRwtz84GHX3Bui3ZSVCcrG8KvGracfbhC:127.0.0.1%3A52788:123456789")]
    fn test_did_ok(#[case] did_tdw: String) -> Result<(), Box<dyn std::error::Error>> {
        let did = Did::new(did_tdw.to_owned())?; // no error expected here
        let did = did.get_url();

        assert!(did.is_ok());
        assert!(!did.unwrap().is_empty()); // panic-safe unwrap call (see the previous line)

        Ok(())
    }

    #[rstest]
    #[case("did:tdw:malformed::::::")]
    #[case("did:tdw:malformed")]
    #[case("did:tdw:identifier#key01")]
    fn test_did_malformed(#[case] did_tdw: String) {
        let did = Did::new(did_tdw.to_owned());

        assert!(did.is_err());
        assert_eq!(did.unwrap_err().kind(), DidResolveErrorKind::MalformedDid); // panic-safe unwrap call (see the previous line)
    }
}
