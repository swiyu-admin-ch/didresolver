// SPDX-License-Identifier: MIT

use crate::methods::resolve_did_tdw;
use didtoolbox::did_tdw::TrustDidWebId;
use didtoolbox::didtoolbox::DidDoc;
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use strum::{AsRefStr as EnumAsRefStr, Display as EnumDisplay};
use thiserror::Error;
use url::Url;

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
            Err(e) => {
                let parts = text.split(":").map(|x| x.to_string()).collect();
                let _method: String = text
                    .split(":")
                    .skip(1)
                    .take(1)
                    .map(|x| x.to_string())
                    .collect();
                let method_id = text.split(":").skip(2).map(|x| x.to_string()).collect();
                match e.kind() {
                    DidResolveErrorKind::MalformedDid => Did {
                        // fallback
                        parts,
                        method: DidMethod::TDW, // TODO convert _method to DidMethod, if possible
                        method_id,
                    },
                    _ => Did {
                        // fallback
                        parts,
                        method: DidMethod::default(),
                        method_id,
                    },
                }
            }
        }
    }

    /// Returns the url part from the supplied DID, if supported and not malformed.
    pub fn get_url(&self) -> Result<String, DidResolveError> {
        let res = match self.method {
            DidMethod::TDW => TrustDidWebId::parse_did_tdw(self.to_string(), Some(false)),
            DidMethod::UNKNOWN => return Err(DidResolveError::DidNotSupported(String::new())),
        };
        match res {
            Ok(x) => Ok(x.get_url()),
            Err(e) => Err(DidResolveError::MalformedDid(e.to_string())),
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
        match TrustDidWebId::parse_did_tdw(value.to_owned(), Some(true)) {
            Ok(buf) => {
                let url = buf.get_url();
                let scid = buf.get_scid();

                let _ = match Url::parse(url.as_str()) {
                    Ok(u) => {
                        let mut host = u.host().unwrap().to_string();
                        let port = u.port_or_known_default().unwrap_or_default();
                        if port > 0 {
                            host.push_str("%3A");
                            host.push_str(port.to_string().as_str());
                        };
                        let path = u.path();
                        let path_sanitized =
                            path[1..path.len()].replace("/did.jsonl", "").to_owned();
                        let mut path_parts: Vec<String> =
                            path_sanitized.split(":").map(|x| x.to_string()).collect();

                        let mut parts =
                            vec!["did".to_string(), "tdw".to_string(), scid.to_owned(), host];
                        parts.append(&mut path_parts);

                        Ok(Did {
                            parts,
                            method: DidMethod::TDW,
                            method_id: scid,
                        })
                    }
                    Err(_e) => {
                        //eprintln!("{_e}");
                        Err(DidResolveError::MalformedDid(value.to_owned()))
                    }
                };

                Err(DidResolveError::MalformedDid(value))
            }
            Err(_e) => {
                //eprintln!("{_e}");
                Err(DidResolveError::MalformedDid(value))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Did;
    use crate::did::DidResolveErrorKind;
    use mockito::{Matcher, Server, ServerOpts};
    use rstest::{fixture, rstest};
    use std::fs;
    use std::path::Path;
    use ureq::get as get_url;

    // For testing purposes only.
    struct HttpClient;
    impl HttpClient {
        /// May panic
        fn fetch_url(&self, url: String) -> String {
            match get_url(&url).call() {
                Ok(response) => match response.into_string() {
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

    // For testing purposes only. Offers everything a test may need.
    struct TdwMock {
        did: String,
        _server: Server, // CAUTION Must be in the struct, otherwise 501 (server) error status is returned
    }
    impl TdwMock {
        pub fn new() -> Self {
            let mut server = Server::new_with_opts(ServerOpts {
                port: 54858, // CAUTION Must match the one residing in the test data file
                ..Default::default()
            });

            let url = format!("{}/123456789/did.jsonl", server.url());
            let did_log_raw_filepath = "test_data/did_2.jsonl";
            // CAUTION Must match the one residing in the test data file
            let did = String::from("did:tdw:QmUSyQohHF4tcRhdkJYoamuMQAXQmYBoFLCot35xd7dPda:127.0.0.1%3A54858:123456789");

            // To setup the GET mock, just load did_log (as body) from the test dats file
            server
                .mock(
                    "GET",
                    Matcher::Regex(r"/[a-z0-9=]+/did.jsonl$".to_string()),
                    //Matcher::Any,
                )
                .with_body_from_file(Path::new(did_log_raw_filepath))
                .create();

            // Smoke test
            let http_client = http_client();
            let _did_log = http_client.fetch_url(url.to_owned());
            //println!("{_did_log}");

            TdwMock {
                did,
                _server: server,
            }
        }

        pub fn get_did(&self) -> String {
            self.did.to_owned()
        }
    }

    #[fixture]
    #[once]
    fn tdw_mock() -> TdwMock {
        TdwMock::new()
    }

    #[rstest]
    fn resolve_did_tdw_via_mock(
        tdw_mock: &TdwMock,       // fixture
        http_client: &HttpClient, // fixture
    ) {
        let did = Did::new(tdw_mock.get_did());

        let url = did.get_url();
        assert!(url.is_ok());
        let url = url.unwrap();
        assert!(!url.is_empty());

        let did_log_raw = http_client.fetch_url(url);
        assert!(!did_log_raw.is_empty());

        let did_doc = did.resolve(did_log_raw);
        assert!(did_doc.is_ok());
        let did_doc = did_doc.unwrap();

        assert_eq!(did_doc.get_id(), did.to_string()); // assuming the Display trait is implemented accordingly for DID struct
        assert!(!did_doc.get_context().is_empty());
        assert!(!did_doc.get_verification_method().is_empty());
        assert!(!did_doc.get_authentication().is_empty());
        assert!(!did_doc.get_assertion_method().is_empty());
    }

    #[rstest]
    // CAUTION A did_url (param #2) MUST match the one residing in did_log_raw_filepath (param #1)
    #[case(
        "test_data/tdw-js.jsonl",
        "did:tdw:Qmb4sce9qf13cwcosaDfRt2NmWpUfqHAdpVfRUCN8gtB8G:example.com"
    )]
    fn test_resolve_did_tdw(#[case] did_log_raw_filepath: String, #[case] did_url: String) {
        let did = Did::new(did_url.to_string());

        let did_log_raw = fs::read_to_string(Path::new(&did_log_raw_filepath));
        assert!(did_log_raw.is_ok());
        let did_log_raw = did_log_raw.unwrap();

        let did_doc = did.resolve(did_log_raw);
        assert!(did_doc.is_ok());
        let did_doc = did_doc.unwrap();
        assert_eq!(did_doc.id, did_url);

        assert_eq!(did_doc.get_id(), did.to_string()); // assuming the Display trait is implemented accordingly for DID struct
        assert!(!did_doc.get_context().is_empty());
        assert!(!did_doc.get_verification_method().is_empty());
        assert!(!did_doc.get_authentication().is_empty());
    }

    #[rstest]
    // CAUTION A did_url (param #2) MUST match the one residing in did_log_raw_filepath (param #1)
    #[case("test_data/did.jsonl", "did:tdw:Q24hsDDvpZHmUyNwXWgy36jhB6SFMLT2Aq7HWmZSk6XyZaM7qJNPNYthtRwtz84GHX3Bui3ZSVCcrG8KvGracfbhC:127.0.0.1%3A52788:123456789"
    )]
    // TODO Remove the should_panic attribute as soon as the error handling is properly done in didtoolbox
    #[should_panic(expected = "Invalid did log. No entries found")]
    fn resolve_did_tdw_invalid_did_log_no_entries(
        #[case] _did_log_raw_filepath: String,
        #[case] did_url: String,
    ) {
        let did = Did::new(did_url.to_string());

        /*
        match did.resolve(String::new()) { // empty string
            Err(e) => assert_eq!(e.kind(), DidResolveErrorKind::InvalidDidLog),
            _ => (),
        }
         */

        did.resolve(String::new()).unwrap(); // empty string
    }

    #[rstest]
    // CAUTION A did_url (param #2) MUST match the one residing in did_log_raw_filepath (param #1)
    #[case(
        "test_data/non_incremented_version_did.jsonl",
        "did:tdw:Qmb4sce9qf13cwcosaDfRt2NmWpUfqHAdpVfRUCN8gtB8G:example.com"
    )]
    // TODO Remove the should_panic attribute as soon as the error handling is properly done in didtoolbox
    #[should_panic(expected = "Invalid did log for version 2. Version id has to be incremented")]
    fn resolve_did_tdw_invalid_did_log_non_incremented_version(
        #[case] did_log_raw_filepath: String,
        #[case] did_url: String,
    ) {
        let did = Did::new(did_url.to_string());

        let did_log_raw = fs::read_to_string(Path::new(&did_log_raw_filepath));
        assert!(did_log_raw.is_ok());
        let did_log_raw = did_log_raw.unwrap();

        did.resolve(did_log_raw).unwrap();
    }

    #[rstest]
    #[case("did:jwk:not_yet_supported")]
    #[case("did:web:not_yet_supported")]
    #[case("completely_irregular_did")]
    fn did_not_supported(#[case] did_url: String) {
        let did = Did::new(did_url.to_owned());

        assert!(!did.parts.is_empty()); // assuming none of the "#[rstest]" cases is empty
        assert_eq!(did.to_string(), did_url); // assuming the Display trait is implemented accordingly for DID struct
                                              //assert_eq!(did.method, DidMethod::default());
        assert!(did_url.ends_with(did.method_id.as_str()));
    }

    #[rstest]
    #[case("did:jwk:not_yet_supported")]
    #[case("did:web:not_yet_supported")]
    fn resolve_did_not_supported(#[case] did_url: String) {
        // Actual DID log is pretty irrelevant for the test, so empty string would suffice
        let resolved = Did::new(did_url).resolve(String::new());

        assert!(resolved.is_err());
        assert_eq!(
            resolved.err().unwrap().kind(),
            DidResolveErrorKind::DidNotSupported
        );
    }

    #[rstest]
    #[case("did:tdw:QMySCID:domain")]
    #[case("did:tdw:QMySCID:domain:path")]
    #[case("did:tdw:Q24hsDDvpZHmUyNwXWgy36jhB6SFMLT2Aq7HWmZSk6XyZaM7qJNPNYthtRwtz84GHX3Bui3ZSVCcrG8KvGracfbhC:127.0.0.1%3A52788:123456789")]
    fn did_ok(#[case] did_url: String) {
        let did = Did::new(did_url.to_owned());
        let did = did.get_url();

        assert!(did.is_ok());
        assert!(!did.unwrap().is_empty());
    }

    #[rstest]
    #[case("did:tdw:malformed::::::")]
    #[case("did:tdw:malformed")]
    #[case("did:tdw:identifier#key01")]
    #[case("did:tdw:grsgcnzqgfstsmbsgbstsmzzgy2diolgheztayzwme4tgzrxmnrtqoddmy2wkzjwgm4tgyjumntgmzrthezggnbwmjstgzjug42tioa=:identifier-data-service-r.bit.admin.ch:api:v1:did:62c3d89f-2ab3-4129-ac1f-595a28c9115f")]
    #[should_panic(expected = "Invalid multibase format for SCID. base58btc identifier expected")]
    fn did_malformed(#[case] did_url: String) {
        let did = Did::new(did_url.to_owned());
        let _url = did.get_url();

        //assert!(url.is_err());
        //assert_eq!(url.err().unwrap().kind(), DidResolveErrorKind::MalformedDid);
    }
}
