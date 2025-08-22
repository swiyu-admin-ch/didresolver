// SPDX-License-Identifier: MIT

use did_sidekicks::did_doc::DidDoc;
use did_tdw::did_tdw::{TrustDidWeb, TrustDidWebId};
use did_webvh::did_webvh::{WebVerifiableHistory, WebVerifiableHistoryId};
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use strum::{AsRefStr as EnumAsRefStr, Display as EnumDisplay};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum DidResolveError {
    /// The supplied DID is not supported (currently supported are: did:tdw, did:webvh)
    #[error(
        "The supplied DID is not supported (currently supported are: did:tdw, did:webvh): {0}"
    )]
    DidNotSupported(String),
    /// The supplied DID is supported, but is malformed
    #[error("the supplied DID is supported, but is malformed: {0}")]
    MalformedDid(String),
    /// The supplied DID log is invalid
    #[error("the supplied DID log is invalid: {0}")]
    InvalidDidLog(String),
    /// The supplied DID log is valid, but it features invalid DID Doc
    #[error("the supplied DID log is valid, but it features invalid DID Doc: {0}")]
    InvalidDidDoc(String),
}

impl DidResolveError {
    /// Returns the error kind.
    pub fn kind(&self) -> DidResolveErrorKind {
        match self {
            Self::DidNotSupported(_) => DidResolveErrorKind::DidNotSupported,
            Self::InvalidDidLog(_) => DidResolveErrorKind::InvalidDidLog,
            Self::InvalidDidDoc(_) => DidResolveErrorKind::InvalidDidDoc,
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
    InvalidDidDoc,
}

#[derive(Debug, Clone, PartialEq, Default, EnumDisplay, EnumAsRefStr)]
pub enum DidMethod {
    #[strum(to_string = "tdw", serialize = "tdw")]
    TDW,
    #[strum(to_string = "webvh", serialize = "webvh")]
    WEBVH,
    #[default]
    UNKNOWN,
}

/// Represents a Decentralized Identifier (DID) in terms of DID Web + Verifiable History ([`did:webvh`](https://identity.foundation/didwebvh/v1.0))
/// that is an enhancement to the `did:web` DID method, providing complementary features
/// that address `did:web`’s limitations as a long-lasting DID.
///
/// Also, the legacy DID method [`did:tdw`](https://identity.foundation/didwebvh/v0.3) is supported as well.
#[derive(Debug, PartialEq)]
// This struct resembles the ssi::dids::DID, which is a way more advanced
pub struct Did {
    parts: Vec<String>,
    method: DidMethod,
    method_id: String,
    url: String,
}

impl Did {
    const DID: &'static str = "did";

    /// The single constructor of [`Did`] expecting a
    /// [DID method-specific identifier](https://identity.foundation/didwebvh/next/#method-specific-identifier) as either:
    /// - a [`did:tdw:0.3`   DID](https://identity.foundation/didwebvh/v0.3) or
    /// - a [`did:webvh:1.0` DID](https://identity.foundation/didwebvh/v1.0).
    ///
    /// The constructor will attempt to [*transform*](https://identity.foundation/didwebvh/next/#the-did-to-https-transformation)
    /// the supplied DID method identifier into a valid
    /// [RFC3986](https://www.rfc-editor.org/rfc/rfc3986)-conform HTTPS URL thus enabling retrival
    /// of its DID log (via an `HTTP GET`). In case of error, the available [`DidResolveError`]
    /// object features all the detailed information required to narrow down the root cause.
    ///
    /// A UniFFI-compliant constructor.
    pub fn new(did: String) -> Result<Self, DidResolveError> {
        Self::try_from(did.to_owned())
    }

    /// Returns the HTTP URL [*transformed*](https://identity.foundation/didwebvh/next/#the-did-to-https-transformation)
    /// from the DID supplied via constructor.
    ///
    /// A UniFFI-compliant method.
    #[deprecated(since = "2.2.0", note = "please use `get_http_url` instead")]
    pub fn get_url(&self) -> Result<String, DidResolveError> {
        Ok(self.get_https_url())
    }

    /// Returns the HTTPS URL [*transformed*](https://identity.foundation/didwebvh/next/#the-did-to-https-transformation)
    /// from the DID supplied via constructor.
    ///
    /// A UniFFI-compliant method.
    pub fn get_https_url(&self) -> String {
        self.url.clone()
    }

    pub fn get_parts(&self) -> Vec<String> {
        self.parts.clone()
    }

    pub fn get_method(&self) -> DidMethod {
        self.method.clone()
    }

    /// The essential method of [`Did`] implementing *Read (Resolve)* DID method operation for:
    /// - [a `did:tdw` DID](https://identity.foundation/didwebvh/v0.3/#read-resolve) as well as for
    /// - [a `did:webvh` DID](https://identity.foundation/didwebvh/v1.0/#read-resolve)
    ///
    /// In case of error, the available [`DidResolveError`] object features all the detailed
    /// information required to narrow down the root cause.
    ///
    /// A UniFFI-compliant method.
    pub fn resolve(&self, did_log: String) -> Result<Arc<DidDoc>, DidResolveError> {
        match self.method {
            DidMethod::TDW => match TrustDidWeb::read(self.to_string(), did_log) {
                Ok(tdw) => match tdw.get_did_doc_obj() {
                    Ok(doc) => Ok(doc),
                    Err(e) => Err(DidResolveError::InvalidDidDoc(e.to_string())),
                },
                Err(e) => Err(DidResolveError::InvalidDidLog(e.to_string())),
            },
            DidMethod::WEBVH => match WebVerifiableHistory::read(self.to_string(), did_log) {
                Ok(web_vh) => match web_vh.get_did_doc_obj() {
                    Ok(doc) => Ok(doc),
                    Err(e) => Err(DidResolveError::InvalidDidDoc(e.to_string())),
                },
                Err(e) => Err(DidResolveError::InvalidDidLog(e.to_string())),
            },
            DidMethod::UNKNOWN => Err(DidResolveError::DidNotSupported(String::new())),
        }
    }
}

/// This implementation reconstructs the original (textual) DID, regardless of its validity.
impl Display for Did {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.parts.join(":"))
    }
}

/// Implementation for a string denoting a DID.
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
                    Ok(buf) => Ok(Did {
                        parts: did_split.into_iter().map(|v| v.to_string()).collect(),
                        method: DidMethod::TDW,
                        method_id: buf.get_scid(),
                        url: buf.get_url(),
                    }),
                    Err(_e) => Err(DidResolveError::MalformedDid(value)),
                }
            }
            WebVerifiableHistoryId::DID_METHOD_NAME => {
                match WebVerifiableHistoryId::parse_did_webvh(value.to_owned()) {
                    Ok(buf) => Ok(Did {
                        parts: did_split.into_iter().map(|v| v.to_string()).collect(),
                        method: DidMethod::WEBVH,
                        method_id: buf.get_scid(),
                        url: buf.get_url(),
                    }),
                    Err(_e) => Err(DidResolveError::MalformedDid(value)),
                }
            }
            _ => Err(DidResolveError::DidNotSupported(value)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DidResolveErrorKind;
    use super::{Did, DidMethod};
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
        "did:tdw:QmRjT8JCbQkEffVBWSbQd8nbMVNfAxiXStLPmqkQUWcsfv:gist.githubusercontent.com:vst-bit:32b64cfac9075b2a3ab7301b772bcdef:raw:8b4bd2b715101d5b69b3395f5c560c37e1ae9992"
    )]
    #[case(
        "did:webvh:QmXi8p2LNXA6kbc2brwdpXwGETHCrPoFk15yPbLaAu27Pj:gist.githubusercontent.com:vst-bit:20c3f59d8179e324a6e29aef45240db4:raw:7870280f80dfcfb7459ee1488df4ab33f2bcf709"
    )]
    fn test_resolve(
        #[case] did: String,
        http_client: &HttpClient, // fixture
    ) -> Result<(), Box<dyn std::error::Error>> {
        let did_obj = Did::new(did)?; // no error expected here

        let url = did_obj.get_https_url();
        assert!(!url.is_empty());

        let did_log_raw = http_client.fetch_url(url);
        assert!(!did_log_raw.is_empty());

        let res = did_obj.resolve(did_log_raw);
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
        "test_data/tdw/did.jsonl",
        "did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    #[case(
        "test_data/tdw/did_without_controller.jsonl",
        "did:tdw:QmYD2gdyU1opYus5bJSoJr4c78mgctJnGHRsgqPv9NoLBh:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    #[case(
        "test_data/webvh/did.jsonl",
        "did:webvh:QmT4kPBFsHpJKvvvxgFUYxnSGPMeaQy1HWwyXMHj8NjLuy:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    #[case(
        "test_data/webvh/did_without_controller.jsonl",
        "did:webvh:QmT4kPBFsHpJKvvvxgFUYxnSGPMeaQy1HWwyXMHj8NjLuy:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    fn test_resolve_did_log_from_file(
        #[case] did_log_raw_filepath: String,
        #[case] did: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let did_obj = Did::new(did.to_string())?; // no error expected here

        let did_log_raw = fs::read_to_string(Path::new(&did_log_raw_filepath));
        assert!(did_log_raw.is_ok());
        let did_log_raw = did_log_raw.unwrap();

        let res = did_obj.resolve(did_log_raw);
        assert!(res.is_ok(), "ERROR: {:?}", res.err().unwrap());
        let did_doc = res.unwrap();
        assert_eq!(did_doc.id, did);

        //assert_eq!(did_doc.get_id(), did.to_string()); // assuming the Display trait is implemented accordingly for DID struct
        assert!(did_obj.to_string().contains(did_doc.get_id().as_str())); // assuming the Display trait is implemented accordingly for DID struct
        assert!(!did_doc.get_context().is_empty());
        assert!(!did_doc.get_verification_method().is_empty());
        assert!(!did_doc.get_authentication().is_empty());

        Ok(())
    }

    #[rstest]
    #[case("did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
        r#"["1-QmdFXCA7RgH2NszV3WgnbemHqLxpXeE66FswLjpTC2hcvV","2025-05-31T14:36:53Z",{"method":"did:tdw:0.3","scid":"QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7","updateKeys":["z6Mkvk4RpEvivSnpEp6zyVW7x3WpLVLs38iAYGFdXvbUJSz8"],"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","authentication":["did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01"],"assertionMethod":["did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01"],"verificationMethod":[{"id":"did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01","controller":"did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"cMuIogOIny4VcE92-KK4Y9AuwSmCX3Ot8MY80aRz__4","y":"ln1g0wrq0IKT3D_GjnBmZhA_tbqlG5p7-7OCk-xMC1g","kid":"auth-key-01"}},{"id":"did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01","controller":"did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"IXXoOILwuY2Z-e3md2vazPghS3cGJEJt8DY7Xcc28NY","y":"vyyaOaGu6ck1uEYjFChLu-cHCoxJ71L8UCQn3mM8xn4","kid":"assert-key-01"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-05-31T14:36:53Z","verificationMethod":"did:key:z6Mkvk4RpEvivSnpEp6zyVW7x3WpLVLs38iAYGFdXvbUJSz8#z6Mkvk4RpEvivSnpEp6zyVW7x3WpLVLs38iAYGFdXvbUJSz8","proofPurpose":"authentication","challenge":"1-QmdFXCA7RgH2NszV3WgnbemHqLxpXeE66FswLjpTC2hcvV","proofValue":"z2JthfEzDiUejxU5ug2MLGJNykDUWPzYGAHDHCUgp25n4cyq3kJwXdJV4QoviFUJwxfT3dbbWY7GPpANz9uq2KTRL"}]]
["2-QmVA5UuLakpdb7yW32Ay1WW1PC1WPRtFNsn86vf1de9djE","2025-05-31T14:36:53Z",{},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","authentication":["did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-auth-key-01"],"assertionMethod":["did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-assert-key-01"],"verificationMethod":[{"id":"did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-auth-key-01","controller":"did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"cMuIogOIny4VcE92-KK4Y9AuwSmCX3Ot8MY80aRz__4","y":"ln1g0wrq0IKT3D_GjnBmZhA_tbqlG5p7-7OCk-xMC1g"}},{"id":"did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-assert-key-01","controller":"did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"IXXoOILwuY2Z-e3md2vazPghS3cGJEJt8DY7Xcc28NY","y":"vyyaOaGu6ck1uEYjFChLu-cHCoxJ71L8UCQn3mM8xn4"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-05-31T14:36:53Z","verificationMethod":"did:key:z6Mkvk4RpEvivSnpEp6zyVW7x3WpLVLs38iAYGFdXvbUJSz8#z6Mkvk4RpEvivSnpEp6zyVW7x3WpLVLs38iAYGFdXvbUJSz8","proofPurpose":"authentication","challenge":"2-QmVA5UuLakpdb7yW32Ay1WW1PC1WPRtFNsn86vf1de9djE","proofValue":"zVjuRUjoWM2aFiFDqqQqtQ6J4Zg4AL3qvoa1oJSFh22TMGUVErtE4XJKNPa8Xr1XXs5nPiqWPYsNC4dzSvdvPd5G"}]]
"#)]
    #[case("did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com",
        r#"{ "versionId": "1-QmQNjSbRroDtnctDN57Fjvd4e5jYHWVTgMZpzJiTbPfQ5K", "versionTime": "2025-08-06T08:55:01Z", "parameters": { "method": "did:webvh:1.0", "scid": "QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX", "updateKeys": [ "z6MkkkjG6shmZk6D2ghgDbpJQHD4xvpZhzYiWSLKDeznibiJ" ], "portable": false }, "state": { "@context": [ "https://www.w3.org/ns/did/v1", "https://w3id.org/security/jwk/v1" ], "id": "did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com", "authentication": [ "did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com#auth-key-01" ], "assertionMethod": [ "did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com#assert-key-01" ], "verificationMethod": [ { "id": "did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com#auth-key-01", "type": "JsonWebKey2020", "publicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "5d-hJaS_UKIU1c05hEBhZa8Xkj_AqBDmqico_PSrRfU", "y": "TK5YKD_osEaVrDBnah-jUDXI27yqFVIo6ZYTfWp-NbY", "kid": "auth-key-01" } }, { "id": "did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com#assert-key-01", "type": "JsonWebKey2020", "publicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "7jWgolr5tQIUIGp9sDaB0clAiXcFwVYXUhEiXXLkmKg", "y": "NYGIxi2VGEv2OL_WqzVOd_VKjOQbl1kaERYbpAjWo58", "kid": "assert-key-01" } } ] }, "proof": [ { "type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "created": "2025-08-13T05:43:17Z", "verificationMethod": "did:key:z6MkkkjG6shmZk6D2ghgDbpJQHD4xvpZhzYiWSLKDeznibiJ#z6MkkkjG6shmZk6D2ghgDbpJQHD4xvpZhzYiWSLKDeznibiJ", "proofPurpose": "assertionMethod", "proofValue": "z3L7j2siRiZ4zziQQmRqLY5qH2RfVz6VTC5gbDE6vntw1De5Ej5DNR3wDU6m9KRiUYPm9o8P89yMzNk5EhWVTo4Tn" } ] }
{ "versionId": "2-QmYkDQ83oPnBqyUEjdUdZZCc8VjQY7aE5BikRaa8cZAxVS", "versionTime": "2025-08-13T08:46:50Z", "parameters": {}, "state": { "@context": [ "https://www.w3.org/ns/did/v1", "https://w3id.org/security/jwk/v1" ], "id": "did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com", "authentication": [ "did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com#auth-key-01" ], "assertionMethod": [ "did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com#assert-key-01" ], "verificationMethod": [ { "id": "did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com#auth-key-01", "type": "JsonWebKey2020", "publicKeyJwk": { "kty": "EC", "crv": "P-256", "kid": "auth-key-01", "x": "Ow_aAo2hbAYgEhKAOeu3TYO8bbKOxgJ2gndk46AaXF0", "y": "hdVPThXbmadBl3L5HaYjiz8ewIAve4VHqOgs98MdV5M" } }, { "id": "did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com#assert-key-01", "type": "JsonWebKey2020", "publicKeyJwk": { "kty": "EC", "crv": "P-256", "kid": "assert-key-02", "x": "oZq9zqDbbYfRV9gdXbLJaaKWF9G27P4CQfTEyC1aT0I", "y": "QS-uHvmj1mVLB5zJtnwTyWYRZIML4RzvCf4qOrsqfWQ" } } ] }, "proof": [ { "type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "created": "2025-08-13T09:02:55Z", "verificationMethod": "did:key:z6MkkkjG6shmZk6D2ghgDbpJQHD4xvpZhzYiWSLKDeznibiJ#z6MkkkjG6shmZk6D2ghgDbpJQHD4xvpZhzYiWSLKDeznibiJ", "proofPurpose": "assertionMethod", "proofValue": "z2tZe9tFzyTKWRX7NEpf3ARRs7yZqu5Kq8jzr5qzzffeN9FeJPzmKs6Jb1TMNfpn8Nar6WEfifvMT5SVWozJruTwD" } ] }
"#)]
    fn test_resolve_did_log(#[case] did: String, #[case] did_log_raw: String) {
        let did_obj = Did::new(did.clone()).unwrap();

        let did_doc = did_obj.resolve(did_log_raw);
        assert!(did_doc.is_ok());
        let did_doc = did_doc.unwrap();
        assert_eq!(did_doc.get_id(), did)
    }

    #[rstest]
    // https://raw.githubusercontent.com/affinidi/affinidi-tdk-rs/refs/tags/did-webvh-v0.1.7/crates/affinidi-did-resolver/affinidi-did-resolver-methods/did-webvh/tests/test_vectors/first_log_entry_good.jsonl
    #[case("did:webvh:QmQHjAiCq1N2dbTPKBkH7xpd93FQCgEPxmR2zTXqt4fndY:localhost%3A8000",
        r#"{"versionId":"1-QmWZWcvritBzgX3JiMz9dSjkTL2Pbw4HmBo4zC3eiNqLy8","versionTime":"2025-07-07T01:52:23Z","parameters":{"method":"did:webvh:1.0","scid":"QmQHjAiCq1N2dbTPKBkH7xpd93FQCgEPxmR2zTXqt4fndY","updateKeys":["z6MkqjRELM1dN43aw6QdkjG46k1fUTjdQJqx7g338djC3Bre"],"portable":true,"nextKeyHashes":["zQmTaTNScJGPSEiHWTxaEpdVExMYqn7DF2DFZ3VqoF9cawN"]},"state":{"@context":["https://www.w3.org/ns/did/v1","https://www.w3.org/ns/cid/v1"],"assertionMethod":["did:webvh:QmQHjAiCq1N2dbTPKBkH7xpd93FQCgEPxmR2zTXqt4fndY:localhost%3A8000#key-0"],"authentication":["did:webvh:QmQHjAiCq1N2dbTPKBkH7xpd93FQCgEPxmR2zTXqt4fndY:localhost%3A8000#key-0"],"capabilityDelegation":[],"capabilityInvocation":[],"id":"did:webvh:QmQHjAiCq1N2dbTPKBkH7xpd93FQCgEPxmR2zTXqt4fndY:localhost%3A8000","keyAgreement":["did:webvh:QmQHjAiCq1N2dbTPKBkH7xpd93FQCgEPxmR2zTXqt4fndY:localhost%3A8000#key-0"],"service":[],"verificationMethod":[{"controller":"did:webvh:QmQHjAiCq1N2dbTPKBkH7xpd93FQCgEPxmR2zTXqt4fndY:localhost%3A8000","id":"did:webvh:QmQHjAiCq1N2dbTPKBkH7xpd93FQCgEPxmR2zTXqt4fndY:localhost%3A8000#key-0","publicKeyMultibase":"z6Mkp6U8WcpWKFi6TFfUpzrtNN99a1aXpWARJEeXh8uFEn7H","type":"Multikey"}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-07-07T01:52:23Z","verificationMethod":"did:key:z6MkqjRELM1dN43aw6QdkjG46k1fUTjdQJqx7g338djC3Bre#z6MkqjRELM1dN43aw6QdkjG46k1fUTjdQJqx7g338djC3Bre","proofPurpose":"assertionMethod","proofValue":"z5VnQYT8GkJ2PQArqaqcFuNjpd8CcueLVT4JriXDYPfUBtS9LJBSMYpLQUAA1oUQQYhLuqemYE8H8Yv1J3i1DYbQj"}]}
"#)]
    // https://raw.githubusercontent.com/affinidi/affinidi-tdk-rs/refs/tags/did-webvh-v0.1.7/crates/affinidi-did-resolver/affinidi-did-resolver-methods/did-webvh/tests/test_vectors/first_log_entry_verify_full.jsonl
    #[case("did:webvh:QmP7NForSYfNsLYSibwCNLv46NeHR8e8JNW4BgMDhB5qia:localhost%3A8000",
        r#"{"versionId":"1-QmRiFdWdyckg8HETNgZWEXP3LGhEZD9pJBVqFRCRWpUrKh","versionTime":"2025-07-09T21:32:15Z","parameters":{"method":"did:webvh:1.0","scid":"QmP7NForSYfNsLYSibwCNLv46NeHR8e8JNW4BgMDhB5qia","updateKeys":["z6Mkg7jJzawE4bCvZ4bNEcXCv77gQb6cWoKS7vR6WvZC91YR"],"portable":true,"nextKeyHashes":["QmUSYM6seDvKtYpSEsr7Y5bmM5owYVGV3EhZ5BCUexrAcR"],"ttl":300},"state":{"@context":["https://www.w3.org/ns/did/v1","https://www.w3.org/ns/cid/v1"],"assertionMethod":["did:webvh:QmP7NForSYfNsLYSibwCNLv46NeHR8e8JNW4BgMDhB5qia:localhost%3A8000#key-0"],"authentication":["did:webvh:QmP7NForSYfNsLYSibwCNLv46NeHR8e8JNW4BgMDhB5qia:localhost%3A8000#key-0"],"capabilityDelegation":[],"capabilityInvocation":[],"id":"did:webvh:QmP7NForSYfNsLYSibwCNLv46NeHR8e8JNW4BgMDhB5qia:localhost%3A8000","keyAgreement":["did:webvh:QmP7NForSYfNsLYSibwCNLv46NeHR8e8JNW4BgMDhB5qia:localhost%3A8000#key-0"],"service":[],"verificationMethod":[{"controller":"did:webvh:QmP7NForSYfNsLYSibwCNLv46NeHR8e8JNW4BgMDhB5qia:localhost%3A8000","id":"did:webvh:QmP7NForSYfNsLYSibwCNLv46NeHR8e8JNW4BgMDhB5qia:localhost%3A8000#key-0","publicKeyMultibase":"z6MkizY3BLE8VwADPdzuhRcsTVDnakfGRNMjWxhk1WJYTjRg","type":"Multikey"}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-07-09T21:32:15Z","verificationMethod":"did:key:z6Mkg7jJzawE4bCvZ4bNEcXCv77gQb6cWoKS7vR6WvZC91YR#z6Mkg7jJzawE4bCvZ4bNEcXCv77gQb6cWoKS7vR6WvZC91YR","proofPurpose":"assertionMethod","proofValue":"z64Ney14a8BVM5XWQ9qHchnmNH2EKwsRpp7y972sxoGc84mDu56Vq8pJHpymZPpcPmcrDPtqKJs1CkapXxc14ZGeM"}]}
"#)]
    // https://raw.githubusercontent.com/affinidi/affinidi-tdk-rs/refs/tags/did-webvh-v0.1.7/crates/affinidi-did-resolver/affinidi-did-resolver-methods/did-webvh/tests/test_vectors/pre-1_0-spec.jsonl
    #[case("did:webvh:QmRcxocrbu6F6nDAiWeFBJXHjqgif3NPnuZyHDzxtEpvjx:example.example",
        r#"{"versionId":"1-QmbN9L4sb5s2brWSomReR9BpH5L3HnbjvC9Wshf1LpeK19","versionTime":"2025-07-19T11:55:46Z","parameters":{"method":"did:webvh:1.0","scid":"QmRcxocrbu6F6nDAiWeFBJXHjqgif3NPnuZyHDzxtEpvjx","updateKeys":["z6MkjV2QDQf7skfEiQ6hN7dPUgyvf8NAXefPFqm5jaczXaoL"],"nextKeyHashes":["QmPyrGjbkwKPbDE33StNmA6v9uwNWB9NWgmxMiQ7tV1uJx"],"watchers":["https://watcher1.example/"]},"state":{"@context":["https://www.w3.org/ns/did/v1","https://www.w3.org/ns/cid/v1"],"assertionMethod":["did:webvh:QmRcxocrbu6F6nDAiWeFBJXHjqgif3NPnuZyHDzxtEpvjx:example.example#key-0"],"authentication":["did:webvh:QmRcxocrbu6F6nDAiWeFBJXHjqgif3NPnuZyHDzxtEpvjx:example.example#key-0"],"capabilityDelegation":[],"capabilityInvocation":[],"id":"did:webvh:QmRcxocrbu6F6nDAiWeFBJXHjqgif3NPnuZyHDzxtEpvjx:example.example","keyAgreement":["did:webvh:QmRcxocrbu6F6nDAiWeFBJXHjqgif3NPnuZyHDzxtEpvjx:example.example#key-0"],"service":[],"verificationMethod":[{"controller":"did:webvh:QmRcxocrbu6F6nDAiWeFBJXHjqgif3NPnuZyHDzxtEpvjx:example.example","id":"did:webvh:QmRcxocrbu6F6nDAiWeFBJXHjqgif3NPnuZyHDzxtEpvjx:example.example#key-0","publicKeyMultibase":"z6MkoStXcsJvsZ8quDUZyRj9xiGRyhBVB4f8Qme1vze8DWLc","type":"Multikey"}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-07-19T11:55:46Z","verificationMethod":"did:key:z6MkjV2QDQf7skfEiQ6hN7dPUgyvf8NAXefPFqm5jaczXaoL#z6MkjV2QDQf7skfEiQ6hN7dPUgyvf8NAXefPFqm5jaczXaoL","proofPurpose":"assertionMethod","proofValue":"z3vfSXEm2fpoahV6Z7dhsWimkn1WfW17AnBrbe1gHmgoccwJ6LQghm9ydf9zbWr295mw6CNRtFU4BzWghasUW2gpK"}]}
"#)]
    fn test_resolve_affinidi_test_vectors(#[case] did: String, #[case] did_log_raw: String) {
        let did_obj = Did::new(did.clone()).unwrap();

        let did_doc = did_obj.resolve(did_log_raw);
        assert!(did_doc.is_ok());
        let did_doc = did_doc.unwrap();
        assert_eq!(did_doc.get_id(), did)
    }

    #[rstest]
    // https://raw.githubusercontent.com/affinidi/affinidi-tdk-rs/refs/tags/did-webvh-v0.1.7/crates/affinidi-did-resolver/affinidi-did-resolver-methods/did-webvh/tests/test_vectors/first_log_entry_verify_tampered.jsonl
    #[case("did:webvh:QmP7NForSYfNsLYSibwCNLv46NeHR8e8JNW4BgMDhB5qia:localhost%3A8000",
        r#"{"versionId":"1-QmRiFdWdyckg8HETNgZWEXP3LGhEZD9pJBVqFRCRWpUrKh","versionTime":"2025-07-09T21:32:16Z","parameters":{"method":"did:webvh:1.0","scid":"QmP7NForSYfNsLYSibwCNLv46NeHR8e8JNW4BgMDhB5qia","updateKeys":["z6Mkg7jJzawE4bCvZ4bNEcXCv77gQb6cWoKS7vR6WvZC91YR"],"portable":true,"nextKeyHashes":["QmUSYM6seDvKtYpSEsr7Y5bmM5owYVGV3EhZ5BCUexrAcR"],"ttl":300},"state":{"@context":["https://www.w3.org/ns/did/v1","https://www.w3.org/ns/cid/v1"],"assertionMethod":["did:webvh:QmP7NForSYfNsLYSibwCNLv46NeHR8e8JNW4BgMDhB5qia:localhost%3A8000#key-0"],"authentication":["did:webvh:QmP7NForSYfNsLYSibwCNLv46NeHR8e8JNW4BgMDhB5qia:localhost%3A8000#key-0"],"capabilityDelegation":[],"capabilityInvocation":[],"id":"did:webvh:QmP7NForSYfNsLYSibwCNLv46NeHR8e8JNW4BgMDhB5qia:localhost%3A8000","keyAgreement":["did:webvh:QmP7NForSYfNsLYSibwCNLv46NeHR8e8JNW4BgMDhB5qia:localhost%3A8000#key-0"],"service":[],"verificationMethod":[{"controller":"did:webvh:QmP7NForSYfNsLYSibwCNLv46NeHR8e8JNW4BgMDhB5qia:localhost%3A8000","id":"did:webvh:QmP7NForSYfNsLYSibwCNLv46NeHR8e8JNW4BgMDhB5qia:localhost%3A8000#key-0","publicKeyMultibase":"z6MkizY3BLE8VwADPdzuhRcsTVDnakfGRNMjWxhk1WJYTjRg","type":"Multikey"}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-07-09T21:32:15Z","verificationMethod":"did:key:z6Mkg7jJzawE4bCvZ4bNEcXCv77gQb6cWoKS7vR6WvZC91YR#z6Mkg7jJzawE4bCvZ4bNEcXCv77gQb6cWoKS7vR6WvZC91YR","proofPurpose":"assertionMethod","proofValue":"z64Ney14a8BVM5XWQ9qHchnmNH2EKwsRpp7y972sxoGc84mDu56Vq8pJHpymZPpcPmcrDPtqKJs1CkapXxc14ZGeM"}]}
"#, "invalid DID log integration proof: Failed to verify proof due to: invalid DID log integration proof: signature error: Verification equation was not satisfied")]
    // https://raw.githubusercontent.com/affinidi/affinidi-tdk-rs/refs/tags/did-webvh-v0.1.7/crates/affinidi-did-resolver/affinidi-did-resolver-methods/did-webvh/tests/test_vectors/pre-1_0-spec.jsonl
    #[case("did:webvh:QmRcxocrbu6F6nDAiWeFBJXHjqgif3NPnuZyHDzxtEpvjx:example.example",
        r#"{"versionId":"1-QmbN9L4sb5s2brWSomReR9BpH5L3HnbjvC9Wshf1LpeK19","versionTime":"2025-07-19T11:55:46Z","parameters":{"method":"did:webvh:1.0","scid":"QmRcxocrbu6F6nDAiWeFBJXHjqgif3NPnuZyHDzxtEpvjx","updateKeys":["z6MkjV2QDQf7skfEiQ6hN7dPUgyvf8NAXefPFqm5jaczXaoL"],"nextKeyHashes":["QmPyrGjbkwKPbDE33StNmA6v9uwNWB9NWgmxMiQ7tV1uJx"],"watchers":["https://watcher1.example/"]},"state":{"@context":["https://www.w3.org/ns/did/v1","https://www.w3.org/ns/cid/v1"],"assertionMethod":["did:webvh:QmRcxocrbu6F6nDAiWeFBJXHjqgif3NPnuZyHDzxtEpvjx:example.example#key-0"],"authentication":["did:webvh:QmRcxocrbu6F6nDAiWeFBJXHjqgif3NPnuZyHDzxtEpvjx:example.example#key-0"],"capabilityDelegation":[],"capabilityInvocation":[],"id":"did:webvh:QmRcxocrbu6F6nDAiWeFBJXHjqgif3NPnuZyHDzxtEpvjx:example.example","keyAgreement":["did:webvh:QmRcxocrbu6F6nDAiWeFBJXHjqgif3NPnuZyHDzxtEpvjx:example.example#key-0"],"service":[],"verificationMethod":[{"controller":"did:webvh:QmRcxocrbu6F6nDAiWeFBJXHjqgif3NPnuZyHDzxtEpvjx:example.example","id":"did:webvh:QmRcxocrbu6F6nDAiWeFBJXHjqgif3NPnuZyHDzxtEpvjx:example.example#key-0","publicKeyMultibase":"z6MkoStXcsJvsZ8quDUZyRj9xiGRyhBVB4f8Qme1vze8DWLc","type":"Multikey"}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-07-19T11:55:46Z","verificationMethod":"did:key:z6MkjV2QDQf7skfEiQ6hN7dPUgyvf8NAXefPFqm5jaczXaoL#z6MkjV2QDQf7skfEiQ6hN7dPUgyvf8NAXefPFqm5jaczXaoL","proofPurpose":"assertionMethod","proofValue":"z3vfSXEm2fpoahV6Z7dhsWimkn1WfW17AnBrbe1gHmgoccwJ6LQghm9ydf9zbWr295mw6CNRtFU4BzWghasUW2gpK"}]}
{"versionId":"2-QmVbgN8zNcZ71aDqP2FMyEkmvo4HJLFGgLnVychU2yANiv","versionTime":"2025-07-19T11:56:22Z","parameters":{"updateKeys":["z6Mkk7qfjoovyci2wpD1GZPvkngtWBjLr4bVdYeZfdWHDkEu"],"nextKeyHashes":["QmWZg7NR5vyjxHFjNLzyUdpHKXFr6MWM7pQJE8wdKrDZwV"],"watchers":null,"ttl":300},"state":{"@context":["https://www.w3.org/ns/did/v1","https://www.w3.org/ns/cid/v1"],"assertionMethod":["did:webvh:QmRcxocrbu6F6nDAiWeFBJXHjqgif3NPnuZyHDzxtEpvjx:example.example#key-0"],"authentication":["did:webvh:QmRcxocrbu6F6nDAiWeFBJXHjqgif3NPnuZyHDzxtEpvjx:example.example#key-0"],"capabilityDelegation":[],"capabilityInvocation":[],"id":"did:webvh:QmRcxocrbu6F6nDAiWeFBJXHjqgif3NPnuZyHDzxtEpvjx:example.example","keyAgreement":["did:webvh:QmRcxocrbu6F6nDAiWeFBJXHjqgif3NPnuZyHDzxtEpvjx:example.example#key-0"],"service":[],"verificationMethod":[{"controller":"did:webvh:QmRcxocrbu6F6nDAiWeFBJXHjqgif3NPnuZyHDzxtEpvjx:example.example","id":"did:webvh:QmRcxocrbu6F6nDAiWeFBJXHjqgif3NPnuZyHDzxtEpvjx:example.example#key-0","publicKeyMultibase":"z6MkoStXcsJvsZ8quDUZyRj9xiGRyhBVB4f8Qme1vze8DWLc","type":"Multikey"}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-07-19T11:56:22Z","verificationMethod":"did:key:z6Mkk7qfjoovyci2wpD1GZPvkngtWBjLr4bVdYeZfdWHDkEu#z6Mkk7qfjoovyci2wpD1GZPvkngtWBjLr4bVdYeZfdWHDkEu","proofPurpose":"assertionMethod","proofValue":"z3r38Tapg67qhu3AmTR7u3HUaDRdRRtUPak3tz6CmFpNgXQ9V6cB1MVLt2LLeTWnpcxt1SfMhuxyRpkAb96hmxMWC"}]}
{"versionId":"3-QmafHpsSfxEjN1nbyP28NmAuUuvznMBvcpozwFTqAwm5KR","versionTime":"2025-07-19T11:57:40Z","parameters":{"updateKeys":["z6MkmpTLDBwKi8qWC6J8jz4sGR9zn1oLTizNt6XbYxDEkFQS"],"nextKeyHashes":["QmdRUWzpVhPdbDgc6jSso9j6UksgMuWoxSAoeN5t9mpfMU"],"watchers":["https://watcher2.example"],"ttl":null},"state":{"@context":["https://www.w3.org/ns/did/v1","https://www.w3.org/ns/cid/v1"],"assertionMethod":["did:webvh:QmRcxocrbu6F6nDAiWeFBJXHjqgif3NPnuZyHDzxtEpvjx:example.example#key-0"],"authentication":["did:webvh:QmRcxocrbu6F6nDAiWeFBJXHjqgif3NPnuZyHDzxtEpvjx:example.example#key-0"],"capabilityDelegation":[],"capabilityInvocation":[],"id":"did:webvh:QmRcxocrbu6F6nDAiWeFBJXHjqgif3NPnuZyHDzxtEpvjx:example.example","keyAgreement":["did:webvh:QmRcxocrbu6F6nDAiWeFBJXHjqgif3NPnuZyHDzxtEpvjx:example.example#key-0"],"service":[],"verificationMethod":[{"controller":"did:webvh:QmRcxocrbu6F6nDAiWeFBJXHjqgif3NPnuZyHDzxtEpvjx:example.example","id":"did:webvh:QmRcxocrbu6F6nDAiWeFBJXHjqgif3NPnuZyHDzxtEpvjx:example.example#key-0","publicKeyMultibase":"z6MkoStXcsJvsZ8quDUZyRj9xiGRyhBVB4f8Qme1vze8DWLc","type":"Multikey"}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-07-19T11:57:40Z","verificationMethod":"did:key:z6MkmpTLDBwKi8qWC6J8jz4sGR9zn1oLTizNt6XbYxDEkFQS#z6MkmpTLDBwKi8qWC6J8jz4sGR9zn1oLTizNt6XbYxDEkFQS","proofPurpose":"assertionMethod","proofValue":"z2xUvaX1TgYkAfp6ujxy6vA1RtEd5NwyQPyzFLfojBjfYASTeCDdvHb4SSoUp4FAmjv8AQ53nyW2NMfePuQseHJuF"}]}
"#, "invalid DID log integration proof: Key extracted from proof is not authorized for update")]
    fn test_resolve_affinidi_invalid_test_vectors(
        #[case] did: String,
        #[case] did_log_raw: String,
        #[case] error_message_contains: String,
    ) {
        let did_obj = Did::new(did.clone()).unwrap();

        let did_doc = did_obj.resolve(did_log_raw);
        assert!(did_doc.is_err());
        let err = did_doc.err().unwrap();
        assert_eq!(DidResolveErrorKind::InvalidDidLog, err.kind());
        assert!(err.to_string().contains(&error_message_contains));
    }

    #[rstest]
    #[case("did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
        r#"["Invalid Log"]"#,
        "the supplied DID log is invalid")]
    #[case(
        "did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com",
        r#"{}"#,
        "the supplied DID log is invalid"
    )]
    #[case("did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
        r#"{ "versionId": "1-QmQNjSbRroDtnctDN57Fjvd4e5jYHWVTgMZpzJiTbPfQ5K", "versionTime": "2025-08-06T08:55:01Z", "parameters": { "method": "did:webvh:1.0", "scid": "QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX", "updateKeys": [ "z6MkkkjG6shmZk6D2ghgDbpJQHD4xvpZhzYiWSLKDeznibiJ" ], "portable": false }, "state": { "@context": [ "https://www.w3.org/ns/did/v1", "https://w3id.org/security/jwk/v1" ], "id": "did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com", "authentication": [ "did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com#auth-key-01" ], "assertionMethod": [ "did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com#assert-key-01" ], "verificationMethod": [ { "id": "did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com#auth-key-01", "type": "JsonWebKey2020", "publicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "5d-hJaS_UKIU1c05hEBhZa8Xkj_AqBDmqico_PSrRfU", "y": "TK5YKD_osEaVrDBnah-jUDXI27yqFVIo6ZYTfWp-NbY", "kid": "auth-key-01" } }, { "id": "did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com#assert-key-01", "type": "JsonWebKey2020", "publicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "7jWgolr5tQIUIGp9sDaB0clAiXcFwVYXUhEiXXLkmKg", "y": "NYGIxi2VGEv2OL_WqzVOd_VKjOQbl1kaERYbpAjWo58", "kid": "assert-key-01" } } ] }, "proof": [ { "type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "created": "2025-08-13T05:43:17Z", "verificationMethod": "did:key:z6MkkkjG6shmZk6D2ghgDbpJQHD4xvpZhzYiWSLKDeznibiJ#z6MkkkjG6shmZk6D2ghgDbpJQHD4xvpZhzYiWSLKDeznibiJ", "proofPurpose": "assertionMethod", "proofValue": "z3L7j2siRiZ4zziQQmRqLY5qH2RfVz6VTC5gbDE6vntw1De5Ej5DNR3wDU6m9KRiUYPm9o8P89yMzNk5EhWVTo4Tn" } ] }
{ "versionId": "2-QmYkDQ83oPnBqyUEjdUdZZCc8VjQY7aE5BikRaa8cZAxVS", "versionTime": "2025-08-13T08:46:50Z", "parameters": {}, "state": { "@context": [ "https://www.w3.org/ns/did/v1", "https://w3id.org/security/jwk/v1" ], "id": "did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com", "authentication": [ "did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com#auth-key-01" ], "assertionMethod": [ "did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com#assert-key-01" ], "verificationMethod": [ { "id": "did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com#auth-key-01", "type": "JsonWebKey2020", "publicKeyJwk": { "kty": "EC", "crv": "P-256", "kid": "auth-key-01", "x": "Ow_aAo2hbAYgEhKAOeu3TYO8bbKOxgJ2gndk46AaXF0", "y": "hdVPThXbmadBl3L5HaYjiz8ewIAve4VHqOgs98MdV5M" } }, { "id": "did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com#assert-key-01", "type": "JsonWebKey2020", "publicKeyJwk": { "kty": "EC", "crv": "P-256", "kid": "assert-key-02", "x": "oZq9zqDbbYfRV9gdXbLJaaKWF9G27P4CQfTEyC1aT0I", "y": "QS-uHvmj1mVLB5zJtnwTyWYRZIML4RzvCf4qOrsqfWQ" } } ] }, "proof": [ { "type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "created": "2025-08-13T09:02:55Z", "verificationMethod": "did:key:z6MkkkjG6shmZk6D2ghgDbpJQHD4xvpZhzYiWSLKDeznibiJ#z6MkkkjG6shmZk6D2ghgDbpJQHD4xvpZhzYiWSLKDeznibiJ", "proofPurpose": "assertionMethod", "proofValue": "z2tZe9tFzyTKWRX7NEpf3ARRs7yZqu5Kq8jzr5qzzffeN9FeJPzmKs6Jb1TMNfpn8Nar6WEfifvMT5SVWozJruTwD" } ] }
"#, "the supplied DID log is invalid")]
    #[case("did:webvh:QmYPmKXuvwHeVF8zWdcMvU3UNksUZnR5kUJbhDjEjbZYvX:example.com",
        r#"["1-QmdFXCA7RgH2NszV3WgnbemHqLxpXeE66FswLjpTC2hcvV","2025-05-31T14:36:53Z",{"method":"did:tdw:0.3","scid":"QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7","updateKeys":["z6Mkvk4RpEvivSnpEp6zyVW7x3WpLVLs38iAYGFdXvbUJSz8"],"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","authentication":["did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01"],"assertionMethod":["did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01"],"verificationMethod":[{"id":"did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01","controller":"did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"cMuIogOIny4VcE92-KK4Y9AuwSmCX3Ot8MY80aRz__4","y":"ln1g0wrq0IKT3D_GjnBmZhA_tbqlG5p7-7OCk-xMC1g","kid":"auth-key-01"}},{"id":"did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01","controller":"did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"IXXoOILwuY2Z-e3md2vazPghS3cGJEJt8DY7Xcc28NY","y":"vyyaOaGu6ck1uEYjFChLu-cHCoxJ71L8UCQn3mM8xn4","kid":"assert-key-01"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-05-31T14:36:53Z","verificationMethod":"did:key:z6Mkvk4RpEvivSnpEp6zyVW7x3WpLVLs38iAYGFdXvbUJSz8#z6Mkvk4RpEvivSnpEp6zyVW7x3WpLVLs38iAYGFdXvbUJSz8","proofPurpose":"authentication","challenge":"1-QmdFXCA7RgH2NszV3WgnbemHqLxpXeE66FswLjpTC2hcvV","proofValue":"z2JthfEzDiUejxU5ug2MLGJNykDUWPzYGAHDHCUgp25n4cyq3kJwXdJV4QoviFUJwxfT3dbbWY7GPpANz9uq2KTRL"}]]
["2-QmVA5UuLakpdb7yW32Ay1WW1PC1WPRtFNsn86vf1de9djE","2025-05-31T14:36:53Z",{},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","authentication":["did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-auth-key-01"],"assertionMethod":["did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-assert-key-01"],"verificationMethod":[{"id":"did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-auth-key-01","controller":"did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"cMuIogOIny4VcE92-KK4Y9AuwSmCX3Ot8MY80aRz__4","y":"ln1g0wrq0IKT3D_GjnBmZhA_tbqlG5p7-7OCk-xMC1g"}},{"id":"did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-assert-key-01","controller":"did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"IXXoOILwuY2Z-e3md2vazPghS3cGJEJt8DY7Xcc28NY","y":"vyyaOaGu6ck1uEYjFChLu-cHCoxJ71L8UCQn3mM8xn4"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-05-31T14:36:53Z","verificationMethod":"did:key:z6Mkvk4RpEvivSnpEp6zyVW7x3WpLVLs38iAYGFdXvbUJSz8#z6Mkvk4RpEvivSnpEp6zyVW7x3WpLVLs38iAYGFdXvbUJSz8","proofPurpose":"authentication","challenge":"2-QmVA5UuLakpdb7yW32Ay1WW1PC1WPRtFNsn86vf1de9djE","proofValue":"zVjuRUjoWM2aFiFDqqQqtQ6J4Zg4AL3qvoa1oJSFh22TMGUVErtE4XJKNPa8Xr1XXs5nPiqWPYsNC4dzSvdvPd5G"}]]
"#, "the supplied DID log is invalid")]
    fn test_resolve_invalid_did_log(
        #[case] did: String,
        #[case] did_log_raw: String,
        #[case] error_message: String,
    ) {
        let did_obj = Did::new(did.clone()).unwrap();

        let did_doc = did_obj.resolve(did_log_raw);
        assert!(did_doc.is_err());
        let err = did_doc.err().unwrap();
        assert!(err.to_string().contains(&error_message));
    }

    #[rstest]
    #[case("did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    fn test_resolve_invalid_did_log_with_no_entries(
        #[case] did: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let did_obj = Did::new(did.to_string())?; // no error expected here

        let res = did_obj.resolve(String::new()); // empty string
        assert!(res.is_err(), "ERROR: {:?}", res.err().unwrap());
        assert_eq!(res.unwrap_err().kind(), DidResolveErrorKind::InvalidDidLog); // panic-safe unwrap call (see the previous line)

        Ok(())
    }

    #[rstest]
    // CAUTION A did_tdw (param #2) MUST match the one residing in did_log_raw_filepath (param #1)
    #[case(
        "test_data/tdw/non_incremented_version_did.jsonl",
        "did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    #[case(
        "test_data/tdw/unordered_did.jsonl",
        "did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    #[case(
        "test_data/webvh/non_incremented_version_did.jsonl",
        "did:webvh:QmT4kPBFsHpJKvvvxgFUYxnSGPMeaQy1HWwyXMHj8NjLuy:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    #[case(
        "test_data/webvh/unordered_did.jsonl",
        "did:webvh:QmT4kPBFsHpJKvvvxgFUYxnSGPMeaQy1HWwyXMHj8NjLuy:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    fn test_resolve_invalid_did_log_non_incremented_version(
        #[case] did_log_raw_filepath: String,
        #[case] did: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let did_obj = Did::new(did.to_string())?; // no error expected here

        let did_log_raw = fs::read_to_string(Path::new(&did_log_raw_filepath));
        assert!(did_log_raw.is_ok());
        let did_log_raw = did_log_raw.unwrap();

        let res = did_obj.resolve(did_log_raw); // panic-safe unwrap call (see above)
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
    fn test_did_not_supported(#[case] did: String) {
        let did_obj = Did::new(did.to_owned());
        assert!(did_obj.is_err());
        assert_eq!(
            did_obj.unwrap_err().kind(), // panic-safe unwrap call (see the previous line)
            DidResolveErrorKind::DidNotSupported
        );
    }

    #[rstest]
    #[case("did:tdw:QMySCID:domain", DidMethod::TDW)]
    #[case("did:tdw:QMySCID:domain:path", DidMethod::TDW)]
    #[case("did:tdw:Q24hsDDvpZHmUyNwXWgy36jhB6SFMLT2Aq7HWmZSk6XyZaM7qJNPNYthtRwtz84GHX3Bui3ZSVCcrG8KvGracfbhC:127.0.0.1%3A52788:123456789", 
        DidMethod::TDW)]
    #[case("did:webvh:QMySCID:domain", DidMethod::WEBVH)]
    #[case("did:webvh:QMySCID:domain:path", DidMethod::WEBVH)]
    #[case("did:webvh:QmSPEpPcSwb3fegq8YE8zotcPEgzHrSFyTJJDAzPo2CYBp:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085", DidMethod::WEBVH)]
    fn test_did_ok(#[case] did: String, #[case] expected_method: DidMethod) {
        let did_obj = Did::new(did.to_owned()); // no errors expected here
        assert!(did_obj.is_ok());
        let did_obj = did_obj.unwrap(); // panic-safe unwrap call (see the previous line)
        let url = did_obj.get_https_url();
        assert!(!url.is_empty());
        assert!(url.starts_with("https://"));
        let method = did_obj.get_method();
        assert_ne!(method, DidMethod::UNKNOWN); // anything but this
        assert_eq!(method, expected_method);
    }

    #[rstest]
    #[case("did:tdw:malformed::::::")]
    #[case("did:tdw:malformed")]
    #[case("did:tdw:identifier#key01")]
    #[case("did:webvh:malformed::::::")]
    #[case("did:webvh:malformed")]
    #[case("did:webvh:identifier#key01")]
    fn test_did_malformed(#[case] did: String) {
        let did_obj = Did::new(did.to_owned()); // error is EXPECTED here

        assert!(did_obj.is_err());
        assert_eq!(
            did_obj.unwrap_err().kind(), // panic-safe unwrap call (see the previous line)
            DidResolveErrorKind::MalformedDid
        );
    }
}
