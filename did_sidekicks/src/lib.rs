// SPDX-License-Identifier: MIT

//! This project implements the following things:
//!
//! - General util structs reused by other libraries of swiyu-admin-ch
//!

extern crate core;

pub mod custom_jsonschema_keywords;
pub mod did_doc;
pub mod did_jsonschema;
pub mod did_method_parameters;
pub mod did_resolver;
pub mod ed25519;
pub mod errors;
pub mod jcs_sha256_hasher;
pub mod multibase;
pub mod vc_data_integrity;

// CAUTION All structs required by UniFFI bindings generator (declared in UDL) MUST also be "used" here
#[allow(unused_imports, reason = "required by the UniFFI compiler!")]
#[expect(clippy::allow_attributes, reason = "..")]
use did_doc::*;
//use ed25519::*;
use did_jsonschema::*;
#[allow(unused_imports, reason = "required by the UniFFI compiler!")]
#[expect(clippy::allow_attributes, reason = "..")]
use did_method_parameters::*;
#[allow(unused_imports, reason = "required by the UniFFI compiler!")]
#[expect(clippy::allow_attributes, reason = "..")]
use ed25519::*;
#[allow(unused_imports, reason = "required by the UniFFI compiler!")]
#[expect(clippy::allow_attributes, reason = "..")]
use errors::*;
#[allow(unused_imports, reason = "required by the UniFFI compiler!")]
#[expect(clippy::allow_attributes, reason = "..")]
use jcs_sha256_hasher::*;
#[allow(unused_imports, reason = "required by the UniFFI compiler!")]
#[expect(clippy::allow_attributes, reason = "..")]
use vc_data_integrity::*;

uniffi::include_scaffolding!("did_sidekicks");

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "unwrap calls are panic-safe as long as test case setup is correct"
)]
mod test {
    use crate::did_doc;
    use crate::errors::*;
    use rand::distributions::Alphanumeric;
    use rand::Rng as _;
    use rstest::{fixture, rstest};
    use serde_json::{json, Value};
    use std::vec;

    #[fixture]
    fn unique_base_url() -> String {
        let random_thing: String = rand::thread_rng()
            .sample_iter(Alphanumeric)
            .take(7)
            .map(char::from)
            .collect();
        format!("https://localhost:8000/{random_thing}")
    }

    /// A rather trivial assertion helper around DidSidekicksError.
    pub fn assert_error<T>(
        res: Result<T, DidSidekicksError>,
        expected_kind: DidSidekicksErrorKind,
        error_contains: &str,
    ) {
        assert!(res.is_err());
        let err_opt = res.err();
        assert!(err_opt.is_some());
        let err = err_opt.unwrap();
        assert_eq!(err.kind(), expected_kind);

        let err_to_string = err.to_string();
        assert!(
            err_to_string.contains(error_contains),
            "expected '{}' is not mentioned in '{}'",
            error_contains,
            err_to_string
        );
    }

    #[rstest]
    #[case(
        json!({
            "@context": [ "https://www.w3.org/ns/did/v1", "https://w3id.org/security/jwk/v1" ],
            "id": "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
            "authentication": [ "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01" ],
            "assertionMethod": [ "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-02" ],
            "verificationMethod": [{
                    "id": "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01",
                    "controller": "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
                    "type": "JsonWebKey2020",
                    "publicKeyJwk": {
                        "kty": "EC",
                        "crv": "P-256",
                        "kid": "auth-key-01",
                        "x": "3-xR-ApvKYCKtXxjvypxIb4tHJSUTHCl0uUYVAvP6sE",
                        "y": "jkQdXwStFmrJjHuWw8PE_AG43c4OQwd6-Rkr4sPiC7Y"
                    }
                },{
                    "id": "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-02",
                    "controller": "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
                    "type": "JsonWebKey2020",
                    "publicKeyJwk": {
                        "kty": "EC",
                        "crv": "P-256",
                        "kid": "assert-key-02",
                        "x": "Ja4P63oUfaUageuu9O_6kOHT6bLe5D4myacZpEICwC8",
                        "y": "A4JwAyrpKxtsNLX50A0pQ_4G2AYO-NJw0dzne11xUj0"
                    }
            }]
        }),
        vec!["auth-key-01", "assert-key-02"],
    )]
    #[case(
        json!({
            "@context": [ "https://www.w3.org/ns/did/v1", "https://w3id.org/security/jwk/v1" ],
            "id": "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
            "authentication": [{
                "id": "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01",
                "controller": "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
                "type": "JsonWebKey2020",
                "publicKeyJwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "kid": "auth-key-01",
                    "x": "3-xR-ApvKYCKtXxjvypxIb4tHJSUTHCl0uUYVAvP6sE",
                    "y": "jkQdXwStFmrJjHuWw8PE_AG43c4OQwd6-Rkr4sPiC7Y"
                }
            }],
            "assertionMethod": [{
                "id": "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-02",
                "controller": "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
                "type": "JsonWebKey2020",
                "publicKeyJwk": {
                    "kty": "EC",
                    "crv":
                    "P-256",
                    "kid": "assert-key-02",
                    "x": "Ja4P63oUfaUageuu9O_6kOHT6bLe5D4myacZpEICwC8",
                    "y": "A4JwAyrpKxtsNLX50A0pQ_4G2AYO-NJw0dzne11xUj0"
                }
            }],
            "verificationMethod": [ ]
        }),
        vec!["auth-key-01", "assert-key-02"],
    )]
    // The example taken from: https://www.w3.org/TR/did-1.0/#example-did-document-with-different-verification-method-types
    #[case(
        json!({
          "@context": [ "https://www.w3.org/ns/did/v1", "https://w3id.org/security/jwk/v1" ],
          "id": "did:example:123",
          "verificationMethod": [{
              "id": "did:example:123#key-3",
              "type": "JsonWebKey2020",
              "controller": "did:example:123",
              "publicKeyJwk": {
                "kty": "EC", // external (property name)
                "crv": "P-256", // external (property name)
                "x": "Er6KSSnAjI70ObRWhlaMgqyIOQYrDJTE94ej5hybQ2M", // external (property name)
                "y": "pPVzCOTJwgikPjuUE6UebfZySqEJ0ZtsWFpj7YSPGEk" // external (property name)
                // "kid" is OPTIONAL (https://www.rfc-editor.org/rfc/rfc7517#section-4.5)
              }
          }]
        }),
        vec!["key-3"],
    )]
    // cases to test
    // - did doc with jwks directly (DidDoc)
    // - did doc with jwks indirectly (DidDocNormalized)
    // - did doc invalid
    fn test_get_key_from_did_doc(#[case] did_doc: Value, #[case] key_ids: Vec<&str>) {
        key_ids.iter().for_each(|key_id| {
            let result = did_doc::get_key_from_did_doc(did_doc.to_string(), key_id.to_string());
            assert!(result.is_ok());
            // CAUTION "kid" is OPTIONAL (https://www.rfc-editor.org/rfc/rfc7517#section-4.5)
            match result.unwrap().kid {
                None => {} // legit
                Some(kid) => {
                    assert!(kid.eq(key_id.to_string().as_str()));
                }
            }
        });
    }

    #[rstest]
    #[case(
        json!({
            "@context": [ "https://www.w3.org/ns/did/v1", "https://w3id.org/security/jwk/v1" ],
            "id": "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
            "authentication": [ "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01" ],
            "assertionMethod": [ "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-02" ],
            "verificationMethod": [{
                "id": "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01",
                "controller": "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
                "type": "JsonWebKey2020",
                "publicKeyJwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "kid": "auth-key-01",
                    "x": "3-xR-ApvKYCKtXxjvypxIb4tHJSUTHCl0uUYVAvP6sE",
                    "y": "jkQdXwStFmrJjHuWw8PE_AG43c4OQwd6-Rkr4sPiC7Y"
                }
            },{
                "id": "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-02",
                "controller": "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
                "type": "JsonWebKey2020",
                "publicKeyJwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "kid": "assert-key-02",
                    "x": "Ja4P63oUfaUageuu9O_6kOHT6bLe5D4myacZpEICwC8",
                    "y": "A4JwAyrpKxtsNLX50A0pQ_4G2AYO-NJw0dzne11xUj0"
                }
            }]
        }),
        vec![
            "invalid_key",
            "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-0"
        ],
        DidSidekicksErrorKind::KeyNotFound,
        "no such JWK in the DID document"
    )]
    #[case(json!({}), vec!["irrelevant"], DidSidekicksErrorKind::DeserializationFailed, "the supplied DID document is invalid")]
    #[case(json!([]), vec!["irrelevant"], DidSidekicksErrorKind::DeserializationFailed, "the supplied DID document is invalid")]
    #[case(
        // currently returns KeyNotFound, should return InvalidDidDoc or DeserializationFailed since the provided JSON is not a valid DID doc
        json!({
            "@context": [],
            "id": "",
            "verificationMethod":[{
                "id": "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01",
                "controller": "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
                "type": "JsonWebKey2020",
                // CAUTION The same effect as omitting "publicKeyJwk" altogether
                "publicKeyJwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "kid": "nothing-but-auth-key-01",
                    "x": "3-xR-ApvKYCKtXxjvypxIb4tHJSUTHCl0uUYVAvP6sE",
                    "y": "jkQdXwStFmrJjHuWw8PE_AG43c4OQwd6-Rkr4sPiC7Y"
                }
            }]
        }),
        vec!["auth-key-01"],
        DidSidekicksErrorKind::NonExistingKeyReferenced,
        "non-existing key referenced in the DID document"
    )]
    // cases to test
    // - did doc with jwks directly (DidDoc)
    // - did doc with jwks indirectly (DidDocNormalized)
    // - did doc invalid
    fn test_get_key_from_did_doc_failure(
        #[case] did_doc: Value,
        #[case] key_ids: Vec<&str>,
        #[case] expected_error_kind: DidSidekicksErrorKind,
        #[case] error_contains: &str,
    ) {
        key_ids.iter().for_each(|key_id| {
            assert_error(
                did_doc::get_key_from_did_doc(did_doc.to_string(), key_id.to_string()),
                expected_error_kind,
                error_contains,
            );
        })
    }
}
