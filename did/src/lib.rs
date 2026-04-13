// SPDX-License-Identifier: MIT
#[macro_use]
extern crate lazy_static;

#[allow(unused_imports, reason = "required by the UniFFI compiler!")]
#[expect(clippy::allow_attributes, reason = "..")]
use crate::did::*;

pub mod did;

#[allow(unused_imports, reason = "required by the UniFFI compiler!")]
#[expect(clippy::allow_attributes, reason = "..")]
use did_sidekicks::did_doc::{DidDoc, DidDocExtended};
//use did_sidekicks::errors::DidResolverError;

uniffi::include_scaffolding!("did");

#[cfg(test)]
mod test {
    use did_webvh::did_webvh::WebVerifiableHistory;
    use rstest::rstest;
    use serde_json::json;

    use crate::did::{DidResolveError, get_metadata_from_error};

    #[test]
    fn foo() {
        let didresolvererror = DidResolveError::SerializationFailed("My Error message".into());
        let foo = get_metadata_from_error(didresolvererror);
        panic!("Message: {}", foo);
    }

    // TODO@MP used for testing during development
    #[rstest]
    pub fn bar() {
        let did_webvh = "did:webvh:Qmb8aoucR7eBFKyZHJgKivUTQhYmzSoi8mM1eDZoQYzefo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085".to_string();

        // let did_log = r#"{"versionId":"1-QmPqd7w6vh1Q4vUynVH7q7FBKapWLX8Sjjj5ALaTbraF7X","versionTime":"2026-03-16T13:04:57Z","parameters":{"method":"did:webvh:1.0","scid":"Qmb8aoucR7eBFKyZHJgKivUTQhYmzSoi8mM1eDZoQYzefo","updateKeys":["z6Mkfi729SiiMBWKNqbJEgyHgckSr77Ddf6T1cvoXktSuKxX"],"portable":false},"state":{"id":"did:webvh:Qmb8aoucR7eBFKyZHJgKivUTQhYmzSoi8mM1eDZoQYzefo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","authentication":["did:webvh:Qmb8aoucR7eBFKyZHJgKivUTQhYmzSoi8mM1eDZoQYzefo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-auth-key-01"],"assertionMethod":["did:webvh:Qmb8aoucR7eBFKyZHJgKivUTQhYmzSoi8mM1eDZoQYzefo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-assert-key-01"],"verificationMethod":[{"id":"did:webvh:Qmb8aoucR7eBFKyZHJgKivUTQhYmzSoi8mM1eDZoQYzefo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-auth-key-01","controller":"did:webvh:Qmb8aoucR7eBFKyZHJgKivUTQhYmzSoi8mM1eDZoQYzefo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"-MUDoZjNImUbo0vNmdAqhAOPdJoptUC0tlK9xvLrqDg","y":"Djlu_TF69xQF5_L3px2FmCDQksM_fIp6kKbHRQLVIb0"}},{"id":"did:webvh:Qmb8aoucR7eBFKyZHJgKivUTQhYmzSoi8mM1eDZoQYzefo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-assert-key-01","controller":"did:webvh:Qmb8aoucR7eBFKyZHJgKivUTQhYmzSoi8mM1eDZoQYzefo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"wdET0dp6vq59s1yyVh_XXyIPPU9Co7PlcTPMRRXx85Y","y":"eThC9-NetN-oXA5WU0Dn0eed7fgHtsXs2E3mU82pA9k"}}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2026-03-16T13:04:57Z","verificationMethod":"did:key:z6Mkfi729SiiMBWKNqbJEgyHgckSr77Ddf6T1cvoXktSuKxX#z6Mkfi729SiiMBWKNqbJEgyHgckSr77Ddf6T1cvoXktSuKxX","proofPurpose":"assertionMethod","proofValue":"z3NuVk69v4fBHnmmZFc7aZ7mGXyNV8X2nxwHhysdF1SHrbderjpTqWVN5W4WJ5nK6dJMkAcCb2Ycn8oecuLVLDNWo"}]}"#.to_string();
        let did_log = json!({"versionId": "aoeu"}).to_string();
        let json: serde_json::Value =
            match WebVerifiableHistory::resolve(did_webvh.clone(), did_log.clone()) {
                Ok(_) => todo!(),
                Err(e) => serde_json::from_str(get_metadata_from_error(&e).as_str()).unwrap(),
            };
        panic!(
            "Resulting metadata: {}\n\nOriginal DID Log: {}",
            json, did_log
        )
    }

    #[rstest]
    #[case((
        "did:INVALID_METHOD:SCID:example.com".to_string(),
        include_str!("../test_data/generated_by_didtoolbox_java/did.jsonl").to_string(),
    ), "https://www.w3.org/ns/did#METHOD_NOT_SUPPORTED")]
    #[case((
        "did:webvh::example.com".to_string(),
        json!({"versionId": "foo"}).to_string(),
    ), "https://www.w3.org/ns/did#INVALID_DID")] // TODO@MP should produce empty SCID error...
    pub fn test_did_resolution_metadata(
        #[case] params: (String, String),
        #[case] expected_type: &str,
    ) {
        let did_resolution_metadata: serde_json::Value =
            match WebVerifiableHistory::resolve(params.0, params.1) {
                Ok(_) => panic!("Expected did resolution to fail"),
                Err(e) => serde_json::from_str(get_metadata_from_error(&e).as_str()).unwrap(),
            };
        let serde_json::Value::Object(map) = did_resolution_metadata else {
            panic!("Expected did_resolution_metadata to be an object.");
        };
        match map.get("error") {
            Some(error) => assert_eq!(error, "invalidDid"),
            None => panic!("Expected did_resolution_metadata to contain 'error'"),
        }

        let Some(serde_json::Value::Object(problem_details)) = map.get("problemDetails") else {
            panic!("'problemDetails' missing in did_resolution_metadata");
        };
        match problem_details.get("type") {
            Some(problem_type) => assert_eq!(problem_type, expected_type),
            None => panic!("Expected did_resolution_metadata.problem_details to contain 'type'"),
        }
    }
}
