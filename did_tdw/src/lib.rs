// SPDX-License-Identifier: MIT

//! This project implements the following things:
//!
//! - General util structs reused by other libraries of swiyu-admin-ch
//! - Trust did web according to the specification [trust-did-web](https://bcgov.github.io/trustdidweb/)
//!

extern crate core;

pub mod did_tdw;
pub mod did_tdw_jsonschema;
pub mod did_tdw_method_parameters;
pub mod errors;

// CAUTION All structs required by UniFFI bindings generator (declared in UDL) MUST also be "used" here
#[allow(unused_imports, reason = "required by the UniFFI compiler!")]
#[expect(clippy::allow_attributes, reason = "..")]
use did_sidekicks::did_doc::*;
#[allow(unused_imports, reason = "required by the UniFFI compiler!")]
#[expect(clippy::allow_attributes, reason = "..")]
use did_sidekicks::errors::*;
#[allow(unused_imports, reason = "required by the UniFFI compiler!")]
#[expect(clippy::allow_attributes, reason = "..")]
use did_tdw::*;
#[allow(unused_imports, reason = "required by the UniFFI compiler!")]
#[expect(clippy::allow_attributes, reason = "..")]
use did_tdw_jsonschema::*;
#[allow(unused_imports, reason = "required by the UniFFI compiler!")]
#[expect(clippy::allow_attributes, reason = "..")]
use did_tdw_method_parameters::*;
#[allow(unused_imports, reason = "required by the UniFFI compiler!")]
#[expect(clippy::allow_attributes, reason = "..")]
use errors::*;

uniffi::include_scaffolding!("did_tdw");

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "unwrap calls are panic-safe as long as test case setup is correct"
)]
#[expect(
    clippy::panic,
    reason = "no panic expected as long as test case setup is correct"
)]
mod test {
    use super::did_tdw::*;
    use crate::errors::*;
    use core::panic;
    use did_sidekicks::did_doc::*;
    use did_sidekicks::errors::{DidResolverError, DidResolverErrorKind};
    use rand::distributions::Alphanumeric;
    use rand::Rng as _;
    use rstest::{fixture, rstest};
    use serde_json::Value as JsonValue;
    use std::fs;
    use std::path::Path;

    #[fixture]
    fn unique_base_url() -> String {
        let random_thing: String = rand::thread_rng()
            .sample_iter(Alphanumeric)
            .take(7)
            .map(char::from)
            .collect();
        format!("https://localhost:8000/{random_thing}")
    }

    // The first four testcases come from: https://identity.foundation/didwebvh/v0.3/#example-7
    #[rstest]
    #[case(
        "did:tdw:{SCID}:example.com",
        "https://example.com/.well-known/did.jsonl"
    )]
    #[case(
        "did:tdw:{SCID}:issuer.example.com",
        "https://issuer.example.com/.well-known/did.jsonl"
    )]
    #[case(
        "did:tdw:{SCID}:example.com:dids:issuer",
        "https://example.com/dids/issuer/did.jsonl"
    )]
    #[case(
        "did:tdw:{SCID}:example.com%3A3000:dids:issuer",
        "https://example.com:3000/dids/issuer/did.jsonl"
    )]
    #[case( // internationalized domain
        "did:tdw:QMySCID:jp納豆.例.jp:用户",
        "https://xn--jp-cd2fp15c.xn--fsq.jp/%E7%94%A8%E6%88%B7/did.jsonl"
    )]
    #[case( // path with null
        "did:tdw:QMySCID:example.com:\0:test",
        "https://example.com/%00/test/did.jsonl"
    )]
    #[case( // path with accents
        "did:tdw:QMySCID:example.com:ar̷̠̗̠͙̜̘͚̼͖̗̯̥̥͙̜͊̈́͆́̽̆̔̏̓͌͑t",
        "https://example.com/ar%CC%B7%CC%A0%CC%97%CC%A0%CD%99%CC%9C%CC%98%CD%9A%CC%BC%CD%96%CC%97%CC%AF%CC%A5%CC%A5%CD%99%CC%9C%CD%8A%CC%88%CC%81%CD%86%CC%81%CC%BD%CC%86%CC%94%CC%8F%CC%93%CD%8C%CD%91t/did.jsonl"
    )]
    #[case( // domain accents
        "did:tdw:QMySCID:ar̷̠̗̠͙̜̘͚̼͖̗̯̥̥͙̜͊̈́͆́̽̆̔̏̓͌͑t.com",
        "https://xn--art-ldca4al3dubi2aam9cc3db7ga2r5fte5a8stdvcxh5erdiy.com/.well-known/did.jsonl"
    )]
    #[case( // domain with emoji
        "did:tdw:QMySCID:I❤You.com",
        "https://xn--iyou-lw4b.com/.well-known/did.jsonl"
    )]
    #[case(
        "did:tdw:QMySCID:example%2Ecom",
        "https://example.com/.well-known/did.jsonl"
    )]
    #[case(
        "did:tdw:{SCID}:ampl.com%3A", // port after ':' is optional
        "https://ampl.com/.well-known/did.jsonl"
    )]
    #[case(
        "did:tdw:{SCID}:example.com%3A3000:dids:issuer",
        "https://example.com:3000/dids/issuer/did.jsonl"
    )]
    #[case(
        "did:tdw:QMySCID:localhost%3A8000:123:456",
        "https://localhost:8000/123/456/did.jsonl"
    )]
    #[case(
        "did:tdw:QMySCID:localhost%3A8000",
        "https://localhost:8000/.well-known/did.jsonl"
    )]
    #[case("did:tdw:QMySCID:localhost", "https://localhost/.well-known/did.jsonl")]
    #[case(
        "did:tdw:QMySCID:admin.ch%3A8000:123:456",
        "https://admin.ch:8000/123/456/did.jsonl"
    )]
    #[case(
        "did:tdw:QMySCID:admin.ch%3A8000",
        "https://admin.ch:8000/.well-known/did.jsonl"
    )]
    #[case("did:tdw:QMySCID:admin.ch", "https://admin.ch/.well-known/did.jsonl")]
    #[case(
        "did:tdw:QMySCID:sub.admin.ch",
        "https://sub.admin.ch/.well-known/did.jsonl"
    )]
    #[case(
        "did:tdw:QMySCID:sub.admin.ch:mypath:mytrala",
        "https://sub.admin.ch/mypath/mytrala/did.jsonl"
    )]
    #[case("did:tdw:QMySCID:localhost:%2A", "https://localhost/%2A/did.jsonl")]
    #[case(
        "did:tdw:QMySCID:localhost:.hidden",
        "https://localhost/.hidden/did.jsonl"
    )]
    //#[expect(clippy::non_ascii_literal, reason = "..")]
    fn test_tdw_to_url_conversion(#[case] tdw: String, #[case] url: String) {
        let tdw_id = TrustDidWebId::parse_did_tdw(tdw).unwrap();
        let resolved_url = tdw_id.get_url();
        assert_eq!(resolved_url, url)
    }

    #[rstest]
    #[case("did:webvh:QMySCID::test")]
    #[case("did:webvh:QMySCID:.")]
    #[case("did:webvh:QMySCID:\0:test")]
    #[case("did:webvh:QMySCID:example\0:test")]
    #[case("did:webvh:QMySCID:example.")]
    #[case("did:webvh:QMySCID:my\0invalid.url:test")]
    #[case("did:webvh:QMySCID:0.0.0.256:test")]
    #[case("did:webvh:QMySCID:ampl.com%3B")]
    #[case("did:webvh:QMySCID:ampl.com%2Ftest")]
    #[case("did:webvh:{SCID}:[0:0::1]")] // ip v6 address
    fn test_webvh_to_url_conversion_invalid(#[case] tdw: String) {
        let res = TrustDidWebId::parse_did_tdw(tdw);
        assert!(
            res.is_err(),
            "URL '{}' should be invalid",
            res.unwrap().get_url()
        );
    }

    #[rstest]
    #[case("did:xyz:QMySCID:localhost%3A8000:123:456")]
    #[case("url:tdw:QMySCID:localhost%3A8000:123:456")]
    fn test_tdw_to_url_conversion_error_kind_method_not_supported(#[case] tdw: String) {
        match TrustDidWebId::parse_did_tdw(tdw) {
            Err(err) => assert_eq!(
                err.kind(),
                TrustDidWebIdResolutionErrorKind::MethodNotSupported
            ),
            _ => panic!(
                "Expected error kind: {:?}",
                TrustDidWebIdResolutionErrorKind::MethodNotSupported
            ),
        }
    }

    #[rstest]
    #[case("did:tdw")] // method only
    #[case("did:tdw::")] // method only
    #[case("did:tdw:::")] // method only
    #[case("did:tdw::::")] // method only
    #[case("did:tdw:SCID")] // no fully qualified domain
    #[case("did:tdw:SCID:::")] // no fully qualified domain
    #[case("did:tdw:SCID::123:")] // no fully qualified domain
    #[case("did:tdw::localhost%3A8000:123:456")] // empty/missing SCID
    fn test_tdw_to_url_conversion_error_kind_invalid_method_specific_id(#[case] tdw: String) {
        match TrustDidWebId::parse_did_tdw(tdw) {
            Err(err) => assert_eq!(
                err.kind(),
                TrustDidWebIdResolutionErrorKind::InvalidMethodSpecificId
            ),
            _ => panic!(
                "Expected error kind: {:?}",
                TrustDidWebIdResolutionErrorKind::InvalidMethodSpecificId
            ),
        }
    }

    /// A rather trivial assertion helper around DidResolverError.
    pub fn assert_trust_did_web_error<T>(
        res: Result<T, DidResolverError>,
        expected_kind: DidResolverErrorKind,
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
            // CAUTION Visible (on the console) only when running 'cargo test' with '-- --nocapture' option
            "expected '{}' is not mentioned in '{}'",
            error_contains,
            err_to_string
        );
    }

    #[rstest]
    #[case("test_data/generated_by_didtoolbox_java/v010_did.jsonl")]
    #[case(
        "test_data/generated_by_didtoolbox_java/v_0_3_eid_conform/did_doc_without_controller.jsonl"
    )]
    //#[case("test_data/generated_by_tdw_js/unique_update_keys.jsonl")]
    fn test_generate_version_id(#[case] did_log_raw_filepath: String) {
        let did_log_raw = fs::read_to_string(Path::new(&did_log_raw_filepath)).unwrap();
        let did_document = TrustDidWebDidLog::try_from(did_log_raw).unwrap();
        for did_log in did_document.did_log_entries {
            let generated_version_id = did_log.build_version_id().unwrap();
            assert!(generated_version_id == did_log.version_id);
        }
    }

    #[rstest]
    /* TODO cleanup and add more test cases
    #[case(
        "test_data/generated_by_tdw_js/single_update_key.jsonl",
        "did:tdw:QmXjp5qhSEvm8oXip43cDX62hZhHZdAMYv7Magy1tkffSz:example.com"
    )]
    #[case(
        "test_data/generated_by_tdw_js/unique_update_keys.jsonl",
        "did:tdw:QmXjp5qhSEvm8oXip43cDX62hZhHZdAMYv7Magy1tkffSz:example.com"
    )]
    #[case(
        "test_data/generated_by_tdw_js/alternate_update_keys.jsonl",
        "did:tdw:QmdSU7F2rF8r4m6GZK7Evi2tthfDDxhw3NppU8pJMbd2hB:example.com"
    )]
    */
    #[case(
        "test_data/generated_by_didtoolbox_java/legacy/did-1.0.0-RC1.jsonl",
        "did:tdw:QmPEZPhDFR4nEYSFK5bMnvECqdpf1tPTPJuWs9QrMjCumw:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:9a5559f0-b81c-4368-a170-e7b4ae424527"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/legacy/did-1.0.0.jsonl",
        "did:tdw:Qmb95hd5nGZvJY3q6mGcmZrLTNYMmzJYuMx94VNFb27oi9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/legacy/did-1.1.0.jsonl",
        "did:tdw:QmVZsmZqj1pGqqdzDeKLwBWZXo5aDucFsYddw9fKPb7e5Z:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/legacy/did-1.2.0.jsonl",
        "did:tdw:QmX4MSeKo17fvrZQbkHSB4BfkEtJXiGhnbnSAu6oCMYtub:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/legacy/did-1.3.0.jsonl",
        "did:tdw:Qmdjf4BZUtYnNKWbL5Lj9MqTeqxq5UQBbgU3p5wriwTzDV:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/legacy/did-1.3.1.jsonl",
        "did:tdw:QmWroVHz78FM6ugJ6MkaD4yu2ihkKmWFiKDcDPXu1AeS1d:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/legacy/did-1.4.0.jsonl",
        "did:tdw:QmSTru6WjboQ24pVdK21AuX4rV6CEqQSjFQKANaXwGM6wz:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/legacy/did-1.4.1.jsonl",
        "did:tdw:QmU8WbF9dMzTMU1snugNConzA4tHvPaXRqzyjXn77pUY8G:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/legacy/did-1.4.2.jsonl",
        "did:tdw:QmYZ5Fdraxo7AMWGLFALawKiq2e5Q17ZUj4XQ5bVwHJYV5:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/legacy/did-1.5.0.jsonl",
        "did:tdw:QmY2E8J9bKkW2mTYQZZXCMMquRtMzaok2jgtHjumWV2E7W:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/legacy/did-1.6.0.jsonl",
        "did:tdw:QmQCsMWrtVWkQAoKg17RmdmnFwhSa8yroKn8udxek22ijs:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/legacy/did-1.7.0.jsonl",
        "did:tdw:QmNqS1CByWQNYTV9X2gDkEziCnpgGbUuMnZfZA1VFzf2Jy:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/v_0_3_eid_conform/did_doc_without_controller.jsonl",
        "did:tdw:QmZf4Pb1GoPdYaZBF3Sc1nVspXef4qc816C7eBzzuXMoGk:domain.com%3A8080:path1:path2"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/v400_did.jsonl",
        "did:tdw:QmPsui8ffosRTxUBP8vJoejauqEUGvhmWe77BNo1StgLk7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"
    )]
    fn test_resolve_did_tdw(#[case] did_log_raw_filepath: String, #[case] did_url: String) {
        let did_log_raw = fs::read_to_string(Path::new(&did_log_raw_filepath)).unwrap();

        // Read the newly did doc
        let tdw_v1 = TrustDidWeb::resolve(did_url.clone(), did_log_raw).unwrap();
        assert!(tdw_v1.get_did_doc().is_some());
        let did_doc = tdw_v1.get_did_doc().unwrap(); // panic-safe unwrap call (as long as #case setup is correct)
        let did_doc_v1: JsonValue = serde_json::from_str(&did_doc).unwrap();
        let did_doc_obj_v1 = DidDoc::from_json(&did_doc).unwrap();

        assert!(!did_doc_v1["@context"].to_string().is_empty());
        match did_doc_v1["id"] {
            JsonValue::String(ref doc_v1) => {
                assert!(doc_v1.eq(did_url.as_str()))
            }
            _ => panic!("Invalid did doc"),
        }
        assert!(!did_doc_v1["verificationMethod"].to_string().is_empty());
        assert!(!did_doc_v1["authentication"].to_string().is_empty());
        assert!(!did_doc_v1["controller"].to_string().is_empty());

        assert_eq!(did_doc_obj_v1.id, tdw_v1.get_did());
        assert!(!did_doc_obj_v1.verification_method.is_empty());
        assert!(!did_doc_obj_v1.authentication.is_empty());
        //assert!(!did_doc_v1_obj.controller.is_empty());
    }

    /* TODO implement the test case using proper input
    #[rstest]
    #[case(
        "test_data/generated_by_tdw_js/deactivated.jsonl",
        "did:tdw:QmdSU7F2rF8r4m6GZK7Evi2tthfDDxhw3NppU8pJMbd2hB:example.com"
    )]
    fn test_read_did_tdw_deactivated(
        #[case] did_log_raw_filepath: String,
        #[case] did_url: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        //let did_log_raw_filepath = "test_data/generated_by_tdw_js/deactivated.jsonl";
        //let did_url: String = String::from("did:tdw:QmdSU7F2rF8r4m6GZK7Evi2tthfDDxhw3NppU8pJMbd2hB:example.com");

        let did_log_raw = fs::read_to_string(Path::new(&did_log_raw_filepath))?;

        // Read the newly did doc
        let tdw_v1 = TrustDidWeb::read(did_url.clone(), did_log_raw)?;
        let did_doc_json_v1: JsonValue = serde_json::from_str(&tdw_v1.get_did_doc())?;
        let did_doc_obj_v1 = DidDoc::from_json(&tdw_v1.get_did_doc())?;

        assert!(!did_doc_json_v1["@context"].to_string().is_empty());
        match did_doc_json_v1["id"] {
            JsonValue::String(ref doc_v1) => {
                assert!(doc_v1.eq(did_url.as_str()), "DID mismatch")
            }
            _ => panic!("Invalid did doc"),
        }
        assert!(!did_doc_json_v1["verificationMethod"].to_string().is_empty());
        assert!(!did_doc_json_v1["authentication"].to_string().is_empty());
        assert!(!did_doc_json_v1["controller"].to_string().is_empty());

        assert_eq!(did_doc_obj_v1.id, tdw_v1.get_did());
        // CAUTION after deactivation these should be empty
        assert!(did_doc_obj_v1.verification_method.is_empty());
        assert!(did_doc_obj_v1.authentication.is_empty());
        //assert!(!did_doc_v1_obj.controller.is_empty());

        Ok(())
    }
     */
}
