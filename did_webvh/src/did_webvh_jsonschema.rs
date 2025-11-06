// SPDX-License-Identifier: MIT

use did_sidekicks::did_jsonschema::DidLogEntryJsonSchema;
use rust_embed::Embed;
use core::str::from_utf8;

/// As defined by https://identity.foundation/didwebvh/v1.0 bzt w.r.t. (eID-conformity) addendum:
/// - https://confluence.bit.admin.ch/display/EIDTEAM/DID+Log+Conformity+Check
/// - https://confluence.bit.admin.ch/display/EIDTEAM/DID+Doc+Conformity+Check
const DID_LOG_ENTRY_JSONSCHEMA_V_1_0_EID_CONFORM_FILENAME: &str =
    "did_log_jsonschema_v_1_0_eid_conform.json";

/// As defined by https://identity.foundation/didwebvh/v1.0
const DID_LOG_ENTRY_JSONSCHEMA_V_1_0_FILENAME: &str = "did_log_jsonschema_v_1_0.json";

#[derive(Embed)]
#[folder = "src/embed/jsonschema"]
#[include = "*.json"]
struct WebVerifiableHistoryDidLogJsonSchemaEmbedFolder;

/// W.r.t. corresponding specification version available at https://identity.foundation/didwebvh
///
/// # CAUTION The single currently supported version is: v1.0
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum WebVerifiableHistoryDidLogEntryJsonSchema {
    /// As (strictly) specified by https://identity.foundation/didwebvh/v1.0
    V1_0,
    /// As defined by https://identity.foundation/didwebvh/v1.0 but w.r.t. (eID-conformity) addendum:
    /// - https://confluence.bit.admin.ch/x/r_0EMw (DID Log Conformity Check)
    /// - https://confluence.bit.admin.ch/x/3e0EMw (DID Doc Conformity Check)
    V1_0EidConform,
}

impl DidLogEntryJsonSchema for WebVerifiableHistoryDidLogEntryJsonSchema {
    /// Converts this type into a corresponding JSON schema in UTF-8 format.
    #[inline]
    #[expect(clippy::unwrap_used, reason = "..")]
    fn get_json_schema(&self) -> String {
        let file_name = match *self {
            Self::V1_0 => DID_LOG_ENTRY_JSONSCHEMA_V_1_0_FILENAME,
            Self::V1_0EidConform => DID_LOG_ENTRY_JSONSCHEMA_V_1_0_EID_CONFORM_FILENAME,
        };
        // CAUTION This unwrap() call will panic only if file denoted by DID_LOG_ENTRY_JSONSCHEMA_V_*_FILENAME does not exist
        let schema_file = WebVerifiableHistoryDidLogJsonSchemaEmbedFolder::get(file_name).unwrap();
        // CAUTION This unwrap() call will panic only if file denoted by schema_file is not UTF-8
        from_utf8(schema_file.data.as_ref()).unwrap().to_owned()
    }
}

#[cfg(test)]
mod test {
    use crate::did_webvh_jsonschema::WebVerifiableHistoryDidLogEntryJsonSchema;
    use did_sidekicks::did_jsonschema::{DidLogEntryJsonSchema, DidLogEntryValidator, DidLogEntryValidatorErrorKind};
    use rstest::rstest;
    use serde_json::{json, Value};

    #[rstest]
    // CAUTION V1_0-specific (happy path) case
    #[case(vec![WebVerifiableHistoryDidLogEntryJsonSchema::V1_0], json!({
    "versionId": "1-QmVCzWgVX2isJE6tsmUcHnNHQJ9WXZb9A26VpkxptB2fqb",
    "versionTime": "2025-05-09T22:33:41Z",
    "parameters": {
      "witness": {
        "threshold": 2,
        "witnesses": [
          {
            "id": "did:key:z6MkrMuMdd6hTJmwf8e6WZz643b7JxYiAnWAFsorDLkaZF5i"
          },
          {
            "id": "did:key:z6MkgXvUbnhiVu1H6SmiPVzC9xpdnCFyE5X2AgxRY4PrbbWN"
          },
          {
            "id": "did:key:z6MkvZ7MQfnCewK2qjqXpDAKBcExAPpLbpWv8khQxZS3RmTj"
          }
        ]
      },
      "updateKeys": [
        "z6Mkh8Pzehru4LVBRftuiLzpMchSzNWbEytus13N8fsfpobs"
      ],
      "nextKeyHashes": [
        "QmRossAYEwzTgLNQx8zEzZPfxUU1WGSZpCFA6T8ZPku3V7"
      ],
      "method": "did:webvh:1.0",
      "scid": "QmNdazvnrgei4agYFMVJjYduyZSYHcYWnHEgNW7A1sMUoU"
    },
    "state": {
      "@context": [
        "https://www.w3.org/ns/did/v1"
      ],
      "id": "did:webvh:QmNdazvnrgei4agYFMVJjYduyZSYHcYWnHEgNW7A1sMUoU:domain.example"
    },
    "proof": [
      {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": "did:key:z6Mkh8Pzehru4LVBRftuiLzpMchSzNWbEytus13N8fsfpobs#z6Mkh8Pzehru4LVBRftuiLzpMchSzNWbEytus13N8fsfpobs",
        "created": "2025-05-09T22:33:41Z",
        "proofPurpose": "assertionMethod",
        "proofValue": "z4rDHfJZ5hxVTu3TYnTLo2tTLyRFfBpzgkoWMnkLcg6tVXerkTXmXduHbM1oaMakhrc6sFt1A5Nj6AH5y63EFJysi"
      }
    ]
  }), true, ""
    )] // example did log entry from https://github.com/decentralized-identity/didwebvh-py/blob/main/sample-diddoc/did.jsonl
    #[case(vec![WebVerifiableHistoryDidLogEntryJsonSchema::V1_0], json!({
        "versionId": "1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR",
        "versionTime": "2012-12-12T12:12:12Z",
        "parameters": {
            "method": "did:webvh:1.0",
            "scid": "QmZ5tnGo1fHNEzHDpG2Bx5dmT3eGNmBY9QATtm6DrFMzcH",
            "updateKeys": [
              "z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP",
              "z6Mkwf4PgXLq8sRfucTggtZXmigKZP7gQhFamk3XHGV54QvF"
            ],
            "portable": false,
            "nextKeyHashes": [],
            "witness": {
                "threshold": 0,
                "witnesses": []
            },
            "deactivated": false
        },
        "state": {
            "id": "did:webvh:QmZ5tnGo1fHNEzHDpG2Bx5dmT3eGNmBY9QATtm6DrFMzcH:example.com",
            "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/jwk/v1"],
            "controller": "did:webvh:QmZ5tnGo1fHNEzHDpG2Bx5dmT3eGNmBY9QATtm6DrFMzcH:example.com",
            "verificationMethod": [{
                "id": "did:webvh:QmT7BM5RsM9SoaqAQKkNKHBzSEzpS2NRzT2oKaaaPYPpGr:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01",
                "controller": "did:webvh:QmT7BM5RsM9SoaqAQKkNKHBzSEzpS2NRzT2oKaaaPYPpGr:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
                "type": "JsonWebKey2020",
                "publicKeyJwk":{
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "N4hbTf7x1eWwjqHOQpAB469BwLYfFzIw7QbSa-vv8VM",
                    "y": "eebnhG9Fmmw2OwW4BPdKJMKm8wGgo18yp_Q2FpvU57U",
                    "kid": "auth-key-01"
                }
            }],
        },
        "proof": [{
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "created": "2012-12-12T12:12:12Z",
            "verificationMethod": "did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP",
            "proofPurpose": "assertionMethod",
            "proofValue": "z4a92V6EKmWvURx99HXVTEM6KJhbVZZ1s4qN8HJXTMesSoDJx1VpTNtuNUpae2eHpXXKwBGjtCYC2EQK7b6eczmnp",
            "challenge": "1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR"
        }]}), true, "")]
    // CAUTION V1_0EidConform-specific (happy path) case
    #[case(vec![WebVerifiableHistoryDidLogEntryJsonSchema::V1_0EidConform], json!({
        "versionId": "1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR",
        "versionTime": "2012-12-12T12:12:12Z",
        "parameters": {
            "method": "did:webvh:1.0",
            "scid": "QmZ5tnGo1fHNEzHDpG2Bx5dmT3eGNmBY9QATtm6DrFMzcH",
            "updateKeys": [
              "z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP",
              "z6Mkwf4PgXLq8sRfucTggtZXmigKZP7gQhFamk3XHGV54QvF"
            ],
            "portable": false,
            "nextKeyHashes": [],
            "witness": {},
            "deactivated": false
        },
        "state": {
            "id": "did:webvh:QmZ5tnGo1fHNEzHDpG2Bx5dmT3eGNmBY9QATtm6DrFMzcH:example.com",
            "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/jwk/v1"],
            "verificationMethod": [{
                "id": "did:webvh:QmT7BM5RsM9SoaqAQKkNKHBzSEzpS2NRzT2oKaaaPYPpGr:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01",
                "type": "JsonWebKey2020",
                "publicKeyJwk":{
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "N4hbTf7x1eWwjqHOQpAB469BwLYfFzIw7QbSa-vv8VM",
                    "y": "eebnhG9Fmmw2OwW4BPdKJMKm8wGgo18yp_Q2FpvU57U",
                    "kid": "auth-key-01"
                }
            }],
        },
        "proof": [{
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "created": "2012-12-12T12:12:12Z",
            "verificationMethod": "did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP",
            "proofPurpose": "authentication",
            "proofValue": "z4a92V6EKmWvURx99HXVTEM6KJhbVZZ1s4qN8HJXTMesSoDJx1VpTNtuNUpae2eHpXXKwBGjtCYC2EQK7b6eczmnp",
            "challenge": "1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR"
        }],}), true, "")]
    #[case(vec![WebVerifiableHistoryDidLogEntryJsonSchema::V1_0, WebVerifiableHistoryDidLogEntryJsonSchema::V1_0EidConform], json!({
        "versionId": "invalid-version-id",
        "versionTime": "2012-12-12T12:12:12Z",
        "parameters": {"method": "did:webvh:1.0"},
        "state": {},
        "proof": [{
            "created": "2012-12-12T12:12:12Z",
            "challenge": "1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR",
            "proofValue": "z4a92V6EKmWvURx99HXVTEM6KJhbVZZ1s4qN8HJXTMesSoDJx1VpTNtuNUpae2eHpXXKwBGjtCYC2EQK7b6eczmnp",
        }],}), false, "\"invalid-version-id\" does not match \"^[1-9][0-9]*-Q[1-9a-zA-NP-Z]{45,}$\""
    )]
    #[case(vec![WebVerifiableHistoryDidLogEntryJsonSchema::V1_0, WebVerifiableHistoryDidLogEntryJsonSchema::V1_0EidConform], json!({
        "versionId": "1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR",
        "versionTime": "invalid-version-time",
        "parameters": {"method": "did:webvh:1.0"},
        "state": {},
        "proof": [{
            "created": "2012-12-12T12:12:12Z",
            "challenge": "1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR",
            "proofValue": "z4a92V6EKmWvURx99HXVTEM6KJhbVZZ1s4qN8HJXTMesSoDJx1VpTNtuNUpae2eHpXXKwBGjtCYC2EQK7b6eczmnp",
        }],}), false, "Datetime not in ISO8601 format")]
    #[case(vec![WebVerifiableHistoryDidLogEntryJsonSchema::V1_0, WebVerifiableHistoryDidLogEntryJsonSchema::V1_0EidConform], json!({
        "versionId": "1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR",
        "versionTime": "2012-12-12T12:12:12Z", 
        "parameters": {"":""},
        "state": {}, 
        "proof": [{"":""}]}), false, "Additional properties are not allowed ('' was unexpected)")]
    #[case(vec![WebVerifiableHistoryDidLogEntryJsonSchema::V1_0, WebVerifiableHistoryDidLogEntryJsonSchema::V1_0EidConform], json!({
        "versionId": "1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR",
        "versionTime": "2012-12-12T12:12:12Z", 
        "parameters": {},
        "state": {"id": "did:webvh:QmT7BM5RsM9SoaqAQKkNKHBzSEzpS2NRzT2oKaaaPYPpGr:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01"}, 
        "proof": [{"":""}]}), false, "\"@context\" is a required property"
    )] // params may be empty, but DID doc must be complete
    #[case(vec![WebVerifiableHistoryDidLogEntryJsonSchema::V1_0, WebVerifiableHistoryDidLogEntryJsonSchema::V1_0EidConform], json!({
        "versionId": "1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR",
        "versionTime": "2012-12-12T12:12:12Z", 
        "parameters": {},
        "state": {
            "id": "did:webvh:QmT7BM5RsM9SoaqAQKkNKHBzSEzpS2NRzT2oKaaaPYPpGr:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
            "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/jwk/v1"],
        }, 
        "proof": [{}]}), false, "\"type\" is a required property")] // proof must not be empty
    #[case(vec![WebVerifiableHistoryDidLogEntryJsonSchema::V1_0EidConform], json!({
        "versionId": "1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR",
        "versionTime": "2012-12-12T12:12:12Z",
        "parameters": {
            "method": "did:webvh:1.0",
            "scid": "QmZ5tnGo1fHNEzHDpG2Bx5dmT3eGNmBY9QATtm6DrFMzcH",
            "updateKeys": [
              "z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP",
              "z6Mkwf4PgXLq8sRfucTggtZXmigKZP7gQhFamk3XHGV54QvF"
            ],
            "portable": false,
            "nextKeyHashes": [
                "invalid-key-hash"
            ],
            "witness": {},
            "deactivated": false
        },
        "state": {
            "id": "did:webvh:QmZ5tnGo1fHNEzHDpG2Bx5dmT3eGNmBY9QATtm6DrFMzcH:example.com",
            "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/jwk/v1"],
            "verificationMethod": [{
                "id": "did:webvh:QmT7BM5RsM9SoaqAQKkNKHBzSEzpS2NRzT2oKaaaPYPpGr:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01",
                "type": "JsonWebKey2020",
                "publicKeyJwk":{
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "N4hbTf7x1eWwjqHOQpAB469BwLYfFzIw7QbSa-vv8VM",
                    "y": "eebnhG9Fmmw2OwW4BPdKJMKm8wGgo18yp_Q2FpvU57U",
                    "kid": "auth-key-01"
                }
            }],
        },
        "proof": [{
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "created": "2012-12-12T12:12:12Z",
            "verificationMethod": "did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP",
            "proofPurpose": "authentication",
            "proofValue": "z4a92V6EKmWvURx99HXVTEM6KJhbVZZ1s4qN8HJXTMesSoDJx1VpTNtuNUpae2eHpXXKwBGjtCYC2EQK7b6eczmnp",
            "challenge": "1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR"
        }],}), false, "\"invalid-key-hash\" does not match \"^Q[1-9a-zA-NP-Z]{45,}$\"")]
    fn test_validate_using_schema(
        #[case] schemata: Vec<WebVerifiableHistoryDidLogEntryJsonSchema>,
        #[case] instance: Value,
        #[case] expected: bool,
        #[case] err_contains_pattern: &str,
    ) {
        schemata.iter().for_each(|schema| {
            let sch: &dyn DidLogEntryJsonSchema = schema;
            let validator = DidLogEntryValidator::from(sch);

            //let is_valid = validator.validate(instance.to_string());
            let is_valid = validator.validate_str(instance.to_string().as_str());

            assert_eq!(expected, is_valid.is_ok());
            assert_eq!(!expected, is_valid.is_err());
            if !expected {
                assert!(is_valid.is_err_and(|err| {
                    assert_eq!(err.kind(), DidLogEntryValidatorErrorKind::ValidationError);
                    assert!(
                        err.to_string().contains(err_contains_pattern),
                        "got: '{}', expected '{}'",
                        err,
                        err_contains_pattern
                    );
                    true
                }));
            }
        });
    }
}
