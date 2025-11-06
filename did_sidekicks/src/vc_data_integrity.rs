// SPDX-License-Identifier: MIT

use crate::ed25519::*;
use crate::errors::DidSidekicksError;
use crate::jcs_sha256_hasher::JcsSha256Hasher;
use chrono::{serde::ts_seconds, DateTime, SecondsFormat, Utc};
use core::ops::Deref as _;
use hex;
use serde::{Deserialize, Serialize};
use serde_json::{
    json, Value::Array as JsonArray, Value::Null as JsonNull, Value::String as JsonString,
};

#[derive(Clone, Debug)]
#[expect(
    clippy::exhaustive_enums,
    reason = "further enum variants may be added in the future"
)]
pub enum CryptoSuiteType {
    Bbs2023,
    EcdsaRdfc2019,
    EcdsaJcs2019,
    EcdsaSd2019,
    EddsaRdfc2022,
    EddsaJcs2022,
}

impl core::fmt::Display for CryptoSuiteType {
    #[inline]
    /*#[expect(
        clippy::min_ident_chars,
        reason = "to prevent clippy::renamed_function_params warning"
    )]*/
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match *self {
            Self::Bbs2023 => write!(f, "bbs-2023"),
            Self::EcdsaRdfc2019 => write!(f, "ecdsa-rdfc-2019"),
            Self::EcdsaJcs2019 => write!(f, "ecdsa-jcs-2019"),
            Self::EcdsaSd2019 => write!(f, "ecdsa-sd-2019"),
            Self::EddsaRdfc2022 => write!(f, "eddsa-rdfc-2022"),
            Self::EddsaJcs2022 => write!(f, "eddsa-jcs-2022"),
        }
    }
}

/// As specified by https://www.w3.org/TR/vc-di-eddsa/#proof-configuration-eddsa-jcs-2022
#[derive(Clone)]
#[expect(clippy::exhaustive_structs, reason = "..")]
pub struct CryptoSuiteProofOptions {
    pub proof_type: String,
    pub crypto_suite: CryptoSuiteType,
    pub created: DateTime<Utc>,
    pub verification_method: String,
    pub proof_purpose: String,
    pub context: Option<Vec<String>>,
    pub challenge: Option<String>,
}

impl CryptoSuiteProofOptions {
    /// The only (super-potent) non-empty constructor.
    ///
    /// As nearly all arguments are optional, see [`Self::default()`] constructor for default values.
    #[inline]
    pub fn new(
        crypto_suite_type: Option<CryptoSuiteType>,
        created_dt: Option<DateTime<Utc>>,
        verification_method: String,
        proof_purpose: Option<String>,
        context: Option<Vec<String>>,
        challenge: Option<String>,
    ) -> Self {
        let mut options = Self::default();
        if let Some(crypto_suite) = crypto_suite_type {
            options.crypto_suite = crypto_suite;
        }
        if let Some(created) = created_dt {
            options.created = created; // otherwise take current time
        }

        options.verification_method = verification_method;
        if let Some(purpose) = proof_purpose {
            options.proof_purpose = purpose;
        }

        options.context = context;
        if let Some(ch) = challenge {
            options.challenge = ch.into();
        }
        options
    }

    /// The default constructor aligned with https://www.w3.org/TR/vc-di-eddsa/#proof-configuration-eddsa-jcs-2022, hence:
    ///
    /// - proof_type: "DataIntegrityProof"
    /// - crypto_suite: "eddsa-jcs-2022"
    /// - created: \<current datetime\>
    /// - proof_purpose: "authentication"
    #[expect(clippy::single_call_fn, reason = "..")]
    pub(crate) fn default() -> Self {
        Self {
            proof_type: "DataIntegrityProof".to_owned(),
            crypto_suite: CryptoSuiteType::EddsaJcs2022,
            created: Utc::now(), // fallback to current datetime
            verification_method: String::from(""),
            proof_purpose: "authentication".to_owned(),
            context: None,
            challenge: None,
        }
    }
}

// See https://www.w3.org/TR/vc-data-integrity/#dataintegrityproof
// For EdDSA Cryptosuites v1.0 suites, see https://www.w3.org/TR/vc-di-eddsa/#dataintegrityproof
#[derive(Serialize, Deserialize, Debug, Clone)]
#[expect(clippy::exhaustive_structs, reason = "..")]
pub struct DataIntegrityProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    #[serde(rename = "cryptosuite")]
    pub crypto_suite: String,
    #[serde(skip)]
    pub crypto_suite_type: Option<CryptoSuiteType>,
    #[serde(with = "ts_seconds")]
    // with = "ts_seconds" requires (in Cargo.toml):
    // chrono = { version = "0.4.39", features = ["serde"] }
    pub created: DateTime<Utc>,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    pub context: Option<Vec<String>>,
    pub challenge: Option<String>,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}
impl DataIntegrityProof {
    /// The non-empty parsing constructor featuring validation in terms of supported type/proofPurpose/cryptosuite
    #[inline]
    // TODO Ensure panic-safe indexing
    #[expect(clippy::indexing_slicing, reason = "see TODO")]
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "wildcard match ignorable as no further JSON variants are possible"
    )]
    pub fn from(json: String) -> Result<Self, DidSidekicksError> {
        let value = match serde_json::from_str(&json) {
            Ok(JsonArray(entry)) => {
                if entry.len() > 1 {
                    return Err(DidSidekicksError::InvalidDataIntegrityProof(
                        "A single proof is currently supported.".to_owned(),
                    ));
                }

                match entry.first() {
                    Some(first) => first.clone(),
                    None => {
                        return Err(DidSidekicksError::InvalidDataIntegrityProof(
                            "Empty proof array detected.".to_owned(),
                        ))
                    }
                }
            }
            Err(err) => {
                return Err(DidSidekicksError::InvalidDataIntegrityProof(format!(
                    "Malformed proof format, expected single-element JSON array: {err}"
                )))
            }
            _ => {
                return Err(DidSidekicksError::InvalidDataIntegrityProof(
                    "Malformed proof format, expected single-element JSON array".to_owned(),
                ))
            }
        };
        Ok(Self {
            proof_type: match value["type"].to_owned() {
                JsonString(str) => {
                    if str != "DataIntegrityProof" {
                        return Err(DidSidekicksError::InvalidDataIntegrityProof(
                            "Unsupported proof's type. Expected 'DataIntegrityProof'".to_owned(),
                        ));
                    }
                    str
                }
                _ => {
                    return Err(DidSidekicksError::InvalidDataIntegrityProof(
                        "Missing proof's type".to_owned(),
                    ))
                }
            },
            crypto_suite: match value["cryptosuite"].to_owned() {
                JsonString(str) => {
                    if str != CryptoSuiteType::EddsaJcs2022.to_string().deref() {
                        return Err(DidSidekicksError::InvalidDataIntegrityProof(format!(
                            "Unsupported proof's cryptosuite. Expected '{}'",
                            CryptoSuiteType::EddsaJcs2022
                        )));
                    }
                    str
                }
                _ => {
                    return Err(DidSidekicksError::InvalidDataIntegrityProof(
                        "Missing proof's cryptosuite".to_owned(),
                    ))
                }
            },
            crypto_suite_type: Some(CryptoSuiteType::EddsaJcs2022), // the only currently supported cryptosuite
            created: match value["created"].to_owned() {
                JsonString(str) => match DateTime::parse_from_rfc3339(&str) {
                    Ok(date) => date.to_utc(),
                    Err(err) => return Err(DidSidekicksError::InvalidDataIntegrityProof(
                        format!("Invalid proof's creation datetime format: {err}"),
                    ))
                },
                _ =>  return Err(DidSidekicksError::InvalidDataIntegrityProof(
                    "Missing proof's creation datetime.".to_owned(),
                )),
            },
            verification_method: match value["verificationMethod"].to_owned() {
                JsonString(str) => {
                    if !str.starts_with("did:key:") {
                        return Err(DidSidekicksError::InvalidDataIntegrityProof(
                            "Unsupported proof's verificationMethod. Expected prefix 'did:key:'"
                                .to_owned(),
                        ));
                    }
                    str
                }
                _ => {
                    return Err(DidSidekicksError::InvalidDataIntegrityProof(
                        "Missing proof's verificationMethod".to_owned(),
                    ))
                }
            },
            proof_purpose: match value["proofPurpose"].to_owned() {
                JsonString(str) => {
                    if str != "authentication" && str != "assertionMethod" {
                        return Err(DidSidekicksError::InvalidDataIntegrityProof(
                            "Unsupported proof's proofPurpose. Expected 'authentication' or 'assertionMethod'"
                                .to_owned(),
                        ));
                    }
                    str
                }
                _ => {
                    return Err(DidSidekicksError::InvalidDataIntegrityProof(
                        "Missing proof's proofPurpose".to_owned(),
                    ))
                }
            },
            context: match value["@context"].to_owned() {
                JsonArray(arr) => {
                    Some(
                        arr.into_iter()
                            .try_fold(Vec::new(), |mut acc, val| match val {
                                JsonString(str) => {
                                    acc.push(str);
                                    Ok(acc)
                                }
                                _ => Err(DidSidekicksError::InvalidDataIntegrityProof(
                                    "Invalid type of 'context' entry, expected a string."
                                        .to_owned(),
                                )),
                            })?,
                    )
                }
                JsonNull => None,
                _ => return Err(DidSidekicksError::InvalidDataIntegrityProof(
                    "Invalid format of 'context' entry, expected array of strings.".to_owned(),
                )),
            },
            challenge: match value["challenge"].to_owned() {
                JsonString(str) => Some(str),
                JsonNull => None,
                _ => return Err(DidSidekicksError::InvalidDataIntegrityProof(
                    "Wrong format of proof's challenge parameter. Expected a challenge of type string.".to_owned(),
                ))
            },
            proof_value: match value["proofValue"].to_owned() {
                JsonString(str) => str,
                JsonNull => return Err(DidSidekicksError::InvalidDataIntegrityProof(
                    "Missing proofValue parameter. Expected a proofValue of type string.".to_owned(),
                )),
                _ => return Err(DidSidekicksError::InvalidDataIntegrityProof(
                    "Wrong format of proofValue parameter. Expected a proofValue of type string.".to_owned(),
                ))
            },
        })
    }

    /// Construct a serde_json::Value from this DataIntegrityProof
    #[inline]
    #[expect(clippy::indexing_slicing, reason = "panic-safe indexing")]
    pub fn json_value(&self) -> Result<serde_json::Value, DidSidekicksError> {
        let mut value = match serde_json::to_value(self) {
            Ok(val) => val,
            Err(err) => {
                return Err(DidSidekicksError::SerializationFailed(format!(
                    "Could not serialize proof: {err}"
                )))
            }
        };

        value["created"] =
            serde_json::Value::String(self.created.to_rfc3339_opts(SecondsFormat::Secs, true));
        Ok(value)
    }

    /// Delivers first available update key
    #[inline]
    #[expect(
        clippy::indexing_slicing,
        reason = "panic-safe indexing ensured directly in code"
    )]
    pub fn extract_update_key(&self) -> Result<String, DidSidekicksError> {
        if self.verification_method.starts_with("did:key:") {
            let hash_separated = self.verification_method.to_owned().replace("did:key:", "");
            let update_key_split = hash_separated.split('#').collect::<Vec<&str>>();
            if update_key_split.is_empty() {
                return Err(DidSidekicksError::InvalidDataIntegrityProof(
                    "A proof's verificationMethod must be #-delimited".to_owned(),
                ));
            }
            Ok(update_key_split[0].to_owned())
        } else {
            Err(DidSidekicksError::InvalidDataIntegrityProof(
                format!("Unsupported proof's verificationMethod (only 'did:key' is currently supported): {}", self.verification_method)
            ))
        }
    }
}

/// This is the main entry point for proof generation and validation of a given verifiable credential.
///
/// Function in this class are based on algorithm section in the vc-data-integrity spec
/// https://www.w3.org/TR/vc-data-integrity/#algorithms
pub trait VCDataIntegrity {
    // See https://www.w3.org/TR/vc-data-integrity/#add-proof
    fn add_proof(
        &self,
        unsecured_document: &serde_json::Value,
        options: &CryptoSuiteProofOptions,
    ) -> Result<serde_json::Value, DidSidekicksError>;
    // See https://www.w3.org/TR/vc-data-integrity/#verify-proof
    fn verify_proof(
        &self,
        proof: &DataIntegrityProof,
        doc_hash: &str,
    ) -> Result<(), DidSidekicksError>;
}

#[expect(clippy::exhaustive_structs, reason = "..")]
pub struct EddsaJcs2022Cryptosuite {
    pub verifying_key: Option<Ed25519VerifyingKey>,
    pub signing_key: Option<Ed25519SigningKey>,
}

// NOTE Only https://www.w3.org/TR/vc-di-eddsa/#eddsa-jcs-2022 is currently supported
impl VCDataIntegrity for EddsaJcs2022Cryptosuite {
    // See https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022
    #[inline]
    #[expect(clippy::indexing_slicing, reason = "panic-safe indexing")]
    fn add_proof(
        &self,
        unsecured_document: &serde_json::Value,
        options: &CryptoSuiteProofOptions,
    ) -> Result<serde_json::Value, DidSidekicksError> {
        // According to https://www.w3.org/TR/vc-di-eddsa/#proof-configuration-eddsa-jcs-2022:
        // If proofConfig.type is not set to DataIntegrityProof or proofConfig.cryptosuite is not set to eddsa-jcs-2022,
        // an error MUST be raised that SHOULD convey an error type of PROOF_GENERATION_ERROR.
        if !matches!(options.crypto_suite, CryptoSuiteType::EddsaJcs2022) {
            return Err(DidSidekicksError::InvalidDataIntegrityProof(format!(
                "Unsupported proof's cryptosuite. Only '{}' is supported",
                CryptoSuiteType::EddsaJcs2022
            )));
        }
        if options.proof_type != "DataIntegrityProof" {
            return Err(DidSidekicksError::InvalidDataIntegrityProof(
                "Unsupported proof's type. Only 'DataIntegrityProof' is supported".to_owned(),
            ));
        }

        // See https://www.w3.org/TR/vc-di-eddsa/#proof-configuration-eddsa-jcs-2022
        let mut proof_without_proof_value = json!({
            "type": options.proof_type,
            "cryptosuite": options.crypto_suite.to_string(),
            "created": options.created.to_rfc3339_opts(SecondsFormat::Secs, true),
            "verificationMethod": options.verification_method,
            "proofPurpose": options.proof_purpose,
        });

        if let Some(challenge) = options.challenge.to_owned() {
            proof_without_proof_value["challenge"] = json!(challenge);
        }

        if let Some(ctx) = options.context.to_owned() {
            proof_without_proof_value["@context"] = json!(ctx);
        }

        // See https://www.w3.org/TR/vc-di-eddsa/#hashing-eddsa-jcs-2022
        // 1) Let transformedDocumentHash be the result of applying the SHA-256 (SHA-2 with 256-bit output)
        //    cryptographic hashing algorithm [RFC6234] to the transformedDocument. transformedDocumentHash will be exactly 32 bytes in size.
        let doc_hash = match JcsSha256Hasher::default().encode_hex(unsecured_document) {
            Ok(doc_hash) => doc_hash,
            Err(err) => {
                return Err(DidSidekicksError::InvalidDataIntegrityProof(format!(
                    "Could not serialize document for hash generation: {err}"
                )))
            }
        };

        // See https://www.w3.org/TR/vc-di-eddsa/#hashing-eddsa-jcs-2022
        // 2) Let proofConfigHash be the result of applying the SHA-256 (SHA-2 with 256-bit output)
        //    cryptographic hashing algorithm [RFC6234] to the canonicalProofConfig. proofConfigHash will be exactly 32 bytes in size.
        let proof_hash = match JcsSha256Hasher::default().encode_hex(&proof_without_proof_value) {
            Ok(proof_hash) => proof_hash,
            Err(err) => {
                return Err(DidSidekicksError::InvalidDataIntegrityProof(format!(
                    "Could not serialize proof: {err}"
                )))
            }
        };

        // See https://www.w3.org/TR/vc-di-eddsa/#hashing-eddsa-jcs-2022
        // 3) Let hashData be the result of joining proofConfigHash (the first hash) with transformedDocumentHash (the second hash).
        // CAUTION Since it's actually hex-encoded at this point, and raw bytes are required
        let decoded_hex_data = match hex::decode(format!("{proof_hash}{doc_hash}")) {
            Ok(hex_data) => hex_data,
            Err(err) => {
                return Err(DidSidekicksError::InvalidDataIntegrityProof(format!(
                    "Unable to decode created hash: {err}"
                )))
            }
        };

        let signature = match self.signing_key.to_owned() {
            Some(signing_key) => signing_key.sign_bytes(&decoded_hex_data),
            None => return Err(DidSidekicksError::InvalidDataIntegrityProof(
                "Invalid eddsa cryptosuite. Signing key is missing but required for proof creation"
                    .to_owned(),
            )),
        };
        //let signature_hex = hex::encode(signature.signature.to_bytes()); // checkpoint

        let proof_value = signature.to_multibase();
        proof_without_proof_value["proofValue"] = JsonString(proof_value);
        let mut secured_document = unsecured_document.clone();
        secured_document["proof"] = json!([proof_without_proof_value]);
        Ok(secured_document)
    }

    // See https://www.w3.org/TR/vc-di-eddsa/#proof-verification-eddsa-jcs-2022
    // See https://www.w3.org/TR/vc-di-eddsa/#verify-proof-eddsa-jcs-2022

    #[inline]
    #[expect(clippy::indexing_slicing, reason = "panic-safe indexing")]
    fn verify_proof(
        &self,
        proof: &DataIntegrityProof,
        doc_hash: &str,
    ) -> Result<(), DidSidekicksError> {
        // CAUTION Beware that only serde_json::json macro is able to serialize proof.created field properly (if used directly)!
        //         (thanks to #[serde(with = "ts_seconds")])
        let mut proof_without_proof_value = json!({
            "type": proof.proof_type,
            "cryptosuite": proof.crypto_suite,
            // The proof.created is not used directly here, due to more error-prone conversion that requires #[serde(with = "ts_seconds")] attribute
            "created": proof.created.to_rfc3339_opts(SecondsFormat::Secs, true),
            "verificationMethod": proof.verification_method,
            "proofPurpose": proof.proof_purpose,
        });
        if let Some(challenge) = proof.challenge.to_owned() {
            proof_without_proof_value["challenge"] = json!(challenge) // EIDSYS-429
        }

        if let Some(ctx) = proof.context.to_owned() {
            proof_without_proof_value["@context"] = json!(ctx);
        }

        // See https://www.w3.org/TR/vc-di-eddsa/#hashing-eddsa-jcs-2022
        // 2) Let proofConfigHash be the result of applying the SHA-256 (SHA-2 with 256-bit output)
        //    cryptographic hashing algorithm [RFC6234] to the canonicalProofConfig. proofConfigHash will be exactly 32 bytes in size.
        let proof_hash = match JcsSha256Hasher::default().encode_hex(&proof_without_proof_value) {
            Ok(proof_hash) => proof_hash,
            Err(err) => {
                return Err(DidSidekicksError::InvalidDataIntegrityProof(format!(
                    "Could not serialize proof: {err}"
                )))
            }
        };

        let signature = Ed25519Signature::from_multibase(proof.proof_value.as_str())?;

        match self.verifying_key.to_owned() {
            Some(verifying_key) => {
                let hash_data_decoded: [u8; 64] = match hex::FromHex::from_hex(format!("{proof_hash}{doc_hash}")) {
                    Ok(decoded_hash) => decoded_hash,
                    Err(_) => return Err(DidSidekicksError::InvalidDataIntegrityProof(
                        "Cannot decode hash value from hex.".to_owned()
                    ))
                };
                // Strictly verify a signature on a message with this keypair's public key.
                // It may respond with: "signature error: Verification equation was not satisfied"
                verifying_key.verifying_key.verify_strict(&hash_data_decoded, &signature.signature)
                    .map_err(|err| DidSidekicksError::InvalidDataIntegrityProof(format!("{err}")))
            }
            None => Err(DidSidekicksError::InvalidDataIntegrityProof(
                "Invalid eddsa cryptosuite. Verifying key is missing but required for proof verification".to_owned()
            ))
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "unwrap calls are panic-safe as long as test case setup is correct"
)]
#[expect(
    clippy::indexing_slicing,
    reason = "panic-safe as long as test case setup is correct"
)]
mod test {
    use crate::ed25519::{Ed25519SigningKey, Ed25519VerifyingKey, MultiBaseConverter as _};
    use crate::errors::DidSidekicksErrorKind;
    use crate::jcs_sha256_hasher::JcsSha256Hasher;
    use crate::test::assert_error;
    use crate::vc_data_integrity::{
        CryptoSuiteProofOptions, DataIntegrityProof, EddsaJcs2022Cryptosuite, VCDataIntegrity as _,
    };
    use chrono::DateTime;
    use rstest::rstest;
    use serde_json::json;

    #[rstest]
    // emtpy proof
    #[case("[]", "Empty proof array detected")]
    // two proofs
    #[case("[\"proof1\", \"proof2\"]", "A single proof is currently supported")]
    // invalid json
    #[case(
        "[{\"key:}]",
        "Malformed proof format, expected single-element JSON array"
    )]
    // invalid type
    #[case(
        "[{\"type\":\"invalidType\", \"cryptosuite\":\"eddsa-jcs-2022\", \"created\":\"2012-12-12T12:12:12Z\", \"verificationMethod\": \"did:key:123\", \"proofPurpose\":\"authentication\"}]",
        "Unsupported proof's type"
    )]
    // unsupported cryptosuite
    #[case(
        "[{\"type\":\"DataIntegrityProof\", \"cryptosuite\":\"unsupportedCrypto\", \"created\":\"2012-12-12T12:12:12Z\", \"verificationMethod\": \"did:key:123\", \"proofPurpose\":\"authentication\"}]",
        "Unsupported proof's cryptosuite"
    )]
    // invalid created date
    #[case("[{\"type\":\"DataIntegrityProof\", \"cryptosuite\":\"eddsa-jcs-2022\", \"created\":\"invalidDate\", \"verificationMethod\": \"did:key:123\", \"proofPurpose\":\"authentication\"}]",
        "Invalid proof's creation datetime format"
    )]
    // invalid verification method
    #[case("[{\"type\":\"DataIntegrityProof\", \"cryptosuite\":\"eddsa-jcs-2022\", \"created\":\"2012-12-12T12:12:12Z\", \"verificationMethod\": \"invalidMethod\", \"proofPurpose\":\"authentication\"}]",
        "Unsupported proof's verificationMethod"
    )]
    // invalid proof purpose
    #[case("[{\"type\":\"DataIntegrityProof\", \"cryptosuite\":\"eddsa-jcs-2022\", \"created\":\"2012-12-12T12:12:12Z\", \"verificationMethod\": \"did:key:123\", \"proofPurpose\":\"invalidPurpose\"}]",
        "Unsupported proof's proofPurpose"
    )]
    // invalid @context
    #[case("[{\"type\":\"DataIntegrityProof\", \"cryptosuite\":\"eddsa-jcs-2022\", \"created\":\"2012-12-12T12:12:12Z\", \"verificationMethod\": \"did:key:123\", \"proofPurpose\":\"authentication\", \"@context\":\"invalidContext\"}]",
        "Invalid format of 'context' entry"
    )]
    #[case("[{\"type\":\"DataIntegrityProof\", \"cryptosuite\":\"eddsa-jcs-2022\", \"created\":\"2012-12-12T12:12:12Z\", \"verificationMethod\": \"did:key:123\", \"proofPurpose\":\"authentication\", \"@context\":[\"validContext\", true, 3]}]",
        "Invalid type of 'context' entry"
    )]
    // invalid proof challenge
    #[case("[{\"type\":\"DataIntegrityProof\", \"cryptosuite\":\"eddsa-jcs-2022\", \"created\":\"2012-12-12T12:12:12Z\", \"verificationMethod\": \"did:key:123\", \"proofPurpose\":\"authentication\"}]",
        "Missing proofValue parameter. Expected a proofValue of type string."
    )]
    #[case("[{\"type\":\"DataIntegrityProof\", \"cryptosuite\":\"eddsa-jcs-2022\", \"created\":\"2012-12-12T12:12:12Z\", \"verificationMethod\": \"did:key:123\", \"proofPurpose\":\"authentication\", \"challenge\":[false, 2]}]",
        "Wrong format of proof's challenge parameter"
    )]
    // invalid proof challenge
    #[case("[{\"type\":\"DataIntegrityProof\", \"cryptosuite\":\"eddsa-jcs-2022\", \"created\":\"2012-12-12T12:12:12Z\", \"verificationMethod\": \"did:key:123\", \"proofPurpose\":\"authentication\", \"challenge\":\"1-hash\"}]",
        "Missing proofValue parameter"
    )]
    #[case("[{\"type\":\"DataIntegrityProof\", \"cryptosuite\":\"eddsa-jcs-2022\", \"created\":\"2012-12-12T12:12:12Z\", \"verificationMethod\": \"did:key:123\", \"proofPurpose\":\"authentication\", \"challenge\":\"1-hash\", \"proofValue\":5}]",
        "Wrong format of proofValue parameter"
    )]
    fn test_invalid_proof_parsing(
        #[case] input_str: String,
        #[case] error_string: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_error(
            DataIntegrityProof::from(input_str),
            DidSidekicksErrorKind::InvalidIntegrityProof,
            error_string,
        );

        Ok(())
    }

    #[rstest]
    fn test_cryptosuite_add_and_verify_proof_example() {
        // From https://www.w3.org/TR/vc-di-eddsa/#example-credential-without-proof-0
        let credentials_without_proof_obj = json!(
            {
                 "@context": [
                     "https://www.w3.org/ns/credentials/v2",
                     "https://www.w3.org/ns/credentials/examples/v2"
                 ],
                 "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
                 "type": ["VerifiableCredential", "AlumniCredential"],
                 "name": "Alumni Credential",
                 "description": "A minimum viable example of an Alumni Credential.",
                 "issuer": "https://vc.example/issuers/5678",
                 "validFrom": "2023-01-01T00:00:00Z",
                 "credentialSubject": {
                     "id": "did:example:abcdefgh",
                     "alumniOf": "The School of Examples"
                 }
            }
        );

        JcsSha256Hasher::default()
            .base58btc_encode_multihash(&credentials_without_proof_obj)
            .unwrap(); // SCID

        // From https://www.w3.org/TR/vc-di-eddsa/#example-proof-options-document-1
        let options = CryptoSuiteProofOptions::new(
            None,
            Some(DateTime::parse_from_rfc3339("2023-02-24T23:36:38Z").unwrap().to_utc()),
            "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2".to_owned(),
            Some("assertionMethod".to_owned()),
            Some(vec![
                "https://www.w3.org/ns/credentials/v2".to_owned(),
                "https://www.w3.org/ns/credentials/examples/v2".to_owned(),
            ]),
            None,
        );

        // From https://www.w3.org/TR/vc-di-eddsa/#example-private-and-public-keys-for-signature-1
        let suite = EddsaJcs2022Cryptosuite {
            verifying_key: Some(
                Ed25519VerifyingKey::from_multibase(
                    "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
                )
                .unwrap(),
            ),
            signing_key: Some(
                Ed25519SigningKey::from_multibase(
                    "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq",
                )
                .unwrap(),
            ),
        };

        let secured_document = suite
            .add_proof(&credentials_without_proof_obj, &options)
            .unwrap();

        assert!(
            !secured_document.is_null(),
            "'add_proof' method returned Value::Null"
        );
        let proof = &secured_document["proof"];
        assert!(proof.is_array(), "'proof' must be a JSON array");
        let proof_value = &proof[0]["proofValue"];
        assert!(proof_value.is_string(), "'proofValue' must be a string");

        // https://www.w3.org/TR/vc-di-eddsa/#example-signature-of-combined-hashes-base58-btc-1
        assert!(proof_value.to_string().contains("z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS93FCzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX"));

        let doc_hash = JcsSha256Hasher::default()
            .encode_hex(&credentials_without_proof_obj)
            .unwrap();
        // From https://www.w3.org/TR/vc-di-eddsa/#example-hash-of-canonical-credential-without-proof-hex-0
        assert_eq!(
            "59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19",
            doc_hash
        );

        // sanity check
        let proof_as_string = serde_json::to_string(proof).unwrap();
        let data_integrity_proof = DataIntegrityProof::from(proof_as_string).unwrap();
        assert!(
            suite.verify_proof(&data_integrity_proof, &doc_hash).is_ok(),
            "Sanity check failed"
        );
    }

    #[rstest]
    fn test_cryptosuite_add_and_verify_proof_with_challenge() {
        // From https://www.w3.org/TR/vc-di-eddsa/#example-credential-without-proof-0
        let credentials_without_proof_obj = json!(
            {
                 "@context": [
                     "https://www.w3.org/ns/credentials/v2",
                     "https://www.w3.org/ns/credentials/examples/v2"
                 ],
                 "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
                 "type": ["VerifiableCredential", "AlumniCredential"],
                 "name": "Alumni Credential",
                 "description": "A minimum viable example of an Alumni Credential.",
                 "issuer": "https://vc.example/issuers/5678",
                 "validFrom": "2023-01-01T00:00:00Z",
                 "credentialSubject": {
                     "id": "did:example:abcdefgh",
                     "alumniOf": "The School of Examples"
                 }
            }
        );

        let scid = JcsSha256Hasher::default()
            .base58btc_encode_multihash(&credentials_without_proof_obj)
            .unwrap();

        // From https://www.w3.org/TR/vc-di-eddsa/#example-proof-options-document-1
        let options = CryptoSuiteProofOptions::new(
            None,
            Some(DateTime::parse_from_rfc3339("2023-02-24T23:36:38Z").unwrap().to_utc()),
            "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2".to_owned(),
            Some("assertionMethod".to_owned()),
            Some(vec![
                "https://www.w3.org/ns/credentials/v2".to_owned(),
                "https://www.w3.org/ns/credentials/examples/v2".to_owned(),
            ]),
            Some(format!("1-{}", scid)),
        );

        // From https://www.w3.org/TR/vc-di-eddsa/#example-private-and-public-keys-for-signature-1
        let suite = EddsaJcs2022Cryptosuite {
            verifying_key: Some(
                Ed25519VerifyingKey::from_multibase(
                    "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
                )
                .unwrap(),
            ),
            signing_key: Some(
                Ed25519SigningKey::from_multibase(
                    "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq",
                )
                .unwrap(),
            ),
        };

        let secured_document = suite
            .add_proof(&credentials_without_proof_obj, &options)
            .unwrap();

        assert!(
            !secured_document.is_null(),
            "'add_proof' method returned Value::Null"
        );
        let proof = &secured_document["proof"];
        assert!(proof.is_array(), "'proof' must be a JSON array");
        let proof_value = &proof[0]["proofValue"];
        assert!(proof_value.is_string(), "'proofValue' must be a string");

        // https://www.w3.org/TR/vc-di-eddsa/#example-signature-of-combined-hashes-base58-btc-1
        // CAUTION The value suggested in the spec (z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS93FCzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX)
        //         is irrelevant here since the add_proof method also computes a proof's challenge (if not supplied already)
        assert!(proof_value.to_string().contains("z3swhrb2DFocc562PATcKiv8YtjUzxLdfr4dhb9DidvG2BNkJqAXe65bsEMiNJdGKDdnYxiBa7cKXXw4cSKCvMcfm"));

        let doc_hash = JcsSha256Hasher::default()
            .encode_hex(&credentials_without_proof_obj)
            .unwrap();
        // From https://www.w3.org/TR/vc-di-eddsa/#example-hash-of-canonical-credential-without-proof-hex-0
        assert_eq!(
            "59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19",
            doc_hash
        );

        // sanity check
        let proof_as_string = serde_json::to_string(proof).unwrap();
        let data_integrity_proof = DataIntegrityProof::from(proof_as_string).unwrap();
        assert!(
            suite.verify_proof(&data_integrity_proof, &doc_hash).is_ok(),
            "Sanity check failed"
        );
    }
}
