// SPDX-License-Identifier: MIT

use crate::ed25519::*;
use crate::errors::DidSidekicksError;
use crate::errors::DidSidekicksError::{InvalidDataIntegrityProof, VCDataIntegrityError};
use crate::jcs_sha256_hasher::JcsSha256Hasher;
use chrono::{serde::ts_seconds, DateTime, SecondsFormat, Utc};
use core::ops::Deref as _;
use hex::decode as hex_decode;
use serde::{Deserialize, Serialize};
use serde_json::{
    from_str as json_from_str, json, Value as JsonValue, Value::Array as JsonArray,
    Value::Null as JsonNull, Value::String as JsonString,
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

    /// The only UniFFI-compliant (super-potent) non-empty constructor.
    ///
    /// As nearly all arguments are optional - see [`Self::default()`] constructor for default values.
    #[inline]
    pub fn new_eddsa_jcs_2022(
        created_dt_rfc3339: Option<String>,
        verification_method: String,
        proof_purpose: Option<String>,
        context: Option<Vec<String>>,
        challenge: Option<String>,
    ) -> Result<Self, DidSidekicksError> {
        let mut options = Self::default();
        if let Some(created_dt) = created_dt_rfc3339 {
            // Parses the supplied RFC 3339 date-and-time string
            match DateTime::parse_from_rfc3339(&created_dt) {
                Ok(created) => {
                    options.created = created.to_utc();
                }
                Err(err) => {
                    return Err(VCDataIntegrityError(format!("{err}")));
                }
            };
        }

        options.verification_method = verification_method;
        if let Some(purpose) = proof_purpose {
            options.proof_purpose = purpose;
        }

        options.context = context;
        if let Some(ch) = challenge {
            options.challenge = ch.into();
        }

        Ok(options)
    }
}

impl Default for CryptoSuiteProofOptions {
    /// The default constructor aligned with
    /// [`eddsa-jcs-2022` proof-configuration](https://www.w3.org/TR/vc-di-eddsa/#proof-configuration-eddsa-jcs-2022), hence:
    ///
    /// - `proof_type: "DataIntegrityProof"`
    /// - `crypto_suite: "eddsa-jcs-2022"`
    /// - `created: <current datetime>`
    /// - `proof_purpose: "authentication"`
    #[inline]
    fn default() -> Self {
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

/// See https://www.w3.org/TR/vc-data-integrity/#dataintegrityproof
///
/// For EdDSA Cryptosuites v1.0 suites, see https://www.w3.org/TR/vc-di-eddsa/#dataintegrityproof
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
    ///
    /// UniFFI-compliant constructor
    #[inline]
    // TODO Ensure panic-safe indexing
    #[expect(clippy::indexing_slicing, reason = "see TODO")]
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "wildcard match ignorable as no further JSON variants are possible"
    )]
    pub fn from_json_string(json: String) -> Result<Self, DidSidekicksError> {
        let value = match json_from_str(&json) {
            Ok(JsonArray(entry)) => {
                if entry.len() > 1 {
                    return Err(InvalidDataIntegrityProof(
                        "A single proof is currently supported.".to_owned(),
                    ));
                }

                match entry.first() {
                    Some(first) => first.clone(),
                    None => {
                        return Err(InvalidDataIntegrityProof(
                            "Empty proof array detected.".to_owned(),
                        ))
                    }
                }
            }
            Err(err) => {
                return Err(InvalidDataIntegrityProof(format!(
                    "Malformed proof format, expected single-element JSON array: {err}"
                )))
            }
            _ => {
                return Err(InvalidDataIntegrityProof(
                    "Malformed proof format, expected single-element JSON array".to_owned(),
                ))
            }
        };
        Ok(Self {
            proof_type: match value["type"].to_owned() {
                JsonString(str) => {
                    if str != "DataIntegrityProof" {
                        return Err(InvalidDataIntegrityProof(
                            "Unsupported proof's type. Expected 'DataIntegrityProof'".to_owned(),
                        ));
                    }
                    str
                }
                _ => {
                    return Err(InvalidDataIntegrityProof(
                        "Missing proof's type".to_owned(),
                    ))
                }
            },
            crypto_suite: match value["cryptosuite"].to_owned() {
                JsonString(str) => {
                    if str != CryptoSuiteType::EddsaJcs2022.to_string().deref() {
                        return Err(InvalidDataIntegrityProof(format!(
                            "Unsupported proof's cryptosuite. Expected '{}'",
                            CryptoSuiteType::EddsaJcs2022
                        )));
                    }
                    str
                }
                _ => {
                    return Err(InvalidDataIntegrityProof(
                        "Missing proof's cryptosuite".to_owned(),
                    ))
                }
            },
            crypto_suite_type: Some(CryptoSuiteType::EddsaJcs2022), // the only currently supported cryptosuite
            created: match value["created"].to_owned() {
                JsonString(str) => match DateTime::parse_from_rfc3339(&str) {
                    Ok(date) => date.to_utc(),
                    Err(err) => return Err(InvalidDataIntegrityProof(
                        format!("Invalid proof's creation datetime format: {err}"),
                    ))
                },
                _ => return Err(InvalidDataIntegrityProof(
                    "Missing proof's creation datetime.".to_owned(),
                )),
            },
            verification_method: match value["verificationMethod"].to_owned() {
                JsonString(str) => {
                    if !str.starts_with("did:key:") {
                        return Err(InvalidDataIntegrityProof(
                            "Unsupported proof's verificationMethod. Expected prefix 'did:key:'"
                                .to_owned(),
                        ));
                    }
                    str
                }
                _ => {
                    return Err(InvalidDataIntegrityProof(
                        "Missing proof's verificationMethod".to_owned(),
                    ))
                }
            },
            proof_purpose: match value["proofPurpose"].to_owned() {
                JsonString(str) => {
                    if str != "authentication" && str != "assertionMethod" {
                        return Err(InvalidDataIntegrityProof(
                            "Unsupported proof's proofPurpose. Expected 'authentication' or 'assertionMethod'"
                                .to_owned(),
                        ));
                    }
                    str
                }
                _ => {
                    return Err(InvalidDataIntegrityProof(
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
                                _ => Err(InvalidDataIntegrityProof(
                                    "Invalid type of 'context' entry, expected a string."
                                        .to_owned(),
                                )),
                            })?,
                    )
                }
                JsonNull => None,
                _ => return Err(InvalidDataIntegrityProof(
                    "Invalid format of 'context' entry, expected array of strings.".to_owned(),
                )),
            },
            challenge: match value["challenge"].to_owned() {
                JsonString(str) => Some(str),
                JsonNull => None,
                _ => return Err(InvalidDataIntegrityProof(
                    "Wrong format of proof's challenge parameter. Expected a challenge of type string.".to_owned(),
                ))
            },
            proof_value: match value["proofValue"].to_owned() {
                JsonString(str) => str,
                JsonNull => return Err(InvalidDataIntegrityProof(
                    "Missing proofValue parameter. Expected a proofValue of type string.".to_owned(),
                )),
                _ => return Err(InvalidDataIntegrityProof(
                    "Wrong format of proofValue parameter. Expected a proofValue of type string.".to_owned(),
                ))
            },
        })
    }

    /// Converts this [`DataIntegrityProof`] to [`serde_json::Value`]
    #[inline]
    #[expect(clippy::indexing_slicing, reason = "panic-safe indexing")]
    pub fn json_value(&self) -> Result<JsonValue, DidSidekicksError> {
        let mut value = match serde_json::to_value(self) {
            Ok(val) => val,
            Err(err) => {
                return Err(VCDataIntegrityError(format!(
                    "Could not serialize proof: {err}"
                )))
            }
        };

        value["created"] =
            JsonValue::String(self.created.to_rfc3339_opts(SecondsFormat::Secs, true));
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
                return Err(InvalidDataIntegrityProof(
                    "A proof's verificationMethod must be #-delimited".to_owned(),
                ));
            }
            Ok(update_key_split[0].to_owned())
        } else {
            Err(InvalidDataIntegrityProof(
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
    /// As specified by https://www.w3.org/TR/vc-data-integrity/#add-proof
    fn add_proof_to_json_value(
        &self,
        unsecured_data_document: &JsonValue, // map that contains no proof values
        options: &CryptoSuiteProofOptions,
    ) -> Result<JsonValue, DidSidekicksError>;

    /// As specified by https://www.w3.org/TR/vc-data-integrity/#verify-proof
    fn verify_proof(
        &self,
        proof: &DataIntegrityProof,
        doc_hash: &str,
    ) -> Result<(), DidSidekicksError>;
}

/// The [`eddsa-jcs-2022`](https://w3c.github.io/vc-di-eddsa/#eddsa-jcs-2022) cryptographic suit.
///
/// It takes an input document, canonicalizes the document using the
/// JSON Canonicalization Scheme [`RFC8785`](https://www.rfc-editor.org/rfc/rfc8785),
/// and then cryptographically hashes and signs the output resulting in the production of a data integrity proof.
pub struct EddsaJcs2022Cryptosuite {
    verifying_key: Option<Ed25519VerifyingKey>,
    signing_key: Option<Ed25519SigningKey>,
}

impl EddsaJcs2022Cryptosuite {
    /// The signing-capable constructor.
    ///
    /// A UniFFI-compliant constructor
    #[inline]
    pub fn from_signing_key(signing_key: &Ed25519SigningKey) -> Self {
        Self {
            verifying_key: Some(signing_key.verifying_key()),
            signing_key: Some(signing_key.to_owned()),
        }
    }

    /// The verifying-capable constructor.
    ///
    /// A UniFFI-compliant constructor
    #[inline]
    pub fn from_verifying_key(verifying_key: &Ed25519VerifyingKey) -> Self {
        Self {
            verifying_key: Some(verifying_key.to_owned()),
            signing_key: None,
        }
    }

    /// The UniFFI-compliant wrapper of [`Self::add_proof_to_json_value`]
    #[inline]
    pub fn add_proof(
        &self,
        unsecured_data_document: &str,
        options: &CryptoSuiteProofOptions,
    ) -> Result<String, DidSidekicksError> {
        match json_from_str(unsecured_data_document) {
            Ok(val) => Ok(self.add_proof_to_json_value(&val, options)?.to_string()),
            Err(err) => Err(VCDataIntegrityError(format!(
                "Failed to deserialize unsecured data document from a string of JSON text: {err}"
            ))),
        }
    }
}

impl VCDataIntegrity for EddsaJcs2022Cryptosuite {
    // See https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022
    #[inline]
    #[expect(clippy::indexing_slicing, reason = "panic-safe indexing")]
    fn add_proof_to_json_value(
        &self,
        unsecured_data_document: &JsonValue, // map that contains no proof values
        options: &CryptoSuiteProofOptions,
    ) -> Result<JsonValue, DidSidekicksError> {
        // According to https://www.w3.org/TR/vc-di-eddsa/#proof-configuration-eddsa-jcs-2022:
        // If proofConfig.type is not set to DataIntegrityProof or proofConfig.cryptosuite is not set to eddsa-jcs-2022,
        // an error MUST be raised that SHOULD convey an error type of PROOF_GENERATION_ERROR.
        if !matches!(options.crypto_suite, CryptoSuiteType::EddsaJcs2022) {
            return Err(VCDataIntegrityError(format!(
                "Unsupported proof's cryptosuite. Only '{}' is supported",
                CryptoSuiteType::EddsaJcs2022
            )));
        }
        if options.proof_type != "DataIntegrityProof" {
            return Err(VCDataIntegrityError(
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

        // According to https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022:
        // 2) If unsecuredDocument.@context is present, set proof.@context to unsecuredDocument.@context.
        if let Some(ctx) = options.context.to_owned() {
            proof_without_proof_value["@context"] = json!(ctx);
        }

        // See https://www.w3.org/TR/vc-di-eddsa/#hashing-eddsa-jcs-2022
        // 1) Let transformedDocumentHash be the result of applying the SHA-256 (SHA-2 with 256-bit output)
        //    cryptographic hashing algorithm [RFC6234] to the transformedDocument.transformedDocumentHash will be exactly 32 bytes in size.
        let doc_hash = JcsSha256Hasher::default().encode_hex_json_value(unsecured_data_document)?;

        // See https://www.w3.org/TR/vc-di-eddsa/#hashing-eddsa-jcs-2022
        // 2) Let proofConfigHash be the result of applying the SHA-256 (SHA-2 with 256-bit output)
        //    cryptographic hashing algorithm [RFC6234] to the canonicalProofConfig.proofConfigHash will be exactly 32 bytes in size.
        let proof_hash =
            JcsSha256Hasher::default().encode_hex_json_value(&proof_without_proof_value)?;

        // See https://www.w3.org/TR/vc-di-eddsa/#hashing-eddsa-jcs-2022
        // 3) Let hashData be the result of joining proofConfigHash (the first hash) with transformedDocumentHash (the second hash).
        // CAUTION Since it's actually hex-encoded at this point, and raw bytes are required
        let decoded_hash_data = match hex_decode(format!("{proof_hash}{doc_hash}")) {
            Ok(hex_data) => hex_data,
            Err(err) => {
                return Err(VCDataIntegrityError(format!(
                    "Unable to decode created hash: {err}"
                )))
            }
        };

        let signature = match self.signing_key.to_owned() {
            Some(signing_key) => signing_key.sign_bytes(&decoded_hash_data),
            None => return Err(VCDataIntegrityError(
                "Invalid eddsa cryptosuite. Signing key is missing but required for proof creation"
                    .to_owned(),
            )),
        };
        //let signature_hex = hex::encode(signature.signature.to_bytes()); // checkpoint

        let proof_value = signature.to_multibase();
        proof_without_proof_value["proofValue"] = JsonString(proof_value);
        let mut secured_document = unsecured_data_document.clone();
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

        // According to https://www.w3.org/TR/vc-di-eddsa/#hashing-eddsa-jcs-2022:
        // 2) Let proofConfigHash be the result of applying the SHA-256 (SHA-2 with 256-bit output)
        //    cryptographic hashing algorithm [RFC6234] to the canonicalProofConfig. proofConfigHash will be exactly 32 bytes in size.
        let proof_hash =
            JcsSha256Hasher::default().encode_hex_json_value(&proof_without_proof_value)?;

        // According to https://www.w3.org/TR/vc-di-eddsa/#hashing-eddsa-jcs-2022:
        // 3) Let hashData be the result of joining proofConfigHash (the first hash) with transformedDocumentHash (the second hash).
        let hash_data = format!("{proof_hash}{doc_hash}");

        // REMINDER A "proof_value" (from DataIntegrityProof) is an Ed25519 signature
        let signature = Ed25519Signature::from_multibase(proof.proof_value.as_str())?;

        self.verifying_key.to_owned().map_or_else(
            || {
                Err(VCDataIntegrityError(
                    "The cryptosuite features no verifying key required for proof verification"
                        .to_owned(),
                ))
            },
            |verifying_key| {
                verifying_key
                    // Strictly verify a signature on a message with this keypair's public key.
                    // It may respond with: "signature error: Verification equation was not satisfied"
                    .verify_strict_from_hex(&hash_data, &signature)
            },
        )
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
    use crate::ed25519::{Ed25519SigningKey, MultiBaseConverter as _};
    use crate::errors::DidSidekicksErrorKind;
    use crate::jcs_sha256_hasher::JcsSha256Hasher;
    use crate::test::assert_error;
    use crate::vc_data_integrity::{
        CryptoSuiteProofOptions, DataIntegrityProof, EddsaJcs2022Cryptosuite, VCDataIntegrity as _,
    };
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
            DataIntegrityProof::from_json_string(input_str),
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

        // From https://www.w3.org/TR/vc-di-eddsa/#example-private-and-public-keys-for-signature-1
        let suite = EddsaJcs2022Cryptosuite::from_signing_key(
            &Ed25519SigningKey::from_multibase("z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq")
                .unwrap(),
        );

        let secured_document = suite
            .add_proof_to_json_value(
                &credentials_without_proof_obj,
                // From https://www.w3.org/TR/vc-di-eddsa/#example-proof-options-document-1
                &CryptoSuiteProofOptions::new_eddsa_jcs_2022(
                    Some("2023-02-24T23:36:38Z".into()),
                    "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2".to_owned(),
                    Some("assertionMethod".to_owned()),
                    Some(vec![
                        "https://www.w3.org/ns/credentials/v2".to_owned(),
                        "https://www.w3.org/ns/credentials/examples/v2".to_owned(),
                    ]),
                  None, // no challenge in this example
                ).unwrap()
            ).unwrap();

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
            .encode_hex_json_value(&credentials_without_proof_obj)
            .unwrap();
        // From https://www.w3.org/TR/vc-di-eddsa/#example-hash-of-canonical-credential-without-proof-hex-0
        assert_eq!(
            "59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19",
            doc_hash
        );

        // sanity check
        assert!(
            suite
                .verify_proof(
                    &DataIntegrityProof::from_json_string(serde_json::to_string(proof).unwrap())
                        .unwrap(),
                    &doc_hash
                )
                .is_ok(),
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

        // From https://www.w3.org/TR/vc-di-eddsa/#example-private-and-public-keys-for-signature-1
        let suite = EddsaJcs2022Cryptosuite::from_signing_key(
            &Ed25519SigningKey::from_multibase("z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq")
                .unwrap(),
        );

        let secured_document = suite
            .add_proof_to_json_value(
                &credentials_without_proof_obj,
                // From https://www.w3.org/TR/vc-di-eddsa/#example-proof-options-document-1
                &CryptoSuiteProofOptions::new_eddsa_jcs_2022(
                    Some("2023-02-24T23:36:38Z".into()),
                    "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2".to_owned(),
                    Some("assertionMethod".to_owned()),
                    Some(vec![
                        "https://www.w3.org/ns/credentials/v2".to_owned(),
                        "https://www.w3.org/ns/credentials/examples/v2".to_owned(),
                    ]),
                    Some(format!("1-{}", JcsSha256Hasher::default()
                        .base58btc_encode_multihash_json_value(&credentials_without_proof_obj).unwrap()
                    )),
                ).unwrap()
            ).unwrap();

        assert!(
            !secured_document.is_null(),
            "'add_proof_json_value' method returned Value::Null"
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
            .encode_hex_json_value(&credentials_without_proof_obj)
            .unwrap();
        // From https://www.w3.org/TR/vc-di-eddsa/#example-hash-of-canonical-credential-without-proof-hex-0
        assert_eq!(
            "59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19",
            doc_hash
        );

        // sanity check
        assert!(
            suite
                .verify_proof(
                    &DataIntegrityProof::from_json_string(serde_json::to_string(proof).unwrap())
                        .unwrap(),
                    &doc_hash
                )
                .is_ok(),
            "Sanity check failed"
        );
    }
}
