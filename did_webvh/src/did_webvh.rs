// SPDX-License-Identifier: MIT

use crate::did_webvh_jsonschema::WebVerifiableHistoryDidLogEntryJsonSchema;
use crate::did_webvh_method_parameters::*;
use crate::errors::*;
use chrono::serde::ts_seconds;
use chrono::{DateTime, SecondsFormat, Utc};
use core::cmp::PartialEq as _;
use did_sidekicks::did_doc::*;
use did_sidekicks::did_jsonschema::{DidLogEntryJsonSchema, DidLogEntryValidator};
use did_sidekicks::did_method_parameters::DidMethodParameter;
use did_sidekicks::did_resolver::DidResolver;
use did_sidekicks::ed25519::*;
use did_sidekicks::errors::DidResolverError;
use did_sidekicks::jcs_sha256_hasher::JcsSha256Hasher;
use did_sidekicks::vc_data_integrity::{
    CryptoSuiteType, DataIntegrityProof, EddsaJcs2022Cryptosuite, VCDataIntegrity as _,
};
use rayon::prelude::*;
use regex;
use regex::Regex;
use serde::de;
use serde::{Deserialize, Serialize};
use serde_json::Value::Object as JsonObject;
use serde_json::{
    from_str as json_from_str, json, to_string as json_to_string, Value as JsonValue,
};
use std::collections::HashMap;
use std::sync::Arc;
use url::Url;
use url_escape;

pub const SCID_PLACEHOLDER: &str = "{SCID}";
pub const DID_LOG_ENTRY_VERSION_ID: &str = "versionId";
pub const DID_LOG_ENTRY_VERSION_TIME: &str = "versionTime";
pub const DID_LOG_ENTRY_PARAMETERS: &str = "parameters";
pub const DID_LOG_ENTRY_STATE: &str = "state";
pub const DID_LOG_ENTRY_PROOF: &str = "proof";

/// Regex to check if a domain follows the assumption described in https://www.rfc-editor.org/rfc/rfc952.html
/// Allowed are lowercase letters (a-z), digits (0-9) dash (-) and period (.). Periods are only allowed to
/// delimit components.
static DOMAIN_REGEX: &str = r"^[\-a-z0-9]+(\.[\-a-z0-9]+)*$";
static HAS_PATH_REGEX: &str = r"([a-z]|[0-9])\/([a-z]|[0-9])";
static HAS_PORT_REGEX: &str = r"\:[0-9]+";

/// Entry in a did log file as shown here
/// https://identity.foundation/didwebvh/v1.0/#term:did-log-entry
#[expect(clippy::exhaustive_structs, reason = "..")]
#[derive(Serialize, Debug, Clone)]
pub struct DidLogEntry {
    /// Since v0.2 (see https://identity.foundation/didwebvh/v1.0/#didwebvh-version-changelog):
    ///            The new versionId takes the form <version number>-<entryHash>, where <version number> is the incrementing integer of version of the entry: 1, 2, 3, etc.
    #[serde(rename = "versionId")]
    pub version: DidLogVersion,

    #[serde(rename = "versionTime")]
    #[serde(with = "ts_seconds")]
    pub version_time: DateTime<Utc>,

    #[serde(rename = "parameters")]
    pub parameters: WebVerifiableHistoryDidMethodParameters,

    #[serde(rename = "state")]
    pub did_doc: DidDoc,

    #[serde(skip)]
    pub did_doc_json: JsonValue,

    #[serde(rename = "proof")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Vec<DataIntegrityProof>>,

    #[serde(skip)]
    pub prev_entry: Option<Arc<Self>>, // Arc-ed to prevent "recursive without indirection"
}

#[expect(clippy::exhaustive_structs, reason = "..")]
#[derive(Debug, Clone)]
pub struct DidLogVersion {
    pub hash: String,
    pub id: String,
    pub index: usize,
}

impl DidLogVersion {
    #[expect(clippy::single_call_fn, reason = "..")]
    fn new(hash: &str) -> Self {
        Self {
            id: hash.to_owned(),
            index: 0,
            hash: hash.to_owned(),
        }
    }
}

impl Serialize for DidLogVersion {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.id)
    }
}

#[expect(clippy::missing_trait_methods, reason = "..")]
impl<'de> Deserialize<'de> for DidLogVersion {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(DidLogVersionVisitor)
    }
}

#[expect(clippy::exhaustive_structs, reason = "..")]
pub struct DidLogVersionVisitor;

#[expect(clippy::missing_trait_methods, reason = "..")]
impl<'de> de::Visitor<'de> for DidLogVersionVisitor {
    type Value = DidLogVersion;

    #[inline]
    fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        formatter.write_str("a versionId in the format '<version_index>-<hash>'")
    }

    #[inline]
    /*#[expect(
        clippy::min_ident_chars,
        reason = "using default name to prevent 'renamed function parameter of trait impl' warning"
    )]*/
    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        v.split_once("-").map_or_else(
            || Err(de::Error::invalid_value(de::Unexpected::Str(v), &self)),
            |index_hash_tuple| match index_hash_tuple.0.parse::<usize>() {
                Ok(val) => Ok(Self::Value {
                    id: v.to_owned(),
                    index: val,
                    hash: index_hash_tuple.1.to_owned(),
                }),
                Err(err) => Err(de::Error::custom(err)),
            },
        )
    }
}

impl DidLogEntry {
    /// Import of existing log entry
    #[inline]
    pub fn new(
        version: DidLogVersion,
        version_time: DateTime<Utc>,
        parameters: WebVerifiableHistoryDidMethodParameters,
        did_doc: DidDoc,
        did_doc_json: JsonValue,
        proof: DataIntegrityProof,
        prev_entry: Option<Arc<Self>>,
    ) -> Self {
        Self {
            version,
            version_time,
            parameters,
            did_doc,
            did_doc_json,
            proof: Some(vec![proof]),
            prev_entry,
        }
    }

    /// Check whether the versionId of this log entry is based on the previous versionId
    #[inline]
    pub fn verify_version_id_integrity(&self) -> Result<(), DidResolverError> {
        // 1 Extract the versionId in the DID log entry, and remove from it the version number and dash prefix, leaving the log entry entryHash value.
        let hash = &self.version.hash;
        let calculated_hash = self.calculate_entry_hash().map_err(|err| {
            DidResolverError::InvalidDataIntegrityProof(format!("Failed to build versionId: {err}"))
        })?;
        if calculated_hash != *hash {
            return Err(DidResolverError::InvalidDataIntegrityProof(format!(
                "Invalid DID log. The DID log entry has invalid entry hash: {}. Expected: {}",
                hash, calculated_hash,
            )));
        }
        Ok(())
    }

    /// Check whether the integrity proof matches the content of the did document of this log entry
    #[inline]
    //#[expect(clippy::unwrap_in_result, reason = "..")]
    pub fn verify_data_integrity_proof(&self) -> Result<(), DidResolverError> {
        let Some(proof_vec) = self.proof.to_owned() else {
            return Err(DidResolverError::InvalidDataIntegrityProof(
                "Invalid did log. Proof is empty.".to_owned(),
            ));
        };

        if proof_vec.is_empty() {
            return Err(DidResolverError::InvalidDataIntegrityProof(
                "Invalid did log. Proof is empty.".to_owned(),
            ));
        }

        let mut prev = self.prev_entry.as_ref().map_or(self, |err| err);
        // In all entries with active Key Pre-Rotation, the update keys of the current log
        // entry are used.
        if prev.parameters.is_key_pre_rotation_active() {
            prev = self;
        }

        for proof in proof_vec {
            let update_key = match proof.extract_update_key() {
                Ok(key) => key,
                Err(err) => {
                    return Err(DidResolverError::InvalidDataIntegrityProof(format!(
                        "Failed to extract update key due to: {err}"
                    )))
                }
            };

            let verifying_key = prev.is_key_authorized_for_update(update_key)?;

            if !matches!(proof.crypto_suite_type, Some(CryptoSuiteType::EddsaJcs2022)) {
                return Err(DidResolverError::InvalidDataIntegrityProof(format!(
                    "Unsupported proof's cryptosuite {}",
                    proof.crypto_suite
                )));
            }

            // use entire DidLogEntry for signature
            let did_log_entry = Self {
                version: self.version.clone(),
                version_time: self.version_time,
                parameters: self.parameters.clone(),
                did_doc: self.did_doc.clone(),
                did_doc_json: self.did_doc_json.clone(),
                proof: None,
                prev_entry: None,
            }
            .to_log_entry_line()?;

            let doc_hash = JcsSha256Hasher::default()
                .encode_hex_json_value(&did_log_entry)
                .map_err(|err| DidResolverError::SerializationFailed(format!("{err}")))?;

            match EddsaJcs2022Cryptosuite::from_verifying_key(&verifying_key)
                .verify_proof(&proof, doc_hash.as_str())
            {
                Ok(_) => (),
                Err(err) => {
                    return Err(DidResolverError::InvalidDataIntegrityProof(format!(
                        "Failed to verify proof due to: {err}"
                    )))
                }
            };
        }

        Ok(())
    }

    /// The new versionId takes the form \<version number\>-\<entryHash\>, where \<version number\> is the incrementing integer of version of the entry: 1, 2, 3, etc.
    #[inline]
    pub fn calculate_entry_hash(&self) -> Result<String, DidResolverError> {
        // According to https://identity.foundation/didwebvh/v1.0/#entry-hash-generation-and-verification
        // 2 Determine hash algorithm from the multihash (https://identity.foundation/didwebvh/v1.0/#term:multihash), value is encoded as base58btc
        // 3 Set the versionId in the entry object to be the versionId from the previous log entry.
        //   If this is the first entry in the log, set the value to <scid>, the value of the SCID of the DID.
        let prev_version_id = match self.prev_entry.to_owned() {
            Some(entr) => entr.version.id.clone(),
            None => match self.parameters.get_scid_option() {
                Some(str) => str,
                None => {
                    return Err(DidResolverError::DeserializationFailed(
                        "Error extracting scid".to_owned(),
                    ))
                }
            },
        };
        // 4. remove Data Integrity proof from the log entry
        let entry = Self {
            version: DidLogVersion::new(&prev_version_id),
            version_time: self.version_time,
            parameters: self.parameters.clone(),
            did_doc: self.did_doc.clone(),
            did_doc_json: self.did_doc_json.clone(),
            proof: None,
            prev_entry: None,
        };
        let entry_json = entry.to_log_entry_line()?;
        // 5 calculate  the hash string
        let calculated_hash = JcsSha256Hasher::default()
            .base58btc_encode_multihash_json_value(&entry_json)
            .map_err(|err| {
                DidResolverError::SerializationFailed(format!("Failed to base58btc-encode SHA2-256 multihash of canonical JSON UTF-8 string: {err}"))
            })?;
        Ok(calculated_hash)
    }

    fn is_key_authorized_for_update(
        &self,
        update_key: String,
    ) -> Result<Ed25519VerifyingKey, DidResolverError> {
        match self.parameters.update_keys.to_owned() {
            Some(update_keys) => {
                if update_keys.is_empty() {
                    return Err(DidResolverError::InvalidDataIntegrityProof(
                        "No update keys detected".to_owned(),
                    ));
                }

                if !update_keys
                    .iter()
                    .any(|entry| *entry == update_key.as_str())
                {
                    return Err(DidResolverError::InvalidDataIntegrityProof(format!(
                        "Key extracted from proof is not authorized for update: {update_key}"
                    )));
                }

                let verifying_key = match Ed25519VerifyingKey::from_multibase(update_key.as_str()) {
                    Ok(key) => key,
                    Err(err) => {
                        return Err(DidResolverError::InvalidDataIntegrityProof(format!(
                        "Failed to convert update key (from its multibase representation): {err}"
                    )))
                    }
                };

                Ok(verifying_key)
            }
            None => {
                let Some(prev_entry) = self.prev_entry.to_owned() else {
                    return Err(DidResolverError::InvalidDataIntegrityProof(
                        "No update keys detected".to_owned(),
                    ));
                };
                prev_entry.is_key_authorized_for_update(update_key) // recursive call
            }
        }
    }

    #[expect(
        clippy::indexing_slicing,
        reason = "panic-free indexing ensured in code"
    )]
    fn to_log_entry_line(&self) -> Result<JsonValue, DidResolverError> {
        let did_doc_json_value = self.did_doc_json.clone();

        let version_time = self
            .version_time
            .to_owned()
            .to_rfc3339_opts(SecondsFormat::Secs, true);

        let mut entry = json!({
            DID_LOG_ENTRY_VERSION_ID: self.version.id,
            DID_LOG_ENTRY_VERSION_TIME: version_time,
            DID_LOG_ENTRY_PARAMETERS: self.parameters,
            DID_LOG_ENTRY_STATE: did_doc_json_value,
        });

        if let Some(proof) = self.proof.to_owned() {
            let Some(first_proof) = proof.first() else {
                return Err(DidResolverError::InvalidDataIntegrityProof(
                    "Proof is empty.".to_owned(),
                ));
            };

            entry[DID_LOG_ENTRY_PROOF] = json!(vec![first_proof.to_json_value()]);
        }

        Ok(entry)
    }

    fn build_original_scid(&self, scid: &String) -> serde_json::Result<String> {
        let did_doc_with_placeholder_scid = str::replace(
            self.did_doc_json.to_string().as_str(),
            scid,
            SCID_PLACEHOLDER,
        );

        let entry_with_placeholder_without_proof = json!({
           DID_LOG_ENTRY_VERSION_ID: SCID_PLACEHOLDER,
           DID_LOG_ENTRY_VERSION_TIME: self.version_time,
           DID_LOG_ENTRY_PARAMETERS: json_from_str::<JsonValue>(str::replace(json_to_string(&self.parameters)?.as_str(), scid, SCID_PLACEHOLDER).as_str())?,
           DID_LOG_ENTRY_STATE : json_from_str::<JsonValue>(did_doc_with_placeholder_scid.as_str())?,
        });

        let hash = JcsSha256Hasher::default()
            .base58btc_encode_multihash_json_value(&entry_with_placeholder_without_proof)?;
        Ok(hash)
    }
}

/// The parser for `did:webvh` DID logs implementing [`TryFrom<String>`] trait.
#[expect(clippy::exhaustive_structs, reason = "..")]
#[derive(Serialize, Debug)]
pub struct WebVerifiableHistoryDidLog {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub did_log_entries: Vec<DidLogEntry>,
    #[serde(skip)]
    pub did_method_parameters: WebVerifiableHistoryDidMethodParameters,
}

impl TryFrom<String> for WebVerifiableHistoryDidLog {
    type Error = DidResolverError;

    #[inline]
    //#[expect(clippy::unwrap_in_result, reason = "..")]
    #[expect(
        clippy::unwrap_used,
        reason = "panic-safe unwrap calls are possible thanks to profilactic JSON schema conformity check"
    )]
    #[expect(clippy::indexing_slicing, reason = "..")]
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "number of entries is always way lower than usize::MIN"
    )]
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "no further variants of serde_json::Value enum are expected in the future"
    )]
    fn try_from(did_log: String) -> Result<Self, Self::Error> {
        // CAUTION Despite parallelization, bear in mind that (according to benchmarks) the overall
        //         performance improvement will be considerable only in case of larger DID logs,
        //         featuring at least as many entries as `std::thread::available_parallelism()` would return.
        let sch: &dyn DidLogEntryJsonSchema =
            &WebVerifiableHistoryDidLogEntryJsonSchema::V1_0EidConform;
        let validator = DidLogEntryValidator::from(sch);
        if let Some(err) = did_log
            .par_lines() // engage a parallel iterator (thanks to 'use rayon::prelude::*;' import)
            // Once a non-None value is produced from the map operation,
            // `find_map_any` will attempt to stop processing the rest of the items in the iterator as soon as possible.
            .find_map_any(|line| validator.validate_str(line).err())
        {
            // The supplied DID log contains at least one entry that violates the JSON schema
            return Err(DidResolverError::DeserializationFailed(err.to_string()));
        }

        let mut current_params: Option<WebVerifiableHistoryDidMethodParameters> = None;
        let mut prev_entry: Option<Arc<DidLogEntry>> = None;

        let mut is_deactivated = false;
        //let now= Local::now();
        let now = Utc::now();

        let did_log_entries = did_log
                .lines()
                .filter(|line| !line.is_empty())
                .map(|line| {
                    if is_deactivated {
                        return Err(DidResolverError::InvalidDidDocument(
                            "This DID document is already deactivated. Therefore no additional DID logs are allowed.".to_owned()
                        ));
                    }

                    // CAUTION: It is assumed that the did:webvh JSON schema conformity check (see above)
                    //          have already been ensured at this point! 
                    //          Therefore, at this point, the current DID log entry may be considered fully JSON-schema-compliant, so...
                    let entry: JsonValue = serde_json::from_str(line).unwrap(); // ...no panic is expected here
                    let version: DidLogVersion = match serde_json::from_str(format!("{}", entry[DID_LOG_ENTRY_VERSION_ID]).as_str()) {
                        Ok(ver) => ver,
                        Err(err) => { return Err(DidResolverError::DeserializationFailed(format!("Invalid versionId: {err}"))); },
                    };

                    if prev_entry.is_none() && version.index != 1
                        || prev_entry.is_some() && (version.index - 1).ne(&prev_entry.to_owned().unwrap().version.index) {
                        return Err(DidResolverError::DeserializationFailed("Version numbers (`versionId`) must be in a sequence of positive consecutive integers.".to_owned()));
                    }

                    // https://identity.foundation/didwebvh/v1.0/#the-did-log-file:
                    // The `versionTime` (as stated by the DID Controller) of the entry,
                    // in ISO8601 format (https://identity.foundation/didwebvh/v0.3/#term:iso8601).
                    let version_time = entry[DID_LOG_ENTRY_VERSION_TIME].as_str()
                        .map(|rfc3339| DateTime::parse_from_rfc3339(rfc3339)
                            .unwrap() // panic-safe unwrap call here (as the entry has already been validated)
                            .to_utc())
                        .unwrap(); // panic-safe unwrap call here (as the entry has already been validated)

                    // CAUTION This check is not really required as it has been already implemented by the JSON schema validator
                    if version_time.ge(&now) {
                        return Err(DidResolverError::DeserializationFailed(format!("`versionTime` '{version_time}' must be before the current datetime '{now}'.")));
                    }

                    if prev_entry.to_owned().is_some_and(|prev_entr| {
                        version_time.lt(&prev_entr.version_time)
                    }) {
                        return Err(DidResolverError::DeserializationFailed("`versionTime` must be greater than the `versionTime` of the previous entry.".to_owned()));
                    }

                    let mut new_params: Option<WebVerifiableHistoryDidMethodParameters> = None;
                    current_params = match entry[DID_LOG_ENTRY_PARAMETERS].to_owned() {
                        JsonObject(obj) => {
                            if !obj.is_empty() {
                                new_params = Some(WebVerifiableHistoryDidMethodParameters::from_json(&entry[DID_LOG_ENTRY_PARAMETERS].to_string())?);
                            }

                            match (current_params.clone(), new_params.clone()) {
                                (None, None) => return Err(DidResolverError::DeserializationFailed(
                                    "Missing DID Document parameters.".to_owned(),
                                )),
                                (None, Some(mut new_par)) => {
                                    // this is the first entry, therefore we check for the base configuration
                                    new_par.validate_initial()?;

                                    Some(new_par) // from the initial log entry
                                }
                                (Some(current_par), None) => {
                                    new_params = Some(WebVerifiableHistoryDidMethodParameters::empty());
                                    Some(current_par)
                                }
                                (Some(mut current_par), Some(new_par)) => {
                                    current_par.merge_from(&new_par)?;
                                    Some(current_par)
                                }
                            }
                        }
                        _ => {
                            return Err(DidResolverError::DeserializationFailed(
                                "Missing DID method parameters.".to_owned(),
                            ))
                        }
                    };

                    is_deactivated = current_params.to_owned().is_some_and(|par| par.deactivated.is_some_and(|dct| dct));
                    if is_deactivated {
                        // https://identity.foundation/didwebvh/v1.0/#deactivate-revoke:
                        // To deactivate the DID, the DID Controller SHOULD add to the DID log entry parameters the item "deactivated": true.
                        // A DID MAY update the DIDDoc further to indicate the deactivation of the DID,
                        // such as including an empty updateKeys list ("updateKeys": []) in the parameters,
                        // preventing further versions of the DID.
                        if let Some(mut _current_params) = current_params.to_owned() {
                            _current_params.deactivate();
                            current_params = Some(_current_params);
                        }
                    }

                    let did_doc_value = entry[DID_LOG_ENTRY_STATE].to_owned();
                    let current_did_doc: DidDoc = match did_doc_value {
                        JsonObject(_) => {
                            if did_doc_value.is_null() {
                                return Err(DidResolverError::DeserializationFailed(
                                    "DID Document was empty.".to_owned(),
                                ));
                            }

                            let json = entry[DID_LOG_ENTRY_STATE].to_string();

                            match serde_json::from_str::<DidDoc>(&json) {
                                Ok(did_doc) => did_doc,
                                Err(_) => {
                                    match serde_json::from_str::<DidDocNormalized>(&json) {
                                        Ok(did_doc_alt) => {
                                            match did_doc_alt.to_did_doc() {
                                                Ok(doc) => doc,
                                                Err(err) => return Err(DidResolverError::DeserializationFailed(format!(
                                                    "Deserialization of DID document failed due to: {err}"
                                                ))),
                                            }
                                        }
                                        Err(err) => return Err(DidResolverError::DeserializationFailed(
                                            format!("Missing DID document: {err}")
                                        ))
                                    }
                                }
                            }
                        }
                        _ => {
                            return Err(DidResolverError::DeserializationFailed(
                                "Missing DID Document.".to_owned(),
                            ))
                        }
                    };

                    let proof = match DataIntegrityProof::from_json_string(entry[DID_LOG_ENTRY_PROOF].to_string()) {
                        Ok(prf) => prf,
                        Err(err) => return Err(DidResolverError::DeserializationFailed(format!(
                            "Failed to deserialize data integrity proof due to: {err}"
                        ))),
                    };

                    let parameters = match new_params {
                        Some(new_par) => new_par,
                        None => return Err(DidResolverError::DeserializationFailed(
                            "Internal error: Missing parameter values.".to_owned(),
                        ))
                    };

                    let current_entry = DidLogEntry::new(
                        version,
                        version_time,
                        parameters,
                        current_did_doc,
                        did_doc_value,
                        proof,
                        prev_entry.to_owned(),
                    );
                    prev_entry = Some(Arc::from(current_entry.to_owned()));

                    Ok(current_entry)
                }).collect::<Result<Vec<DidLogEntry>, DidResolverError>>()?;

        current_params.map_or_else(
            || {
                Err(DidResolverError::DeserializationFailed(
                    "Missing DID method parameters.".to_owned(),
                ))
            },
            |params| {
                Ok(Self {
                    did_method_parameters: params,
                    did_log_entries,
                })
            },
        )
    }
}

impl WebVerifiableHistoryDidLog {
    #[inline]
    pub fn get_did_method_parameters(&self) -> WebVerifiableHistoryDidMethodParameters {
        self.did_method_parameters.clone()
    }

    /// Checks if all entries in the did log are valid (data integrity, versioning etc.)
    #[inline]
    pub fn validate(&self) -> Result<DidDoc, DidResolverError> {
        self.validate_with_scid(None)
    }

    /// Checks if all entries in the did log are valid (data integrity, versioning etc.)
    #[inline]
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "number of entries is always way lower than usize::MAX"
    )]
    pub fn validate_with_scid(
        &self,
        scid_to_validate: Option<String>,
    ) -> Result<DidDoc, DidResolverError> {
        let mut expected_version_index = 0;
        for entry in &self.did_log_entries {
            expected_version_index += 1;

            if entry.version.index != expected_version_index {
                return if expected_version_index == 1 {
                    Err(DidResolverError::InvalidDataIntegrityProof(
                        "Invalid did log. First entry has to have version id 1".to_owned(),
                    ))
                } else {
                    Err(DidResolverError::InvalidDataIntegrityProof(format!(
                        "Invalid did log for version {}. Version id has to be incremented",
                        entry.version.index,
                    )))
                };
            }

            // Verify data integrity proof
            entry.verify_data_integrity_proof()?;

            // Verify the entryHash
            entry.verify_version_id_integrity()?;

            if expected_version_index == 1 {
                // Verify that the SCID is correct
                let scid = match entry.parameters.get_scid_option() {
                    Some(scid_value) => scid_value,
                    None => {
                        return Err(DidResolverError::InvalidDataIntegrityProof(
                            "Missing SCID inside the DID document.".to_owned(),
                        ))
                    }
                };

                if let Some(res) = scid_to_validate.to_owned() {
                    if res.ne(scid.as_str()) {
                        return Err(DidResolverError::InvalidDataIntegrityProof(format!(
                                        "The SCID '{scid}' supplied inside the DID document does not match the one supplied for validation: '{res}'"
                                    )));
                    }
                }

                let original_scid = entry.build_original_scid(&scid).map_err(|err| {
                    DidResolverError::InvalidDataIntegrityProof(format!(
                        "Failed to build original SCID: {err}"
                    ))
                })?;
                if original_scid != scid {
                    return Err(DidResolverError::InvalidDataIntegrityProof(
                        "Invalid did log. Genesis entry has invalid SCID".to_owned(),
                    ));
                }
            }
        }

        self.did_log_entries.last().map_or_else(
            || {
                Err(DidResolverError::InvalidDataIntegrityProof(
                    "Invalid did log. No entries found".to_owned(),
                ))
            },
            |entry| Ok(entry.clone().did_doc),
        )
    }
}

impl core::fmt::Display for WebVerifiableHistoryDidLog {
    #[inline]
    /*#[expect(
        clippy::min_ident_chars,
        reason = "using default name (f) to prevent 'renamed function parameter of trait impl' warning"
    )]*/
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let mut log = String::new();
        for entry in &self.did_log_entries {
            let log_line = entry.to_log_entry_line().map_err(|_x| core::fmt::Error)?;
            let serialized = serde_json::to_string(&log_line).map_err(|_x| core::fmt::Error)?;
            log.push_str(serialized.as_str());
            log.push('\n');
        }
        write!(f, "{log}")
    }
}

/// As specified at https://identity.foundation/didwebvh/v1.0/#method-specific-identifier:
///
/// "The did:webvh method-specific identifier contains both the self-certifying identifier (SCID) for the DID,
/// and a fully qualified domain name (with an optional path) that is secured by a TLS/SSL certificate."
pub struct WebVerifiableHistoryId {
    scid: String,
    url: String,
}

impl WebVerifiableHistoryId {
    pub const DID_METHOD_NAME: &'static str = "webvh";

    /// Yet another UniFFI-compliant method.
    ///
    /// Otherwise, the idiomatic counterpart (try_from(did_webvh: String) -> Result<Self, Self::Error>) may be used as well.
    #[inline]
    pub fn parse_did_webvh(
        did_webvh: String,
    ) -> Result<Self, WebVerifiableHistoryIdResolutionError> {
        Self::try_from(did_webvh)
    }

    #[inline]
    pub fn get_scid(&self) -> String {
        self.scid.clone()
    }

    #[inline]
    pub fn get_url(&self) -> String {
        self.url.clone()
    }
}

/// Implementation for a string denoting did_webvh
impl TryFrom<String> for WebVerifiableHistoryId {
    type Error = WebVerifiableHistoryIdResolutionError;

    /// It basically implements the 'The DID to HTTPS Transformation',
    /// as specified by https://identity.foundation/didwebvh/v1.0/#the-did-to-https-transformation
    #[inline]
    #[expect(
        clippy::indexing_slicing,
        reason = "panic-free indexing ensured in code"
    )]
    #[expect(
        clippy::unwrap_in_result,
        reason = "panic-free as long as the regex is valid"
    )]
    #[expect(
        clippy::unwrap_used,
        reason = "panic-free as long as the regex is valid"
    )]
    fn try_from(did_webvh: String) -> Result<Self, Self::Error> {
        let did_webvh_split: Vec<&str> = did_webvh.splitn(4, ":").collect();
        if did_webvh_split.len() < 4 {
            return Err(WebVerifiableHistoryIdResolutionError::InvalidMethodSpecificId(did_webvh));
        };

        let method_name = format!("{}:{}", did_webvh_split[0], did_webvh_split[1]);
        if method_name != format!("did:{}", Self::DID_METHOD_NAME) {
            return Err(WebVerifiableHistoryIdResolutionError::MethodNotSupported(
                method_name,
            ));
        };

        let scid = did_webvh_split[2];
        if scid.is_empty() {
            // the SCID MUST be present in the DID string
            return Err(WebVerifiableHistoryIdResolutionError::InvalidMethodSpecificId(
                String::from("Empty self-certifying identifier (SCID) detected. An object identifier derived from initial data is expected"),
            ));
        };

        if did_webvh_split[3].replace(":", "").is_empty() || did_webvh_split[3].starts_with(":") {
            return Err(
                WebVerifiableHistoryIdResolutionError::InvalidMethodSpecificId(String::from(
                    "No fully qualified domain detected",
                )),
            );
        };

        // 1. Remove the ‘did:webvh:’ prefix from the input identifier.
        // 2. Remove the SCID segment, which is the first segment after the prefix.
        // 3. Transform the domain segment, the first segment (up to the first ':' character) of the remaining string.
        let url_split: Vec<&str> = did_webvh_split[3].splitn(2, ":").collect();
        // if the domain segment contains a port, decode percent-encoding and preserve the port.
        let domain = url_split[0].replace("%3A", ":"); //.nfc().collect::<String>();
                                                       // 4. Transform the path, the 0 or more segments after the first : character, delimited by : characters.
        let path = if url_split.len() > 1 {
            url_split[1].replace(":", "/")
        } else {
            // if no path segments exist, path becomes '.well-known'
            ".well-known".to_owned()
        };

        // 5. Reconstruct the HTTPS URL
        let url_string = format!("https://{domain}/{path}");
        let mut url = match Url::parse(&url_string) {
            Ok(url) => url,
            Err(err) => {
                return Err(
                    WebVerifiableHistoryIdResolutionError::InvalidMethodSpecificId(format!(
                        "Not a valid URL: {err}"
                    )),
                )
            }
        };

        //#[expect(clippy::unwrap_used, reason = "panic-free as long as the regex is valid")]

        // Verify that the host is a valid domain.
        // Special characters were encoded by `Url::parse`.
        // URL without domain, that instead use an ip address are already validated in step 5
        if let url::Origin::Tuple(_, url::Host::Domain(dom), _) = url.origin() {
            if Regex::new(DOMAIN_REGEX)
                .unwrap()
                .captures(dom.as_str())
                .is_none()
            {
                return Err(
                    WebVerifiableHistoryIdResolutionError::InvalidMethodSpecificId(
                        "Domain of provided DID is invalid".to_owned(),
                    ),
                );
            }
        }

        // append '/did.jsonl' to complete the URL.
        match url.path_segments_mut() {
            Ok(mut path_segments) => {
                // 7. Append /did.jsonl to complete the URL.
                path_segments.push("did.jsonl");
            }
            Err(_) => {
                // path_segments_mut "Return Err(()) if this URL is cannot-be-a-base."
                return Err(
                    WebVerifiableHistoryIdResolutionError::InvalidMethodSpecificId(
                        "This URL cannot-be-a-base".to_owned(),
                    ),
                );
            }
        };

        Ok(Self {
            scid: scid.to_owned(),
            url: url.to_string(),
        })
    }
}

/// Implementation for a tuple denoting did_webvh and allow_http.
#[diagnostic::do_not_recommend]
impl TryFrom<(String, Option<bool>)> for WebVerifiableHistoryId {
    type Error = WebVerifiableHistoryIdResolutionError;

    #[inline]
    #[expect(
        clippy::indexing_slicing,
        reason = "panic-free indexing ensured in code"
    )]
    #[expect(
        clippy::unwrap_in_result,
        reason = "panic-free as long as the regex is valid"
    )]
    #[expect(
        clippy::unwrap_used,
        reason = "panic-free as long as the regex is valid"
    )]
    fn try_from(value: (String, Option<bool>)) -> Result<Self, Self::Error> {
        let did_webvh = value.0;
        let allow_http = value.1;

        let split: Vec<&str> = did_webvh.splitn(3, ":").collect();
        if split.len() < 3 || split[2].is_empty() {
            return Err(WebVerifiableHistoryIdResolutionError::InvalidMethodSpecificId(did_webvh));
        };

        let method_name = format!("{}:{}", split[0], split[1]);
        if method_name != format!("did:{}", Self::DID_METHOD_NAME) {
            return Err(WebVerifiableHistoryIdResolutionError::MethodNotSupported(
                method_name,
            ));
        };

        let mut decoded_url = String::from("");
        match split[2].split_once(":") {
            Some((scid, did_webvh_reduced)) => {
                url_escape::decode_to_string(did_webvh_reduced.replace(":", "/"), &mut decoded_url);
                let url = match String::from_utf8(decoded_url.into_bytes()) {
                    Ok(url) => {
                        if url.starts_with("localhost")
                            || url.starts_with("127.0.0.1")
                            || allow_http.unwrap_or(false)
                        {
                            format!("http://{url}")
                        } else {
                            format!("https://{url}")
                        }
                    }
                    Err(_) => {
                        return Err(
                            WebVerifiableHistoryIdResolutionError::InvalidMethodSpecificId(
                                did_webvh_reduced.to_owned(),
                            ),
                        )
                    }
                };
                if Regex::new(HAS_PATH_REGEX)
                    .unwrap()
                    .captures(url.as_str())
                    .is_some()
                    || Regex::new(HAS_PORT_REGEX)
                        .unwrap()
                        .captures(url.as_str())
                        .is_some()
                {
                    Ok(Self {
                        scid: scid.to_owned(),
                        url: format!("{url}/did.jsonl"),
                    })
                } else {
                    Ok(Self {
                        scid: scid.to_owned(),
                        url: format!("{url}/.well-known/did.jsonl"),
                    })
                }
            }
            None => Err(WebVerifiableHistoryIdResolutionError::InvalidMethodSpecificId(did_webvh)),
        }
    }
}

/// The container for any *valid* `did:webvh` DID log in terms of the
/// [*DID resolution*](https://identity.foundation/didwebvh/v1.0/#read-resolve).
///
/// Namely, the struct implements the
/// [*Read (Resolve)* DID method operation for a `did:webvh` DID](https://identity.foundation/didwebvh/v1.0/#read-resolve)
/// in its constructor.
///
/// A fully UniFFI-compliant struct.
pub struct WebVerifiableHistory {
    did: String,
    did_doc: String,
    did_doc_obj: DidDoc,
    did_log: String,
    did_method_parameters: WebVerifiableHistoryDidMethodParameters,
}

impl WebVerifiableHistory {
    /// Delivers the fully qualified DID identifier (as [`String`]) of the DID log previously supplied via [`WebVerifiableHistory::read`] constructor.
    ///
    /// Yet another UniFFI-compliant method.
    #[inline]
    pub fn get_did(&self) -> String {
        self.did.clone()
    }

    /// Delivers the very same DID log (as [`String`]) previously supplied via [`WebVerifiableHistory::read`] constructor.
    ///
    /// Yet another UniFFI-compliant method.
    #[inline]
    pub fn get_did_log(&self) -> String {
        self.did_log.clone()
    }

    /// Delivers the fully qualified DID document (as [`String`]) contained within the DID log previously supplied via [`WebVerifiableHistory::read`] constructor.
    ///
    /// Yet another UniFFI-compliant method.
    #[inline]
    pub fn get_did_doc(&self) -> String {
        self.did_doc.clone()
    }

    /// Delivers the fully qualified DID document (as [`DidDoc`]) contained within the DID log previously supplied via [`WebVerifiableHistory::read`] constructor.
    fn get_did_doc_obj(&self) -> DidDoc {
        self.did_doc_obj.clone()
    }

    /// The thread-safe version of [`WebVerifiableHistory::get_did_doc_obj`].
    ///
    /// Yet another UniFFI-compliant getter.
    #[inline]
    pub fn get_did_doc_obj_thread_safe(&self) -> Arc<DidDoc> {
        Arc::new(self.get_did_doc_obj())
    }

    fn get_did_method_parameters_obj(&self) -> WebVerifiableHistoryDidMethodParameters {
        self.did_method_parameters.clone()
    }

    /// The thread-safe version of [`WebVerifiableHistory::get_did_method_parameters_obj`].
    ///
    /// Yet another UniFFI-compliant getter.
    #[inline]
    pub fn get_did_method_parameters(&self) -> Arc<WebVerifiableHistoryDidMethodParameters> {
        Arc::new(self.get_did_method_parameters_obj())
    }

    /// The single constructor of [`WebVerifiableHistory`] implementing the
    /// [*Read (Resolve)* DID method operation for a `did:webvh` DID](https://identity.foundation/didwebvh/v1.0/#read-resolve)
    ///
    /// In case of error, the available [`DidResolverError`] object features all the detailed
    /// information required to narrow down the root cause.
    ///
    /// A UniFFI-compliant constructor.
    #[inline]
    pub fn resolve(did_webvh: String, did_log: String) -> Result<Self, DidResolverError> {
        // according to https://identity.foundation/didwebvh/v1.0/#read-resolve
        // parse did logs
        let did_log_obj = WebVerifiableHistoryDidLog::try_from(did_log)?;

        // 1. DID-to-HTTPS Transformation
        let did = WebVerifiableHistoryId::parse_did_webvh(did_webvh)
            .map_err(|err| DidResolverError::InvalidMethodSpecificId(format!("{err}")))?;

        let did_doc_valid = did_log_obj.validate_with_scid(Some(did.get_scid()))?;
        let did_doc_str = match serde_json::to_string(&did_doc_valid) {
            Ok(val) => val,
            Err(err) => return Err(DidResolverError::SerializationFailed(err.to_string())),
        };

        Ok(Self {
            did: did_doc_valid.to_owned().id,
            did_log: did_log_obj.to_string(), // the type implements std::fmt::Display trait
            did_doc: did_doc_str,
            did_doc_obj: did_doc_valid,
            did_method_parameters: did_log_obj.get_did_method_parameters(),
        })
    }
}

impl DidResolver for WebVerifiableHistory {
    //type Error = DidResolverError;

    #[inline]
    fn collect_did_method_parameters_map(
        &self,
    ) -> Result<HashMap<String, Arc<DidMethodParameter>>, DidResolverError> {
        self.get_did_method_parameters_obj()
            .try_into()
            .map_err(|err| DidResolverError::InvalidDidParameter(format!("{err}")))
    }

    #[inline]
    fn get_did_doc_obj(&self) -> DidDoc {
        self.get_did_doc_obj()
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "unwrap calls are panic-safe as long as test case setup is correct"
)]
mod test {
    use crate::did_webvh::{WebVerifiableHistory, WebVerifiableHistoryDidLog};
    use crate::test::assert_trust_did_web_error;
    use did_sidekicks::errors::DidResolverErrorKind;
    use rstest::rstest;
    use std::fs;
    use std::path::Path;

    #[rstest]
    // doc needs to be an object
    #[case("[1,2,3,4,5]", "is not of type \"object\"")]
    // invalid version Id
    #[case(
        r#"{"versionId":"","versionTime":"2025-04-29T17:15:59Z", "parameters":{}, "state":{}}"#,
        "does not match"
    )]
    #[case(
        r#"{"versionId":"1","versionTime":"2025-04-29T17:15:59Z", "parameters":{}, "state":{}}"#,
        "\"1\" does not match"
    )]
    #[case(
        r#"{"versionId":"hash","versionTime":"2025-04-29T17:15:59Z", "parameters":{}, "state":{}}"#,
        "\"hash\" does not match"
    )]
    // invalid time
    #[case(
        r#"{"versionId":"1-Qhashhashhashhashhashhashhashhashhashhashhashhash","versionTime":"", "parameters":{}, "state":{}}"#,
        "Datetime not in ISO8601 format"
    )]
    #[case(
        r#"{"versionId":"1-Qhashhashhashhashhashhashhashhashhashhashhashhash","versionTime":"invalid time", "parameters":{}, "state":{}}"#,
        "Datetime not in ISO8601 format"
    )]
    #[case(
        r#"{"versionId":"1-Qhashhashhashhashhashhashhashhashhashhashhashhash","versionTime":"2025-04-29 17:15:59", "parameters":{}, "state":{}}"#,
        "Datetime not in ISO8601 format"
    )]
    // invalid state
    #[case(
        r#"{"versionId":"1-Qhashhashhashhashhashhashhashhashhashhashhashhash","versionTime":"2025-04-29T17:15:59Z", "parameters":{}, "state":{"@context":["https://www.w3.org/ns/did/v1", "https://w3id.org/security/jwk/v1"]} }"#,
        "\"id\" is a required property"
    )]
    #[case(
        r#"{"versionId":"1-Qhashhashhashhashhashhashhashhashhashhashhashhash","versionTime":"2025-04-29T17:15:59Z", "parameters":{}, "state":{"id":""}}"#,
        "\"@context\" is a required property"
    )]
    // did doc context needs to be filled
    #[case(
        r#"{"versionId":"1-Qhashhashhashhashhashhashhashhashhashhashhashhash","versionTime":"2025-04-29T17:15:59Z", "parameters":{}, "state":{"@context":[], "id":""} }"#,
        "[] is not valid under any of the schemas listed in the 'anyOf' keyword"
    )]
    #[case(
        r#"{"versionId":"1-Qhashhashhashhashhashhashhashhashhashhashhashhash","versionTime":"2025-04-29T17:15:59Z", "parameters":{}, "state":{"@context":["https://w3id.org/security/jwk/v1"], "id":""} }"#,
        "] is not valid under any of the schemas listed in the 'anyOf' keyword"
    )]
    // empty parameters
    #[case(
        r#"{"versionId":"1-Qhashhashhashhashhashhashhashhashhashhashhashhash","versionTime":"2025-04-29T17:15:59Z", "parameters":{}, "state":{"@context":["https://www.w3.org/ns/did/v1", "https://w3id.org/security/jwk/v1"], "id":"did:webvh:QmQyDxVnosYTzHAMbzYDRZkVrD32ea9Sr2XNs8NkgMB5mn:domain.example"}, "proof": [ { "type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "created": "2025-08-13T05:43:17Z", "verificationMethod": "did:key:z6MkkkjG6shmZk6D2ghgDbpJQHD4xvpZhzYiWSLKDeznibiJ#z6MkkkjG6shmZk6D2ghgDbpJQHD4xvpZhzYiWSLKDeznibiJ", "proofPurpose": "assertionMethod", "proofValue": "z3L7j2siRiZ4zziQQmRqLY5qH2RfVz6VTC5gbDE6vntw1De5Ej5DNR3wDU6m9KRiUYPm9o8P89yMzNk5EhWVTo4Tn" } ] }"#,
        "Missing DID Document parameters"
    )]
    #[case(
        r#"{"versionId":"1-Qhashhashhashhashhashhashhashhashhashhashhashhash","versionTime":"2025-04-29T17:15:59Z", "parameters":{"invalidParameter": 1}, "state":{"@context":["https://www.w3.org/ns/did/v1", "https://w3id.org/security/jwk/v1"], "id":"did:webvh:QmQyDxVnosYTzHAMbzYDRZkVrD32ea9Sr2XNs8NkgMB5mn:domain.example"} }"#,
        "Additional properties are not allowed ('invalidParameter' was unexpected)"
    )]
    // invalid proof
    fn test_invalid_did_log(#[case] did_log: String, #[case] error_string: &str) {
        assert_trust_did_web_error(
            WebVerifiableHistoryDidLog::try_from(did_log),
            DidResolverErrorKind::DeserializationFailed,
            error_string,
        );
    }

    #[rstest]
    #[case(
        "test_data/manually_created/unhappy_path/invalid_scid.jsonl",
        "did:webvh:QmT7BM5RsM9SoaqAQKkNKHBzSEzpS2NRzT2oKaaaPYPpGr:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
        DidResolverErrorKind::InvalidIntegrityProof,
        "invalid DID log integration proof: The SCID"
        )]
    #[case(
        "test_data/manually_created/unhappy_path/signed_with_unauthorized_key.jsonl",
        "did:webvh:QmT7BM5RsM9SoaqAQKkNKHBzSEzpS2NRzT2oKaaaPYPpGr:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
        DidResolverErrorKind::InvalidIntegrityProof,
        "Key extracted from proof is not authorized for update"
    )]
    #[case(
        "test_data/manually_created/unhappy_path/invalid_scid.jsonl",
        "did:webvh:QmT7BM5RsM9SoaqAQKkNKHBzSEzpS2NRzT2oKaaaPYPpGr:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
        DidResolverErrorKind::InvalidIntegrityProof,
        "invalid DID log integration proof: The SCID"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/unhappy_path/descending_version_datetime_did.jsonl",
        "did:webvh:QmT4kPBFsHpJKvvvxgFUYxnSGPMeaQy1HWwyXMHj8NjLuy:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
        DidResolverErrorKind::DeserializationFailed,
        "`versionTime` must be greater than the `versionTime` of the previous entry"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/unhappy_path/invalid_initial_version_number_did.jsonl",
        "did:webvh:QmT4kPBFsHpJKvvvxgFUYxnSGPMeaQy1HWwyXMHj8NjLuy:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
        DidResolverErrorKind::DeserializationFailed,
        "Version numbers (`versionId`) must be in a sequence of positive consecutive integers"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/unhappy_path/inconsecutive_version_numbers_did.jsonl",
        "did:webvh:QmT4kPBFsHpJKvvvxgFUYxnSGPMeaQy1HWwyXMHj8NjLuy:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
        DidResolverErrorKind::DeserializationFailed,
        "Version numbers (`versionId`) must be in a sequence of positive consecutive integers"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/unhappy_path/version_time_in_the_future_did.jsonl",
        "did:tdw:QmT4kPBFsHpJKvvvxgFUYxnSGPMeaQy1HWwyXMHj8NjLuy:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
        DidResolverErrorKind::DeserializationFailed,
        "must be before the current datetime"
    )]
    #[case(
        "test_data/manually_created/unhappy_path/signed_with_outdated_key.jsonl",
        "did:webvh:QmYDETZ8E1Sj3FiXubkw2D3XRa7Fxz26ykE8JFDZFUHzNU:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
        DidResolverErrorKind::InvalidDidParameter,
        "Illegal update key detected"
    )]
    /* TODO generate a proper (did:webvh) test case data using didtoolbox-java
    #[case(
        "test_data/generated_by_tdw_js/already_deactivated.jsonl",
        "did:tdw:QmdSU7F2rF8r4m6GZK7Evi2tthfDDxhw3NppU8pJMbd2hB:example.com",
        DidResolverErrorKind::InvalidDidDocument,
        "This DID document is already deactivated"
    )]
    #[case(
        "test_data/generated_by_tdw_js/unhappy_path/not_authorized.jsonl",
        "did:tdw:QmXjp5qhSEvm8oXip43cDX62hZhHZdAMYv7Magy1tkffSz:example.com",
        DidResolverErrorKind::InvalidIntegrityProof,
        "Key extracted from proof is not authorized for update"
    )]
    */
    fn test_read_invalid_did_log(
        #[case] did_log_raw_filepath: String,
        #[case] did_url: String,
        #[case] error_kind: DidResolverErrorKind,
        #[case] err_contains_pattern: String,
    ) {
        let did_log_raw = fs::read_to_string(Path::new(&did_log_raw_filepath)).unwrap();

        // CAUTION No ? operator required here as we want to inspect the expected error
        let webvh = WebVerifiableHistory::resolve(did_url, did_log_raw);

        assert!(webvh.is_err());
        let err_opt = webvh.err();
        assert!(err_opt.is_some());
        let err = err_opt.unwrap(); // panic-safe (see the previous line)
        assert_eq!(err.kind(), error_kind);
        assert!(
            err.to_string().contains(&err_contains_pattern),
            "err message should contain '{}', but got '{}'",
            err_contains_pattern,
            err
        );
    }
}
