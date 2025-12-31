// SPDX-License-Identifier: MIT

use crate::did_tdw_jsonschema::TrustDidWebDidLogEntryJsonSchema;
use crate::did_tdw_method_parameters::*;
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
use did_sidekicks::vc_data_integrity::*;
use rayon::prelude::*;
use regex;
use regex::Regex;
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

/// Regex to check if a domain follows the assumption described in https://www.rfc-editor.org/rfc/rfc952.html
/// Allowed are lowercase letters (a-z), digits (0-9) dash (-) and period (.). Periods are only allowed to
/// delimit components.
static DOMAIN_REGEX: &str = r"^[\-a-z0-9]+(\.[\-a-z0-9]+)*$";
static HAS_PATH_REGEX: &str = r"([a-z]|[0-9])\/([a-z]|[0-9])";
static HAS_PORT_REGEX: &str = r"\:[0-9]+";

/// Entry in a did log file as shown here
/// https://identity.foundation/didwebvh/v0.3/#the-did-log-file
#[expect(clippy::exhaustive_structs, reason = "..")]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DidLogEntry {
    /// Since v0.2 (see https://identity.foundation/trustdidweb/v0.3/#didtdw-version-changelog):
    ///            The new versionId takes the form <version number>-<entryHash>, where <version number> is the incrementing integer of version of the entry: 1, 2, 3, etc.
    pub version_id: String,
    #[serde(skip)]
    pub version_index: usize,
    #[serde(with = "ts_seconds")]
    pub version_time: DateTime<Utc>,
    pub parameters: TrustDidWebDidMethodParameters,
    pub did_doc: DidDoc,
    #[serde(skip)]
    pub did_doc_json: String,
    #[serde(skip)]
    pub did_doc_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Vec<DataIntegrityProof>>,
    #[serde(skip)]
    pub prev_entry: Option<Arc<Self>>, // Arc-ed to prevent "recursive without indirection"
}

impl DidLogEntry {
    /// Import of existing log entry
    #[inline]
    #[expect(clippy::too_many_arguments, reason = "..")]
    pub fn new(
        version_id: String,
        version_index: usize,
        version_time: DateTime<Utc>,
        parameters: TrustDidWebDidMethodParameters,
        did_doc: DidDoc,
        did_doc_json: String,
        did_doc_hash: String,
        proof: DataIntegrityProof,
        prev_entry: Option<Arc<Self>>,
    ) -> Self {
        Self {
            version_id,
            version_index,
            version_time,
            parameters,
            did_doc,
            did_doc_json,
            did_doc_hash,
            proof: Some(vec![proof]),
            prev_entry,
        }
    }

    /// Check whether the versionId of this log entry is based on the previous versionId
    #[inline]
    pub fn verify_version_id_integrity(&self) -> Result<(), DidResolverError> {
        let version_id = self.build_version_id().map_err(|err| {
            DidResolverError::InvalidDataIntegrityProof(format!("Failed to build versionId: {err}"))
        })?;
        if version_id != self.version_id {
            return Err(DidResolverError::InvalidDataIntegrityProof(format!(
                "Invalid DID log. The DID log entry has invalid entry hash: {}. Expected: {}",
                self.version_id, version_id
            )));
        }
        Ok(())
    }

    /// Check whether the integrity proof matches the content of the did document of this log entry
    #[inline]
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

        let prev = self.prev_entry.as_ref().map_or(self, |err| err);

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

            match EddsaJcs2022Cryptosuite::from_verifying_key(&verifying_key)
                .verify_proof(&proof, self.did_doc_hash.as_str())
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
    pub fn build_version_id(&self) -> Result<String, DidResolverError> {
        // Since v0.2 (see https://identity.foundation/trustdidweb/v0.3/#didtdw-version-changelog):
        //            The new versionId takes the form <version number>-<entry_hash>, where <version number> is the incrementing integer of version of the entry: 1, 2, 3, etc.
        // Also see https://identity.foundation/trustdidweb/v0.3/#the-did-log-file:
        //            A Data Integrity Proof across the entry, signed by a DID authorized to update the DIDDoc, using the versionId as the challenge.
        let prev_version_id = match self.prev_entry.to_owned() {
            Some(entry) => entry.version_id.to_owned(),
            None => match self.parameters.get_scid_option() {
                Some(scid) => scid,
                None => {
                    return Err(DidResolverError::DeserializationFailed(
                        "Error extracting SCID".to_owned(),
                    ))
                }
            },
        };

        let entry_without_proof = Self {
            version_id: prev_version_id,
            version_index: self.version_index,
            version_time: self.version_time,
            parameters: self.parameters.clone(),
            did_doc: self.did_doc.clone(),
            did_doc_json: self.did_doc_json.clone(),
            did_doc_hash: self.did_doc_hash.clone(),
            proof: None,
            prev_entry: None,
        };
        let entry_line = entry_without_proof.to_log_entry_line()?;
        let entry_hash = JcsSha256Hasher::default()
            .base58btc_encode_multihash_json_value(&entry_line)
            .map_err(|err| {
                DidResolverError::SerializationFailed(format!(
                    "Failed to base58btc-encode canonical JSON multihash: {err}"
                ))
            })?;

        Ok(format!("{}-{}", self.version_index, entry_hash))
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

                match update_keys.iter().find(|entry| *entry == &update_key) {
                    Some(_) => {}
                    _ => {
                        return Err(DidResolverError::InvalidDataIntegrityProof(format!(
                            "Key extracted from proof is not authorized for update: {update_key}"
                        )))
                    }
                };

                let verifying_key = match Ed25519VerifyingKey::from_multibase(update_key.as_str()) {
                    Ok(key) => key,
                    Err(err) => {
                        return Err(DidResolverError::InvalidDataIntegrityProof(format!(
                        "Failed to convert update key (from its multibase representation): {err}"
                    )))
                    }
                };

                //Ok(Ed25519VerifyingKey::from_multibase(update_key.as_str())?)
                Ok(verifying_key)
            }
            None => {
                let prev_entry = match self.prev_entry.to_owned() {
                    Some(err) => err,
                    _ => {
                        return Err(DidResolverError::InvalidDataIntegrityProof(
                            "No update keys detected".to_owned(),
                        ));
                    }
                };
                prev_entry.is_key_authorized_for_update(update_key) // recursive call
            }
        }
    }

    fn to_log_entry_line(&self) -> Result<JsonValue, DidResolverError> {
        let did_doc_json_value: JsonValue = match serde_json::from_str(&self.did_doc_json) {
            Ok(val) => val,
            Err(err) => return Err(DidResolverError::DeserializationFailed(format!("{err}"))),
        };

        let version_time = self
            .version_time
            .to_owned()
            .to_rfc3339_opts(SecondsFormat::Secs, true);
        match self.proof.to_owned() {
            Some(proof) => {
                let first_proof = match proof.first() {
                    Some(pr) => pr,
                    None => {
                        return Err(DidResolverError::InvalidDataIntegrityProof(
                            "Proof is empty.".to_owned(),
                        ))
                    }
                };

                Ok(json!([
                    self.version_id,
                    version_time,
                    self.parameters,
                    {
                        "value": did_doc_json_value
                    },

                    vec![first_proof.to_json_value()]
                ]))
            }
            None => Ok(json!([
                self.version_id,
                version_time,
                self.parameters,
                {
                    "value": did_doc_json_value
                }
            ])),
        }
    }

    fn build_original_scid(&self, scid: &String) -> serde_json::Result<String> {
        let entry_with_placeholder_without_proof = json!([
            SCID_PLACEHOLDER,
            self.version_time,
            json_from_str::<JsonValue>(str::replace(json_to_string(&self.parameters)?.as_str(), scid, SCID_PLACEHOLDER).as_str())?,
            { "value" : json_from_str::<JsonValue>(str::replace(&self.did_doc_json, scid, SCID_PLACEHOLDER).as_str())?},
        ]);

        let hash = JcsSha256Hasher::default()
            .base58btc_encode_multihash_json_value(&entry_with_placeholder_without_proof)?;
        Ok(hash)
    }
}

/// The parser for `did:tdw` DID logs implementing [`TryFrom<String>`] trait.
#[expect(clippy::exhaustive_structs, reason = "..")]
#[derive(Serialize, Deserialize, Debug)]
pub struct TrustDidWebDidLog {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub did_log_entries: Vec<DidLogEntry>,
    pub did_method_parameters: TrustDidWebDidMethodParameters,
}

impl TryFrom<String> for TrustDidWebDidLog {
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
        let sch: &dyn DidLogEntryJsonSchema = &TrustDidWebDidLogEntryJsonSchema::V03EidConform;
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

        let mut current_params: Option<TrustDidWebDidMethodParameters> = None;
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

                    // CAUTION: It is assumed that the did:tdw JSON schema conformity check (see above) 
                    //          have already been ensured at this point! 
                    //          Therefore, at this point, the current DID log entry may be considered fully JSON-schema-compliant, so...
                    let entry: JsonValue = serde_json::from_str(line).unwrap();     // ...no panic is expected here
                    let version_id = entry[0].as_str().unwrap().to_owned(); // ...or here

                    // Since v0.2 (see https://identity.foundation/trustdidweb/v0.3/#didtdw-version-changelog):
                    //            The new versionId takes the form <versionNumber>-<entryHash>, where <version number> is the incrementing integer of version of the entry: 1, 2, 3, etc.
                    let version_index: usize = version_id.split_once("-")
                        .map(|(index, _)| index.parse::<usize>().unwrap()) // no panic is expected here...
                        .unwrap(); // ...or here (as the entry has already been validated)

                    if prev_entry.is_none() && version_index != 1
                        || prev_entry.is_some() && (version_index - 1).ne(&prev_entry.to_owned().unwrap().version_index) {
                        return Err(DidResolverError::DeserializationFailed("Version numbers (`versionId`) must be in a sequence of positive consecutive integers.".to_owned()));
                    }

                    // https://identity.foundation/didwebvh/v0.3/#the-did-log-file:
                    // The `versionTime` (as stated by the DID Controller) of the entry,
                    // in ISO8601 format (https://identity.foundation/didwebvh/v0.3/#term:iso8601).
                    let version_time = entry[1].as_str()
                        .map(|str| DateTime::parse_from_rfc3339(str)
                            .unwrap() // no panic is expected here...
                            .to_utc())
                        .unwrap(); // ...or here (as the entry has already been validated)

                    // CAUTION This check is not really required as it has been already implemented by the JSON schema validator
                    if version_time.ge(&now) {
                        return Err(DidResolverError::DeserializationFailed(format!("`versionTime` '{version_time}' must be before the current datetime '{now}'.")));
                    }

                    if prev_entry.is_some() && version_time.lt(&prev_entry.to_owned().unwrap().version_time) {
                        return Err(DidResolverError::DeserializationFailed("`versionTime` must be greater then the `versionTime` of the previous entry.".to_owned()));
                    }

                    let mut new_params: Option<TrustDidWebDidMethodParameters> = None;
                    current_params = match entry[2].to_owned() {
                        JsonObject(obj) => {
                            if !obj.is_empty() {
                                new_params = Some(TrustDidWebDidMethodParameters::from_json(&entry[2].to_string())?);
                            }

                            match (current_params.clone(), new_params.clone()) {
                                (None, None) => return Err(DidResolverError::DeserializationFailed(
                                    "Missing DID method parameters.".to_owned(),
                                )),
                                (None, Some(params)) => {
                                    // this is the first entry, therefore we check for the base configuration
                                    params.validate_initial()?;

                                    Some(params) // from the initial log entry
                                }
                                (Some(params), None) => {
                                    new_params = Some(TrustDidWebDidMethodParameters::empty());
                                    Some(params)
                                }
                                (Some(mut current_par), Some(new_par)) => {
                                    current_par.merge_from(&new_par)?;
                                    Some(current_par)
                                }
                            }
                        }
                        _ => {
                            return Err(DidResolverError::DeserializationFailed(
                                "Missing DID Document parameters.".to_owned(),
                            ))
                        }
                    };

                    is_deactivated = current_params.to_owned().is_some_and(|params| params.deactivated.is_some_and(|deact| deact));
                    if is_deactivated {
                        // https://identity.foundation/didwebvh/v0.3/#deactivate-revoke:
                        // To deactivate the DID, the DID Controller SHOULD add to the DID log entry parameters the item "deactivated": true.
                        // A DID MAY update the DIDDoc further to indicate the deactivation of the DID,
                        // such as including an empty updateKeys list ("updateKeys": []) in the parameters,
                        // preventing further versions of the DID.
                        if let Some(mut _current_params) = current_params.to_owned() {
                            _current_params.deactivate();
                            current_params = Some(_current_params);
                        }
                    }

                    let did_doc_hash: String;
                    let did_doc_json: String;

                    let current_did_doc: DidDoc = match entry[3].to_owned() {
                        JsonObject(obj) => {
                            if obj.contains_key("value") {
                                let did_doc_value: JsonValue = obj["value"].to_owned();
                                if !did_doc_value.is_null() {
                                    did_doc_json = did_doc_value.to_string();
                                    did_doc_hash = match JcsSha256Hasher::default().encode_hex_json_value(&did_doc_value) {
                                        Ok(did_doc_hash_value) => did_doc_hash_value,
                                        Err(err) => return Err(DidResolverError::DeserializationFailed(
                                            format!("Deserialization of DID document failed due to: {err}")
                                        ))
                                    };

                                    match serde_json::from_str::<DidDoc>(&did_doc_json) {
                                        Ok(did_doc) => did_doc,
                                        Err(_) => {
                                            match serde_json::from_str::<DidDocNormalized>(&did_doc_json) {
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
                                } else {
                                    return Err(DidResolverError::DeserializationFailed(
                                        "Missing DID Document. JSON 'value' was empty.".to_owned(),
                                    ));
                                }
                            } else if obj.contains_key("patch") {
                                return Err(DidResolverError::DeserializationFailed(
                                    "Missing DID Document. JSON 'patch' is not supported.".to_owned(),
                                ))
                            } else {
                                return Err(DidResolverError::DeserializationFailed(
                                    "Missing DID Document. No 'value' detected.".to_owned(),
                                ))
                            }
                        }
                        _ => {
                            return Err(DidResolverError::DeserializationFailed(
                                "Missing DID Document.".to_owned(),
                            ))
                        }
                    };

                    let proof = match DataIntegrityProof::from_json_string(entry[4].to_string()) {
                        Ok(pr) => pr,
                        Err(err) => return Err(DidResolverError::DeserializationFailed(format!(
                            "Failed to deserialize data integrity proof due to: {err}"
                        ))),
                    };

                    let parameters = match new_params {
                        Some(params) => params,
                        None => return Err(DidResolverError::DeserializationFailed(
                            "Internal error: Missing parameter values.".to_owned(),
                        ))
                    };

                    let current_entry = DidLogEntry::new(
                        version_id,
                        version_index,
                        version_time,
                        parameters,
                        current_did_doc,
                        did_doc_json,
                        did_doc_hash,
                        proof,
                        prev_entry.clone(),
                    );
                    prev_entry = Some(Arc::from(current_entry.clone()));

                    Ok(current_entry)
                }).collect::<Result<Vec<DidLogEntry>, DidResolverError>>()?;

        if current_params.is_none() {
            // unlikely, but still
            return Err(DidResolverError::DeserializationFailed(
                "Missing DID method parameters.".to_owned(),
            ));
        }

        Ok(Self {
            did_method_parameters: current_params.unwrap(), // a panic-safe unwrap call, due to the previous line
            did_log_entries,
        })
    }
}

impl TrustDidWebDidLog {
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
        let mut previous_entry: Option<DidLogEntry> = None;
        for entry in &self.did_log_entries {
            match previous_entry.to_owned() {
                Some(prev) => {
                    // Check if version has incremented
                    if entry.version_index != prev.version_index + 1 {
                        return Err(DidResolverError::InvalidDataIntegrityProof(format!(
                            "Invalid did log for version {}. Version id has to be incremented",
                            entry.version_index
                        )));
                    }
                    // Verify data integrity proof
                    entry.verify_data_integrity_proof()?;

                    // Verify the entryHash
                    entry.verify_version_id_integrity()?;
                    previous_entry = Some(entry.clone());
                }
                None => {
                    // First / genesis entry in did log
                    let genesis_entry = entry;
                    if genesis_entry.version_index != 1 {
                        return Err(DidResolverError::InvalidDataIntegrityProof(
                            "Invalid did log. First entry has to have version id 1".to_owned(),
                        ));
                    }

                    // Verify data integrity proof
                    genesis_entry.verify_data_integrity_proof()?;

                    // Verify the entryHash
                    genesis_entry.verify_version_id_integrity()?;

                    // Verify that the SCID is correct
                    let scid = match genesis_entry.parameters.get_scid_option() {
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

                    let original_scid =
                        genesis_entry.build_original_scid(&scid).map_err(|err| {
                            DidResolverError::InvalidDataIntegrityProof(format!(
                                "Failed to build original SCID: {err}"
                            ))
                        })?;
                    if original_scid != scid {
                        return Err(DidResolverError::InvalidDataIntegrityProof(
                            "Invalid did log. Genesis entry has invalid SCID".to_owned(),
                        ));
                    }
                    previous_entry = Some(genesis_entry.clone());
                }
            };
        }
        match previous_entry {
            Some(entry) => Ok(entry.did_doc),
            None => Err(DidResolverError::InvalidDataIntegrityProof(
                "Invalid did log. No entries found".to_owned(),
            )),
        }
    }

    /// Checks if all entries in the did log are valid (data integrity, versioning etc.)
    #[inline]
    pub fn validate(&self) -> Result<DidDoc, DidResolverError> {
        self.validate_with_scid(None)
    }

    #[inline]
    pub fn get_did_method_parameters(&self) -> TrustDidWebDidMethodParameters {
        self.did_method_parameters.clone()
    }
}

impl core::fmt::Display for TrustDidWebDidLog {
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

/// As specified at https://identity.foundation/trustdidweb/#method-specific-identifier:
///
/// "The did:tdw method-specific identifier contains both the self-certifying identifier (SCID) for the DID,
/// and a fully qualified domain name (with an optional path) that is secured by a TLS/SSL certificate."
pub struct TrustDidWebId {
    scid: String,
    url: String,
}

impl TrustDidWebId {
    pub const DID_METHOD_NAME: &'static str = "tdw";

    /// Yet another UniFFI-compliant method.
    ///
    /// Otherwise, the idiomatic counterpart (try_from(did_tdw: String) -> Result<Self, Self::Error>) may be used as well.
    #[inline]
    pub fn parse_did_tdw(did_tdw: String) -> Result<Self, TrustDidWebIdResolutionError> {
        match Self::try_from(did_tdw) {
            Ok(parsed) => Ok(parsed),
            Err(err) => Err(err),
        }
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

/// Implementation for a string denoting did_tdw
impl TryFrom<String> for TrustDidWebId {
    type Error = TrustDidWebIdResolutionError;

    /// It basically implements the 'The DID to HTTPS Transformation',
    /// as specified by https://identity.foundation/didwebvh/v0.3/#the-did-to-https-transformation
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
    fn try_from(did_tdw: String) -> Result<Self, Self::Error> {
        let did_tdw_split: Vec<&str> = did_tdw.splitn(4, ":").collect();
        if did_tdw_split.len() < 4 {
            return Err(TrustDidWebIdResolutionError::InvalidMethodSpecificId(
                did_tdw,
            ));
        };

        let method_name = format!("{}:{}", did_tdw_split[0], did_tdw_split[1]);
        if method_name != format!("did:{}", Self::DID_METHOD_NAME) {
            return Err(TrustDidWebIdResolutionError::MethodNotSupported(
                method_name,
            ));
        };

        let scid = did_tdw_split[2];
        if scid.is_empty() {
            // the SCID MUST be present in the DID string
            return Err(TrustDidWebIdResolutionError::InvalidMethodSpecificId(
                String::from("Empty self-certifying identifier (SCID) detected. An object identifier derived from initial data is expected"),
            ));
        };

        if did_tdw_split[3].replace(":", "").is_empty() || did_tdw_split[3].starts_with(":") {
            return Err(TrustDidWebIdResolutionError::InvalidMethodSpecificId(
                String::from("No fully qualified domain detected"),
            ));
        };

        // https://identity.foundation/didwebvh/v0.3/#the-did-to-https-transformation:
        // 1. Remove the literal did:tdw: prefix from the DID, leaving the method specific identifier.
        // 2. Remove the SCID by removing the text up to and including the first colon (<scid>:) from the method-specific identifier and continue processing.
        // 3. Replace : with / in the method-specific identifier to obtain the fully qualified domain name and optional path.
        let domain_and_optional_path = did_tdw_split[3].replace(":", "/");

        // 5. If the domain contains a port, percent decode the colon.
        let decoded_url = domain_and_optional_path.replace("%3A", ":"); // Decode percent-encoded byte '%3A' (the percent-encoded semicolon (':') char/byte)

        // 6. Generate an HTTPS URL to the expected location of the DIDDoc by prepending https://.
        let url_string = format!("https://{decoded_url}");

        let mut url = match Url::parse(&url_string) {
            Ok(url) => url,
            Err(err) => {
                return Err(TrustDidWebIdResolutionError::InvalidMethodSpecificId(
                    format!("Not a valid URL: {err}"),
                ))
            }
        };

        // Verify that the host is a valid domain.
        // Special characters were encoded by `Url::parse`.
        // URL without domain, that instead use an ip address are already validated in step 5
        if let url::Origin::Tuple(_, url::Host::Domain(domain), _) = url.origin() {
            if Regex::new(DOMAIN_REGEX)
                .unwrap()
                .captures(domain.as_str())
                .is_none()
            {
                return Err(TrustDidWebIdResolutionError::InvalidMethodSpecificId(
                    "Domain of provided DID is invalid".to_owned(),
                ));
            }
        }

        let has_no_url_path = url.path().is_empty() || url.path() == "/";
        // get an object with methods to manipulate this URL’s path segments
        match url.path_segments_mut() {
            Ok(mut path_segments) => {
                if has_no_url_path {
                    // 4. If there is no optional path, append '/.well-known' to the URL.
                    path_segments.push(".well-known");
                }

                // 7. Append /did.jsonl to complete the URL.
                path_segments.push("did.jsonl");
            }
            Err(_) => {
                // path_segments_mut "Return Err(()) if this URL is cannot-be-a-base."
                return Err(TrustDidWebIdResolutionError::InvalidMethodSpecificId(
                    "This URL cannot-be-a-base".to_owned(),
                ));
            }
        };

        Ok(Self {
            scid: scid.to_owned(),
            url: url.to_string(),
        })
    }
}

/// Implementation for a tuple denoting did_tdw and allow_http.
#[diagnostic::do_not_recommend]
impl TryFrom<(String, Option<bool>)> for TrustDidWebId {
    type Error = TrustDidWebIdResolutionError;

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
        let did_tdw = value.0;
        let allow_http = value.1;

        let split: Vec<&str> = did_tdw.splitn(3, ":").collect();
        if split.len() < 3 || split[2].is_empty() {
            return Err(TrustDidWebIdResolutionError::InvalidMethodSpecificId(
                did_tdw,
            ));
        };

        let method_name = format!("{}:{}", split[0], split[1]);
        if method_name != format!("did:{}", Self::DID_METHOD_NAME) {
            return Err(TrustDidWebIdResolutionError::MethodNotSupported(
                method_name,
            ));
        };
        let scid = split[2];

        let mut decoded_url = String::from("");
        match scid.split_once(":") {
            Some((scid_str, did_tdw_reduced)) => {
                url_escape::decode_to_string(did_tdw_reduced.replace(":", "/"), &mut decoded_url);
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
                        return Err(TrustDidWebIdResolutionError::InvalidMethodSpecificId(
                            did_tdw_reduced.to_owned(),
                        ))
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
                        scid: scid_str.to_owned(),
                        url: format!("{url}/did.jsonl"),
                    })
                } else {
                    Ok(Self {
                        scid: scid_str.to_owned(),
                        url: format!("{url}/.well-known/did.jsonl"),
                    })
                }
            }
            None => Err(TrustDidWebIdResolutionError::InvalidMethodSpecificId(
                did_tdw,
            )),
        }
    }
}

/// TODO Doc comments missing
pub struct TrustDidWeb {
    did: String,
    did_log: String,
    did_doc: String,
    did_doc_obj: DidDoc,
    did_method_parameters: TrustDidWebDidMethodParameters,
}

impl TrustDidWeb {
    #[inline]
    pub fn get_did(&self) -> String {
        self.did.clone()
    }

    #[inline]
    pub fn get_did_log(&self) -> String {
        self.did_log.clone()
    }

    #[inline]
    pub fn get_did_doc(&self) -> String {
        self.did_doc.clone()
    }

    /// Delivers the fully qualified DID document (as [`DidDoc`]) contained within the DID log previously supplied via [`TrustDidWeb::resolve`] constructor.
    fn get_did_doc_obj(&self) -> DidDoc {
        self.did_doc_obj.clone()
    }

    /// The thread-safe version of [`TrustDidWeb::get_did_doc_obj`].
    ///
    /// Yet another UniFFI-compliant getter.
    #[inline]
    pub fn get_did_doc_obj_thread_safe(&self) -> Arc<DidDoc> {
        Arc::new(self.get_did_doc_obj())
    }

    fn get_did_method_parameters_obj(&self) -> TrustDidWebDidMethodParameters {
        self.did_method_parameters.clone()
    }

    /// The thread-safe version of [`TrustDidWeb::get_did_method_parameters_obj`].
    ///
    /// Yet another UniFFI-compliant getter.
    #[inline]
    pub fn get_did_method_parameters(&self) -> Arc<TrustDidWebDidMethodParameters> {
        Arc::new(self.get_did_method_parameters_obj())
    }

    /// A UniFFI-compliant constructor.
    #[deprecated(note = "use `resolve` instead")]
    #[inline]
    pub fn read(did_tdw: String, did_log: String) -> Result<Self, TrustDidWebError> {
        match Self::resolve(did_tdw, did_log) {
            Ok(tdw) => Ok(tdw),
            Err(err) => Err(TrustDidWebError::from(err)),
        }
    }

    /// A UniFFI-compliant constructor.
    #[inline]
    pub fn resolve(did_tdw: String, did_log: String) -> Result<Self, DidResolverError> {
        let did_log_obj = TrustDidWebDidLog::try_from(did_log)?;

        let did = TrustDidWebId::parse_did_tdw(did_tdw)
            .map_err(|err| DidResolverError::InvalidMethodSpecificId(format!("{err}")))?;

        let did_doc_valid = did_log_obj.validate_with_scid(Some(did.get_scid()))?;
        let did_doc_str = match serde_json::to_string(&did_doc_valid) {
            Ok(str) => str,
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

impl DidResolver for TrustDidWeb {
    //type Error = DidResolverError;

    #[inline]
    fn get_did_doc_obj(&self) -> DidDoc {
        self.get_did_doc_obj()
    }

    #[inline]
    fn collect_did_method_parameters_map(
        &self,
    ) -> Result<HashMap<String, Arc<DidMethodParameter>>, DidResolverError> {
        match self.get_did_method_parameters_obj().try_into() {
            Ok(map) => Ok(map),
            Err(err) => Err(DidResolverError::InvalidDidParameter(format!("{err}"))),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::did_tdw::{TrustDidWeb, TrustDidWebDidLog};
    use crate::did_tdw_method_parameters::TrustDidWebDidMethodParameters;
    use crate::test::assert_trust_did_web_error;
    use did_sidekicks::errors::DidResolverErrorKind;
    use rstest::rstest;
    use serde_json::json;
    use std::fs;
    use std::path::Path;

    /// A rather trivial unit testing helper.
    fn build_valid_params_json_string() -> String {
        json!(TrustDidWebDidMethodParameters::for_genesis_did_doc(
            "123".to_string(),
            "123".to_string()
        ))
        .to_string()
    }

    #[rstest]
    // doc needs 5 entries
    #[case("[1,2,3]")]
    // invalid version id
    #[case("[\"1\",2,3,4,5]")]
    #[case("[\"invalidNumber-hash\",2,3,4,5]")]
    // invalid time
    #[case("[\"1-hash\",[1234],3,4,5]")]
    #[case("[\"1-hash\",\"invalidTime\",3,4,5]")]
    // missing params
    #[case("[\"1-hash\",\"2012-12-12T12:12:12Z\",{},4,5]")]
    // JSON 'patch' is not supported
    #[case(format!("[\"1-hash\",\"2012-12-12T12:12:12Z\",{},{{\"patch\":0}},5]", build_valid_params_json_string()))]
    // JSON 'value' needs to be a valid did doc
    #[case(format!("[\"1-hash\",\"2012-12-12T12:12:12Z\",{},{{\"value\":\"invalidDoc\"}},5]", build_valid_params_json_string()))]
    fn test_invalid_did_log(#[case] did_log: String) {
        assert_trust_did_web_error(
            TrustDidWebDidLog::try_from(did_log),
            DidResolverErrorKind::DeserializationFailed,
            "the supplied DID document is invalid or contains an argument which isn't part of the did specification/recommendation: the supplied JSON instance is not a valid DID log: A DID log entry must include a JSON array of five items of the following types: string, string, object, object and array",
        );
    }

    #[rstest]
    #[case(
        "test_data/generated_by_didtoolbox_java/unhappy_path/descending_version_datetime_did.jsonl",
        "did:tdw:QmT7BM5RsM9SoaqAQKkNKHBzSEzpS2NRzT2oKaaaPYPpGr:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
        DidResolverErrorKind::DeserializationFailed,
        "`versionTime` must be greater then the `versionTime` of the previous entry"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/unhappy_path/invalid_initial_version_number_did.jsonl",
        "did:tdw:QmT7BM5RsM9SoaqAQKkNKHBzSEzpS2NRzT2oKaaaPYPpGr:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
        DidResolverErrorKind::DeserializationFailed,
        "Version numbers (`versionId`) must be in a sequence of positive consecutive integers"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/unhappy_path/inconsecutive_version_numbers_did.jsonl",
        "did:tdw:QmT7BM5RsM9SoaqAQKkNKHBzSEzpS2NRzT2oKaaaPYPpGr:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
        DidResolverErrorKind::DeserializationFailed,
        "Version numbers (`versionId`) must be in a sequence of positive consecutive integers"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/unhappy_path/version_time_in_the_future_did.jsonl",
        "did:tdw:QmT7BM5RsM9SoaqAQKkNKHBzSEzpS2NRzT2oKaaaPYPpGr:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
        DidResolverErrorKind::DeserializationFailed,
        "must be before the current datetime"
    )]
    /* TODO generate a proper test case data using didtoolbox-java
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
        let tdw = TrustDidWeb::resolve(did_url.clone(), did_log_raw);

        assert!(tdw.is_err());
        let err = tdw.err();
        assert!(err.is_some());
        let err = err.unwrap();
        assert_eq!(err.kind(), error_kind);
        assert!(
            err.to_string().contains(&err_contains_pattern),
            "err message should contain '{}', but got '{}'",
            err_contains_pattern,
            err
        );
    }
}
