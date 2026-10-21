// SPDX-License-Identifier: MIT

use std::str::FromStr;

use chrono::{DateTime, SecondsFormat, Utc, serde::ts_seconds};
use did_sidekicks::{
    did_doc::{DidDoc, DidDocNormalized},
    ed25519::Ed25519VerifyingKey,
    errors::DidResolverError,
    jcs_sha256_hasher::JcsSha256Hasher,
    multibase::MultiBaseConvertible as _,
    vc_data_integrity::{
        CryptoSuiteType, DataIntegrityProof, EddsaJcs2022Cryptosuite, VCDataIntegrity as _,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{
    method_parameters::WebVerifiableHistoryDidMethodParameters, version_id::DidLogVersion,
};

type DidLogVersionTime = DateTime<Utc>;

pub const SCID_PLACEHOLDER: &str = "{SCID}";
pub const DID_LOG_ENTRY_VERSION_ID: &str = "versionId";
pub const DID_LOG_ENTRY_VERSION_TIME: &str = "versionTime";
pub const DID_LOG_ENTRY_PARAMETERS: &str = "parameters";
pub const DID_LOG_ENTRY_STATE: &str = "state";
pub const DID_LOG_ENTRY_PROOF: &str = "proof";

/// Entry in a did log file as shown here
/// https://identity.foundation/didwebvh/v1.0/#term:did-log-entry.
#[expect(clippy::exhaustive_structs, reason = "..")]
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct DidLogEntry {
    /// Since v0.2 (see https://identity.foundation/didwebvh/v1.0/#didwebvh-version-changelog):
    ///            The new versionId takes the form <version number>-<entryHash>, where <version number> is the incrementing integer of version of the entry: 1, 2, 3, etc.
    #[serde(rename = "versionId")]
    pub version: DidLogVersion,

    #[serde(rename = "versionTime")]
    #[serde(with = "ts_seconds")]
    pub version_time: DidLogVersionTime,

    #[serde(rename = "parameters")]
    pub parameters: WebVerifiableHistoryDidMethodParameters,

    #[serde(rename = "state")]
    pub did_doc: DidDoc,

    #[serde(skip)]
    pub did_doc_json: Value,

    #[serde(rename = "proof")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Vec<DataIntegrityProof>>,
}

impl DidLogEntry {
    /// Import of existing log entry.
    #[inline]
    pub fn new(
        version: DidLogVersion,
        version_time: DidLogVersionTime,
        parameters: WebVerifiableHistoryDidMethodParameters,
        did_doc: DidDoc,
        did_doc_json: Value,
        proof: DataIntegrityProof,
    ) -> Self {
        Self {
            version,
            version_time,
            parameters,
            did_doc,
            did_doc_json,
            proof: Some(vec![proof]),
        }
    }

    /// Executes validation specific to the initial entry in a DID log. This does NOT fully validate
    /// the log entry.
    #[inline]
    pub fn validate_initial_entry_properties(
        &self,
    ) -> Result<(String, WebVerifiableHistoryDidMethodParameters), DidResolverError> {
        let mut params = self.parameters.clone();
        let scid = params.validate_initial()?;

        let original_scid = self.build_original_scid(&scid).map_err(|err| {
            DidResolverError::InvalidDataIntegrityProof(format!(
                "Failed to build original SCID: {err}"
            ))
        })?;
        if original_scid != scid {
            return Err(DidResolverError::InvalidDataIntegrityProof(
                "Invalid did log. Genesis entry has invalid SCID".to_owned(),
            ));
        }

        // keep track of update keys
        if self.parameters.update_keys.is_none() {
            return Err(DidResolverError::InvalidDidParameter(
                "No update keys found in initial log entry".into(),
            ));
        }
        Ok((scid, params))
    }

    /// Check whether the versionId of this log entry is based on the previous versionId.
    #[inline]
    pub fn verify_version_id_integrity(
        &self,
        prev_version_id: &str,
    ) -> Result<(), DidResolverError> {
        // 1 Extract the versionId in the DID log entry, and remove from it the version number and dash prefix, leaving the log entry entryHash value.
        let hash = &self.version.hash;
        let calculated_hash = self.calculate_entry_hash(prev_version_id).map_err(|err| {
            DidResolverError::InvalidDataIntegrityProof(format!("Failed to build versionId: {err}"))
        })?;
        if calculated_hash != *hash {
            return Err(DidResolverError::InvalidDataIntegrityProof(format!(
                "The DID log entry has invalid entry hash: {}. Expected: {}",
                hash, calculated_hash,
            )));
        }
        Ok(())
    }

    /// Check whether the integrity proof matches the content of the did document of this log
    /// entry. Update keys must be validated outside of this function.
    #[inline]
    pub fn verify_data_integrity_proof(
        &self,
        update_keys: &[String],
    ) -> Result<(), DidResolverError> {
        let proof_vec = if let Some(proof_vec) = self.proof.as_ref()
            && !proof_vec.is_empty()
        {
            proof_vec
        } else {
            return Err(DidResolverError::InvalidDataIntegrityProof(
                "Proof is empty.".to_owned(),
            ));
        };

        for proof in proof_vec {
            let update_key = proof.extract_update_key().map_err(|err| {
                DidResolverError::InvalidDataIntegrityProof(format!(
                    "Failed to extract update key due to: {err}"
                ))
            })?;

            if !update_keys.contains(&update_key) {
                return Err(DidResolverError::InvalidDataIntegrityProof(
                    "Data Integrity Proof signed with unauthorized key".into(),
                ));
            }

            let verifying_key =
                Ed25519VerifyingKey::from_multibase(update_key.as_str()).map_err(|err| {
                    DidResolverError::InvalidDataIntegrityProof(format!(
                        "Failed to convert update key (from its multibase representation): {err}"
                    ))
                })?;

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
            }
            .to_log_entry_line()?;

            let doc_hash = JcsSha256Hasher::default()
                .encode_hex_json_value(&did_log_entry)
                .map_err(|err| DidResolverError::SerializationFailed(format!("{err}")))?;

            if let Err(err) = EddsaJcs2022Cryptosuite::from_verifying_key(&verifying_key)
                .verify_proof(proof, doc_hash.as_str())
            {
                return Err(DidResolverError::InvalidDataIntegrityProof(format!(
                    "Failed to verify proof due to: {err}"
                )));
            }
        }

        Ok(())
    }

    /// The new versionId takes the form \<version number\>-\<entryHash\>, where \<version number\> is the incrementing integer of version of the entry: 1, 2, 3, etc.
    #[inline]
    pub fn calculate_entry_hash(&self, prev_version_id: &str) -> Result<String, DidResolverError> {
        // According to https://identity.foundation/didwebvh/v1.0/#entry-hash-generation-and-verification
        // 2 Determine hash algorithm from the multihash (https://identity.foundation/didwebvh/v1.0/#term:multihash), value is encoded as base58btc
        // 3 Set the versionId in the entry object to be the versionId from the previous log entry.
        //   If this is the first entry in the log, set the value to <scid>, the value of the SCID of the DID.
        // 4. remove Data Integrity proof from the log entry
        let entry = Self {
            // SAFETY: allowed as it's only used for serialization.
            version: unsafe { DidLogVersion::new_forced(prev_version_id.into()) },
            version_time: self.version_time,
            parameters: self.parameters.clone(),
            did_doc: self.did_doc.clone(),
            did_doc_json: self.did_doc_json.clone(),
            proof: None,
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

    #[expect(
        clippy::indexing_slicing,
        reason = "panic-free indexing ensured in code"
    )]
    fn to_log_entry_line(&self) -> Result<Value, DidResolverError> {
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
           DID_LOG_ENTRY_PARAMETERS: serde_json::from_str::<Value>(str::replace(serde_json::to_string(&self.parameters)?.as_str(), scid, SCID_PLACEHOLDER).as_str())?,
           DID_LOG_ENTRY_STATE :     serde_json::from_str::<Value>(did_doc_with_placeholder_scid.as_str())?,
        });

        let hash = JcsSha256Hasher::default()
            .base58btc_encode_multihash_json_value(&entry_with_placeholder_without_proof)?;
        Ok(hash)
    }
}

impl FromStr for DidLogEntry {
    type Err = DidResolverError;

    fn from_str(line: &str) -> Result<Self, Self::Err> {
        #[derive(Deserialize)]
        struct ParsableDidLogEntry {
            #[serde(rename = "versionId")]
            pub version: DidLogVersion,

            #[serde(rename = "versionTime")]
            pub version_time: String,

            #[serde(rename = "parameters")]
            pub parameters: WebVerifiableHistoryDidMethodParameters,

            #[serde(rename = "state")]
            pub did_doc: DidDocNormalized,
        }

        let log = serde_json::from_str::<ParsableDidLogEntry>(line)
            .map_err(|err| {
                DidResolverError::DeserializationFailed(format!("Invalid log entry: {err}"))
            })
            .map_err(|err| DidResolverError::DeserializationFailed(err.to_string()))?;

        let entry: Value = serde_json::from_str(line)
            .map_err(|err| DidResolverError::DeserializationFailed(err.to_string()))?;

        // https://identity.foundation/didwebvh/v1.0/#the-did-log-file:
        // The `versionTime` (as stated by the DID Controller) of the entry,
        // in ISO8601 format (https://identity.foundation/didwebvh/v0.3/#term:iso8601).
        let version_time = DateTime::parse_from_rfc3339(log.version_time.as_str())
            .map_err(|err| {
                DidResolverError::DeserializationFailed(format!(
                    "Failed to parse versionTime: {err}",
                ))
            })?
            .to_utc();

        let proof =
            match DataIntegrityProof::from_json_string(entry[DID_LOG_ENTRY_PROOF].to_string()) {
                Ok(prf) => prf,
                Err(err) => {
                    return Err(DidResolverError::DeserializationFailed(format!(
                        "Failed to deserialize data integrity proof due to: {err}"
                    )));
                }
            };

        Ok(DidLogEntry {
            version: log.version,
            version_time,
            parameters: log.parameters,
            did_doc: log.did_doc.to_did_doc().map_err(|err| {
                DidResolverError::DeserializationFailed(format!(
                    "Deserialization of DID document failed due to: {err}"
                ))
            })?,
            did_doc_json: entry[DID_LOG_ENTRY_STATE].to_owned(),
            proof: Some(vec![proof]),
        })
    }
}
