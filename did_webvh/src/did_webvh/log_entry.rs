// SPDX-License-Identifier: MIT

use std::str::FromStr;

use chrono::{DateTime, Utc, serde::ts_seconds};
use did_sidekicks::{
    did_doc::DidDoc,
    did_doc::DidDocNormalized,
    ed25519::Ed25519VerifyingKey,
    errors::DidResolverError,
    jcs_sha256_hasher::JcsSha256Hasher,
    multibase::MultiBaseConvertible as _,
    vc_data_integrity::{
        CryptoSuiteType, DataIntegrityProof, EddsaJcs2022Cryptosuite, VCDataIntegrity as _,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

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

    #[serde(rename = "proof")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Vec<DataIntegrityProof>>,

    #[serde(skip)]
    pub json: Value,
}

impl DidLogEntry {
    /// Import of existing log entry.
    #[inline]
    pub fn new(
        version: DidLogVersion,
        version_time: DidLogVersionTime,
        parameters: WebVerifiableHistoryDidMethodParameters,
        did_doc: DidDoc,
        json: Value,
        proof: DataIntegrityProof,
    ) -> Self {
        Self {
            version,
            version_time,
            parameters,
            did_doc,
            proof: Some(vec![proof]),
            json,
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

        #[expect(clippy::pattern_type_mismatch, reason = "false positive")]
        let Value::Object(values) = &self.json else {
            return Err(DidResolverError::InvalidDataIntegrityProof(
                "DID log must be a JSON object.".to_owned(),
            ));
        };
        let original_scid = Self::build_original_scid(values.clone(), &scid).map_err(|err| {
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
            let did_log_entry = self.to_log_entry_line(self.version.id.as_str())?;

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
        let entry_json = self.to_log_entry_line(prev_version_id)?;
        // 5 calculate  the hash string
        let calculated_hash = JcsSha256Hasher::default()
            .base58btc_encode_multihash_json_value(&entry_json)
            .map_err(|err| {
                DidResolverError::SerializationFailed(format!("Failed to base58btc-encode SHA2-256 multihash of canonical JSON UTF-8 string: {err}"))
            })?;
        Ok(calculated_hash)
    }

    fn to_log_entry_line(&self, prev_version_id: &str) -> Result<Value, DidResolverError> {
        let Value::Object(mut values) = self.json.clone() else {
            return Err(DidResolverError::InvalidDidLog(
                "DID Log must be a json object".to_owned(),
            ));
        };
        values.insert(
            DID_LOG_ENTRY_VERSION_ID.to_owned(),
            Value::String(prev_version_id.to_owned()),
        );
        let Some(Value::Array(proofs)) = values.remove(DID_LOG_ENTRY_PROOF) else {
            return Err(DidResolverError::InvalidDataIntegrityProof(
                "Proof is empty.".to_owned(),
            ));
        };
        if proofs.is_empty() {
            return Err(DidResolverError::InvalidDataIntegrityProof(
                "Proof is empty.".to_owned(),
            ));
        }

        Ok(Value::Object(values))
    }

    #[inline]
    #[expect(clippy::single_call_fn, reason = "encapsulate logic")]
    fn build_original_scid(
        mut values: Map<String, Value>,
        scid: &String,
    ) -> serde_json::Result<String> {
        values.remove(DID_LOG_ENTRY_PROOF);
        values.insert(
            DID_LOG_ENTRY_VERSION_ID.to_owned(),
            Value::String(SCID_PLACEHOLDER.to_owned()),
        );
        let did_doc_with_placeholder_scid = values
            .get(DID_LOG_ENTRY_STATE)
            .unwrap_or(&Value::Null)
            .to_string()
            .replace(scid, SCID_PLACEHOLDER);
        values.insert(
            DID_LOG_ENTRY_STATE.to_owned(),
            serde_json::from_str::<Value>(did_doc_with_placeholder_scid.as_str())?,
        );

        let did_parameters_with_placeholder_scid = values
            .get(DID_LOG_ENTRY_PARAMETERS)
            .unwrap_or(&Value::Null)
            .to_string()
            .replace(scid, SCID_PLACEHOLDER);
        values.insert(
            DID_LOG_ENTRY_PARAMETERS.to_owned(),
            serde_json::from_str::<Value>(did_parameters_with_placeholder_scid.as_str())?,
        );
        JcsSha256Hasher::default().base58btc_encode_multihash_json_value(&Value::Object(values))
    }
}

impl FromStr for DidLogEntry {
    type Err = DidResolverError;

    #[expect(clippy::indexing_slicing, reason = "..")]
    #[inline]
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

        let entry: Value = serde_json::from_str(line)
            .map_err(|err| DidResolverError::DeserializationFailed(err.to_string()))?;

        let proof =
            match DataIntegrityProof::from_json_string(entry[DID_LOG_ENTRY_PROOF].to_string()) {
                Ok(prf) => prf,
                Err(err) => {
                    return Err(DidResolverError::DeserializationFailed(format!(
                        "Failed to deserialize data integrity proof due to: {err}"
                    )));
                }
            };

        let log = serde_json::from_value::<ParsableDidLogEntry>(entry.clone())
            .map_err(|err| {
                DidResolverError::DeserializationFailed(format!("Invalid log entry: {err}"))
            })
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

        Ok(Self {
            version: log.version,
            version_time,
            parameters: log.parameters,
            did_doc: log.did_doc.to_did_doc().map_err(|err| {
                DidResolverError::DeserializationFailed(format!(
                    "Deserialization of DID document failed due to: {err}"
                ))
            })?,
            proof: Some(vec![proof]),
            json: entry,
        })
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use rstest::rstest;
    use serde_json::{Value, json};

    use crate::did_webvh::{DidLogEntry, SCID_PLACEHOLDER};

    #[rstest]
    fn entry_hash_accounts_for_unsupported_fields() {
        let mut did_log = json!({
            "versionId": "1-SCID",
            "versionTime": "2026-11-03T06:24:32Z",
            "parameters": {
                "method": "did:webvh:1.0",
                "scid": SCID_PLACEHOLDER.to_owned(),
                "updateKeys": [
                    "z6MkiFBLvXjD9QWCUCmgF7jzD9ZCTL8rMvYDKoUNU4TEzP55",
                ],
                "portable": false
            },
            "state": {
                "id": format!(
                   "did:webvh:{}:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
                   SCID_PLACEHOLDER,
                ),
                "profile_version": "swiss-profile-anchor:1.0.0",
            },
            "proof": [
                {
                    "type": "DataIntegrityProof",
                    "cryptosuite": "eddsa-jcs-2022",
                    "created": "2026-11-03T06:24:32Z",
                    "verificationMethod": "did:key:z6MkiFBLvXjD9QWCUCmgF7jzD9ZCTL8rMvYDKoUNU4TEzP55#z6MkiFBLvXjD9QWCUCmgF7jzD9ZCTL8rMvYDKoUNU4TEzP55",
                    "proofPurpose": "assertionMethod",
                    "proofValue": "z2KTb6zrPiAAJFVtiK5AWyZgC1XTxZVhaux4KMwWdTzxAcYCcD2jMn9nQbNVvbNU7sHrTynadPsfDpdHXn4RTYthH"
                }
            ],
        });
        let log1 = DidLogEntry::from_str(did_log.to_string().as_str()).unwrap();
        let hash1 = log1.calculate_entry_hash(SCID_PLACEHOLDER).unwrap();

        did_log["parameters"]["foo"] = Value::String("bar".to_owned());
        let log2 = DidLogEntry::from_str(did_log.to_string().as_str()).unwrap();
        let hash2 = log2.calculate_entry_hash(SCID_PLACEHOLDER).unwrap();
        // Hashes shouldn't match as hash2 has the additional field foo
        assert_ne!(hash1, hash2);
    }
}
