// SPDX-License-Identifier: MIT

use did_sidekicks::did_method_parameters::DidMethodParameter;
use did_sidekicks::errors::DidResolverError;
use did_sidekicks::jcs_sha256_hasher::JcsSha256Hasher;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

// See https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters
#[expect(clippy::exhaustive_structs, reason = "..")]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WebVerifiableHistoryDidMethodParameters {
    /// Specifies the did:webvh specification version to be used for processing the DID’s log.
    /// Each acceptable value in turn defines what cryptographic algorithms are permitted for the current and
    /// subsequent DID log entries. An update to the specification version in the middle of a DID Log could introduce new parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub method: Option<String>,

    /// The SCID value for the DID
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub scid: Option<String>,

    /// A JSON array of multikey formatted public keys associated with the private keys that are authorized to sign the log entries that update the DID.
    /// See the Authorized Keys section of this specification for additional details.
    #[serde(default)]
    #[serde(rename = "updateKeys", skip_serializing_if = "Option::is_none")]
    pub update_keys: Option<Vec<String>>,

    /// A JSON array of strings that are hashes of multikey formatted public keys that MAY be added to the updateKeys list in the next log entry.
    /// At least one entry of nextKeyHashes MUST be added to the next updateKeys list.
    #[serde(default)]
    #[serde(rename = "nextKeyHashes", skip_serializing_if = "Option::is_none")]
    pub next_keys: Option<Vec<String>>,

    /// A JSON object declaring the set of witnesses and threshold number of witness proofs required to update the DID.
    #[serde(default)]
    #[serde(rename = "witnesses", skip_serializing_if = "Option::is_none")]
    pub witnesses: Option<Witness>,

    /// An optional entry whose value is a JSON array containing a list of URLs ([RFC9110]) that have notified the DID Controller that they are willing to watch the DID. See the Watchers section of this specification for more details.
    #[serde(rename = "watchers", default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub watchers: Option<Vec<String>>,

    /// Indicating if the DID is portable, allowing a DID Controller to control if a DID can be moved, while retaining its SCID and verifiable history.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub portable: Option<bool>,

    /// Indicates whether the DID has been deactivated.
    /// A deactivated DID is no longer subject to updates but remains resolvable.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub deactivated: Option<bool>,

    /// Indicates how long, in seconds, a resolver should cache the resolved did:webvh DID before refreshing.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub ttl: Option<usize>,
}

impl WebVerifiableHistoryDidMethodParameters {
    #[inline]
    pub const fn empty() -> Self {
        Self {
            method: None,
            scid: None,
            update_keys: None,
            next_keys: None,
            witnesses: None,
            watchers: None,
            deactivated: None,
            portable: None,
            ttl: None,
        }
    }

    #[inline]
    pub fn for_genesis_did_doc(scid: String, update_key: String) -> Self {
        Self {
            method: Some(String::from(DID_METHOD_PARAMETER_VERSION)),
            scid: Some(scid),
            update_keys: Some(vec![update_key]),
            next_keys: None,
            witnesses: None,
            watchers: None,
            deactivated: None,
            ttl: None,
            portable: Some(false),
        }
    }

    /// Validation against all the criteria and sets default values described in https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters
    ///
    /// Furthermore, the relevant Swiss profile checks are also taken into account here:
    /// https://github.com/e-id-admin/open-source-community/blob/main/tech-roadmap/swiss-profile.md#didtdwdidwebvh
    #[inline]
    pub fn validate_initial(&mut self) -> Result<(), DidResolverError> {
        if let Some(method) = self.method.to_owned() {
            // This item MAY appear in later DID log entries to indicate that the processing rules
            // for that and later entries have been changed to a different specification version.
            if method != DID_METHOD_PARAMETER_VERSION {
                return Err(DidResolverError::InvalidDidParameter(format!(
                    "Invalid 'method' DID parameter. Expected '{DID_METHOD_PARAMETER_VERSION}'"
                )));
            }
        } else {
            // This item MUST appear in the first DID log entry.
            return Err(DidResolverError::InvalidDidParameter(
                "Missing 'method' DID parameter. This item MUST appear in the first DID log entry."
                    .to_owned(),
            ));
        }

        if let Some(scid) = self.scid.to_owned() {
            if scid.is_empty() {
                return Err(DidResolverError::InvalidDidParameter(
                    "Invalid 'scid' DID parameter. This item MUST appear in the first DID log entry.".to_owned(),
                ));
            }
        } else {
            return Err(DidResolverError::InvalidDidParameter(
                "Missing 'scid' DID parameter. This item MUST appear in the first DID log entry."
                    .to_owned(),
            ));
        }

        if let Some(update_keys) = self.update_keys.to_owned() {
            if update_keys.is_empty() {
                return Err(DidResolverError::InvalidDidParameter(
                    "Empty 'updateKeys' DID parameter. This item MUST appear in the first DID log entry.".to_owned(),
                ));
            }
        } else {
            return Err(DidResolverError::InvalidDidParameter(
                "Missing 'updateKeys' DID parameter. This item MUST appear in the first DID log entry.".to_owned(),
            ));
        }

        // As specified by https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters:
        // Defaults to [] if not set in the first log entry.
        if self.watchers.is_none() {
            self.watchers = Some(Vec::new());
        }

        // As specified by https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters:
        // If not set in the first log entry, its value defaults to an empty array ([])
        if self.next_keys.is_none() {
            self.next_keys = Some(Vec::new());
        }

        // https://confluence.bit.admin.ch/display/EIDTEAM/DID+Log+Conformity+Check:
        // Witnesses won't be supported as they are not needed from the current point of view.
        // As the DIDs are published on a central base registry the DID controller and the hoster
        // are different actors and the chance that both are compromised is minimized.
        // It would add complexity to the resolving of a DID and the base registry would need to also host did-witness.json file.
        if let Some(witness) = self.witnesses.to_owned() {
            if witness.threshold > 0 || !witness.witnesses.is_empty() {
                // A witness item in the first DID log entry is used to define the witnesses and necessary threshold for that initial log entry.
                // In all other DID log entries, a witness item becomes active after the publication of its entry.
                return Err(DidResolverError::InvalidDidParameter(
                    "Unsupported non-empty 'witness' DID parameter.".to_owned(),
                ));
            }
        }

        /* TODO Ensure validity of the "portable" DID parameter. Currently ignored/disabled for the sake of being able to use test vectors from third parties
        if let Some(portable) = self.portable {
            if portable {
                return Err(DidResolverError::InvalidDidParameter(
                    "Unsupported 'portable' DID parameter. We currently don't support portable DIDs".to_string(),
                ));
            }
        }
         */

        Ok(())
    }

    #[inline]
    pub fn merge_from(&mut self, other: &Self) -> Result<(), DidResolverError> {
        let new_params = other.to_owned();
        let current_params = self.clone();
        self.method = match new_params.method {
            Some(method) => {
                // This item MAY appear in later DID log entries to indicate that the processing rules
                // for that and later entries have been changed to a different specification version.
                if method != DID_METHOD_PARAMETER_VERSION {
                    return Err(DidResolverError::InvalidDidParameter(
                        format!("Invalid 'method' DID parameter. Expected '{DID_METHOD_PARAMETER_VERSION}'.")
                    ));
                }
                Some(method)
            }
            None => current_params.method.clone(),
        };

        self.scid = match new_params.scid {
            Some(scid) => {
                if current_params
                    .scid
                    .as_ref()
                    .is_none_or(|x| x != scid.as_str())
                {
                    return Err(DidResolverError::InvalidDidParameter(
                        "Invalid 'scid' DID parameter. The 'scid' parameter is not allowed to change."
                        .to_owned(),
                    ));
                };
                Some(scid)
            }
            None => self.scid.clone(),
        };

        // During key pre-rotation, new log entries
        // - must have 1 key in updateKeys
        // - all updateKey must be in nextKeyHashes
        #[expect(clippy::else_if_without_else, reason = "no else required at the end")]
        if current_params.is_key_pre_rotation_active() {
            if new_params
                .update_keys
                .as_ref()
                .is_none_or(|keys| keys.is_empty())
            {
                return Err(DidResolverError::InvalidDidParameter(
                    "updatesKeys must not be empty during key pre-rotation.".to_owned(),
                ));
            }

            // If Key Pre-Rotation is active, the hash of all updateKeys entries in the parameters property
            // MUST match a hash in the array of nextKeyHashes parameter from the previous DID log entry,
            // with exception of the first entry, as defined in the Pre-Rotation[Key Pre-Rotation Hash Generation and
            // Verification](#pre-rotation-key-hash-generation-and-verification) section of this specification.
            let mut hasher = JcsSha256Hasher::default();
            for update_key in new_params.update_keys.iter().flatten() {
                let hashed_update_key = hasher.base58btc_encode_multihash_multikey(update_key);
                if !current_params
                    .next_keys
                    .iter()
                    .flatten()
                    .any(|next_key_hash| *next_key_hash == hashed_update_key)
                {
                    return Err(DidResolverError::InvalidDidParameter(
                        format!("Illegal update key detected: {update_key}. All multikey formatted public keys added in a new 'updateKeys' list MUST have their hashes listed in the 'nextKeyHashes' list from the previous log entry (except for the first log entry)")
                    ));
                }
            }
        } else if new_params
            .update_keys
            .as_ref()
            .is_some_and(|update_keys| !update_keys.is_empty())
        {
            return Err(DidResolverError::InvalidDidParameter(
                "Invalid update key found. UpdateKey may only be set during key pre-rotation."
                    .to_owned(),
            ));
        }

        self.update_keys = new_params.update_keys.or(current_params.update_keys);

        self.next_keys = new_params.next_keys.or(current_params.next_keys);

        self.witnesses = match new_params.witnesses {
            Some(witness) => {
                if witness.threshold > 0 || !witness.witnesses.is_empty() {
                    return Err(DidResolverError::InvalidDidParameter(
                        "Unsupported non-empty 'witnesses' DID parameter.".to_owned(),
                    ));
                }
                Some(Witness {
                    threshold: 0,
                    witnesses: vec![],
                })
            }
            None => current_params.witnesses,
        };

        self.watchers = new_params.watchers.or(current_params.watchers);

        self.portable = match (current_params.portable, new_params.portable) {
            (Some(true), Some(true)) => return Err(DidResolverError::InvalidDidParameter(
                "Unsupported 'portable' DID parameter. We currently don't support portable dids".to_owned(),
            )),
            (_, Some(true)) =>  return Err(DidResolverError::InvalidDidParameter(
                "Invalid 'portable' DID parameter. The value can ONLY be set to true in the first log entry, the initial version of the DID.".to_owned(),
            )),
            (_, Some(false)) => Some(false),
            (_, None) => current_params.portable

        };

        self.deactivated = match (current_params.deactivated, new_params.deactivated) {
            (Some(true), _) => return Err(DidResolverError::InvalidDidDocument(
                "This DID document is already deactivated. Therefore no additional DID logs are allowed.".to_owned()
            )),
            (_, Some(deactivate)) => Some(deactivate),
            (_, None) => current_params.deactivated,
        };

        self.ttl = new_params.ttl.or(self.ttl);

        Ok(())
    }

    /// As specified by https://identity.foundation/didwebvh/v0.3/#deactivate-revoke
    #[inline]
    pub fn deactivate(&mut self) {
        self.update_keys = Some(vec![]);
        self.deactivated = Some(true);
    }

    #[inline]
    pub fn from_json(json_content: &str) -> Result<Self, DidResolverError> {
        let did_method_parameters: Self = match serde_json::from_str(json_content) {
            Ok(did_method_parameters) => did_method_parameters,
            Err(err) => {
                return Err(DidResolverError::DeserializationFailed(format!(
                    "Error parsing DID method parameters: {err}"
                )));
            }
        };
        Ok(did_method_parameters)
    }

    /// Yet another UniFFI-compliant getter.
    #[inline]
    pub fn get_scid(&self) -> String {
        if let Some(val) = self.scid.to_owned() {
            return val;
        }
        "".to_owned()
    }

    #[inline]
    pub fn get_scid_option(&self) -> Option<String> {
        self.scid.clone()
    }

    /// Yet another UniFFI-compliant getter.
    #[inline]
    pub fn get_update_keys(&self) -> Vec<String> {
        if let Some(val) = self.update_keys.to_owned() {
            return val;
        }
        vec![]
    }

    /// Yet another UniFFI-compliant getter.
    #[inline]
    pub const fn is_deactivated(&self) -> bool {
        if let Some(val) = self.deactivated {
            if val {
                return val;
            }
        }
        false
    }

    #[inline]
    pub fn is_key_pre_rotation_active(&self) -> bool {
        self.next_keys.as_ref().is_some_and(|keys| !keys.is_empty())
    }
}

impl TryInto<HashMap<String, Arc<DidMethodParameter>>> for WebVerifiableHistoryDidMethodParameters {
    type Error = DidResolverError;

    /// Conversion of [`WebVerifiableHistoryDidMethodParameters`] into map of [`DidMethodParameter`] objects.
    ///
    /// A UniFFI-compliant method.
    #[inline]
    //#[expect(clippy::unwrap_in_result, reason = "..")]
    #[expect(clippy::unwrap_used, reason = "..")]
    fn try_into(self) -> Result<HashMap<String, Arc<DidMethodParameter>>, Self::Error> {
        // MUST appear in the first DID log entry
        let method = DidMethodParameter::new_string_from_option("method", self.method)
            .map_err(|err| DidResolverError::InvalidDidParameter(format!("{err}")))?;

        // MUST appear in the first log entry. MUST NOT appear in later log entries
        let scid = DidMethodParameter::new_string_from_option("scid", self.scid)
            .map_err(|err| DidResolverError::InvalidDidParameter(format!("{err}")))?;

        // This property MUST appear in the first log entry and MAY appear in subsequent entries
        let update_keys =
            DidMethodParameter::new_string_array_from_option("updateKeys", self.update_keys)
                .map_err(|err| DidResolverError::InvalidDidParameter(format!("{err}")))?;

        let mut map = HashMap::from([
            (method.get_name(), Arc::new(method)),
            (scid.get_name(), Arc::new(scid)),
            ("updateKeys".to_owned(), Arc::new(update_keys)),
            // Defaults to false if omitted in the first entry
            (
                "portable".to_owned(),
                Arc::new(DidMethodParameter::new_bool_from_option(
                    "portable",
                    self.deactivated,
                )),
            ),
            // Defaults to false if not set in the first DID log entry
            (
                "deactivated".to_owned(),
                Arc::new(DidMethodParameter::new_bool_from_option(
                    "deactivated",
                    self.deactivated,
                )),
            ),
            // Defaults to 3600 (1 hour) if not set in the first DID log entry
            (
                "ttl".to_owned(),
                Arc::new(
                    DidMethodParameter::new_number_from_option("ttl", self.ttl).unwrap_or_else(
                        |_| DidMethodParameter::new_number_from_option("ttl", Some(3600)).unwrap(),
                    ),
                ),
            ),
        ]);

        if let Ok(next_key_hashes) =
            DidMethodParameter::new_string_array_from_option("nextKeyHashes", self.next_keys)
        {
            map.insert("nextKeyHashes".to_owned(), Arc::new(next_key_hashes));
        }

        Ok(map)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[non_exhaustive]
pub struct Witness {
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(default)]
    pub threshold: u32,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub witnesses: Vec<String>,
}

/// This is only used for serialize
const fn is_zero(num: &u32) -> bool {
    *num == 0
}

/// As defined by https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters
const DID_METHOD_PARAMETER_VERSION: &str = "did:webvh:1.0";

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "unwrap calls are panic-safe as long as test case setup is correct"
)]
mod test {
    use crate::did_webvh_method_parameters::{
        WebVerifiableHistoryDidMethodParameters, Witness, DID_METHOD_PARAMETER_VERSION,
    };
    use crate::test::assert_trust_did_web_error;
    use did_sidekicks::did_method_parameters::DidMethodParameter;
    use did_sidekicks::errors::DidResolverErrorKind;
    use did_sidekicks::jcs_sha256_hasher::JcsSha256Hasher;
    use rstest::rstest;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[rstest]
    fn test_did_webvh_parameters_validate_initial() {
        let mut params_for_genesis_did_doc =
            WebVerifiableHistoryDidMethodParameters::for_genesis_did_doc(
                "scid".to_owned(),
                "update_key".to_owned(),
            );
        params_for_genesis_did_doc.validate_initial().unwrap(); // should not panic

        let mut params = params_for_genesis_did_doc.clone();

        // Test "method" DID parameter
        params.method = Some("invalidVersion".to_owned());
        assert_trust_did_web_error(
            params.validate_initial(),
            DidResolverErrorKind::InvalidDidParameter,
            "Invalid 'method' DID parameter.",
        );
        params.method = None;
        assert_trust_did_web_error(
            params.validate_initial(),
            DidResolverErrorKind::InvalidDidParameter,
            "Missing 'method' DID parameter.",
        );

        // Test "scid" DID parameter
        params = params_for_genesis_did_doc.clone();
        params.scid = Some("".to_owned());
        assert_trust_did_web_error(
            params.validate_initial(),
            DidResolverErrorKind::InvalidDidParameter,
            "Invalid 'scid' DID parameter.",
        );
        params.scid = None;
        assert_trust_did_web_error(
            params.validate_initial(),
            DidResolverErrorKind::InvalidDidParameter,
            "Missing 'scid' DID parameter.",
        );

        // Test "update_keys" DID parameter
        params = params_for_genesis_did_doc.clone();
        params.update_keys = Some(vec![]);
        assert_trust_did_web_error(
            params.validate_initial(),
            DidResolverErrorKind::InvalidDidParameter,
            "Empty 'updateKeys' DID parameter.",
        );
        params.update_keys = None;
        assert_trust_did_web_error(
            params.validate_initial(),
            DidResolverErrorKind::InvalidDidParameter,
            "Missing 'updateKeys' DID parameter.",
        );

        params = params_for_genesis_did_doc.clone();
        /* TODO Test the "portable" DID parameter properly. Currently ignored/disabled for the sake of being able to use test vectors from third parties
        params.portable = Some(true);
        assert_trust_did_web_error(
            params.validate_initial(),
            DidResolverErrorKind::InvalidDidParameter,
            "Unsupported 'portable' DID parameter",
        );
        */
        params.portable = Some(false);
        params.validate_initial().unwrap(); // should not panic
        params.portable = None;
        params.validate_initial().unwrap(); // should not panic

        // Test "next_keys" DID parameter
        params = params_for_genesis_did_doc.clone();
        params.next_keys = Some(vec![]);
        params.validate_initial().unwrap(); // should not panic
        params.next_keys = Some(vec!["some_valid_key".to_owned()]);
        params.validate_initial().unwrap(); // should not panic
        params.next_keys = None;
        params.validate_initial().unwrap(); // should not panic

        // Test "witnesses" DID parameter
        params = params_for_genesis_did_doc;
        params.witnesses = Some(Witness {
            threshold: 1,
            witnesses: vec!["some_valid_witness".to_owned()],
        });
        assert_trust_did_web_error(
            params.validate_initial(),
            DidResolverErrorKind::InvalidDidParameter,
            "Unsupported non-empty 'witness' DID parameter.",
        );
        params.witnesses = Some(Witness {
            threshold: 0,
            witnesses: vec![],
        });
        params.validate_initial().unwrap(); // should not panic
        params.witnesses = None;
        params.validate_initial().unwrap(); // should not panic
    }

    #[rstest]
    fn test_did_webvh_parameters_validate_transition() {
        let base_params = WebVerifiableHistoryDidMethodParameters::for_genesis_did_doc(
            "scid".to_owned(),
            "update_key".to_owned(),
        );

        let mut new_base_params = base_params.clone();
        new_base_params.update_keys = None;

        let mut old_params = base_params.clone();
        let mut new_params = new_base_params.clone();
        old_params.merge_from(&new_params).unwrap(); // should not panic

        // Test "method" DID parameter
        old_params = base_params.clone();
        new_params = new_base_params.clone();
        new_params.method = Some("invalidVersion".to_owned());
        assert_trust_did_web_error(
            old_params.merge_from(&new_params),
            DidResolverErrorKind::InvalidDidParameter,
            "Invalid 'method' DID parameter.",
        );
        new_params.method = None;
        old_params.merge_from(&new_params).unwrap(); // should not panic

        // Test "scid" DID parameter
        old_params = old_params.clone();
        new_params = new_params.clone();
        new_params.scid = Some("otherSCID".to_owned());
        assert_trust_did_web_error(
            old_params.merge_from(&new_params),
            DidResolverErrorKind::InvalidDidParameter,
            "Invalid 'scid' DID parameter.",
        );
        new_params.scid = None;
        old_params.merge_from(&new_params).unwrap(); // should not panic
        new_params.scid = Some("scid".to_owned()); // SAME scid value
        old_params.merge_from(&new_params).unwrap(); // should not panic

        // "update_keys" and "next_keys" tested in separate test

        // Test "witness" DID parameter
        old_params = base_params.clone();
        new_params = new_base_params.clone();
        new_params.witnesses = Some(Witness {
            threshold: 1,
            witnesses: vec!["some_valid_witness".to_owned()],
        });
        assert_trust_did_web_error(
            old_params.merge_from(&new_params),
            DidResolverErrorKind::InvalidDidParameter,
            "Unsupported non-empty 'witnesses' DID parameter.",
        );
        new_params.witnesses = Some(Witness {
            threshold: 0,
            witnesses: vec![],
        });
        old_params.merge_from(&new_params).unwrap(); // should not panic
        new_params.witnesses = None;
        old_params.merge_from(&new_params).unwrap(); // should not panic

        // Test watchers
        old_params = base_params.clone();
        new_params = new_base_params.clone();
        new_params.watchers = Some(vec!["https://example.domain".to_owned()]);
        old_params.merge_from(&new_params).unwrap(); // should not panic
        new_params.watchers = None;
        old_params.merge_from(&new_params).unwrap(); // should not panic
        new_params.watchers = Some(vec![]);
        old_params.merge_from(&new_params).unwrap(); // should not panic

        // Test "portable" DID parameter
        old_params = base_params;
        new_params = new_base_params;

        new_params.portable = Some(true);
        assert_trust_did_web_error(
            old_params.merge_from(&new_params),
            DidResolverErrorKind::InvalidDidParameter,
            "Invalid 'portable' DID parameter.",
        );
        new_params.portable = Some(false);
        old_params.merge_from(&new_params).unwrap(); // should not panic
        new_params.portable = None;
        old_params.merge_from(&new_params).unwrap(); // should not panic
        new_params.portable = Some(true);
        old_params.portable = Some(true);
        assert_trust_did_web_error(
            old_params.merge_from(&new_params),
            DidResolverErrorKind::InvalidDidParameter,
            "Unsupported 'portable' DID parameter.",
        );
    }

    #[rstest]
    fn test_did_webvh_parameters_validate_key_pre_rotation() {
        let base_params = WebVerifiableHistoryDidMethodParameters::for_genesis_did_doc(
            "scid".to_owned(),
            "some_update_key".to_owned(),
        );

        // Test "updateKeys" DID parameter without pre-rotation
        let mut old_params = base_params.clone();

        let mut new_params = base_params.clone();
        new_params.update_keys = None;
        new_params.next_keys = None;
        old_params.merge_from(&new_params).unwrap(); // should not panic

        // Test "updateKeys" DID parameter with starting pre-rotation
        let mut old_params = base_params.clone();

        let mut new_params = base_params.clone();
        new_params.update_keys = None;
        new_params.next_keys = Some(vec!["new_update_key".to_owned()]);
        old_params.merge_from(&new_params).unwrap(); // should not panic

        // Test "updateKeys" DID parameter with pre-rotation illegal values
        let mut old_params = base_params.clone();
        old_params.next_keys = Some(vec!["new_update_key".to_owned()]);

        let mut new_params = base_params.clone();
        new_params.next_keys = None;
        new_params.update_keys = None;

        let failed_to_update = old_params.merge_from(&new_params); // should return an error
        assert!(failed_to_update.is_err());

        // Test "updateKeys" DID parameter with pre-rotation illegal values
        let mut old_params = base_params.clone();
        old_params.next_keys = Some(vec!["new_update_key".to_owned()]);

        let mut new_params = base_params.clone();
        new_params.update_keys = Some(vec!["illegalUpdateKey".to_owned()]);

        let failed_to_update = old_params.merge_from(&new_params); // should return an error
        assert!(failed_to_update.is_err());

        // Test "updateKeys" DID parameter with pre-rotation illegal values
        let mut old_params = base_params.clone();
        old_params.next_keys = Some(vec!["new_update_key".to_owned()]);

        let mut new_params = base_params.clone();
        new_params.update_keys = Some(vec!["illegalUpdateKey".to_owned()]);

        let failed_to_update = old_params.merge_from(&new_params); // should return an error
        assert!(failed_to_update.is_err());

        // Test "updateKeys" DID parameter with pre-rotation illegal updateKeys
        let mut old_params = base_params.clone();
        old_params.next_keys = Some(vec!["new_update_key".to_owned()]);

        let mut new_params = base_params.clone();
        new_params.update_keys = Some(vec!["new_update_key".to_owned(), "update_key".to_owned()]);

        let failed_to_update = old_params.merge_from(&new_params); // should return an error
        assert!(failed_to_update.is_err());

        // Test "updateKeys" DID parameter with pre-rotation illegal values
        let mut old_params = base_params.clone();
        old_params.next_keys = Some(vec![
            JcsSha256Hasher::default().base58btc_encode_multihash_multikey("new_update_key")
        ]);

        let mut new_params = base_params.clone();
        new_params.update_keys = Some(vec!["new_update_key".to_owned()]);
        new_params.next_keys = Some(Vec::new());

        old_params.merge_from(&new_params).unwrap(); // should not panic

        // Test "updateKeys" DID parameter with pre-rotation illegal values
        let mut old_params = base_params.clone();
        old_params.next_keys = Some(vec![
            JcsSha256Hasher::default().base58btc_encode_multihash_multikey("new_update_key"),
            "another_new_update_key".to_owned(),
        ]);

        let mut new_params = base_params.clone();
        new_params.update_keys = Some(vec!["new_update_key".to_owned()]);
        new_params.next_keys = Some(Vec::new());

        old_params.merge_from(&new_params).unwrap(); // should not panic
        new_params = base_params.clone();
        new_params.update_keys = Some(vec!["another_new_update_key".to_owned()]);

        let failed_to_update = old_params.merge_from(&new_params); // should return an error
        assert!(failed_to_update.is_err());

        // Test "updateKeys" DID parameter with pre-rotation illegal values
        let mut old_params = base_params.clone();
        old_params.next_keys = Some(vec![
            JcsSha256Hasher::default().base58btc_encode_multihash_multikey("new_update_key"),
            JcsSha256Hasher::default()
                .base58btc_encode_multihash_multikey("another_new_update_key"),
        ]);

        let mut new_params = base_params.clone();
        new_params.update_keys = Some(vec![
            "new_update_key".to_owned(),
            "another_new_update_key".to_owned(),
        ]);
        new_params.next_keys = Some(Vec::new());

        old_params.merge_from(&new_params).unwrap(); // should not panic
        new_params = base_params.clone();
        new_params.update_keys = Some(vec!["another_new_update_key".to_owned()]);
        new_params.next_keys = None;

        let failed_to_update = old_params.merge_from(&new_params); // should return an error
        assert!(failed_to_update.is_err());

        // Test "updateKeys" DID parameter with pre-rotation twice
        let mut old_params = base_params.clone();
        old_params.next_keys = Some(vec![
            JcsSha256Hasher::default().base58btc_encode_multihash_multikey("new_update_key"),
            JcsSha256Hasher::default()
                .base58btc_encode_multihash_multikey("another_new_update_key"),
        ]);

        let mut new_params = base_params.clone();
        new_params.update_keys = Some(vec![
            "new_update_key".to_owned(),
            "another_new_update_key".to_owned(),
        ]);
        new_params.next_keys = None;

        old_params.merge_from(&new_params).unwrap(); // should not panic
        new_params = base_params;
        new_params.update_keys = Some(vec!["another_new_update_key".to_owned()]);

        old_params.merge_from(&new_params).unwrap(); // should not panic
    }

    #[rstest]
    fn test_did_webvh_method_parameters_try_into() {
        let mut base_params = WebVerifiableHistoryDidMethodParameters::for_genesis_did_doc(
            "scid".to_owned(),
            "some_update_key".to_owned(),
        );
        base_params.next_keys = Some(vec!["some_next_key_hash".to_owned()]);
        base_params.portable = Some(true);
        base_params.deactivated = Some(true);
        base_params.ttl = Some(7200);

        let try_into = base_params.try_into(); // MUT

        assert!(try_into.is_ok());
        let param_map: HashMap<String, Arc<DidMethodParameter>> = try_into.unwrap();
        assert!(!param_map.is_empty());

        assert!(param_map.contains_key("method"));
        let method_option = param_map.get("method");
        assert!(method_option.is_some());
        let method = method_option.unwrap();
        assert!(method.is_string());
        assert!(method.get_string_value().is_some());
        assert_eq!(
            DID_METHOD_PARAMETER_VERSION,
            method.get_string_value().unwrap()
        );

        assert!(param_map.contains_key("scid"));
        let scid_option = param_map.get("scid");
        assert!(scid_option.is_some());
        let scid = scid_option.unwrap();
        assert!(scid.is_string());
        assert!(method.get_string_value().is_some());
        assert_eq!("scid", scid.get_string_value().unwrap());

        assert!(param_map.contains_key("updateKeys"));
        let update_keys_option = param_map.get("updateKeys");
        assert!(update_keys_option.is_some());
        let update_keys = update_keys_option.unwrap();
        assert!(update_keys.is_array());
        assert!(!update_keys.is_empty_array());
        assert!(update_keys.get_string_array_value().is_some());
        assert!(!update_keys.get_string_array_value().unwrap().is_empty());
        assert!(!update_keys
            .get_string_array_value()
            .unwrap()
            .iter()
            .all(|str| str.is_empty()));
        assert!(update_keys
            .get_string_array_value()
            .unwrap()
            .iter()
            .any(|str| str.contains("some_update_key")));

        assert!(param_map.contains_key("nextKeyHashes"));
        let next_key_hashes_option = param_map.get("nextKeyHashes");
        assert!(next_key_hashes_option.is_some());
        let next_key_hashes = next_key_hashes_option.unwrap();
        assert!(next_key_hashes.is_array());
        assert!(!next_key_hashes.is_empty_array());
        assert!(next_key_hashes.get_string_array_value().is_some());
        assert!(!next_key_hashes.get_string_array_value().unwrap().is_empty());
        assert!(!next_key_hashes
            .get_string_array_value()
            .unwrap()
            .iter()
            .all(|str| str.is_empty()));
        assert!(next_key_hashes
            .get_string_array_value()
            .unwrap()
            .iter()
            .any(|str| str.contains("some_next_key_hash")));

        assert!(param_map.contains_key("portable"));
        let portable_option = param_map.get("portable");
        assert!(portable_option.is_some());
        let portable = portable_option.unwrap();
        assert!(portable.is_bool());
        assert!(portable.get_bool_value().is_some_and(|bool| { bool }));

        assert!(param_map.contains_key("deactivated"));
        let deactivated_option = param_map.get("deactivated");
        assert!(deactivated_option.is_some());
        let deactivated = deactivated_option.unwrap();
        assert!(deactivated.is_bool());
        assert!(deactivated.get_bool_value().is_some_and(|bool| { bool }));

        assert!(param_map.contains_key("ttl"));
        let ttl_option = param_map.get("ttl");
        assert!(ttl_option.is_some());
        let ttl = ttl_option.unwrap();
        assert!(!ttl.is_f64());
        assert!(ttl.is_i64());
        assert!(!ttl.is_u64());
        assert!(ttl.get_f64_value().is_none());
        assert!(ttl.get_i64_value().is_some());
        assert!(ttl.get_u64_value().is_none());
        assert_eq!(7200, ttl.get_i64_value().unwrap());
    }
}
