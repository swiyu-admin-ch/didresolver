// SPDX-License-Identifier: MIT

use did_sidekicks::did_method_parameters::DidMethodParameter;
use did_sidekicks::errors::DidResolverError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

// See https://identity.foundation/trustdidweb/#didtdw-did-method-parameters
#[expect(clippy::exhaustive_structs, reason = "..")]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TrustDidWebDidMethodParameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub scid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub prerotation: Option<bool>,
    #[serde(default)]
    #[serde(rename = "updateKeys", skip_serializing_if = "Option::is_none")]
    pub update_keys: Option<Vec<String>>,
    #[serde(default)]
    #[serde(rename = "nextKeyHashes", skip_serializing_if = "Option::is_none")]
    pub next_keys: Option<Vec<String>>,
    #[serde(default)]
    #[serde(rename = "witnesses", skip_serializing_if = "Option::is_none")]
    pub witnesses: Option<Vec<String>>,
    #[serde(
        rename = "witnessThreshold",
        skip_serializing_if = "Option::is_none",
        default
    )]
    #[deprecated(
        note = "kept for historical reasons only (backward compatibility in regard to unit testing) and should therefore not be used"
    )]
    pub witness_threshold: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub deactivated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub portable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub ttl: Option<usize>,
}

impl TrustDidWebDidMethodParameters {
    #[inline]
    pub fn for_genesis_did_doc(scid: String, update_key: String) -> Self {
        Self {
            method: Some(String::from(DID_METHOD_PARAMETER_VERSION)),
            scid: Some(scid),
            prerotation: None,
            update_keys: Some(vec![update_key]),
            next_keys: None,
            witnesses: None,
            witness_threshold: None,
            deactivated: None,
            portable: Some(false),
            ttl: None,
        }
    }

    #[inline]
    pub const fn empty() -> Self {
        Self {
            method: None,
            scid: None,
            prerotation: None,
            update_keys: None,
            next_keys: None,
            witnesses: None,
            witness_threshold: None,
            deactivated: None,
            portable: None,
            ttl: None,
        }
    }

    /// Validation against all the criteria described in https://identity.foundation/didwebvh/v0.3/#didtdw-did-method-parameters
    ///
    /// Furthermore, the relevant Swiss profile checks are also taken into account here:
    /// https://github.com/e-id-admin/open-source-community/blob/main/tech-roadmap/swiss-profile.md#didtdwdidwebvh
    #[inline]
    pub fn validate_initial(&self) -> Result<(), DidResolverError> {
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

        if let Some(portable) = self.portable {
            if portable {
                return Err(DidResolverError::InvalidDidParameter(
                    "Unsupported 'portable' DID parameter. We currently don't support portable dids".to_owned(),
                ));
            }
        }

        if let Some(prerotation) = self.prerotation {
            if prerotation {
                return Err(DidResolverError::InvalidDidParameter(
                    "Unsupported 'prerotation' DID parameter. We currently don't support prerotation".to_owned(),
                ));
            }
        }

        if let Some(next_keys) = self.next_keys.to_owned() {
            if !next_keys.is_empty() {
                return Err(DidResolverError::InvalidDidParameter(
                    "Unsupported non-empty 'nextKeyHashes' DID parameter.".to_owned(),
                ));
            }
        }

        if let Some(witnesses) = self.witnesses.to_owned() {
            if !witnesses.is_empty() {
                // A witness item in the first DID log entry is used to define the witnesses and necessary threshold for that initial log entry.
                // In all other DID log entries, a witness item becomes active after the publication of its entry.
                return Err(DidResolverError::InvalidDidParameter(
                    "Unsupported non-empty 'witnesses' DID parameter.".to_owned(),
                ));
            }
        }

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
            None => current_params.method,
        };

        self.scid = match new_params.scid {
            Some(scid) => {
                if current_params.scid.is_none_or(|x| x != scid) {
                    return Err(DidResolverError::InvalidDidParameter(
                        "Invalid 'scid' DID parameter. The 'scid' parameter is not allowed to change.".to_owned(),
                    ));
                };
                Some(scid)
            }
            None => self.scid.clone(),
        };

        self.update_keys = new_params.update_keys.or(current_params.update_keys);

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

        self.prerotation = match (current_params.prerotation, new_params.prerotation) {
            (Some(true), Some(false)) => return Err(DidResolverError::InvalidDidParameter(
                "Invalid 'prerotation' DID parameter. Once the value is set to true in a DID log entry it MUST NOT be set to false in a subsequent entry.".to_owned(),
            )),
            (_, Some(new_pre)) => Some(new_pre),
            (_, None) => current_params.prerotation
        };
        self.next_keys = new_params.next_keys.or(current_params.next_keys);

        self.witnesses = match new_params.witnesses {
            Some(witnesses) => {
                if !witnesses.is_empty() {
                    return Err(DidResolverError::InvalidDidParameter(
                        "Unsupported non-empty 'witnesses' DID parameter.".to_owned(),
                    ));
                }
                Some(vec![])
            }
            None => current_params.witnesses,
        };

        self.deactivated = match (current_params.deactivated, new_params.deactivated) {
            (Some(true), _) => return Err(DidResolverError::InvalidDidDocument(
                "This DID document is already deactivated. Therefore no additional DID logs are allowed.".to_owned()
            )),
            (_, Some(deactivate)) => Some(deactivate),
            (_, None) => current_params.deactivated,
        };

        self.ttl = new_params.ttl.or(self.ttl);

        self.witness_threshold = new_params
            .witness_threshold
            .or(current_params.witness_threshold);

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

    #[inline]
    pub fn get_scid_option(&self) -> Option<String> {
        self.scid.clone()
    }

    /// Yet another UniFFI-compliant getter.
    #[inline]
    pub fn get_scid(&self) -> String {
        if let Some(scid) = self.scid.to_owned() {
            return scid;
        }
        "".to_owned()
    }

    /// Yet another UniFFI-compliant getter.
    #[inline]
    pub fn get_update_keys(&self) -> Vec<String> {
        if let Some(update_keys) = self.update_keys.to_owned() {
            return update_keys;
        }
        vec![]
    }

    /// Yet another UniFFI-compliant getter.
    #[inline]
    pub const fn is_deactivated(&self) -> bool {
        if let Some(deactivated) = self.deactivated {
            if deactivated {
                return deactivated;
            }
        }
        false
    }
}

impl TryInto<HashMap<String, Arc<DidMethodParameter>>> for TrustDidWebDidMethodParameters {
    type Error = DidResolverError;

    /// Conversion of [`TrustDidWebDidMethodParameters`] into map of [`DidMethodParameter`] objects.
    ///
    /// A UniFFI-compliant method.
    #[inline]
    //#[expect(clippy::unwrap_in_result, reason = "..")]
    #[expect(clippy::unwrap_used, reason = "..")]
    fn try_into(self) -> Result<HashMap<String, Arc<DidMethodParameter>>, Self::Error> {
        // MUST appear in the first DID log entry
        let method = match DidMethodParameter::new_string_from_option("method", self.method) {
            Ok(val) => val,
            Err(err) => return Err(DidResolverError::InvalidDidParameter(format!("{err}"))),
        };

        // MUST appear in the first log entry. MUST NOT appear in later log entries
        let scid = match DidMethodParameter::new_string_from_option("scid", self.scid) {
            Ok(val) => val,
            Err(err) => return Err(DidResolverError::InvalidDidParameter(format!("{err}"))),
        };

        // This property MUST appear in the first log entry and MAY appear in subsequent entries
        let update_keys = match DidMethodParameter::new_string_array_from_option(
            "updateKeys",
            self.update_keys,
        ) {
            Ok(val) => val,
            Err(err) => return Err(DidResolverError::InvalidDidParameter(format!("{err}"))),
        };

        Ok(HashMap::from([
            (method.get_name(), Arc::new(method)),
            (scid.get_name(), Arc::new(scid)),
            //(update_keys.get_name(), Arc::new(update_keys)),
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
        ]))
    }
}

/// As defined by https://identity.foundation/trustdidweb/v0.3/#didtdw-did-method-parameters
const DID_METHOD_PARAMETER_VERSION: &str = "did:tdw:0.3";

#[cfg(test)]
mod test {
    use crate::did_tdw_method_parameters::{
        TrustDidWebDidMethodParameters, DID_METHOD_PARAMETER_VERSION,
    };
    use crate::test::assert_trust_did_web_error;
    use did_sidekicks::did_method_parameters::DidMethodParameter;
    use did_sidekicks::errors::DidResolverErrorKind;
    use rstest::rstest;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[rstest]
    fn test_did_tdw_parameters_validate_initial() {
        let params_for_genesis_did_doc = TrustDidWebDidMethodParameters::for_genesis_did_doc(
            "scid".to_string(),
            "update_key".to_string(),
        );
        assert!(params_for_genesis_did_doc.validate_initial().is_ok());

        let mut params = params_for_genesis_did_doc.clone();

        // Test "method" DID parameter
        params.method = Some("invalidVersion".to_string());
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
        params.scid = Some("".to_string());
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

        // Test "portable" DID parameter
        params = params_for_genesis_did_doc.clone();
        params.portable = Some(true);
        assert_trust_did_web_error(
            params.validate_initial(),
            DidResolverErrorKind::InvalidDidParameter,
            "Unsupported 'portable' DID parameter",
        );
        params.portable = Some(false);
        assert!(params.validate_initial().is_ok());
        params.portable = None;
        assert!(params.validate_initial().is_ok());

        // Test "prerotation" DID parameter
        params = params_for_genesis_did_doc.clone();
        params.prerotation = Some(true);
        assert_trust_did_web_error(
            params.validate_initial(),
            DidResolverErrorKind::InvalidDidParameter,
            "Unsupported 'prerotation' DID parameter",
        );
        params.prerotation = Some(false);
        assert!(params.validate_initial().is_ok());
        params.prerotation = None;
        assert!(params.validate_initial().is_ok());

        // Test "next_keys" DID parameter
        params = params_for_genesis_did_doc.clone();
        params.next_keys = Some(vec!["some_valid_key".to_string()]);
        assert_trust_did_web_error(
            params.validate_initial(),
            DidResolverErrorKind::InvalidDidParameter,
            "Unsupported non-empty 'nextKeyHashes' DID parameter",
        );
        params.next_keys = Some(vec![]);
        assert!(params.validate_initial().is_ok());
        params.next_keys = None;
        assert!(params.validate_initial().is_ok());

        // Test "witnesses" DID parameter
        params = params_for_genesis_did_doc.clone();
        params.witnesses = Some(vec!["some_valid_witness".to_string()]);
        assert_trust_did_web_error(
            params.validate_initial(),
            DidResolverErrorKind::InvalidDidParameter,
            "Unsupported non-empty 'witnesses' DID parameter.",
        );
        params.witnesses = Some(vec![]);
        assert!(params.validate_initial().is_ok());
        params.witnesses = None;
        assert!(params.validate_initial().is_ok());
    }

    #[rstest]
    fn test_did_tdw_parameters_validate_transition() {
        let base_params = TrustDidWebDidMethodParameters::for_genesis_did_doc(
            "scid".to_string(),
            "update_key".to_string(),
        );

        let mut old_params = base_params.clone();
        let mut new_params = base_params.clone();
        assert!(old_params.merge_from(&new_params).is_ok());

        // Test "method" DID parameter
        old_params = base_params.clone();
        new_params = base_params.clone();
        new_params.method = Some("invalidVersion".to_string());
        assert_trust_did_web_error(
            old_params.merge_from(&new_params),
            DidResolverErrorKind::InvalidDidParameter,
            "Invalid 'method' DID parameter.",
        );
        new_params.method = None;
        assert!(old_params.merge_from(&new_params).is_ok());
        // Test "scid" DID parameter
        old_params = old_params.clone();
        new_params = new_params.clone();
        new_params.scid = Some("otherSCID".to_string());
        assert_trust_did_web_error(
            old_params.merge_from(&new_params),
            DidResolverErrorKind::InvalidDidParameter,
            "Invalid 'scid' DID parameter.",
        );
        new_params.scid = None;
        assert!(old_params.merge_from(&new_params).is_ok());
        new_params.scid = Some("scid".to_string()); // SAME scid value
        assert!(old_params.merge_from(&new_params).is_ok());

        // Test "update_keys" DID parameter
        old_params = base_params.clone();
        new_params = base_params.clone();
        new_params.update_keys = Some(vec!["newUpdateKey".to_string()]);
        assert!(old_params.merge_from(&new_params).is_ok());
        new_params.update_keys = None;
        assert!(old_params.merge_from(&new_params).is_ok());
        new_params.update_keys = Some(vec![]);
        assert!(old_params.merge_from(&new_params).is_ok());

        // Test "portable" DID parameter
        old_params = base_params.clone();
        new_params = base_params.clone();

        new_params.portable = Some(true);
        assert_trust_did_web_error(
            old_params.merge_from(&new_params),
            DidResolverErrorKind::InvalidDidParameter,
            "Invalid 'portable' DID parameter.",
        );
        new_params.portable = Some(false);
        assert!(old_params.merge_from(&new_params).is_ok());
        new_params.portable = None;
        assert!(old_params.merge_from(&new_params).is_ok());
        new_params.portable = Some(true);
        old_params.portable = Some(true);
        assert_trust_did_web_error(
            old_params.merge_from(&new_params),
            DidResolverErrorKind::InvalidDidParameter,
            "Unsupported 'portable' DID parameter.",
        );

        // Test "prerotation" DID parameter
        old_params = base_params.clone();
        new_params = base_params.clone();
        old_params.prerotation = Some(true);
        new_params.prerotation = Some(false);
        assert_trust_did_web_error(
            old_params.merge_from(&new_params),
            DidResolverErrorKind::InvalidDidParameter,
            "Invalid 'prerotation' DID parameter.",
        );
        old_params.prerotation = Some(true);
        new_params.prerotation = Some(true);
        assert!(old_params.merge_from(&new_params).is_ok());
        old_params.prerotation = Some(false);
        new_params.prerotation = Some(false);
        assert!(old_params.merge_from(&new_params).is_ok());
        old_params.prerotation = Some(false);
        new_params.prerotation = Some(true);
        assert!(old_params.merge_from(&new_params).is_ok());
        new_params.prerotation = None;
        assert!(old_params.merge_from(&new_params).is_ok());

        // Test "next_keys" DID parameter
        old_params = base_params.clone();
        new_params = base_params.clone();
        new_params.next_keys = Some(vec!["newUpdateKeyHash".to_string()]);
        assert!(old_params.merge_from(&new_params).is_ok());
        new_params.next_keys = None;
        assert!(old_params.merge_from(&new_params).is_ok());
        new_params.next_keys = Some(vec![]);
        assert!(old_params.merge_from(&new_params).is_ok());

        // Test "witnesses" DID parameter
        old_params = base_params.clone();
        new_params = base_params.clone();
        new_params.witnesses = Some(vec!["some_valid_witness".to_string()]);
        assert_trust_did_web_error(
            old_params.merge_from(&new_params),
            DidResolverErrorKind::InvalidDidParameter,
            "Unsupported non-empty 'witnesses' DID parameter.",
        );
        new_params.witnesses = Some(vec![]);
        assert!(old_params.merge_from(&new_params).is_ok());
        new_params.witnesses = None;
        assert!(old_params.merge_from(&new_params).is_ok());
    }

    #[rstest]
    fn test_did_webvh_method_parameters_try_into() {
        let mut base_params = TrustDidWebDidMethodParameters::for_genesis_did_doc(
            "scid".to_string(),
            "some_update_key".to_string(),
        );
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
            .all(|v| v.is_empty()));
        assert!(update_keys
            .get_string_array_value()
            .unwrap()
            .iter()
            .any(|v| v.contains("some_update_key")));

        assert!(param_map.contains_key("portable"));
        let portable_option = param_map.get("portable");
        assert!(portable_option.is_some());
        let portable = portable_option.unwrap();
        assert!(portable.is_bool());
        assert!(portable.get_bool_value().is_some_and(|t| { t }));

        assert!(param_map.contains_key("deactivated"));
        let deactivated_option = param_map.get("deactivated");
        assert!(deactivated_option.is_some());
        let deactivated = deactivated_option.unwrap();
        assert!(deactivated.is_bool());
        assert!(deactivated.get_bool_value().is_some_and(|t| { t }));

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
