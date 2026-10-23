// SPDX-License-Identifier: MIT

use std::{collections::HashMap, str::FromStr as _, sync::Arc};

use crate::{
    did_webvh_jsonschema::WebVerifiableHistoryDidLogEntryJsonSchema,
    errors::WebVerifiableHistoryIdResolutionError,
};
use chrono::{DateTime, Utc};
use did_sidekicks::{
    did_doc::DidDoc,
    did_jsonschema::{DidLogEntryJsonSchema, DidLogEntryValidator},
    did_method_parameters::DidMethodParameter,
    did_resolver::DidResolver,
    errors::DidResolverError,
};
use log_entry::DidLogEntry;
use method_parameters::{WebVerifiableHistoryDidMethodParameters, hash_update_key};
use regex::Regex;
use url::Url;

pub mod log_entry;
pub mod method_parameters;
pub mod version_id;

#[expect(
    clippy::useless_attribute,
    reason = "to fix the false positive of the below expect"
)]
#[expect(clippy::pub_use, reason = "for single definition of the max size")]
pub use did_sidekicks::did_doc::MAX_DID_LOG_FILE_SIZE;
// String here to easily be updated with changes to MAX_DID_LOG_FILE_SIZE
const MAX_DID_LOG_FILE_SIZE_ERROR_MESSAGE: &str = "DID log must not be bigger than 1MiB";

/// Regex to check if a domain follows the assumption described in https://www.rfc-editor.org/rfc/rfc952.html
/// Allowed are lowercase letters (a-z), digits (0-9) dash (-) and period (.). Periods are only allowed to
/// delimit components.
static DOMAIN_REGEX_STR: &str = r"^[\-a-z0-9]+(\.[\-a-z0-9]+)*$";
static HAS_PATH_REGEX_STR: &str = r"([a-z]|[0-9])\/([a-z]|[0-9])";
static HAS_PORT_REGEX_STR: &str = r"\:[0-9]+";

lazy_static! {
    static ref DOMAIN_REGEX: Regex = #[expect(
        clippy::unwrap_used,
        reason = "string manually checked that it compiles"
    )]
    Regex::new(DOMAIN_REGEX_STR).unwrap();
    static ref HAS_PATH_REGEX: Regex = #[expect(
        clippy::unwrap_used,
        reason = "string manually checked that it compiles"
    )]
    Regex::new(HAS_PATH_REGEX_STR).unwrap();
    static ref HAS_PORT_REGEX: Regex = #[expect(
        clippy::unwrap_used,
        reason = "string manually checked that it compiles"
    )]
    Regex::new(HAS_PORT_REGEX_STR).unwrap();
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

/// Implementation for a string denoting did_webvh.
impl TryFrom<String> for WebVerifiableHistoryId {
    type Error = WebVerifiableHistoryIdResolutionError;

    /// It basically implements the 'The DID to HTTPS Transformation',
    /// as specified by https://identity.foundation/didwebvh/v1.0/#the-did-to-https-transformation.
    #[inline]
    #[expect(
        clippy::indexing_slicing,
        reason = "panic-free indexing ensured in code"
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
            return Err(
                WebVerifiableHistoryIdResolutionError::InvalidMethodSpecificId(String::from(
                    "Empty self-certifying identifier (SCID) detected. An object identifier derived from initial data is expected",
                )),
            );
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
                );
            }
        };

        // Verify that the host is a valid domain.
        // Special characters were encoded by `Url::parse`.
        // URL without domain, that instead use an ip address are already validated in step 5
        if let url::Origin::Tuple(_, url::Host::Domain(dom), _) = url.origin()
            && DOMAIN_REGEX.captures(dom.as_str()).is_none()
        {
            return Err(
                WebVerifiableHistoryIdResolutionError::InvalidMethodSpecificId(
                    "Domain of provided DID is invalid".to_owned(),
                ),
            );
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
                        );
                    }
                };
                if HAS_PATH_REGEX.captures(url.as_str()).is_some()
                    || HAS_PORT_REGEX.captures(url.as_str()).is_some()
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

/// The parser for `did:webvh` DID logs implementing [`TryFrom<String>`] trait.
#[expect(clippy::exhaustive_structs, reason = "..")]
#[derive(Debug)]
pub struct WebVerifiableHistoryDidLog {
    pub did_doc: DidDoc,
    pub did_method_parameters: WebVerifiableHistoryDidMethodParameters,
    pub did_log: String,
}

impl TryFrom<String> for WebVerifiableHistoryDidLog {
    type Error = DidResolverError;

    #[inline]
    fn try_from(did_log: String) -> Result<Self, Self::Error> {
        if did_log.len() > MAX_DID_LOG_FILE_SIZE {
            return Err(DidResolverError::InvalidDidLog(
                MAX_DID_LOG_FILE_SIZE_ERROR_MESSAGE.into(),
            ));
        }

        let sch: &dyn DidLogEntryJsonSchema =
            &WebVerifiableHistoryDidLogEntryJsonSchema::V1_0EidConform;
        let schema_validator = DidLogEntryValidator::from(sch);
        let mut is_deactivated = false;
        let did_log_entries = did_log
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| {
                    schema_validator.validate_str(line).map_err(|err| DidResolverError::DeserializationFailed(err.to_string()))?;

                    if is_deactivated {
                        return Err(DidResolverError::InvalidDidDocument(
                            "This DID document is already deactivated. Therefore no additional DID logs are allowed.".to_owned()
                        ));
                    }

                    let current_entry = DidLogEntry::from_str(line)?;
                    is_deactivated = current_entry.parameters.is_deactivated();
                    Ok(current_entry)
                }).collect::<Result<Vec<DidLogEntry>, DidResolverError>>()?;

        Self::new(did_log_entries, did_log)
    }
}

impl WebVerifiableHistoryDidLog {
    #[inline]
    pub fn new<I>(did_log_entries: I, original_log: String) -> Result<Self, DidResolverError>
    where
        I: IntoIterator<Item = DidLogEntry>,
    {
        let mut entries = did_log_entries.into_iter().peekable();

        let (mut prev_version_id, mut params) = match entries.peek() {
            Some(did_log) => did_log.validate_initial_entry_properties()?,
            None => return Err(DidResolverError::InvalidDidLog("DID log is empty".into())),
        };

        let mut update_keys = params.update_keys.clone().unwrap_or(Vec::new());
        let mut next_key_hashes: Vec<String> = Vec::new();
        let mut prev_version_time = DateTime::<Utc>::MIN_UTC;
        let now = Utc::now();

        // Validation for all entries
        let mut prev_did_doc: Option<DidDoc> = None;
        for (entry, index) in entries.zip(1..) {
            // validate version index
            if entry.version.index != index {
                // +1 because logs start at index 1 not 0
                return Err(DidResolverError::InvalidDidLog(if index == 1 {
                    "Invalid did log. First entry must start with versionId 1".to_owned()
                } else {
                    format!(
                        "Invalid did log, entry {} has versionId {}, entry number must match versionId.",
                        index, entry.version.index,
                    )
                }));
            }

            // validate version time
            if entry.version_time.lt(&prev_version_time) {
                return Err(DidResolverError::InvalidDidLog(
                    "`versionTime` must be greater than the `versionTime` of the previous entry."
                        .to_owned(),
                ));
            }
            if entry.version_time.gt(&now) {
                return Err(DidResolverError::InvalidDidLog(
                    "`versionTime` must be in the past.".to_owned(),
                ));
            }
            prev_version_time = entry.version_time;

            // for 2nd entry onwards specific validations
            if let Some(prev_doc) = prev_did_doc.as_ref() {
                params.merge_from(&entry.parameters)?;
                params.validate()?;

                #[expect(clippy::else_if_without_else, reason = "else case not needed")]
                if matches!(entry.parameters.portable, Some(true)) {
                    // Validate that changed identifier keeps the same SCID
                    match (
                        WebVerifiableHistoryId::parse_did_webvh(entry.did_doc.get_id()),
                        WebVerifiableHistoryId::parse_did_webvh(prev_doc.get_id()),
                    ) {
                        (Ok(current_did_doc_id), Ok(previous_did_doc_id)) => {
                            if current_did_doc_id.scid != previous_did_doc_id.scid {
                                return Err(DidResolverError::InvalidDidDocument(
                                    "SCID may NOT change between DID log entries.".into(),
                                ));
                            }
                        }
                        _ => {
                            return Err(DidResolverError::InvalidDidDocument(
                                "DID Document contains invalid id".into(),
                            ));
                        } // Missing validation for alsoKnownAs to include previous entry
                    }
                    // Check that DID Document ID stayed the same
                } else if entry.did_doc.get_id() != prev_doc.get_id() {
                    return Err(DidResolverError::InvalidDidDocument(
                        "ID of DID Document may only change when portable is active.".into(),
                    ));
                }
            }

            // If key rotation is active, validate and use incoming update_keys
            if let Some(new_update_keys) = entry.parameters.update_keys.as_ref()
                && !next_key_hashes.is_empty()
            {
                // Check if incoming update_keys are authorized
                if index != 1
                    && new_update_keys.iter().any(|new_update_key| {
                        let new_update_key_hash = hash_update_key(new_update_key.as_str());
                        !next_key_hashes.contains(&new_update_key_hash)
                    })
                {
                    return Err(DidResolverError::InvalidDidParameter(
                        "Unauthorized update key detected.".into(),
                    ));
                }
                update_keys = new_update_keys.clone();
            }

            // Verify data integrity proof
            entry.verify_data_integrity_proof(&update_keys)?;

            // Verify the entryHash
            entry.verify_version_id_integrity(prev_version_id.as_str())?;

            // Without key rotation, new update keys only take effect for following log entries
            if let Some(new_update_keys) = entry.parameters.update_keys
                && next_key_hashes.is_empty()
            {
                update_keys = new_update_keys;
            }

            // Update next_key_hashes when the entry is valid
            if let Some(new_next_keys) = entry.parameters.next_keys {
                next_key_hashes = new_next_keys;
            }

            // Verify did document
            entry
                .did_doc
                .validate()
                .map_err(|err| DidResolverError::InvalidDidDocument(err.to_string()))?;

            prev_version_id = entry.version.id;
            prev_did_doc = Some(entry.did_doc);
        }

        #[expect(
            clippy::unwrap_used,
            reason = "Check at start of function for at least 1 entry"
        )]
        Ok(Self {
            did_doc: prev_did_doc.unwrap(), // is safe since size check is done before
            did_method_parameters: params,
            did_log: original_log,
        })
    }

    #[inline]
    pub fn get_did_method_parameters(&self) -> WebVerifiableHistoryDidMethodParameters {
        self.did_method_parameters.clone()
    }
}

impl core::fmt::Display for WebVerifiableHistoryDidLog {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str(self.did_log.as_str())
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
    /// [*Read (Resolve)* DID method operation for a `did:webvh` DID](https://identity.foundation/didwebvh/v1.0/#read-resolve).
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
        // Validates that it can be parsed -> Return value is ignored
        WebVerifiableHistoryId::parse_did_webvh(did_webvh.clone())
            .map_err(|err| DidResolverError::InvalidMethodSpecificId(format!("{err}")))?;

        let did_doc_valid = did_log_obj.did_doc.clone();
        let did_doc_str = match serde_json::to_string(&did_doc_valid) {
            Ok(val) => val,
            Err(err) => return Err(DidResolverError::SerializationFailed(err.to_string())),
        };

        // Verify that the document matches the did
        if did_webvh != did_doc_valid.get_id() {
            return Err(DidResolverError::InvalidDidDocument(
                "id in did document doesn't match did".into(),
            ));
        }

        Ok(Self {
            did: did_webvh,
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
    fn get_did_doc_obj(&self) -> Result<DidDoc, DidResolverError> {
        if self.did_method_parameters.is_deactivated() {
            return Err(DidResolverError::InvalidDidDocument(
                "Document has been deactivated.".into(),
            ));
        }
        Ok(self.get_did_doc_obj())
    }
}
