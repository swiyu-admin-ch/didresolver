// SPDX-License-Identifier: MIT

use chrono::{DateTime, Local};
use core::cmp::Ordering;
use jsonschema::{
    paths::{LazyLocation, Location},
    Keyword, ValidationError,
};
use serde_json::{Map, Value};

/// Yet another custom [`Keyword`] trait implementation able to validate if a JSON array represents
/// a regular `didwebvh` DID log entry (as defined by https://identity.foundation/didwebvh/v0.3/#overview).
///
/// This [`Keyword`] trait implementation validates instances according to https://identity.foundation/didwebvh/v0.3/#overview
#[expect(clippy::exhaustive_structs, reason = "..")]
pub struct DidLogEntryKeyword;

impl DidLogEntryKeyword {
    /// The constant required to register this custom keyword validator using `jsonschema::ValidationOptions::with_keyword`.
    pub const KEYWORD_NAME: &'static str = "did-log-entry";

    /// The factory method required to register this custom keyword validator using `jsonschema::ValidationOptions::with_keyword`.
    #[inline]
    //#[expect(clippy::result_large_err, reason = "..")] // "the `Err`-variant is at least 224 bytes" (default: 128)
    #[expect(clippy::single_char_lifetime_names, reason = "for the sake of brevity")]
    pub fn factory<'a>(
        _parent: &'a Map<String, Value>,
        value: &'a Value,
        path: Location,
    ) -> Result<Box<dyn Keyword>, ValidationError<'a>> {
        // You can use the `value` parameter to configure your validator if needed
        if value
            .as_bool()
            .is_some_and(|_| path.to_string().ends_with(Self::KEYWORD_NAME))
        {
            Ok(Box::new(Self))
        } else {
            Err(ValidationError::custom(
                Location::new(),
                path,
                value,
                "The 'did-log-entry' keyword must be set to true",
            ))
        }
    }
}

impl Keyword for DidLogEntryKeyword {
    /// Validate instance according to https://identity.foundation/didwebvh/v0.3/#overview - each DID log entry includes a JSON array of five items:
    ///
    /// 1. The `versionId` of the entry, a value that combines the version number (starting at 1 and incrementing by one per version), a literal dash -, and a hash of the entry. The entry hash calculation links each entry to its predecessor in a ledger-like chain.
    /// 2. The `versionTime` (as stated by the DID Controller) of the entry.
    /// 3. A set of `parameters` that impact the processing of the current and future log entries. Example parameters are the version of the `did:tdw` specification and hash algorithm being used as well as the SCID and update key(s).
    /// 4. The new version of the DIDDoc as either a `value` (the full document) or a `patch` derived using JSON Patch to update the new version from the previous entry.
    /// 5. A Data Integrity (DI) proof across the entry, signed by a DID authorized to update the DIDDoc, using the `versionId` as the challenge.
    #[inline]
    #[expect(clippy::single_char_lifetime_names, reason = "for the sake of brevity")]
    fn validate<'i>(
        &self,
        instance: &'i Value,
        location: &LazyLocation,
    ) -> Result<(), ValidationError<'i>> {
        if let Value::Array(_) = *instance {
            if self.is_valid(instance) {
                Ok(())
            } else {
                Err(ValidationError::custom(
                    Location::new(),
                    location.into(),
                    instance,
                    "A DID log entry must include a JSON array of five items of the following types: string, string, object, object and array",
                ))
            }
        } else {
            Err(ValidationError::custom(
                Location::new(),
                location.into(),
                instance,
                "Value must be an array",
            ))
        }
    }

    /// Validate instance and return a boolean result.
    ///
    /// Instance is validated according to https://identity.foundation/didwebvh/v0.3/#overview - each DID log entry includes a JSON array of five items:
    ///
    /// 1. The `versionId` of the entry, a value that combines the version number (starting at 1 and incrementing by one per version), a literal dash -, and a hash of the entry. The entry hash calculation links each entry to its predecessor in a ledger-like chain.
    /// 2. The `versionTime` (as stated by the DID Controller) of the entry.
    /// 3. A set of `parameters` that impact the processing of the current and future log entries. Example parameters are the version of the `did:tdw` specification and hash algorithm being used as well as the SCID and update key(s).
    /// 4. The new version of the DIDDoc as either a `value` (the full document) or a `patch` derived using JSON Patch to update the new version from the previous entry.
    /// 5. A Data Integrity (DI) proof across the entry, signed by a DID authorized to update the DIDDoc, using the `versionId` as the challenge.
    #[inline]
    fn is_valid(&self, instance: &Value) -> bool {
        // "each DID log entry includes a JSON array of five items"
        instance.as_array().is_some_and(|inst| {
            inst.len() == 5
                && inst.first().is_some_and(|val| {
                    val.is_string() && val.as_str().is_some_and(|str| !str.is_empty())
                })
                && inst.get(1).is_some_and(|val| {
                    val.is_string() && val.as_str().is_some_and(|str| !str.is_empty())
                })
                && inst.get(2).is_some_and(|val| val.is_object())
                && inst.get(3).is_some_and(|val| {
                    val.is_object() && val.as_object().is_some_and(|map| !map.is_empty())
                })
                && inst.get(4).is_some_and(|val| {
                    val.is_array()
                        && val.as_array().is_some_and(|vec| {
                            !vec.is_empty()
                                && vec.iter().all(|vec_val| {
                                    vec_val.is_object()
                                        && vec_val.as_object().is_some_and(|map| !map.is_empty())
                                })
                        })
                })
        })
    }
}

/// Yet another custom [`Keyword`] trait implementation.
///
/// It is able to validate the rule in regard to `versionTime` DID log entry item
/// (as defined by https://confluence.bit.admin.ch/display/EIDTEAM/DID+Log+Conformity+Check).
#[expect(clippy::exhaustive_structs, reason = "..")]
pub struct DidVersionTimeKeyword;

impl DidVersionTimeKeyword {
    /// Required to register this custom keyword validator using `jsonschema::ValidationOptions::with_keyword`.
    pub const KEYWORD_NAME: &'static str = "did-version-time";

    /// Required to register this custom keyword validator using `jsonschema::ValidationOptions::with_keyword`.
    #[inline]
    //#[expect(clippy::result_large_err, reason = "..")] // "the `Err`-variant is at least 224 bytes" (default: 128)
    #[expect(clippy::single_char_lifetime_names, reason = "..")]
    pub fn factory<'a>(
        _parent: &'a Map<String, Value>,
        value: &'a Value,
        path: Location,
    ) -> Result<Box<dyn Keyword>, ValidationError<'a>> {
        // You can use the `value` parameter to configure your validator if needed
        if value
            .as_bool()
            .is_some_and(|_| path.to_string().ends_with(Self::KEYWORD_NAME))
        {
            Ok(Box::new(Self))
        } else {
            Err(ValidationError::custom(
                Location::new(),
                path,
                value,
                "The 'did-version-time' keyword must be set to true",
            ))
        }
    }
}

impl Keyword for DidVersionTimeKeyword {
    /// Validate instance according to a custom specification i.e. a `versionTime` string representation qualifies as "valid" if:
    /// 1. is valid datetime in `ISO8601` format
    /// 2. is (as datetime) before the current time
    #[inline]
    #[expect(clippy::single_char_lifetime_names, reason = "for the sake of brevity")]
    #[expect(clippy::pattern_type_mismatch, reason = "..")]
    fn validate<'i>(
        &self,
        instance: &'i Value,
        location: &LazyLocation,
    ) -> Result<(), ValidationError<'i>> {
        if let Value::String(dt) = instance {
            // versionTime:
            // 1. Valid datetime in ISO8601 format SPEC
            // 2. datetime is before the current time

            match DateTime::parse_from_rfc3339(dt) {
                Ok(parsed_dt) => {
                    let now = Local::now();
                    if parsed_dt.ge(&now) {
                        return Err(ValidationError::custom(
                            Location::new(),
                            location.into(),
                            instance,
                            format!("`versionTime` '{parsed_dt}' must be before the current datetime '{now}'"),
                        ));
                    }
                    Ok(())
                }
                Err(_) => Err(ValidationError::custom(
                    Location::new(),
                    location.into(),
                    instance,
                    "Datetime not in ISO8601 format",
                )),
            }
        } else {
            Err(ValidationError::custom(
                Location::new(),
                location.into(),
                instance,
                "Value must be a string representing some datetime in ISO8601 format",
            ))
        }
    }

    /// Validate instance and return a boolean result.
    ///
    /// A `versionTime` string representation qualifies as "valid" if:
    /// 1. is valid datetime in `ISO8601` format
    /// 2. is (as datetime) before the current time
    #[inline]
    fn is_valid(&self, instance: &Value) -> bool {
        instance.as_str().is_some_and(|str| {
            DateTime::parse_from_rfc3339(str)
                .is_ok_and(|dt| dt.cmp(&Local::now().fixed_offset()) == Ordering::Less)
        })
    }
}

#[cfg(test)]
#[expect(clippy::shadow_unrelated, reason = "..")]
#[expect(
    clippy::unwrap_used,
    reason = "unwrap calls are panic-safe as long as test case setup is correct"
)]
mod test {
    use crate::custom_jsonschema_keywords::*;
    use jsonschema::options as jsch_opts;
    use rstest::rstest;
    use serde_json::{json, Value};

    #[rstest]
    fn test_did_log_entry_keyword_wrong_keyword() {
        const WRONG_KEYWORD_NAME: &str = "anything-but-proper-keyword-name";
        let schema = json!({WRONG_KEYWORD_NAME: true, "type": "array"});

        let validator = jsch_opts()
            /*
            .with_keyword(WRONG_KEYWORD_NAME, |_, _, _| {
                Ok(Box::new(DidLogEntryKeyword))
            }) // using closure
             */
            .with_keyword(WRONG_KEYWORD_NAME, DidLogEntryKeyword::factory) // using factory
            .build(&schema);

        assert!(validator.is_err());
        assert!(validator.err().is_some_and(|err| {
            err.to_string()
                .contains("The 'did-log-entry' keyword must be set to true")
        }));
    }

    #[rstest]
    #[case(json!(["some-version-id","some-version-time",{"":""},{"":""},[{"":""}]]), true)]
    #[case(json!(["some-version-id","some-version-time",{},{"":""},[{"":""}]]), true)] // params may be empty
    #[case(json!(["some-version-id","some-version-time",{},{"":""},[{"":""},{}]]), false)] // proof must not be empty
    #[case(json!(["","",{},{},[]]), false)] // all empty
    #[case(json!(["","",{},{},[{}]]), false)] // all empty
    #[case(json!(["","","","",""]), false)] // all JSON strings
    #[case(json!([]), false)] // empty array
    fn test_did_log_entry_keyword_validate(#[case] instance: Value, #[case] expected: bool) {
        let schema = json!({DidLogEntryKeyword::KEYWORD_NAME: true, "type": "array"});

        let validator = jsch_opts()
            .with_keyword(
                DidLogEntryKeyword::KEYWORD_NAME,
                DidLogEntryKeyword::factory,
            ) // using factory
            .build(&schema)
            .unwrap(); // panic-safe

        let validate = validator.validate(&instance);

        assert_eq!(expected, validate.is_ok());

        let schema = json!({DidLogEntryKeyword::KEYWORD_NAME: true, "type": "integer"}); // CAUTION wrong "type"

        let validator = jsch_opts()
            .with_keyword(
                DidLogEntryKeyword::KEYWORD_NAME,
                DidLogEntryKeyword::factory,
            ) // using factory
            .build(&schema)
            .unwrap(); // panic-safe

        let validate = validator.validate(&instance);

        // should always fail since "type" is wrong ("integer" instead of "array")
        assert!(validate.is_err());
        assert!(validate.err().is_some());
    }

    #[rstest]
    fn test_did_version_time_keyword_wrong_keyword() {
        const WRONG_KEYWORD_NAME: &str = "anything-but-proper-keyword-name";
        let schema = json!({WRONG_KEYWORD_NAME: true, "type": "string"});

        let validator = jsch_opts()
            /*
            .with_keyword(WRONG_KEYWORD_NAME, |_, _, _| {
                Ok(Box::new(DidVersionTimeKeyword))
            }) // using closure
             */
            .with_keyword(WRONG_KEYWORD_NAME, DidVersionTimeKeyword::factory) // using factory
            .build(&schema);

        assert!(validator.is_err());
        assert!(validator.err().is_some_and(|err| {
            err.to_string()
                .contains("The 'did-version-time' keyword must be set to true")
        }));
    }

    #[rstest]
    #[case("2012-12-12T12:12:12Z", true)]
    #[case("9999-12-12T12:12:12Z", false)] // CAUTION far beyond today
    #[case("2012-12-12T12:12:12", false)]
    #[case("2012-12-12X12:12:12X", false)]
    #[case("9999-99-99T99:99:99Z", false)]
    #[case("2012-12-12", false)]
    #[case("12:12:12", false)]
    #[case("anything but datetime", false)]
    fn test_did_version_time_keyword_validate(#[case] instance: String, #[case] expected: bool) {
        let schema = json!({DidVersionTimeKeyword::KEYWORD_NAME: true, "type": "string"});

        let validator = jsch_opts()
            .with_keyword(DidVersionTimeKeyword::KEYWORD_NAME, |_, _, _| {
                Ok(Box::new(DidVersionTimeKeyword))
            }) // using closure
            .build(&schema)
            .unwrap();

        let instance_value = json!(instance);
        let validate = validator.validate(&instance_value);

        assert_eq!(expected, validate.is_ok());

        let schema = json!({DidVersionTimeKeyword::KEYWORD_NAME: true, "type": "integer"}); // CAUTION wrong "type"

        let validator = jsch_opts()
            .with_keyword(DidVersionTimeKeyword::KEYWORD_NAME, |_, _, _| {
                Ok(Box::new(DidVersionTimeKeyword))
            }) // using closure
            .build(&schema)
            .unwrap();

        let instance_value = json!(instance);
        let validate = validator.validate(&instance_value);

        // should always fail since "type" is wrong ("integer" instead of "string")
        assert!(validate.is_err());
        assert!(validate.err().is_some());
    }

    #[rstest]
    #[case("2012-12-12T12:12:12Z", true)]
    #[case("9999-12-12T12:12:12Z", false)] // CAUTION far beyond today
    #[case("2012-12-12T12:12:12", false)]
    #[case("2012-12-12X12:12:12X", false)]
    #[case("9999-99-99T99:99:99Z", false)]
    #[case("2012-12-12", false)]
    #[case("12:12:12", false)]
    #[case("anything but datetime", false)]
    fn test_did_version_time_keyword_is_valid(#[case] instance: String, #[case] expected: bool) {
        let schema = json!({DidVersionTimeKeyword::KEYWORD_NAME: true, "type": "string"});

        let validator = jsch_opts()
            .with_keyword(DidVersionTimeKeyword::KEYWORD_NAME, |_, _, _| {
                Ok(Box::new(DidVersionTimeKeyword))
            }) // using closure
            .build(&schema)
            .unwrap();

        assert_eq!(expected, validator.is_valid(&json!(instance)));

        assert!(!validator.is_valid(&json!(1234)));

        let validator = jsch_opts()
            .with_keyword(
                DidVersionTimeKeyword::KEYWORD_NAME,
                DidVersionTimeKeyword::factory,
            ) // using factory
            .build(&schema)
            .unwrap();

        assert_eq!(expected, validator.is_valid(&json!(instance)));

        assert!(!validator.is_valid(&json!(1234)));

        let schema = json!({DidVersionTimeKeyword::KEYWORD_NAME: true, "type": "integer"}); // CAUTION wrong "type"

        let validator = jsch_opts()
            .with_keyword(
                DidVersionTimeKeyword::KEYWORD_NAME,
                DidVersionTimeKeyword::factory,
            ) // using factory
            .build(&schema)
            .unwrap();

        // should always fail since "type" is wrong ("integer" instead of "string")
        assert!(!validator.is_valid(&json!(instance)));
    }
}
