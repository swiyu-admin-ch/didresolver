// SPDX-License-Identifier: MIT

use std::sync::Arc;
use thiserror::Error;

use crate::custom_jsonschema_keywords::*;
use jsonschema::draft202012::meta as jsch_meta;
use jsonschema::{options as jsch_opts, Draft, Validator as ValidatorBase};
use serde_json::from_str as json_from_str;

/// Represents any error condition that might occur in conjunction with [`DidLogEntryValidator`].
///
/// Yet another UniFFI-compliant error.
#[derive(Error, Debug, PartialEq, Eq)]
#[expect(
    clippy::exhaustive_enums,
    reason = "further enum variants may be added in the future"
)]
pub enum DidLogEntryValidatorError {
    #[error("the supplied JSON instance is not a valid DID log: {0}")]
    ValidationError(String),
    #[error("the supplied JSON instance cannot be deserialized: {0}")]
    DeserializationError(String),
}

impl DidLogEntryValidatorError {
    /// Returns the error kind.
    #[inline]
    pub const fn kind(&self) -> DidLogEntryValidatorErrorKind {
        match *self {
            Self::ValidationError(_) => DidLogEntryValidatorErrorKind::ValidationError,
            Self::DeserializationError(_) => DidLogEntryValidatorErrorKind::DeserializationError,
        }
    }
}

/// [`DidLogEntryValidatorError`] kind.
///
/// Each [`DidLogEntryValidatorError`] variant has a kind provided by the [`DidLogEntryValidatorError::kind`] method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[expect(
    clippy::exhaustive_enums,
    reason = "further enum variants may be added in the future"
)]
pub enum DidLogEntryValidatorErrorKind {
    ValidationError,
    DeserializationError,
}

/// W.r.t. any of specification versions available at https://identity.foundation/didwebvh
///
/// A UniFFI-compliant trait.
pub trait DidLogEntryJsonSchema: Send + Sync {
    /// Delivers a proper JSON schema (in UTF-8 format) fully describing a DID log entry.
    fn get_json_schema(&self) -> String;
}

/// A compiled JSON Schema validator.
///
/// This structure represents a JSON Schema that has been parsed and compiled into
/// an efficient internal representation for validation. It contains the root node
/// of the schema tree and the configuration options used during compilation.
///
/// Intended to be used predominantly in conjunction with [`DidLogEntryJsonSchema`] trait implementations.
//#[derive(Debug, Default, PartialEq)]
#[derive(Debug)]
pub struct DidLogEntryValidator {
    validator: ValidatorBase,
}

impl DidLogEntryValidator {
    /// Validate the supplied `instance` against the `schema` (supplied earlier via constructor).
    ///
    /// [`DidLogEntryValidatorError`] is returned as soon the very first validation error occurs.
    ///
    /// A UniFFI-compliant method.
    #[inline]
    pub fn validate(&self, instance: String) -> Result<(), DidLogEntryValidatorError> {
        self.validate_str(&instance)
    }

    /// Validate `instance` against `schema` and return the first error if any.
    #[inline]
    pub fn validate_str(&self, instance: &str) -> Result<(), DidLogEntryValidatorError> {
        match json_from_str(instance) {
            Ok(val) => match self.validator.validate(&val) {
                Ok(_) => Ok(()),
                Err(err) => Err(DidLogEntryValidatorError::ValidationError(err.to_string())),
            },
            Err(err) => Err(DidLogEntryValidatorError::DeserializationError(
                err.to_string(),
            )),
        }
    }
}

impl From<Arc<dyn DidLogEntryJsonSchema>> for DidLogEntryValidator {
    /// Create a new JSON Schema validator using `JSON Schema Draft 2020-12` specifications
    /// and supplied thread-safe [`DidLogEntryJsonSchema`] trait implementation.
    ///
    /// Relies heavily on custom [`jsonschema::Keyword`] trait implementation like:
    /// - [`DidLogEntryKeyword`] and
    /// - [`DidVersionTimeKeyword`].
    ///
    /// A UniFFI-compliant constructor.
    #[inline]
    fn from(schema: Arc<dyn DidLogEntryJsonSchema>) -> Self {
        Self::from(schema.get_json_schema().as_str())
    }
}

impl From<&dyn DidLogEntryJsonSchema> for DidLogEntryValidator {
    /// Create a new JSON Schema validator using `JSON Schema Draft 2020-12` specifications
    /// and supplied [`DidLogEntryJsonSchema`] trait implementation.
    ///
    /// Relies heavily on custom [`jsonschema::Keyword`] trait implementation like:
    /// - [`DidLogEntryKeyword`] and
    /// - [`DidVersionTimeKeyword`].
    #[inline]
    fn from(schema: &dyn DidLogEntryJsonSchema) -> Self {
        Self::from(schema.get_json_schema().as_str())
    }
}

impl From<String> for DidLogEntryValidator {
    /// Create a new JSON Schema validator using `JSON Schema Draft 2020-12` specifications
    /// and supplied [`String`].
    ///
    /// Relies heavily on custom [`jsonschema::Keyword`] trait implementation like:
    /// - [`DidLogEntryKeyword`] and
    /// - [`DidVersionTimeKeyword`].
    ///
    /// A UniFFI-compliant constructor.
    #[inline]
    fn from(value: String) -> Self {
        Self::from(value.as_str())
    }
}

#[expect(clippy::fallible_impl_from, reason = "..")]
#[expect(clippy::panic, reason = "..")]
impl From<&str> for DidLogEntryValidator {
    /// Create a new JSON Schema validator using `JSON Schema Draft 2020-12` specifications
    /// and a schema supplied as `&str`.
    ///
    /// Relies heavily on custom [`jsonschema::Keyword`] trait implementation like:
    /// - [`DidLogEntryKeyword`] and
    /// - [`DidVersionTimeKeyword`].
    #[inline]
    fn from(value: &str) -> Self {
        match json_from_str(value) {
            Ok(sch) => {
                let _x = jsch_meta::validate(&sch).is_err_and(|err| panic!("{err}"));
                match jsch_opts()
                    .with_draft(Draft::Draft202012)
                    .with_keyword(
                        DidLogEntryKeyword::KEYWORD_NAME,
                        DidLogEntryKeyword::factory,
                    )
                    .with_keyword(
                        DidVersionTimeKeyword::KEYWORD_NAME,
                        DidVersionTimeKeyword::factory,
                    )
                    .build(&sch)
                {
                    Ok(validator) => Self { validator },
                    Err(err) => panic!("{err}"),
                }
            }
            Err(err) => panic!("{err}"),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{DidLogEntryJsonSchema, DidLogEntryValidator};
    use rstest::rstest;
    use std::sync::Arc;

    struct EmptyDidLogEntryJsonSchemaImpl;
    impl DidLogEntryJsonSchema for EmptyDidLogEntryJsonSchemaImpl {
        fn get_json_schema(&self) -> String {
            "".to_owned()
        }
    }

    #[rstest]
    #[should_panic(expected = "EOF while parsing a value at line 1 column 0")]
    fn test_create_validator_from_empty_schema_thread_safe() {
        let schema: Arc<dyn DidLogEntryJsonSchema> = Arc::new(EmptyDidLogEntryJsonSchemaImpl {});
        let _x = DidLogEntryValidator::from(schema);
    }

    #[rstest]
    #[should_panic(expected = "EOF while parsing a value at line 1 column 0")]
    fn test_create_validator_from_empty_schema() {
        let schema: &dyn DidLogEntryJsonSchema = &EmptyDidLogEntryJsonSchemaImpl {};
        let _x = DidLogEntryValidator::from(schema);
    }
}
