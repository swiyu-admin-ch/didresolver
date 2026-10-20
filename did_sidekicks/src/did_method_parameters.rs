// SPDX-License-Identifier: MIT

use crate::errors::DidSidekicksError;
use serde_json::Value;

/// A generic DID method parameter as seen from the perspective of a JSON deserializer.
///
/// The value returned by [`DidMethodParameter::get_json_text`] is guaranteed to be deserializable back into a JSON object.
#[derive(Debug, Clone)]
pub struct DidMethodParameter {
    name: String,
    json_text: String,
    value: DidMethodValue,
}

#[derive(Debug, Clone)]
enum DidMethodValue {
    Bool(bool),
    String(String),
    I64(i64),
    U64(u64),
    F64(f64),
    StringArray(Vec<String>),
    EmptyArray,
    Object,
    Array,
    Null,
}

impl DidMethodParameter {
    /// Yet another non-empty constructor of the type.
    #[inline]
    #[expect(clippy::unwrap_used, reason = "Covered by test")]
    pub fn new_bool(name: &str, value: bool) -> Self {
        Self::new(name, value.to_string()).unwrap()
    }

    /// Yet another non-empty constructor of the type.
    #[inline]
    pub fn new_bool_from_option(name: &str, value: Option<bool>) -> Self {
        if let Some(val) = value {
            return Self::new_bool(name, val);
        }
        Self::new_false(name) // fallback for an optional param
    }

    /// Yet another non-empty constructor of the type.
    #[inline]
    #[expect(clippy::unwrap_used, reason = "Covered by test")]
    pub fn new_true(name: &str) -> Self {
        // panic-safe unwrap call
        Self::new(name, "true".to_owned()).unwrap()
    }

    /// Yet another non-empty constructor of the type.
    #[inline]
    #[expect(clippy::unwrap_used, reason = "Covered by test")]
    pub fn new_false(name: &str) -> Self {
        // panic-safe unwrap call
        Self::new(name, "false".to_owned()).unwrap()
    }

    /// Yet another non-empty constructor of the type.
    #[inline]
    pub fn new_string(name: &str, value: String) -> Result<Self, DidSidekicksError> {
        Self::new(name, format!("\"{value}\""))
    }

    /// Yet another non-empty constructor of the type.
    #[inline]
    pub fn new_string_from_option(
        name: &str,
        value: Option<String>,
    ) -> Result<Self, DidSidekicksError> {
        if let Some(val) = value {
            return Self::new_string(name, val);
        }
        Err(DidSidekicksError::InvalidDidMethodParameter(format!(
            "DID method parameter omitted: {name}"
        )))
    }

    /// Yet another non-empty constructor of the type.
    #[inline]
    #[expect(clippy::unwrap_in_result, reason = "panic-safe unwrap call")]
    #[expect(clippy::unwrap_used, reason = "panic-safe unwrap call")]
    pub fn new_string_array_from_option(
        name: &str,
        value: Option<Vec<String>>,
    ) -> Result<Self, DidSidekicksError> {
        if let Some(val) = value {
            // panic-safe unwrap call
            return Self::new(name, serde_json::to_string(&val).unwrap());
        }
        Err(DidSidekicksError::InvalidDidMethodParameter(format!(
            "DID method parameter omitted: {name}"
        )))
    }

    /// Yet another non-empty constructor of the type.
    #[inline]
    pub fn new_number_from_option(
        name: &str,
        value: Option<usize>,
    ) -> Result<Self, DidSidekicksError> {
        if let Some(size) = value {
            return Self::new(name, size.to_string());
        }
        Err(DidSidekicksError::InvalidDidMethodParameter(format!(
            "DID method parameter omitted: {name}"
        )))
    }

    /// The only non-empty constructor of the type.
    ///
    /// The supplied string of JSON text (`json_text`) must be deserializable into a JSON object.
    fn new(name: &str, json_text: String) -> Result<Self, DidSidekicksError> {
        if name.is_empty() {
            return Err(DidSidekicksError::InvalidDidMethodParameter(
                "a DID method parameter must be properly named".to_owned(),
            ));
        }

        let json_value = match serde_json::from_str::<Value>(json_text.as_str()) {
            Ok(value) => value,
            Err(err) => {
                return Err(DidSidekicksError::InvalidDidMethodParameter(format!(
                    "'{json_text}' denoting the DID method parameter '{name}' is not a valid JSON text: {err}"
                )));
            }
        };

        let value = match json_value {
            Value::Bool(entry) => DidMethodValue::Bool(entry),
            Value::String(entry) => DidMethodValue::String(entry),
            Value::Number(entry) => {
                if entry.is_f64() {
                    // panic-safe unwrap call: For any Number on which is_f64 returns true, as_f64 is guaranteed to return the floating point value
                    #[expect(clippy::unwrap_used, reason = "Unwrap is checked")]
                    DidMethodValue::F64(entry.as_f64().unwrap())
                } else if entry.is_i64() {
                    // panic-safe unwrap call: If the Number is an integer represent it as i64 if possible. Returns None otherwise
                    #[expect(clippy::unwrap_used, reason = "Unwrap is checked")]
                    DidMethodValue::I64(entry.as_i64().unwrap())
                } else if entry.is_u64() {
                    // panic-safe unwrap call: If the Number is an integer, represent it as u64 if possible. Returns None otherwise
                    #[expect(clippy::unwrap_used, reason = "Unwrap is checked")]
                    DidMethodValue::U64(entry.as_u64().unwrap())
                } else {
                    return Err(DidSidekicksError::InvalidDidMethodParameter(format!(
                        "Integer type for value of {} not supported",
                        name,
                    )));
                }
            }
            Value::Object(_) => DidMethodValue::Object,
            Value::Array(entry) => {
                if entry.is_empty() {
                    DidMethodValue::EmptyArray
                } else {
                    entry
                        .iter()
                        .map(|element| element.as_str().map(str::to_owned))
                        .collect::<Option<Vec<String>>>()
                        .map_or(DidMethodValue::Array, DidMethodValue::StringArray)
                }
            }
            Value::Null => DidMethodValue::Null,
        };
        Ok(Self {
            name: name.into(),
            json_text,
            value,
        })
    }

    /// A UniFFI-compliant getter.
    #[inline]
    pub fn get_name(&self) -> String {
        self.name.clone()
    }

    /// A UniFFI-compliant getter.
    ///
    /// The value returned by the getter is guaranteed to be deserializable back into a JSON object.
    #[inline]
    pub fn get_json_text(&self) -> String {
        self.json_text.clone()
    }

    /// A UniFFI-compliant getter.
    #[inline]
    pub const fn is_bool(&self) -> bool {
        matches!(self.value, DidMethodValue::Bool(_))
    }

    /// A UniFFI-compliant getter.
    #[inline]
    pub const fn is_string(&self) -> bool {
        matches!(self.value, DidMethodValue::String(_))
    }

    /// A UniFFI-compliant getter.
    #[inline]
    pub const fn is_f64(&self) -> bool {
        matches!(self.value, DidMethodValue::F64(_))
    }

    /// A UniFFI-compliant getter.
    #[inline]
    pub const fn is_i64(&self) -> bool {
        matches!(self.value, DidMethodValue::I64(_))
    }

    /// A UniFFI-compliant getter.
    #[inline]
    pub const fn is_u64(&self) -> bool {
        matches!(self.value, DidMethodValue::U64(_))
    }

    /// A UniFFI-compliant getter.
    #[inline]
    pub const fn is_object(&self) -> bool {
        matches!(self.value, DidMethodValue::Object)
    }

    /// A UniFFI-compliant getter.
    #[inline]
    pub const fn is_array(&self) -> bool {
        matches!(
            self.value,
            DidMethodValue::Array | DidMethodValue::EmptyArray | DidMethodValue::StringArray(_)
        )
    }

    /// A UniFFI-compliant getter.
    #[inline]
    pub const fn is_empty_array(&self) -> bool {
        matches!(self.value, DidMethodValue::EmptyArray)
    }

    /// A UniFFI-compliant getter.
    #[inline]
    pub const fn is_string_array(&self) -> bool {
        matches!(self.value, DidMethodValue::StringArray(_))
    }

    /// A UniFFI-compliant getter.
    #[inline]
    pub const fn is_null(&self) -> bool {
        matches!(self.value, DidMethodValue::Null)
    }

    /// A UniFFI-compliant getter.
    ///
    /// For any [`DidMethodParameter`] on which [`DidMethodParameter::is_bool`] returns `true`,
    /// the getter is guaranteed to return a `bool` value.
    #[inline]
    pub const fn get_bool_value(&self) -> Option<bool> {
        if let DidMethodValue::Bool(value) = self.value {
            return Some(value);
        }
        None
    }

    /// A UniFFI-compliant getter.
    ///
    /// For any [`DidMethodParameter`] on which [`DidMethodParameter::is_string`] returns `true`,
    /// the getter is guaranteed to return a [`String`] value.
    #[inline]
    pub fn get_string_value(&self) -> Option<String> {
        if let DidMethodValue::String(value) = self.value.to_owned() {
            return Some(value);
        }
        None
    }

    /// A UniFFI-compliant getter.
    ///
    /// For any [`DidMethodParameter`] on which [`DidMethodParameter::is_string_array`] returns `true`,
    /// the getter is guaranteed to return a `Vec<String>` value.
    #[inline]
    pub fn get_string_array_value(&self) -> Option<Vec<String>> {
        if let DidMethodValue::StringArray(value) = self.value.to_owned() {
            return Some(value);
        }
        None
    }

    /// A UniFFI-compliant getter.
    ///
    /// For any [`DidMethodParameter`] on which [`DidMethodParameter::is_f64`] returns `true`,
    /// the getter is guaranteed to return a `f64` value.
    #[inline]
    pub const fn get_f64_value(&self) -> Option<f64> {
        if let DidMethodValue::F64(value) = self.value {
            return Some(value);
        }
        None
    }

    /// A UniFFI-compliant getter.
    ///
    /// For any [`DidMethodParameter`] on which [`DidMethodParameter::is_i64`] returns `true`,
    /// the getter is guaranteed to return a `i64` value.
    #[inline]
    pub const fn get_i64_value(&self) -> Option<i64> {
        if let DidMethodValue::I64(value) = self.value {
            return Some(value);
        }
        None
    }

    /// A UniFFI-compliant getter.
    ///
    /// For any [`DidMethodParameter`] on which [`DidMethodParameter::is_u64`] returns `true`,
    /// the getter is guaranteed to return a `u64` value.
    #[inline]
    pub const fn get_u64_value(&self) -> Option<u64> {
        if let DidMethodValue::U64(value) = self.value {
            return Some(value);
        }
        None
    }
}

#[cfg(test)]
mod test {
    use crate::did_method_parameters::DidMethodParameter;

    #[test]
    fn new_bool() {
        let name = "some name";
        let true_parameter = DidMethodParameter::new_bool(name, true);
        assert!(true_parameter.is_bool());
        assert_eq!(Some(true), true_parameter.get_bool_value());
        assert_eq!(name, true_parameter.get_name());

        let false_parameter = DidMethodParameter::new_bool(name, false);
        assert!(false_parameter.is_bool());
        assert_eq!(Some(false), false_parameter.get_bool_value());
        assert_eq!(name, false_parameter.get_name());
    }

    #[test]
    fn new_true() {
        let name = "some name";
        let parameter = DidMethodParameter::new_true(name);
        assert!(parameter.is_bool());
        assert_eq!(Some(true), parameter.get_bool_value());
        assert_eq!(name, parameter.get_name());
    }

    #[test]
    fn new_false() {
        let name = "some name";
        let parameter = DidMethodParameter::new_false(name);
        assert!(parameter.is_bool());
        assert_eq!(Some(false), parameter.get_bool_value());
        assert_eq!(name, parameter.get_name());
    }

    #[test]
    fn new_string() {
        let name = "some name";
        let value = "value";
        let parameter = DidMethodParameter::new_string(name, value.to_string()).unwrap();
        assert!(parameter.is_string());
        assert_eq!(Some(value.to_string()), parameter.get_string_value());
        assert_eq!(name, parameter.get_name());
    }
}
