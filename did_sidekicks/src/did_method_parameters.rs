// SPDX-License-Identifier: MIT

use crate::errors::DidSidekicksError;
use serde_json::{from_str as json_from_str, to_string as json_to_string, Value};

/// A generic DID method parameter as seen from the perspective of a JSON deserializer.
///
/// The value returned by [`DidMethodParameter::get_json_text`] is guaranteed to be deserializable back into a JSON object.
#[derive(Debug, Clone)]
pub struct DidMethodParameter {
    name: String,
    json_text: String,
    is_bool: bool,
    is_string: bool,
    is_f64: bool,
    is_i64: bool,
    is_u64: bool,
    is_object: bool,
    is_array: bool,
    is_empty_array: bool,
    is_string_array: bool,
    is_null: bool,
    bool_value: Option<bool>,
    string_value: Option<String>,
    string_array_value: Option<Vec<String>>,
    f64_value: Option<f64>,
    i64_value: Option<i64>,
    u64_value: Option<u64>,
}

impl DidMethodParameter {
    /// Yet another non-empty constructor of the type.
    #[inline]
    // TODO Ensure panic-safety
    #[expect(clippy::unwrap_used, reason = "see TODO")]
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
    #[expect(clippy::unwrap_used, reason = "panic-safe unwrap call")]
    pub fn new_true(name: &str) -> Self {
        // panic-safe unwrap call
        Self::new(name, "true".to_owned()).unwrap()
    }

    /// Yet another non-empty constructor of the type.
    #[inline]
    #[expect(clippy::unwrap_used, reason = "panic-safe unwrap call")]
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
            return Self::new(name, json_to_string(&val).unwrap());
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
    //#[expect(clippy::unwrap_in_result, reason = "..")]
    #[expect(
        clippy::unwrap_used,
        reason = "panic-safe unwrap call, see comments below"
    )]
    fn new(name: &str, json_text: String) -> Result<Self, DidSidekicksError> {
        if name.is_empty() {
            return Err(DidSidekicksError::InvalidDidMethodParameter(
                "a DID method parameter must be properly named".to_owned(),
            ));
        }

        let mut param = Self {
            name: name.to_owned(),
            json_text: json_text.clone(),
            is_bool: false,
            is_string: false,
            is_f64: false,
            is_i64: false,
            is_u64: false,
            is_object: false,
            is_array: false,
            is_empty_array: true, // CAUTION
            is_string_array: false,
            is_null: false,
            bool_value: None,
            string_value: None,
            string_array_value: None,
            f64_value: None,
            i64_value: None,
            u64_value: None,
        };

        match json_from_str::<Value>(json_text.as_str()) {
            Ok(Value::Bool(entry)) => {
                param.is_bool = true;
                param.bool_value = Some(entry);
            }
            Ok(Value::String(entry)) => {
                param.is_string = true;
                param.string_value = Some(entry);
            }
            Ok(Value::Number(entry)) => {
                if entry.is_f64() {
                    param.is_f64 = true;
                    // panic-safe unwrap call: For any Number on which is_f64 returns true,
                    //                         as_f64 is guaranteed to return the floating point value
                    param.f64_value = Some(entry.as_f64().unwrap());
                } else if entry.is_i64() {
                    param.is_i64 = true;
                    // panic-safe unwrap call: If the Number is an integer
                    //                         represent it as i64 if possible. Returns None otherwise
                    param.i64_value = Some(entry.as_i64().unwrap());
                } else { //} else if entry.is_u64() {
                    param.is_u64 = true;
                    // panic-safe unwrap call: If the Number is an integer,
                    //                         represent it as u64 if possible. Returns None otherwise
                    param.u64_value = Some(entry.as_u64().unwrap());
                }
            }
            Ok(Value::Object(_)) => {
                param.is_object = true;
            }
            Ok(Value::Array(entry)) => {
                param.is_array = true;
                if !entry.is_empty() {
                    param.is_empty_array = false;
                    let mut arr= vec![];
                    entry.iter().for_each(|err| {
                        if err.is_string() {
                            // panic-safe unwrap call: For any Value on which is_string returns true,
                            //                         as_str is guaranteed to return the string slice
                            arr.push(err.as_str().unwrap().to_owned());
                            // TODO } else if e.is_object() {
                        }
                    });
                    param.is_string_array = true;
                    param.string_array_value = Some(arr);
                };
            }
            Ok(Value::Null) => {
                param.is_null = true;
            }
            Err(err) => {
                return Err(DidSidekicksError::InvalidDidMethodParameter(format!(
                    "'{json_text}' denoting the DID method parameter '{name}' is not a valid JSON text: {err}"
                )))
            }
        };

        Ok(param)
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
        self.is_bool
    }

    /// A UniFFI-compliant getter.
    #[inline]
    pub const fn is_string(&self) -> bool {
        self.is_string
    }

    /// A UniFFI-compliant getter.
    #[inline]
    pub const fn is_f64(&self) -> bool {
        self.is_f64
    }

    /// A UniFFI-compliant getter.
    #[inline]
    pub const fn is_i64(&self) -> bool {
        self.is_i64
    }

    /// A UniFFI-compliant getter.
    #[inline]
    pub const fn is_u64(&self) -> bool {
        self.is_u64
    }

    /// A UniFFI-compliant getter.
    #[inline]
    pub const fn is_object(&self) -> bool {
        self.is_object
    }

    /// A UniFFI-compliant getter.
    #[inline]
    pub const fn is_array(&self) -> bool {
        self.is_array
    }

    /// A UniFFI-compliant getter.
    #[inline]
    pub const fn is_empty_array(&self) -> bool {
        self.is_empty_array
    }

    /// A UniFFI-compliant getter.
    #[inline]
    pub const fn is_string_array(&self) -> bool {
        self.is_string_array
    }

    /// A UniFFI-compliant getter.
    #[inline]
    pub const fn is_null(&self) -> bool {
        self.is_null
    }

    /// A UniFFI-compliant getter.
    ///
    /// For any [`DidMethodParameter`] on which [`DidMethodParameter::is_bool`] returns `true`,
    /// the getter is guaranteed to return a `bool` value.
    #[inline]
    pub const fn get_bool_value(&self) -> Option<bool> {
        if let Some(x) = self.bool_value {
            return Some(x);
        }

        None
    }

    /// A UniFFI-compliant getter.
    ///
    /// For any [`DidMethodParameter`] on which [`DidMethodParameter::is_string`] returns `true`,
    /// the getter is guaranteed to return a [`String`] value.
    #[inline]
    pub fn get_string_value(&self) -> Option<String> {
        if let Some(x) = self.string_value.to_owned() {
            return Some(x);
        }

        None
    }

    /// A UniFFI-compliant getter.
    ///
    /// For any [`DidMethodParameter`] on which [`DidMethodParameter::is_string_array`] returns `true`,
    /// the getter is guaranteed to return a `Vec<String>` value.
    #[inline]
    pub fn get_string_array_value(&self) -> Option<Vec<String>> {
        if let Some(x) = self.string_array_value.to_owned() {
            return Some(x);
        }

        None
    }

    /// A UniFFI-compliant getter.
    ///
    /// For any [`DidMethodParameter`] on which [`DidMethodParameter::is_f64`] returns `true`,
    /// the getter is guaranteed to return a `f64` value.
    #[inline]
    pub const fn get_f64_value(&self) -> Option<f64> {
        if let Some(x) = self.f64_value {
            return Some(x);
        }

        None
    }

    /// A UniFFI-compliant getter.
    ///
    /// For any [`DidMethodParameter`] on which [`DidMethodParameter::is_i64`] returns `true`,
    /// the getter is guaranteed to return a `i64` value.
    #[inline]
    pub const fn get_i64_value(&self) -> Option<i64> {
        if let Some(x) = self.i64_value {
            return Some(x);
        }

        None
    }

    /// A UniFFI-compliant getter.
    ///
    /// For any [`DidMethodParameter`] on which [`DidMethodParameter::is_u64`] returns `true`,
    /// the getter is guaranteed to return a `u64` value.
    #[inline]
    pub const fn get_u64_value(&self) -> Option<u64> {
        if let Some(x) = self.u64_value {
            return Some(x);
        }

        None
    }
}
