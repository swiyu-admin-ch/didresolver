// SPDX-License-Identifier: MIT

use crate::did_method_parameters::DidMethodParameter;
use crate::errors::DidSidekicksError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// An entry in DID log file as shown here
/// https://bcgov.github.io/trustdidweb/#term:did-log-entry.

// Implement basic properties related to EC algorithm
// https://www.rfc-editor.org/rfc/rfc7517#section-4
// https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.1
#[derive(Serialize, Deserialize, Debug, Clone)]
#[expect(clippy::exhaustive_structs, reason = "..")]
pub struct Jwk {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kty: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub key_use: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,
}

// See https://www.w3.org/TR/did-core/#verification-methods
#[derive(Serialize, Deserialize, Debug)]
#[expect(clippy::exhaustive_structs, reason = "..")]
pub struct VerificationMethod {
    pub id: String,
    // CAUTION The "controller" property must not be present w.r.t.:
    // - https://jira.bit.admin.ch/browse/EIDSYS-352
    // - https://confluence.bit.admin.ch/display/EIDTEAM/DID+Doc+Conformity+Check
    // It is kept for the sake of backward compatibility only.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub controller: String,
    #[serde(rename = "type")]
    pub verification_type: VerificationType,
    // CAUTION The "publicKeyMultibase" property must not be present w.r.t.:
    // - https://jira.bit.admin.ch/browse/EIDOMNI-35
    // - https://confluence.bit.admin.ch/display/EIDTEAM/DID+Doc+Conformity+Check
    // It is kept for the sake of backward compatibility only.
    #[deprecated(note = "Use not allowed by the swiss profile anchor specification")]
    #[serde(rename = "publicKeyMultibase", skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,
    #[serde(rename = "publicKeyJwk", skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<Jwk>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[expect(
    clippy::exhaustive_enums,
    reason = "further enum variants may be added in the future"
)]
pub enum VerificationType {
    Multikey,
    // https://w3c-ccg.github.io/lds-jws2020/#json-web-key-2020
    // https://www.w3.org/TR/did-extensions-properties/#jsonwebkey2020
    JsonWebKey2020,
    // https://www.w3.org/TR/vc-di-eddsa/#ed25519verificationkey2020
    Ed25519VerificationKey2020,
}

impl core::fmt::Display for VerificationType {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let string_representation = match *self {
            Self::Multikey => "Multikey",
            Self::JsonWebKey2020 => "JsonWebKey2020",
            Self::Ed25519VerificationKey2020 => "Ed25519VerificationKey2020",
        };
        write!(f, "{string_representation}")
    }
}

impl VerificationMethod {
    #[inline]
    #[deprecated]
    pub const fn new(
        id: String,
        controller: String,
        public_key_multibase: String,
        verification_type: VerificationType,
    ) -> Self {
        Self {
            id,
            controller,
            verification_type,
            public_key_multibase: Some(public_key_multibase),
            public_key_jwk: None,
        }
    }
}

#[expect(
    clippy::missing_trait_methods,
    reason = "not all trait methods required and implemented to prevent error[E0599]: the method `clone` exists for struct `Vec<did_doc::VerificationMethod>`, but its trait bounds were not satisfied"
)]
impl Clone for VerificationMethod {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            controller: self.controller.clone(),
            verification_type: self.verification_type.clone(),
            public_key_multibase: self.public_key_multibase.clone(),
            public_key_jwk: self.public_key_jwk.clone(),
        }
    }
}

// See      https://www.w3.org/TR/did-core/#dfn-did-documents
// Examples https://www.w3.org/TR/did-core/#did-documents
// According to https://www.w3.org/TR/did-core/#did-document-properties
#[derive(Serialize, Deserialize, Debug, Clone)]
#[expect(clippy::exhaustive_structs, reason = "..")]
pub struct DidDoc {
    #[deprecated]
    #[serde(rename = "@context", skip_serializing_if = "Vec::is_empty", default)]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub authentication: Vec<VerificationMethod>,
    #[serde(
        rename = "capabilityInvocation",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub capability_invocation: Vec<VerificationMethod>,
    #[serde(
        rename = "capabilityDelegation",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub capability_delegation: Vec<VerificationMethod>,
    #[serde(
        rename = "assertionMethod",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub assertion_method: Vec<VerificationMethod>,
    #[serde(
        rename = "keyAgreement",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub key_agreement: Vec<VerificationMethod>,
    // CAUTION The "controller" property must not be present w.r.t.:
    // - https://jira.bit.admin.ch/browse/EIDSYS-352
    // - https://confluence.bit.admin.ch/display/EIDTEAM/DID+Doc+Conformity+Check
    // It is kept for the sake of backward compatibility only.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub controller: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[deprecated(note = "not part of specification, should not be used")]
    pub deactivated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_version: Option<String>,
}

// See      https://www.w3.org/TR/did-core/#dfn-did-documents
// Examples https://www.w3.org/TR/did-core/#did-documents
// According to https://www.w3.org/TR/did-core/#did-document-properties
#[derive(Serialize, Deserialize, Debug, Clone)]
#[expect(clippy::exhaustive_structs, reason = "..")]
pub struct DidDocNormalized {
    #[deprecated]
    #[serde(rename = "@context", skip_serializing_if = "Vec::is_empty", default)]
    pub context: Vec<String>,
    pub id: String,
    #[serde(
        rename = "verificationMethod",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub verification_method: Vec<VerificationMethod>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub authentication: Vec<String>,
    #[serde(
        rename = "capabilityInvocation",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub capability_invocation: Vec<String>,
    #[serde(
        rename = "capabilityDelegation",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub capability_delegation: Vec<String>,
    #[serde(
        rename = "assertionMethod",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub assertion_method: Vec<String>,
    #[serde(
        rename = "keyAgreement",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub key_agreement: Vec<String>,
    //#[serde(skip_serializing_if = "Vec::is_empty", default)]
    //pub controller: Vec<String>,
    // CAUTION The "controller" property must not be present w.r.t.:
    // - https://jira.bit.admin.ch/browse/EIDSYS-352
    // - https://confluence.bit.admin.ch/display/EIDTEAM/DID+Doc+Conformity+Check
    // It is kept for the sake of backward compatibility only.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub controller: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub profile_version: Option<String>,
}

impl DidDocNormalized {
    #[inline]
    pub fn to_did_doc(&self) -> Result<DidDoc, DidSidekicksError> {
        let mut did_doc = DidDoc {
            context: self.context.to_owned(), // vec![],
            id: self.id.clone(),
            verification_method: self.verification_method.clone(),
            authentication: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
            assertion_method: vec![],
            key_agreement: vec![],
            controller: self.controller.to_owned(),
            deactivated: self.deactivated,
            profile_version: self.profile_version.to_owned(),
        };
        if !self.authentication.is_empty() {
            did_doc.authentication = vec![];
            self.authentication.iter().try_for_each(|id| -> Result<(), DidSidekicksError> {
                match self.verification_method.iter().find(|meth| meth.id == *id) {
                    Some(obj) => {
                        did_doc.authentication.push(obj.clone());
                        Ok(())
                    }
                    None => Err(DidSidekicksError::InvalidDidDocument(format!("Authentication (reference) key refers to non-existing verification method: {id}")))
                }
            })?;
        }
        if !self.capability_invocation.is_empty() {
            did_doc.capability_invocation = vec![];
            self.capability_invocation.iter().try_for_each(|id| -> Result<(), DidSidekicksError> {
                match self.verification_method.iter().find(|meth| meth.id == *id) {
                    Some(obj) => {
                        did_doc.capability_invocation.push(obj.clone());
                        Ok(())
                    }
                    None => Err(DidSidekicksError::InvalidDidDocument(format!("Capability invocation (reference) key refers to non-existing verification method: {id}")))
                }
            })?;
        }
        if !self.capability_delegation.is_empty() {
            did_doc.capability_delegation = vec![];
            self.capability_delegation.iter().try_for_each(|id| -> Result<(), DidSidekicksError> {
                match self.verification_method.iter().find(|meth| meth.id == *id) {
                    Some(obj) => {
                        did_doc.capability_delegation.push(obj.clone());
                        Ok(())
                    }
                    None => Err(DidSidekicksError::InvalidDidDocument(format!("Capability delegation (reference) key refers to non-existing verification method: {id}")))
                }
            })?;
        }
        if !self.assertion_method.is_empty() {
            did_doc.assertion_method = vec![];
            self.assertion_method.iter().try_for_each(|id| -> Result<(), DidSidekicksError> {
                match self.verification_method.iter().find(|meth| meth.id == *id)
                {
                    Some(obj) => {
                        did_doc.assertion_method.push(obj.clone());
                        Ok(())
                    }
                    None => Err(DidSidekicksError::InvalidDidDocument(format!("Assertion method (reference) key refers to non-existing verification method: {id}")))
                }
            })?;
        }
        if !self.key_agreement.is_empty() {
            did_doc.key_agreement = vec![];
            self.key_agreement.iter().try_for_each(|id| -> Result<(), DidSidekicksError> {
                match self.verification_method.iter().find(|meth| meth.id == *id) {
                    Some(obj) => {
                        did_doc.key_agreement.push(obj.clone());
                        Ok(())
                    }
                    None => Err(DidSidekicksError::InvalidDidDocument(format!("Key agreement (reference) key refers to non-existing verification method: {id}")))
                }
            })?;
        }
        Ok(did_doc)
    }

    /// The deserialization-based constructor. It attempts to deserialize an instance of type [`DidDocNormalized`] from a string of JSON text.
    ///
    /// # Errors
    ///
    /// The [`DidSidekicksError::DeserializationFailed`] error code denotes a deserialization failure:
    /// - if the structure of the input does not match the structure expected by [`DidDocNormalized`].
    #[inline]
    pub fn from_json(json_content: &str) -> Result<Self, DidSidekicksError> {
        serde_json::from_str(json_content)
            .map_err(|err| DidSidekicksError::DeserializationFailed(err.to_string()))
    }

    /// Serializes this [`DidDocNormalized`] object as a [`String`] of JSON.
    ///
    /// # Errors
    ///
    /// The [`DidSidekicksError::SerializationFailed`] error code denotes a serialization failure:
    /// - if [`DidDocNormalized`]'s implementation of [`Serialize`] decides to fail, or
    /// - if [`DidDocNormalized`] contains a map with non-string keys.
    #[inline]
    pub fn to_json(&self) -> Result<String, DidSidekicksError> {
        serde_json::to_string(&self)
            .map_err(|err| DidSidekicksError::SerializationFailed(err.to_string()))
    }
}

/// A simple container for both [`DidDoc`] and the related collection of [`DidMethodParameter`] objects.
#[derive(Debug, Clone)]
pub struct DidDocExtended {
    did_doc: DidDoc,
    did_method_parameters: HashMap<String, Arc<DidMethodParameter>>,
}

impl DidDoc {
    #[deprecated]
    #[inline]
    pub fn get_context(&self) -> Vec<String> {
        self.context.clone()
    }

    #[inline]
    pub fn get_id(&self) -> String {
        self.id.clone()
    }

    #[inline]
    pub fn get_verification_method(&self) -> Vec<VerificationMethod> {
        self.verification_method.clone()
    }

    #[inline]
    pub fn get_authentication(&self) -> Vec<VerificationMethod> {
        self.authentication.clone()
    }

    #[inline]
    pub fn get_capability_invocation(&self) -> Vec<VerificationMethod> {
        self.capability_invocation.clone()
    }

    #[inline]
    pub fn get_capability_delegation(&self) -> Vec<VerificationMethod> {
        self.capability_delegation.clone()
    }

    #[inline]
    pub fn get_assertion_method(&self) -> Vec<VerificationMethod> {
        self.assertion_method.clone()
    }

    #[inline]
    pub fn get_controller(&self) -> Option<String> {
        self.controller.to_owned()
    }

    #[inline]
    pub fn get_profile_version(&self) -> Option<String> {
        self.profile_version.to_owned()
    }

    #[inline]
    #[deprecated(note = "not part of specification, should not be used")]
    pub fn get_deactivated(&self) -> bool {
        self.deactivated.unwrap_or(false)
    }

    /// The deserialization-based constructor. It attempts to deserialize an instance of type `[`DidDoc`] from a string of JSON text.
    ///
    /// # Errors
    ///
    /// The [`DidSidekicksError::DeserializationFailed`] error code denotes a deserialization failure:
    /// - if the structure of the input does not match the structure expected by [`DidDoc`].
    #[inline]
    pub fn from_json(json_content: &str) -> Result<Self, DidSidekicksError> {
        serde_json::from_str(json_content)
            .map_err(|err| DidSidekicksError::DeserializationFailed(err.to_string()))
    }

    /// Serializes this [`DidDoc`] object as a [`String`] of JSON.
    ///
    /// A UniFFI-compliant method.
    ///
    /// # Errors
    ///
    /// The [`DidSidekicksError::SerializationFailed`] error code denotes a serialization failure:
    /// - if [`DidDoc`]'s implementation of [`Serialize`] decides to fail, or
    /// - if [`DidDoc`] contains a map with non-string keys.
    #[inline]
    pub fn to_json(&self) -> Result<String, DidSidekicksError> {
        // Normalization due to DID log JSON schema compliance
        serde_json::to_string(&DidDocNormalized {
            context: self.context.to_owned(),
            id: self.id.to_owned(),
            verification_method: self.verification_method.to_owned(),
            authentication: self
                .authentication
                .iter()
                .map(|x| x.id.to_owned())
                .collect(),
            capability_invocation: self
                .capability_invocation
                .iter()
                .map(|x| x.id.to_owned())
                .collect(),
            capability_delegation: self
                .capability_delegation
                .iter()
                .map(|x| x.id.to_owned())
                .collect(),
            assertion_method: self
                .assertion_method
                .iter()
                .map(|x| x.id.to_owned())
                .collect(),
            key_agreement: self.key_agreement.iter().map(|x| x.id.to_owned()).collect(),
            controller: self.controller.to_owned(),
            deactivated: self.deactivated.to_owned(),
            profile_version: self.profile_version.to_owned(),
        })
        .map_err(|err| DidSidekicksError::SerializationFailed(err.to_string()))
    }

    /// Returns a cryptographic public key ([`Jwk`]) referenced by the supplied fragment (`key_id`), if any.
    ///
    /// The key lookup is always done across all verification methods (`verificationMethod`) and
    /// verification relationships
    /// (`authentication`, `assertionMethod`, `keyAgreement`, `capabilityInvocation`, `capabilityInvocation`).
    ///
    /// If no such key exists, [`DidSidekicksError::KeyNotFound`] is returned.
    #[inline]
    #[deprecated(
        since = "2.6.0",
        note = "please use `get_key_by_fragment` instead for 1 to 1 compatibility, or `get_key_by_method_id` to retrieve the key based on the entire id e.g. did:webvh:scid:example.com#fragment"
    )]
    pub fn get_key(&self, key_id: String) -> Result<Jwk, DidSidekicksError> {
        self.get_key_by_fragment(key_id)
    }

    /// Returns a cryptographic public key ([`Jwk`]) referenced by the supplied fragment (`key_id`), if any.
    ///
    /// The key lookup is always done across all verification methods (`verificationMethod`) and
    /// verification relationships
    /// (`authentication`, `assertionMethod`, `keyAgreement`, `capabilityInvocation`, `capabilityInvocation`).
    ///
    /// If no such key exists, [`DidSidekicksError::KeyNotFound`] is returned.
    #[inline]
    pub fn get_key_by_fragment(&self, key_id: String) -> Result<Jwk, DidSidekicksError> {
        // A JWK referenced by the supplied key_id might be anywhere in this DID doc
        match self
            .verification_method
            .iter()
            .chain(self.authentication.iter())
            .chain(self.capability_invocation.iter())
            .chain(self.capability_delegation.iter())
            .chain(self.assertion_method.iter())
            .chain(self.key_agreement.iter())
            .find(|&key| key.id.ends_with(format!("#{}", key_id).as_str()))
        {
            Some(key) => match key.public_key_jwk.to_owned() {
                Some(jwk) => match jwk.kid.to_owned() {
                    Some(kid) => {
                        if kid.as_str() == key_id {
                            return Ok(jwk);
                        }
                        Err(DidSidekicksError::NonExistingKeyReferenced(kid))
                    }
                    None => Ok(jwk),
                },
                None => Err(DidSidekicksError::NonExistingKeyReferenced(key_id)),
            },
            None => Err(DidSidekicksError::KeyNotFound(key_id)),
        }
    }

    /// Returns a cryptographic public key ([`Jwk`]) referenced by the supplied id of the
    /// verification method, if any.
    ///
    /// The key lookup is always done across all verification methods (`verificationMethod`) and
    /// verification relationships
    /// (`authentication`, `assertionMethod`, `keyAgreement`, `capabilityInvocation`, `capabilityInvocation`).
    ///
    /// If no such key exists, [`DidSidekicksError::KeyNotFound`] is returned.
    #[inline]
    pub fn get_key_by_method_id(&self, kid: String) -> Result<Jwk, DidSidekicksError> {
        // A JWK referenced by the supplied key_id might be anywhere in this DID doc
        match self
            .verification_method
            .iter()
            .chain(self.authentication.iter())
            .chain(self.capability_invocation.iter())
            .chain(self.capability_delegation.iter())
            .chain(self.assertion_method.iter())
            .chain(self.key_agreement.iter())
            .find(|&key| key.id.eq(&kid))
        {
            Some(key) => key
                .public_key_jwk
                .to_owned()
                .ok_or(DidSidekicksError::NonExistingKeyReferenced(kid)),
            None => Err(DidSidekicksError::KeyNotFound(kid)),
        }
    }

    #[inline]
    pub fn validate(&self) -> Result<(), DidSidekicksError> {
        let id = self.get_id();

        // Only validate controller if a value is present
        if let Some(controller) = self.get_controller()
            && controller != id.as_str()
        {
            return Err(DidSidekicksError::InvalidDidDocument(
                "controller must be set to the id of the DID log".into(),
            ));
        }

        for vm in self.verification_method.iter() {
            // Only validate controller if a value is present
            if !vm.controller.is_empty() && vm.controller != id.as_str() {
                return Err(DidSidekicksError::InvalidDidDocument(format!(
                    "controller of the verificationMethod '{}' must be set to the id of the DID log",
                    &vm.id
                )));
            }
        }
        Ok(())
    }
}

/// The helper parses the supplied DID doc as string and returns a cryptographic public key ([`Jwk`]) referenced by the supplied `key_id`, if any.
///
/// Parsing failure is denoted by returning [`DidSidekicksError::DeserializationFailed`].
///
/// The key lookup is always done across all verification methods (`verificationMethod`) and
/// verification relationships
/// (`authentication`, `assertionMethod`, `keyAgreement`, `capabilityInvocation`, `capabilityInvocation`).
///
/// If no such key exists, [`DidSidekicksError::KeyNotFound`] is returned.
#[inline]
pub fn get_key_from_did_doc(did_doc: String, key_id: String) -> Result<Jwk, DidSidekicksError> {
    let doc = match serde_json::from_str::<DidDocNormalized>(did_doc.as_str()) {
        Ok(doc_norm) => match doc_norm.to_did_doc() {
            Ok(doc) => doc,
            Err(err) => return Err(DidSidekicksError::DeserializationFailed(err.to_string())),
        },
        Err(_) => match serde_json::from_str::<DidDoc>(did_doc.as_str()) {
            Ok(doc) => doc,
            Err(err) => return Err(DidSidekicksError::DeserializationFailed(err.to_string())),
        },
    };

    doc.get_key_by_method_id(key_id.clone())
        .map_or_else(|_| doc.get_key_by_fragment(key_id), Ok)
}

impl DidDocExtended {
    /// The only non-empty constructor of the type.
    #[inline]
    pub const fn new(
        did_doc: DidDoc,
        did_method_parameters: HashMap<String, Arc<DidMethodParameter>>,
    ) -> Self {
        Self {
            did_doc,
            did_method_parameters,
        }
    }

    #[inline]
    pub fn get_did_doc_obj(&self) -> DidDoc {
        self.did_doc.clone()
    }

    /// A UniFFI-compliant version of [`DidDocExtended::get_did_doc_obj`] getter.
    #[inline]
    pub fn get_did_doc(&self) -> Arc<DidDoc> {
        Arc::new(self.get_did_doc_obj())
    }

    /// A UniFFI-compliant getter.
    #[inline]
    pub fn get_did_method_parameters(&self) -> HashMap<String, Arc<DidMethodParameter>> {
        self.did_method_parameters.clone()
    }
}

#[cfg(test)]
mod test {
    #![allow(
        non_snake_case,
        reason = "consistent naming for test in form type_function_description_expectedResult"
    )]
    use super::*;
    use rstest::rstest;
    use serde_json::{Value as JsonValue, json};
    use std::assert_matches;

    /// A did doc as json used for tests to easier instantiate one.
    static DIDDOC_JSON: &str = r#"{
      "id": "did:webvh:{SCID}:domain.example",
      "controller": "did:webvh:{SCID}:domain.example",
      "profile_version": "swiss-profile-anchor:1.0.0",
      "authentication": [
        "did:webvh:{SCID}:domain.example#auth-key-01"
      ],
      "assertionMethod": [
        "did:webvh:{SCID}:domain.example#assert-key-01"
      ],
      "verificationMethod": [
        {
          "id": "did:webvh:{SCID}:domain.example#auth-key-01",
          "controller": "did:webvh:{SCID}:domain.example",
          "type": "JsonWebKey2020",
          "publicKeyJwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": "cMuIogOIny4VcE92-KK4Y9AuwSmCX3Ot8MY80aRz__4",
            "y": "ln1g0wrq0IKT3D_GjnBmZhA_tbqlG5p7-7OCk-xMC1g",
            "kid": "auth-key-01"
          }
        },
        {
          "id": "did:webvh:{SCID}:domain.example#assert-key-01",
          "controller": "did:webvh:{SCID}:domain.example",
          "type": "JsonWebKey2020",
          "publicKeyJwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": "IXXoOILwuY2Z-e3md2vazPghS3cGJEJt8DY7Xcc28NY",
            "y": "vyyaOaGu6ck1uEYjFChLu-cHCoxJ71L8UCQn3mM8xn4",
            "kid": "assert-key-01"
          }
        }
      ]
    }"#;

    #[rstest]
    #[case(
        json!({
            "@context": [ "https://www.w3.org/ns/did/v1", "https://w3id.org/security/jwk/v1" ],
            "id": "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
            "authentication": [ "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01" ],
            "assertionMethod": [ "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-02" ],
            "verificationMethod": [{
                    "id": "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01",
                    "controller": "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
                    "type": "JsonWebKey2020",
                    "publicKeyJwk": {
                        "kty": "EC",
                        "crv": "P-256",
                        "kid": "auth-key-01",
                        "x": "3-xR-ApvKYCKtXxjvypxIb4tHJSUTHCl0uUYVAvP6sE",
                        "y": "jkQdXwStFmrJjHuWw8PE_AG43c4OQwd6-Rkr4sPiC7Y"
                    }
                },{
                    "id": "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-02",
                    "controller": "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
                    "type": "JsonWebKey2020",
                    "publicKeyJwk": {
                        "kty": "EC",
                        "crv": "P-256",
                        "kid": "assert-key-02",
                        "x": "Ja4P63oUfaUageuu9O_6kOHT6bLe5D4myacZpEICwC8",
                        "y": "A4JwAyrpKxtsNLX50A0pQ_4G2AYO-NJw0dzne11xUj0"
                    }
            }]
        }),
    )]
    fn test_did_doc_json_conversion(#[case] did_doc_norm_json: JsonValue) {
        use serde_json::json;

        let did_doc = DidDocNormalized::from_json(&did_doc_norm_json.to_string())
            .unwrap()
            .to_did_doc()
            .unwrap();
        let did_doc_json_str = did_doc.to_json().unwrap(); // MUT
        assert!(!did_doc_json_str.is_empty());

        // should also match the input value (after canonicalization)
        assert_eq!(
            serde_json_canonicalizer::to_string(&did_doc_norm_json).unwrap(),
            serde_json_canonicalizer::to_string(&json!({
                "@context": did_doc.context,
                "id": did_doc.id,
                "authentication": did_doc.authentication.iter()
                    .map(|x| x.id.to_owned())
                    .collect::<Vec<String>>(),
                "assertionMethod": did_doc.assertion_method.iter()
                    .map(|x| x.id.to_owned())
                    .collect::<Vec<String>>(),
                "verificationMethod": did_doc.verification_method
            }))
            .unwrap()
        );
    }

    #[rstest]
    fn DidDoc_getters_validDocument() {
        let doc = get_did_doc();
        assert_eq!("did:webvh:{SCID}:domain.example", doc.get_id().as_str());
        assert_eq!(
            Some("did:webvh:{SCID}:domain.example".to_string()),
            doc.get_controller()
        );
        assert_eq!(2, doc.get_verification_method().len(), "expected left");
        assert_eq!(1, doc.get_authentication().len(), "expected left");
        assert_eq!(1, doc.get_assertion_method().len(), "expected left");
        assert_eq!(0, doc.get_capability_invocation().len(), "expected left");
        assert_eq!(0, doc.get_capability_delegation().len(), "expected left");
        assert_eq!(
            Some("swiss-profile-anchor:1.0.0".to_string()),
            doc.get_profile_version(),
            "expected left"
        );

        assert_matches!(
            doc.get_key_by_method_id("did:webvh:{SCID}:domain.example#assert-key-01".into()),
            Ok(_),
        );

        assert_eq!(
            doc.get_key_by_method_id("did:webvh:{SCID}:domain.example#assert-key-01".into())
                .unwrap()
                .kid,
            doc.get_key_by_fragment("assert-key-01".into()).unwrap().kid
        );
    }

    #[test]
    fn DidDoc_validate_validWithController_returnsOk() {
        // No controller is valid
        let doc = DidDoc {
            context: Vec::new(),
            id: "did:webvh:{SCID}:example.domain".into(),
            verification_method: vec![],
            authentication: Vec::new(),
            capability_invocation: Vec::new(),
            capability_delegation: Vec::new(),
            assertion_method: Vec::new(),
            key_agreement: Vec::new(),
            controller: Some("did:webvh:{SCID}:example.domain".into()),
            deactivated: None,
            profile_version: None,
        };
        if let Err(err) = doc.validate() {
            panic!(
                "DID should be valid with no controller, but got error: {}",
                err
            );
        }
    }

    #[test]
    fn DidDoc_validate_validWithoutController_returnsOk() {
        // No controller is valid
        let doc = DidDoc {
            context: Vec::new(),
            id: "did:webvh:{SCID}:example.domain".into(),
            verification_method: vec![],
            authentication: Vec::new(),
            capability_invocation: Vec::new(),
            capability_delegation: Vec::new(),
            assertion_method: Vec::new(),
            key_agreement: Vec::new(),
            controller: None,
            deactivated: None,
            profile_version: None,
        };
        if let Err(err) = doc.validate() {
            panic!(
                "DID should be valid with no controller, but got error: {}",
                err
            );
        }
    }

    #[test]
    fn DidDoc_validate_wrongController_returnsErr() {
        // Controller pointing to other did
        let doc = DidDoc {
            context: Vec::new(),
            id: "did:webvh:{SCID}:example.domain".into(),
            verification_method: vec![],
            authentication: Vec::new(),
            capability_invocation: Vec::new(),
            capability_delegation: Vec::new(),
            assertion_method: Vec::new(),
            key_agreement: Vec::new(),
            controller: Some("did:webvh:{SCID}:other.domain".into()),
            deactivated: None,
            profile_version: None,
        };
        if let Err(err) = doc.validate() {
            assert!(
                err.to_string()
                    .contains("controller must be set to the id of the DID log"),
                "Received unexpected error message: {}",
                err.to_string()
            );
        }

        // No controller is valid
        let doc = DidDoc {
            context: Vec::new(),
            id: "did:webvh:{SCID}:example.domain#assert-key".into(),
            verification_method: vec![],
            authentication: Vec::new(),
            capability_invocation: Vec::new(),
            capability_delegation: Vec::new(),
            assertion_method: Vec::new(),
            key_agreement: Vec::new(),
            controller: None,
            deactivated: None,
            profile_version: None,
        };
        if let Err(err) = doc.validate() {
            panic!(
                "DID should be valid with no controller, but got error: {}",
                err
            );
        }
    }

    #[test]
    fn DidDoc_validate_verificationMethodWrongController_returnsErr() {
        let doc = DidDoc {
            context: Vec::new(),
            id: "did:webvh:{SCID}:example.domain".into(),
            verification_method: vec![VerificationMethod {
                id: "did:webvh:{SCID}:example.domain#assert-key#assert-key".into(),
                controller: "did:webvh:{SCID}:example.domain".into(),
                verification_type: VerificationType::JsonWebKey2020,
                public_key_multibase: None,
                public_key_jwk: Some(jwk("did:webvh:{SCID}:example.domain#assert-key")),
            }],
            authentication: Vec::new(),
            capability_invocation: Vec::new(),
            capability_delegation: Vec::new(),
            assertion_method: Vec::new(),
            key_agreement: Vec::new(),
            controller: None,
            deactivated: None,
            profile_version: None,
        };
        if let Err(err) = doc.validate() {
            panic!("Expected document to be valid, but got an error: {}", err);
        }
    }

    // Helper functions
    fn jwk(kid: &str) -> Jwk {
        Jwk {
            alg: None,
            kid: Some(kid.into()),
            kty: Some("EC".into()),
            crv: Some("P-256".into()),
            x: Some("Ja4P63oUfaUageuu9O_6kOHT6bLe5D4myacZpEICwC8".into()),
            y: Some("A4JwAyrpKxtsNLX50A0pQ_4G2AYO-NJw0dzne11xUj0".into()),
            key_use: None,
            key_ops: None,
        }
    }

    fn get_did_doc() -> DidDoc {
        let doc = serde_json::from_str::<DidDocNormalized>(DIDDOC_JSON).unwrap();
        doc.to_did_doc().unwrap()
    }
}
