// SPDX-License-Identifier: MIT

use crate::did_method_parameters::DidMethodParameter;
use crate::errors::DidSidekicksError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// An entry in DID log file as shown here
/// https://bcgov.github.io/trustdidweb/#term:did-log-entry

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
    JsonWebKey2020,
    // https://www.w3.org/TR/vc-di-eddsa/#ed25519verificationkey2020
    Ed25519VerificationKey2020,
}

impl core::fmt::Display for VerificationType {
    #[inline]
    /*#[expect(
        clippy::min_ident_chars,
        reason = "default name of function parameter of trait impl. used to prevent clippy::renamed_function_params warning"
    )]*/
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let string_representation = match *self {
            Self::Multikey => String::from("Multikey"),
            Self::JsonWebKey2020 => String::from("JsonWebKey2020"),
            Self::Ed25519VerificationKey2020 => String::from("Ed25519VerificationKey2020"),
        };
        write!(f, "{string_representation}")
    }
}

impl VerificationMethod {
    #[inline]
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
    #[serde(rename = "@context")]
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
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub controller: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated: Option<bool>,
}

// See      https://www.w3.org/TR/did-core/#dfn-did-documents
// Examples https://www.w3.org/TR/did-core/#did-documents
// According to https://www.w3.org/TR/did-core/#did-document-properties
#[derive(Serialize, Deserialize, Debug, Clone)]
#[expect(clippy::exhaustive_structs, reason = "..")]
pub struct DidDocNormalized {
    #[serde(rename = "@context")]
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
}

impl DidDocNormalized {
    #[inline]
    pub fn to_did_doc(&self) -> Result<DidDoc, DidSidekicksError> {
        let controller = self
            .controller
            .clone()
            .map_or_else(Vec::new, |ctrl| vec![ctrl]);

        let mut did_doc = DidDoc {
            context: self.context.clone(), // vec![],
            id: self.id.clone(),
            verification_method: self.verification_method.clone(),
            authentication: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
            assertion_method: vec![],
            key_agreement: vec![],
            //controller: self.controller.clone(),
            controller,
            deactivated: self.deactivated,
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
}

/// A simple container for both [`DidDoc`] and the related collection of [`DidMethodParameter`] objects.
#[derive(Debug, Clone)]
pub struct DidDocExtended {
    did_doc: DidDoc,
    did_method_parameters: HashMap<String, Arc<DidMethodParameter>>,
}

impl DidDoc {
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
    pub fn get_controller(&self) -> Vec<String> {
        self.controller.clone()
    }

    #[inline]
    pub fn get_deactivated(&self) -> bool {
        self.deactivated.unwrap_or(false)
    }

    /// The deserialization-based constructor. It attempts to deserialize an instance of type `[`DidDoc`] from a string of JSON text.
    ///
    /// # Errors
    ///
    /// The conversion can fail if the structure of the input does not match the structure expected by [`DidDoc`].
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
    /// Serialization can fail if [`DidDoc`]'s implementation of [`Serialize`] decides to fail,
    /// or if [`DidDoc`] contains a map with non-string keys.
    #[inline]
    pub fn to_json(&self) -> Result<String, DidSidekicksError> {
        serde_json::to_string(&self)
            .map_err(|err| DidSidekicksError::SerializationFailed(err.to_string()))
    }

    /// Returns a cryptographic public key ([`Jwk`]) referenced by the supplied `key_id`, if any.
    ///
    /// The key lookup is always done across all verification methods (`verificationMethod`) and
    /// verification relationships
    /// (`authentication`, `assertionMethod`, `keyAgreement`, `capabilityInvocation`, `capabilityInvocation`).
    ///
    /// If no such key exists, [`DidSidekicksError::KeyNotFound`] is returned.
    #[inline]
    pub fn get_key(&self, key_id: String) -> Result<Jwk, DidSidekicksError> {
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

    doc.get_key(key_id)
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
