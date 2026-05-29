// SPDX-License-Identifier: MIT

//use std::cmp::PartialEq;

use did_sidekicks::errors::DidResolverError;

/// Yet another UniFFI-compliant error.
///
/// Resembles ssi::dids::resolution::Error.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[expect(clippy::exhaustive_enums, reason = "..")]
pub enum TrustDidWebIdResolutionError {
    /// DID method is not supported by this resolver.
    #[error("DID method `{0:.256}` not supported")]
    MethodNotSupported(String),
    /// Invalid method-specific identifier.
    #[error("invalid method specific identifier: {0:.256}")]
    InvalidMethodSpecificId(String),
}

impl TrustDidWebIdResolutionError {
    /// Returns the error kind.
    #[inline]
    pub const fn kind(&self) -> TrustDidWebIdResolutionErrorKind {
        match *self {
            Self::MethodNotSupported(_) => TrustDidWebIdResolutionErrorKind::MethodNotSupported,
            Self::InvalidMethodSpecificId(_) => {
                TrustDidWebIdResolutionErrorKind::InvalidMethodSpecificId
            }
        }
    }
}

/// TrustDidWebIdResolutionError kind.
///
/// Each [`TrustDidWebIdResolutionError`] has a kind provided by the [`TrustDidWebIdResolutionErrorKind::kind`] method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[expect(clippy::exhaustive_enums, reason = "..")]
pub enum TrustDidWebIdResolutionErrorKind {
    MethodNotSupported,
    InvalidMethodSpecificId,
}

/// Yet another UniFFI-compliant error.
///
/// Resembles ssi::dids::resolution::Error.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[expect(clippy::exhaustive_enums, reason = "..")]
pub enum TrustDidWebError {
    /// DID method is not supported by this resolver.
    #[error("DID method `{0}` not supported")]
    #[deprecated(note = "as redundant")]
    MethodNotSupported(String),
    /// Invalid method-specific identifier.
    #[error("invalid method specific identifier: {0}")]
    InvalidMethodSpecificId(String),
    /// Failed to serialize DID document (to JSON).
    #[error("failed to serialize DID document (to JSON): {0}")]
    SerializationFailed(String),
    /// The supplied did doc is invalid or contains an argument which isn't part of the did specification/recommendation.
    #[error(
        "The supplied did doc is invalid or contains an argument which isn't part of the did specification/recommendation: {0}"
    )]
    DeserializationFailed(String),
    /// Invalid (or not yet supported) operation against DID doc.
    #[deprecated(note = "as redundant")]
    #[error("invalid (or not yet supported) operation against DID doc: {0}")]
    InvalidOperation(String),
    /// Invalid DID parameter.
    #[error("invalid DID parameter: {0}")]
    InvalidDidParameter(String),
    /// Invalid DID document.
    #[error("invalid DID document: {0}")]
    InvalidDidDocument(String),
    /// Invalid DID log integration proof.
    #[error("invalid DID log integration proof: {0}")]
    InvalidDataIntegrityProof(String),
}

impl TrustDidWebError {
    /// Returns the error kind.
    #[inline]
    pub const fn kind(&self) -> TrustDidWebErrorKind {
        match *self {
            Self::MethodNotSupported(_) => TrustDidWebErrorKind::MethodNotSupported,
            Self::InvalidMethodSpecificId(_) => TrustDidWebErrorKind::InvalidMethodSpecificId,
            Self::SerializationFailed(_) => TrustDidWebErrorKind::SerializationFailed,
            Self::DeserializationFailed(_) => TrustDidWebErrorKind::DeserializationFailed,
            Self::InvalidOperation(_) => TrustDidWebErrorKind::InvalidOperation,
            Self::InvalidDidParameter(_) => TrustDidWebErrorKind::InvalidDidParameter,
            Self::InvalidDidDocument(_) => TrustDidWebErrorKind::InvalidDidDocument,
            Self::InvalidDataIntegrityProof(_) => TrustDidWebErrorKind::InvalidIntegrityProof,
        }
    }
}

impl From<DidResolverError> for TrustDidWebError {
    #[inline]
    fn from(value: DidResolverError) -> Self {
        match value {
            DidResolverError::InvalidMethodSpecificId(invalid_method_id) => {
                Self::InvalidMethodSpecificId(invalid_method_id)
            }
            DidResolverError::SerializationFailed(serialization_error) => {
                Self::SerializationFailed(serialization_error)
            }
            DidResolverError::DeserializationFailed(deserialization_error) => {
                Self::DeserializationFailed(deserialization_error)
            }
            DidResolverError::InvalidDidParameter(invalid_parameter) => {
                Self::InvalidDidParameter(invalid_parameter)
            }
            DidResolverError::InvalidDidLog(document_error)
            | DidResolverError::InvalidDidDocument(document_error) => {
                Self::InvalidDidDocument(document_error)
            }
            DidResolverError::InvalidDataIntegrityProof(error) => {
                Self::InvalidDataIntegrityProof(error)
            }
        }
    }
}

/// TrustDidWebError kind.
///
/// Each [`TrustDidWebError`] has a kind provided by the [`TrustDidWebErrorKind::kind`] method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[expect(clippy::exhaustive_enums, reason = "..")]
pub enum TrustDidWebErrorKind {
    #[deprecated(note = "as redundant")]
    MethodNotSupported,
    InvalidMethodSpecificId,
    SerializationFailed,
    DeserializationFailed,
    #[deprecated(note = "as redundant")]
    InvalidOperation,
    InvalidDidParameter,
    InvalidDidDocument,
    InvalidIntegrityProof,
}
