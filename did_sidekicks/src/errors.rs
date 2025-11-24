// SPDX-License-Identifier: MIT

//use std::cmp::PartialEq;

/// Yet another UniFFI-compliant error.
///
/// Resembles ssi::dids::resolution::Error
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[expect(
    clippy::exhaustive_enums,
    reason = "further enum variants may be added in the future"
)]
pub enum DidSidekicksError {
    /// Failed to serialize DID document (to JSON)
    #[error("failed to serialize DID document (to JSON): {0}")]
    SerializationFailed(String),
    /// The supplied DID document is invalid or contains an argument which isn't part of the did specification/recommendation
    #[error("the supplied DID document is invalid or contains an argument which isn't part of the did specification/recommendation: {0}"
    )]
    DeserializationFailed(String),
    /// Invalid DID document
    #[error("invalid DID document: {0}")]
    InvalidDidDocument(String),
    /// Invalid DID log integration proof
    #[error("invalid DID log integration proof: {0}")]
    InvalidDataIntegrityProof(String),
    /// Invalid DID method parameter
    #[error("invalid DID method parameter: {0}")]
    InvalidDidMethodParameter(String),
    /// No such JWK in the DID document
    #[error("no such JWK in the DID document: {0}")]
    KeyNotFound(String),
    /// Non-existing key referenced in the DID document
    #[error("non-existing key referenced in the DID document: {0}")]
    NonExistingKeyReferenced(String),
}

impl DidSidekicksError {
    /// Returns the error kind.
    #[inline]
    pub const fn kind(&self) -> DidSidekicksErrorKind {
        match *self {
            Self::SerializationFailed(_) => DidSidekicksErrorKind::SerializationFailed,
            Self::DeserializationFailed(_) => DidSidekicksErrorKind::DeserializationFailed,
            Self::InvalidDidDocument(_) => DidSidekicksErrorKind::InvalidDidDocument,
            Self::InvalidDataIntegrityProof(_) => DidSidekicksErrorKind::InvalidIntegrityProof,
            Self::InvalidDidMethodParameter(_) => DidSidekicksErrorKind::InvalidDidMethodParameter,
            Self::KeyNotFound(_) => DidSidekicksErrorKind::KeyNotFound,
            Self::NonExistingKeyReferenced(_) => DidSidekicksErrorKind::NonExistingKeyReferenced,
        }
    }
}

/// TrustDidWebError kind.
///
/// Each [`DidSidekicksError`] has a kind provided by the [`DidSidekicksErrorKind::kind`] method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[expect(
    clippy::exhaustive_enums,
    reason = "further enum variants may be added in the future"
)]
pub enum DidSidekicksErrorKind {
    SerializationFailed,
    DeserializationFailed,
    InvalidDidDocument,
    InvalidIntegrityProof,
    InvalidDidMethodParameter,
    KeyNotFound,
    NonExistingKeyReferenced,
}

/// The error accompanying [`DidResolver`] trait.
///
/// Yet another UniFFI-compliant error.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[expect(
    clippy::exhaustive_enums,
    reason = "further enum variants may be added in the future"
)]
pub enum DidResolverError {
    /// Invalid method-specific identifier
    #[error("invalid method specific identifier: {0}")]
    InvalidMethodSpecificId(String),
    /// Failed to serialize DID document (to JSON)
    #[error("failed to serialize DID document (to JSON): {0}")]
    SerializationFailed(String),
    /// The supplied DID document is invalid or contains an argument which isn't part of the did specification/recommendation
    #[error("the supplied DID document is invalid or contains an argument which isn't part of the did specification/recommendation: {0}"
    )]
    DeserializationFailed(String),
    /// Invalid DID parameter
    #[error("invalid DID parameter: {0}")]
    InvalidDidParameter(String),
    /// Invalid DID document
    #[error("invalid DID document: {0}")]
    InvalidDidDocument(String),
    /// Invalid DID log integration proof
    #[error("invalid DID log integration proof: {0}")]
    InvalidDataIntegrityProof(String),
}

impl DidResolverError {
    /// Returns the error kind.
    #[inline]
    pub const fn kind(&self) -> DidResolverErrorKind {
        match *self {
            Self::InvalidMethodSpecificId(_) => DidResolverErrorKind::InvalidMethodSpecificId,
            Self::SerializationFailed(_) => DidResolverErrorKind::SerializationFailed,
            Self::DeserializationFailed(_) => DidResolverErrorKind::DeserializationFailed,
            Self::InvalidDidParameter(_) => DidResolverErrorKind::InvalidDidParameter,
            Self::InvalidDidDocument(_) => DidResolverErrorKind::InvalidDidDocument,
            Self::InvalidDataIntegrityProof(_) => DidResolverErrorKind::InvalidIntegrityProof,
        }
    }
}

/// WebVerfiableHistoryError kind.
///
/// Each [`DidResolverError`] has a kind provided by the [`DidResolverErrorErrorKind::kind`] method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[expect(
    clippy::exhaustive_enums,
    reason = "further enum variants may be added in the future"
)]
pub enum DidResolverErrorKind {
    InvalidMethodSpecificId,
    SerializationFailed,
    DeserializationFailed,
    InvalidDidParameter,
    InvalidDidDocument,
    InvalidIntegrityProof,
}
