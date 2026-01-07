// SPDX-License-Identifier: MIT

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
    /// The supplied DID document is invalid or contains an argument which isn't part of the DID specification/recommendation
    #[error("the supplied DID document is invalid or contains an argument which isn't part of the DID specification/recommendation: {0}"
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
    /// Failed to calculate SHA2-256 hash of canonical JSON UTF-8 string
    #[error("failed to calculate SHA2-256 hash of canonical JSON UTF-8 string: {0}")]
    JscHashingFailed(String),
    /// No such JWK in the DID document
    #[error("no such JWK in the DID document: {0}")]
    KeyNotFound(String),
    /// Failed to save key
    #[error("failed to save key: {0}")]
    KeySerializationFailed(String),
    /// Failed to load key
    #[error("failed to load key: {0}")]
    KeyDeserializationFailed(String),
    /// Failure of a signature to satisfy the verification equation
    #[error("failure of a signature to satisfy the verification equation: {0}")]
    KeySignatureError(String),
    /// Failed to convert key from multibase format
    #[error("failed to convert key from multibase format: {0}")]
    MultibaseKeyConversionFailed(String),
    /// Non-existing key referenced in the DID document
    #[error("non-existing key referenced in the DID document: {0}")]
    NonExistingKeyReferenced(String),
    /// A request to generate a proof failed, as specified by https://www.w3.org/TR/vc-data-integrity/#processing-errors
    #[error("a request to generate a proof failed: {0}")]
    VCDataIntegrityProofGenerationError(String),
    /// An error was encountered during proof verification, as specified by https://www.w3.org/TR/vc-data-integrity/#processing-errors
    #[error("an error was encountered during proof verification: {0}")]
    VCDataIntegrityProofVerificationError(String),
    /// An error was encountered during the transformation process, as specified by https://www.w3.org/TR/vc-data-integrity/#processing-errors
    #[error("an error was encountered during the transformation process: {0}")]
    VCDataIntegrityProofTransformationError(String),
    /*
    /// The domain value in a proof did not match the expected value, as specified by https://www.w3.org/TR/vc-data-integrity/#processing-errors
    #[error("the domain value in a proof did not match the expected value: {0}")]
    VCDataIntegrityInvalidDomainError(String),
    /// The challenge value in a proof did not match the expected value, as specified by https://www.w3.org/TR/vc-data-integrity/#processing-errors
    #[error("the challenge value in a proof did not match the expected value: {0}")]
    VCDataIntegrityInvalidChallengeError(String),
     */
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
            Self::JscHashingFailed(_) => DidSidekicksErrorKind::JscHashingFailed,
            Self::KeyNotFound(_) => DidSidekicksErrorKind::KeyNotFound,
            Self::KeySerializationFailed(_) => DidSidekicksErrorKind::KeySerializationFailed,
            Self::KeySignatureError(_) => DidSidekicksErrorKind::KeySignatureError,
            Self::KeyDeserializationFailed(_) => DidSidekicksErrorKind::KeyDeserializationFailed,
            Self::MultibaseKeyConversionFailed(_) => {
                DidSidekicksErrorKind::MultibaseKeyConversionFailed
            }
            Self::NonExistingKeyReferenced(_) => DidSidekicksErrorKind::NonExistingKeyReferenced,
            Self::VCDataIntegrityProofGenerationError(_) => {
                DidSidekicksErrorKind::VCDataIntegrityProofGenerationError
            }
            Self::VCDataIntegrityProofVerificationError(_) => {
                DidSidekicksErrorKind::VCDataIntegrityProofVerificationError
            }
            Self::VCDataIntegrityProofTransformationError(_) => {
                DidSidekicksErrorKind::VCDataIntegrityProofTransformationError
            }
            /*
            Self::VCDataIntegrityInvalidDomainError(_) => DidSidekicksErrorKind::VCDataIntegrityInvalidDomainError,
            Self::VCDataIntegrityInvalidChallengeError(_) => DidSidekicksErrorKind::VCDataIntegrityInvalidChallengeError,
             */
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
    JscHashingFailed,
    KeyNotFound,
    KeySerializationFailed,
    KeySignatureError,
    KeyDeserializationFailed,
    MultibaseKeyConversionFailed,
    NonExistingKeyReferenced,
    VCDataIntegrityProofGenerationError,
    VCDataIntegrityProofVerificationError,
    VCDataIntegrityProofTransformationError,
    /*
    VCDataIntegrityInvalidDomainError,
    VCDataIntegrityInvalidChallengeError,
     */
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
