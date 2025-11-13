// SPDX-License-Identifier: MIT

//use std::cmp::PartialEq;

/// Yet another UniFFI-compliant error.
///
/// Resembles ssi::dids::resolution::Error
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[expect(clippy::exhaustive_enums, reason = "..")]
pub enum WebVerifiableHistoryIdResolutionError {
    /// Invalid method-specific identifier.
    #[error("invalid method specific identifier: {0}")]
    InvalidMethodSpecificId(String),
    /// DID method is not supported by this resolver.
    #[error("DID method `{0}` not supported")]
    MethodNotSupported(String),
}

impl WebVerifiableHistoryIdResolutionError {
    /// Returns the error kind.
    #[inline]
    pub const fn kind(&self) -> WebVerifiableHistoryIdResolutionErrorKind {
        match *self {
            Self::MethodNotSupported(_) => {
                WebVerifiableHistoryIdResolutionErrorKind::MethodNotSupported
            }
            Self::InvalidMethodSpecificId(_) => {
                WebVerifiableHistoryIdResolutionErrorKind::InvalidMethodSpecificId
            }
        }
    }
}

/// [`WebVerfiableHistoryIdResolutionError`]'s kind.
///
/// Each [`WebVerifiableHistoryIdResolutionError`] has a kind provided by the [`WebVerifiableHistoryIdResolutionErrorKind::kind`] method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[expect(clippy::exhaustive_enums, reason = "..")]
pub enum WebVerifiableHistoryIdResolutionErrorKind {
    InvalidMethodSpecificId,
    MethodNotSupported,
}
