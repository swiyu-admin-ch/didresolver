// SPDX-License-Identifier: MIT

use std::sync::Arc;

use crate::errors::DidSidekicksError;
use crate::multibase::MultibaseEncoderDecoder;
use ed25519_dalek::{
    Signature, Signer as _, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH,
    SIGNATURE_LENGTH,
};
use rand::rngs::OsRng;

pub trait MultiBaseConverter {
    fn to_multibase(&self) -> String;
    fn from_multibase(multibase: &str) -> Result<Self, DidSidekicksError>
    where
        Self: Sized;
}

#[derive(Clone)]
#[expect(clippy::exhaustive_structs, reason = "..")]
pub struct Ed25519Signature {
    pub signature: Signature,
}
impl MultiBaseConverter for Ed25519Signature {
    #[inline]
    fn to_multibase(&self) -> String {
        let signature_bytes = self.signature.to_bytes();
        MultibaseEncoderDecoder::default().encode_base58btc(&signature_bytes)
    }

    #[inline]
    fn from_multibase(multibase: &str) -> Result<Self, DidSidekicksError> {
        let mut signature_bytes: [u8; SIGNATURE_LENGTH] = [0; SIGNATURE_LENGTH];
        match MultibaseEncoderDecoder::default().decode_base58_onto(multibase, &mut signature_bytes)
        {
            Err(err) => Err(DidSidekicksError::DeserializationFailed(format!("{err}"))),
            Ok(_) => Ok(Self {
                signature: Signature::from_bytes(&signature_bytes),
            }),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Ed25519SigningKey {
    signing_key: SigningKey,
}

/// As specified by https://www.w3.org/TR/controller-document/#Multikey
impl MultiBaseConverter for Ed25519SigningKey {
    /// As specified by https://www.w3.org/TR/controller-document/#Multikey:
    ///
    /// The encoding of an Ed25519 secret key MUST start with the two-byte prefix 0x8026 (the varint expression of 0x1300),
    /// followed by the 32-byte secret key data. The resulting 34-byte value MUST then be encoded using the base-58-btc alphabet,
    /// according to Section 2.4 Multibase (https://www.w3.org/TR/controller-document/#multibase-0),
    /// and then prepended with the base-58-btc Multibase header (z).
    #[inline]
    fn to_multibase(&self) -> String {
        let signing_key_bytes = self.signing_key.to_bytes();
        let mut signing_key_with_prefix: [u8; PUBLIC_KEY_LENGTH + 2] = [0; PUBLIC_KEY_LENGTH + 2];
        signing_key_with_prefix[0] = 0x13;
        signing_key_with_prefix[1] = 0x00;
        signing_key_with_prefix[2..].copy_from_slice(&signing_key_bytes);
        MultibaseEncoderDecoder::default().encode_base58btc(&signing_key_with_prefix)
    }

    /// As specified by https://www.w3.org/TR/controller-document/#Multikey:
    ///
    /// The encoding of an Ed25519 secret key MUST start with the two-byte prefix 0x8026 (the varint expression of 0x1300),
    /// followed by the 32-byte secret key data. The resulting 34-byte value MUST then be encoded using the base-58-btc alphabet,
    /// according to Section 2.4 Multibase (https://www.w3.org/TR/controller-document/#multibase-0),
    /// and then prepended with the base-58-btc Multibase header (z).
    #[inline]
    fn from_multibase(multibase: &str) -> Result<Self, DidSidekicksError> {
        let mut signing_key_buff: [u8; SECRET_KEY_LENGTH + 2] = [0; SECRET_KEY_LENGTH + 2];
        if let Err(err) =
            MultibaseEncoderDecoder::default().decode_base58_onto(multibase, &mut signing_key_buff)
        {
            return Err(DidSidekicksError::DeserializationFailed(format!("{err}")));
        }

        let mut signing_key: [u8; SECRET_KEY_LENGTH] = [0; SECRET_KEY_LENGTH];
        signing_key.copy_from_slice(&signing_key_buff[2..]); // get rid of the multibase header

        Ok(Self {
            signing_key: SigningKey::from_bytes(&signing_key),
        })
    }
}
impl Ed25519SigningKey {
    #[inline]
    pub const fn new(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    #[inline]
    pub fn sign(&self, message: String) -> Arc<Ed25519Signature> {
        let signature = self.signing_key.sign(message.as_bytes());
        Ed25519Signature { signature }.into()
    }
    #[inline]
    pub fn sign_bytes(&self, message: &[u8]) -> Ed25519Signature {
        // uniffi-irrelevant
        let signature = self.signing_key.sign(message);
        Ed25519Signature { signature }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[expect(clippy::exhaustive_structs, reason = "..")]
pub struct Ed25519VerifyingKey {
    pub verifying_key: VerifyingKey,
}

/// As specified by https://www.w3.org/TR/controller-document/#Multikey
impl MultiBaseConverter for Ed25519VerifyingKey {
    /// As specified by https://www.w3.org/TR/controller-document/#Multikey:
    ///
    /// The encoding of an Ed25519 public key MUST start with the two-byte prefix 0xed01 (the varint expression of 0xed),
    /// followed by the 32-byte public key data.
    /// The resulting 34-byte value MUST then be encoded using the base-58-btc alphabet,
    /// according to Section 2.4 Multibase (https://www.w3.org/TR/controller-document/#multibase-0),
    /// and then prepended with the base-58-btc Multibase header (z).
    #[inline]
    fn to_multibase(&self) -> String {
        let public_key_without_prefix = self.verifying_key.to_bytes();
        let mut public_key_with_prefix: [u8; PUBLIC_KEY_LENGTH + 2] = [0; PUBLIC_KEY_LENGTH + 2];
        public_key_with_prefix[0] = 0xed;
        public_key_with_prefix[1] = 0x01;
        public_key_with_prefix[2..].copy_from_slice(&public_key_without_prefix);
        MultibaseEncoderDecoder::default().encode_base58btc(&public_key_with_prefix)
    }

    /// As specified by https://www.w3.org/TR/controller-document/#Multikey:
    ///
    /// The encoding of an Ed25519 public key MUST start with the two-byte prefix 0xed01 (the varint expression of 0xed),
    /// followed by the 32-byte public key data.
    /// The resulting 34-byte value MUST then be encoded using the base-58-btc alphabet,
    /// according to Section 2.4 Multibase (https://www.w3.org/TR/controller-document/#multibase-0),
    /// and then prepended with the base-58-btc Multibase header (z).
    #[inline]
    fn from_multibase(multibase: &str) -> Result<Self, DidSidekicksError> {
        let mut verifying_key_buff: [u8; PUBLIC_KEY_LENGTH + 2] = [0; PUBLIC_KEY_LENGTH + 2];
        if let Err(err) = MultibaseEncoderDecoder::default()
            .decode_base58_onto(multibase, &mut verifying_key_buff)
        {
            return Err(DidSidekicksError::DeserializationFailed(format!("{err}")));
        }

        let mut verifying_key: [u8; PUBLIC_KEY_LENGTH] = [0; PUBLIC_KEY_LENGTH];
        verifying_key.copy_from_slice(&verifying_key_buff[2..]); // get rid of the multibase header

        VerifyingKey::from_bytes(&verifying_key).map_or_else(
            |_| {
                Err(DidSidekicksError::InvalidDataIntegrityProof(format!(
                    "{multibase} is an invalid ed25519 verifying key"
                )))
            },
            |key| Ok(Self { verifying_key: key }),
        )
    }
}
impl Ed25519VerifyingKey {
    #[inline]
    pub const fn new(verifying_key: VerifyingKey) -> Self {
        Self { verifying_key }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[expect(clippy::exhaustive_structs, reason = "..")]
pub struct Ed25519KeyPair {
    pub verifying_key: Ed25519VerifyingKey,
    pub signing_key: Ed25519SigningKey,
}

impl Ed25519KeyPair {
    #[inline]
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key: SigningKey = SigningKey::generate(&mut csprng);
        Self {
            verifying_key: Ed25519VerifyingKey::new(signing_key.verifying_key()),
            signing_key: Ed25519SigningKey::new(signing_key),
        }
    }

    /// As specified by https://www.w3.org/TR/controller-document/#Multikey:
    ///
    /// The encoding of an Ed25519 secret key MUST start with the two-byte prefix 0x8026 (the varint expression of 0x1300),
    /// followed by the 32-byte secret key data. The resulting 34-byte value MUST then be encoded using the base-58-btc alphabet,
    /// according to Section 2.4 Multibase (https://www.w3.org/TR/controller-document/#multibase-0),
    /// and then prepended with the base-58-btc Multibase header (z).
    #[inline]
    pub fn from(signing_key_multibase: &str) -> Result<Self, DidSidekicksError> {
        let signing_key = Ed25519SigningKey::from_multibase(signing_key_multibase)?;
        let signing_key_bytes = SigningKey::from_bytes(&signing_key.signing_key.to_bytes());
        Ok(Self {
            verifying_key: Ed25519VerifyingKey::new(signing_key_bytes.verifying_key()),
            signing_key,
        })
    }

    #[inline]
    pub fn get_signing_key(&self) -> Arc<Ed25519SigningKey> {
        self.signing_key.clone().into()
    }

    #[inline]
    pub fn get_verifying_key(&self) -> Arc<Ed25519VerifyingKey> {
        self.verifying_key.clone().into()
    }

    #[inline]
    pub fn sign(&self, message: String) -> Arc<Ed25519Signature> {
        self.signing_key.sign(message)
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "unwrap calls are panic-safe as long as test case setup is correct"
)]
mod tests {
    use super::*;
    use rstest::{fixture, rstest};

    #[fixture]
    #[once]
    fn ed25519_key_pair() -> Ed25519KeyPair {
        Ed25519KeyPair::generate()
    }

    #[rstest]
    fn test_key_pair_multibase_conversion(ed25519_key_pair: &Ed25519KeyPair, // fixture
    ) {
        let original_private = ed25519_key_pair.get_signing_key();
        let original_public = ed25519_key_pair.get_verifying_key();

        let new_private =
            Ed25519SigningKey::from_multibase(&original_private.to_multibase()).unwrap();
        let new_public =
            Ed25519VerifyingKey::from_multibase(&original_public.to_multibase()).unwrap();

        assert_eq!(original_private.to_multibase(), new_private.to_multibase());
        assert_eq!(original_public.to_multibase(), new_public.to_multibase());
    }

    #[rstest]
    fn test_key_pair_creation_from_multibase(ed25519_key_pair: &Ed25519KeyPair, // fixture
    ) {
        let new_ed25519_key_pair =
            Ed25519KeyPair::from(&ed25519_key_pair.get_signing_key().to_multibase()).unwrap();

        assert_eq!(ed25519_key_pair, &new_ed25519_key_pair);
        assert_eq!(
            ed25519_key_pair.get_signing_key().to_multibase(),
            new_ed25519_key_pair.signing_key.to_multibase()
        );
        assert_eq!(
            ed25519_key_pair.get_verifying_key().to_multibase(),
            new_ed25519_key_pair.verifying_key.to_multibase()
        );
    }
}
