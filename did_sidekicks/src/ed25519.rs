// SPDX-License-Identifier: MIT

use std::path::Path;
use std::sync::Arc;

use crate::errors::DidSidekicksError;
use crate::errors::DidSidekicksError::{
    KeyDeserializationFailed, KeySerializationFailed, MultibaseKeyConversionFailed,
};
use crate::multibase::MultibaseEncoderDecoder as multibase;
use ed25519_dalek::{
    pkcs8::{
        spki::der::pem::LineEnding, DecodePrivateKey as _, DecodePublicKey as _,
        EncodePrivateKey as _, EncodePublicKey as _,
    },
    Signature, Signer as _, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH,
    SIGNATURE_LENGTH,
};
use hex::FromHex as from_hex;
use rand::rngs::OsRng;

pub trait MultiBaseConverter {
    fn to_multibase(&self) -> String;
    fn from_multibase(multibase: &str) -> Result<Self, DidSidekicksError>
    where
        Self: Sized;
}

/// A [`Signature`] derivation implementing [`MultiBaseConverter`] trait.
#[derive(Clone)]
pub struct Ed25519Signature {
    signature: Signature,
}
impl MultiBaseConverter for Ed25519Signature {
    #[inline]
    fn to_multibase(&self) -> String {
        let signature_bytes = self.signature.to_bytes();
        multibase::default().encode_base58btc(&signature_bytes)
    }

    #[inline]
    fn from_multibase(multibase: &str) -> Result<Self, DidSidekicksError> {
        let mut signature_bytes: [u8; SIGNATURE_LENGTH] = [0; SIGNATURE_LENGTH];
        match multibase::default().decode_base58_onto(multibase, &mut signature_bytes) {
            Err(err) => Err(MultibaseKeyConversionFailed(format!("{err}"))),
            Ok(_) => Ok(Self {
                signature: Signature::from_bytes(&signature_bytes),
            }),
        }
    }
}

/// A [`SigningKey`] derivation implementing [`MultiBaseConverter`] trait.
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
        signing_key_with_prefix[0] = 0x80;
        signing_key_with_prefix[1] = 0x26;
        signing_key_with_prefix[2..].copy_from_slice(&signing_key_bytes);
        multibase::default().encode_base58btc(&signing_key_with_prefix)
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
        if let Err(err) = multibase::default().decode_base58_onto(multibase, &mut signing_key_buff)
        {
            return Err(MultibaseKeyConversionFailed(format!("{err}")));
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
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key: SigningKey = SigningKey::generate(&mut csprng);
        Self { signing_key }
    }

    /// Deserialize PKCS#8-encoded private key from PEM.
    #[inline]
    pub fn from_pkcs8_pem(pkcs8_pem: &str) -> Result<Self, DidSidekicksError> {
        SigningKey::from_pkcs8_pem(pkcs8_pem).map_or_else(
            |err| {
                Err(KeyDeserializationFailed(format!(
                    //"'{pksc8_pem}' is not a PKCS#8-encoded private key"
                    "supplied &str denotes no valid PKCS#8-encoded Ed25519 private/signing key: {err}"
                )))
            },
            |key| Ok(Self { signing_key: key }),
        )
    }

    /// Load public key object from a PEM-encoded file on the local filesystem.
    #[inline]
    pub fn read_pkcs8_pem_file(pkcs8_pem_file: &str) -> Result<Self, DidSidekicksError> {
        SigningKey::read_pkcs8_pem_file(Path::new(pkcs8_pem_file)).map_or_else(
            |err| {
                Err(KeyDeserializationFailed(format!(
                    "'{pkcs8_pem_file}' denotes no valid PKCS#8-encoded Ed25519 private/signing key file: {err}"
                )))
            },
            |key| Ok(Self { signing_key: key }),
        )
    }

    /// Write ASN.1 DER-encoded PKCS#8 private key to the given path
    #[inline]
    pub fn write_pkcs8_pem_file(&self, public_key_pem_file: &str) -> Result<(), DidSidekicksError> {
        self.signing_key
            .write_pkcs8_pem_file(Path::new(public_key_pem_file), LineEnding::default())
            .map_err(|err| KeySerializationFailed(format!("{err}")))
    }

    /// Sign the given message and return a digital signature
    ///
    /// UniFFI-compliant method
    #[inline]
    pub fn sign(&self, message: &str) -> Arc<Ed25519Signature> {
        self.sign_bytes(message.as_bytes()).into()
    }

    /// Sign the given message and return a digital signature
    ///
    /// UniFFI-irrelevant
    #[inline]
    pub fn sign_bytes(&self, message: &[u8]) -> Ed25519Signature {
        let signature = self.signing_key.sign(message);
        Ed25519Signature { signature }
    }

    /// Get the [`Ed25519VerifyingKey`] for this [`Ed25519SigningKey`].
    #[inline]
    pub fn verifying_key(&self) -> Ed25519VerifyingKey {
        Ed25519VerifyingKey {
            verifying_key: self.signing_key.verifying_key(),
        }
    }

    /// Get the [`Ed25519VerifyingKey`] for this [`Ed25519SigningKey`].
    ///
    /// UniFFI-compliant getter
    #[inline]
    pub fn get_verifying_key(&self) -> Arc<Ed25519VerifyingKey> {
        self.verifying_key().into()
    }
}

/// A [`VerifyingKey`] derivation implementing [`MultiBaseConverter`] trait.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Ed25519VerifyingKey {
    verifying_key: VerifyingKey,
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
        multibase::default().encode_base58btc(&public_key_with_prefix)
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
        if let Err(err) =
            multibase::default().decode_base58_onto(multibase, &mut verifying_key_buff)
        {
            return Err(MultibaseKeyConversionFailed(format!("{err}")));
        }

        let mut verifying_key: [u8; PUBLIC_KEY_LENGTH] = [0; PUBLIC_KEY_LENGTH];
        verifying_key.copy_from_slice(&verifying_key_buff[2..]); // get rid of the multibase header

        VerifyingKey::from_bytes(&verifying_key).map_or_else(
            |_| {
                Err(MultibaseKeyConversionFailed(format!(
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

    /// Deserialize PKCS#8-encoded public key from PEM
    #[inline]
    pub fn from_public_key_pem(public_key_pem: &str) -> Result<Self, DidSidekicksError> {
        VerifyingKey::from_public_key_pem(public_key_pem).map_or_else(
            |err| {
                Err(KeyDeserializationFailed(format!(
                    //"'{public_key_pem}' is not a PKCS#8-encoded public key"
                    "supplied &str denotes no valid PEM-encoded Ed25519 public/verifying key: {err}"
                )))
            },
            |key| Ok(Self { verifying_key: key }),
        )
    }

    /// Load public key object from a PEM-encoded file on the local filesystem.
    #[inline]
    pub fn read_public_key_pem_file(public_key_pem_file: &str) -> Result<Self, DidSidekicksError> {
        VerifyingKey::read_public_key_pem_file(Path::new(public_key_pem_file)).map_or_else(
            |err| {
                Err(KeyDeserializationFailed(format!(
                    "'{public_key_pem_file}' denotes no valid PEM-encoded Ed25519 public/verifying key file: {err}"
                )))
            },
            |key| Ok(Self { verifying_key: key }),
        )
    }

    /// Write ASN.1 DER-encoded public key to the given path
    #[inline]
    pub fn write_public_key_pem_file(
        &self,
        public_key_pem_file: &str,
    ) -> Result<(), DidSidekicksError> {
        self.verifying_key
            .write_public_key_pem_file(Path::new(public_key_pem_file), LineEnding::default())
            .map_err(|err| KeySerializationFailed(format!("{err}")))
    }

    /// Strictly verify a signature on a message with this keypair's public key.
    ///
    /// Basically, calling the method is the same as calling [`Self::verify_strict_bytes`],
    /// but with previous conversion from a `&str`.
    #[inline]
    pub fn verify_strict(
        &self,
        message: &str,
        signature: &Ed25519Signature,
    ) -> Result<(), DidSidekicksError> {
        self.verify_strict_bytes(message.as_bytes(), signature)
    }

    /// Strictly verify a signature on a message with this keypair's public key.
    ///
    /// UniFFI-irrelevant
    #[inline]
    pub fn verify_strict_bytes(
        &self,
        message_bytes: &[u8],
        signature: &Ed25519Signature,
    ) -> Result<(), DidSidekicksError> {
        // Strictly verify a signature on a message with this keypair's public key.
        // It may respond with: "signature error: Verification equation was not satisfied"
        self.verifying_key
            .verify_strict(message_bytes, &signature.signature)
            .map_err(|err| DidSidekicksError::InvalidDataIntegrityProof(format!("{err}")))
    }

    /// Strictly verify a signature on a hex message with this keypair's public key.
    ///
    /// Basically, calling the method is the same as calling [`Self::verify_strict_bytes`],
    /// but with previous decoding from a hex string.
    #[inline]
    pub fn verify_strict_from_hex(
        &self,
        message_hex: &str,
        signature: &Ed25519Signature,
    ) -> Result<(), DidSidekicksError> {
        let hash_data_decoded: [u8; 64] = match from_hex::from_hex(message_hex) {
            Ok(decoded_hash) => decoded_hash,
            Err(_) => {
                return Err(DidSidekicksError::InvalidDataIntegrityProof(
                    "Failed to decode from hex string.".to_owned(),
                ))
            }
        };
        // Strictly verify a signature on a message with this keypair's public key.
        // It may respond with: "signature error: Verification equation was not satisfied"
        self.verify_strict_bytes(&hash_data_decoded, signature)
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
    fn generated_signing_key() -> Ed25519SigningKey {
        Ed25519SigningKey::generate()
    }

    #[fixture]
    #[once]
    fn signing_key_test_vector() -> Ed25519SigningKey {
        // From https://www.w3.org/TR/vc-di-eddsa/#example-private-and-public-keys-for-signature-1:
        // {
        //     publicKeyMultibase: "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
        //     secretKeyMultibase: "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq"
        // }
        Ed25519SigningKey::from_multibase("z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq")
            .unwrap() // no panic expected here
    }

    #[fixture]
    #[once]
    fn verifying_key_test_vector() -> Ed25519VerifyingKey {
        // From https://www.w3.org/TR/vc-di-eddsa/#example-private-and-public-keys-for-signature-1:
        // {
        //     publicKeyMultibase: "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
        //     secretKeyMultibase: "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq"
        // }
        Ed25519VerifyingKey::from_multibase("z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2")
            .unwrap() // no panic expected here
    }

    #[rstest]
    fn test_ed25519_signing_key_from_multibase(
        generated_signing_key: &Ed25519SigningKey, // fixture
    ) {
        let another_ed25519_signing_key =
            Ed25519SigningKey::from_multibase(&generated_signing_key.to_multibase()).unwrap();

        assert_eq!(generated_signing_key, &another_ed25519_signing_key);
        assert_eq!(
            generated_signing_key.to_multibase(),
            another_ed25519_signing_key.to_multibase()
        );
        assert_eq!(
            generated_signing_key.verifying_key().to_multibase(),
            another_ed25519_signing_key.verifying_key().to_multibase()
        );
    }

    #[rstest]
    fn test_ed25519_to_multibase_test_vectors(
        signing_key_test_vector: &Ed25519SigningKey,
        verifying_key_test_vector: &Ed25519VerifyingKey,
    ) {
        // From https://www.w3.org/TR/vc-di-eddsa/#example-private-and-public-keys-for-signature-1:
        // {
        //     publicKeyMultibase: "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
        //     secretKeyMultibase: "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq"
        // }

        assert_eq!(
            signing_key_test_vector.to_multibase(),
            "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq"
        );
        assert_eq!(
            verifying_key_test_vector.to_multibase(),
            "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"
        );
    }

    #[rstest]
    fn test_ed25519_sign_and_verify_against_test_vectors(
        signing_key_test_vector: &Ed25519SigningKey,
        verifying_key_test_vector: &Ed25519VerifyingKey,
    ) {
        let message = "This is a test of the tsunami alert system.";
        let signature = signing_key_test_vector.sign(message.into());

        assert!(signing_key_test_vector
            .verifying_key()
            .verify_strict(message, &signature)
            .is_ok());

        assert!(verifying_key_test_vector
            .verify_strict(message, &signature)
            .is_ok());
    }

    #[rstest]
    fn test_ed25519_signing_key_from_pkcs8_pem() {
        /*
        The test data used here may be easily generated using openssl command by running the following script:

        openssl genpkey -algorithm ed25519 -out private.pem
        openssl pkey -in private.pem -pubout -out public.pem
        openssl pkey -inform pem -in private.pem -outform der -out private.der
        cat private.pem | openssl pkey -pubout -outform der -out public.der
        # CAUTION The bs58 command MUST be installed first by running 'cargo install bs58-cli'
        secret_key_multibase=z$(echo 8026$(xxd -plain -cols 32 -s -32 private.der) | xxd -r -p | bs58)
        public_key_multibase=z$(echo ed01$(xxd -plain -cols 32 -s -32 public.der)  | xxd -r -p | bs58)
        echo "{\"${secret_key_multibase}\", \"${public_key_multibase}\"}"
         */

        let signing_key = Ed25519SigningKey::from_pkcs8_pem(
            "
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPf7l3y23VrVWsZVrsN2+YuICyrZeAKIZfyyp6iSolRI
-----END PRIVATE KEY-----
",
        )
        .unwrap();

        // matches signing_key
        let verifying_key = Ed25519VerifyingKey::from_public_key_pem(
            "
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA8ETLwQBKgk9fM2V0tQV5AdjrMvetLrgj5C+FOmYGTJg=
-----END PUBLIC KEY-----
",
        )
        .unwrap();

        assert_eq!(
            signing_key.to_multibase(),
            "z3u2hupzknQ8uB64d7RudVnXhyzHXnya3jfrSNkoXZ116XwD"
        );
        assert_eq!(
            signing_key.verifying_key().to_multibase(),
            "z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"
        );
        assert_eq!(
            signing_key.verifying_key().to_multibase(),
            verifying_key.to_multibase()
        );

        let message = "This is a test of the tsunami alert system.";
        let signature = signing_key.sign(message.into());
        assert!(signing_key
            .verifying_key()
            .verify_strict(message, &signature)
            .is_ok());
        assert!(verifying_key.verify_strict(message, &signature).is_ok());
    }

    #[rstest]
    #[case("test_data/keys/private.pem", "test_data/keys/public.pem")]
    fn test_ed25519_signing_key_read_pkcs8_pem_file(
        #[case] pkcs8_pem_file: &str,
        #[case] public_key_pem_file: &str,
    ) {
        /*
        The test data used here may be easily generated using openssl command by running the following script:

        openssl genpkey -algorithm ed25519 -out private.pem
        openssl pkey -in private.pem -pubout -out public.pem
         */

        let signing_key = Ed25519SigningKey::read_pkcs8_pem_file(pkcs8_pem_file).unwrap();

        // matches signing_key
        let verifying_key =
            Ed25519VerifyingKey::read_public_key_pem_file(public_key_pem_file).unwrap();

        assert_eq!(
            signing_key.verifying_key().to_multibase(),
            verifying_key.to_multibase()
        );

        let message = "This is a test of the tsunami alert system.";
        let signature = signing_key.sign(message.into());
        assert!(signing_key
            .verifying_key()
            .verify_strict(message, &signature)
            .is_ok());
        assert!(verifying_key.verify_strict(message, &signature).is_ok());
    }
}
