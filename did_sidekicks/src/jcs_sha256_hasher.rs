// SPDX-License-Identifier: MIT

use crate::errors::DidSidekicksError;
use crate::errors::DidSidekicksError::JscHashingFailed;
use bs58::{encode as base58_encode, Alphabet as Alphabet58};
use hex;
use hex::ToHex as _;
// CAUTION Beware that using the "serde_jcs" crate here may cause
//         "not yet implemented: Handle number str (u128/i128)" error
//         in case of numeric json properties, e.g. "witnessThreshold".
use serde_json::{from_str as json_from_str, Value as JsonValue};
use serde_json_canonicalizer::to_string as jcs_to_string;
use sha2::{Digest as _, Sha256};

/// A [`SHA2`](https://en.wikipedia.org/wiki/SHA-2) (SHA-256) hasher with [`RFC-8785`](https://datatracker.ietf.org/doc/html/rfc8785) in mind.
///
/// It is capable of hashing any JSON structure
/// w.r.t. JSON Canonicalization Scheme (JCS) [`RFC-8785`](https://datatracker.ietf.org/doc/html/rfc8785).
//#[derive(Default, Clone)]
pub struct JcsSha256Hasher {
    hasher: Sha256,
}
impl JcsSha256Hasher {
    /// The UniFFI-compliant wrapper of [`Self::encode_hex_json_value`] method
    #[inline]
    pub fn encode_hex(&self, json: &str) -> Result<String, DidSidekicksError> {
        let json_value: JsonValue =
            json_from_str(json).map_err(|err| JscHashingFailed(format!("{err}")))?;

        (Self {
            hasher: self.hasher.to_owned(),
        })
        .encode_hex_json_value(&json_value)
        .map_err(|err| JscHashingFailed(format!("{err}")))
    }

    /// Serialize the given data structure as a JCS UTF-8 string and calculate SHA2-256 hash out of it.
    /// The hash encoded as hex strict representation is returned. Lower case letters are used (e.g. f9b4ca)
    ///
    /// # Errors
    ///
    /// Serialization can fail if `T`'s implementation of `Serialize` decides to
    /// fail, or if `T` contains a map with non-string keys.
    #[inline]
    pub fn encode_hex_json_value(&mut self, json: &JsonValue) -> Result<String, DidSidekicksError> {
        self.hasher.reset();
        self.hasher
            .update(jcs_to_string(json).map_err(|err| JscHashingFailed(format!("{err}")))?);
        Ok(self.hasher.clone().finalize().encode_hex())
    }

    /// Implementation of the multihash specification (https://www.w3.org/TR/controller-document/#multihash).
    /// Its output is a hash of the input using the associated <hash algorithm>, prefixed with a hash algorithm identifier and the hash size.
    #[inline]
    #[expect(
        clippy::unseparated_literal_suffix,
        reason = "to prevent clippy::separated_literal_suffix warning"
    )]
    #[expect(clippy::as_conversions, reason = "..")]
    fn encode_multihash(&mut self, str: String) -> Vec<u8> {
        self.hasher.reset();
        self.hasher.update(str);
        let digest = self.hasher.to_owned().finalize();

        // According to https://identity.foundation/trustdidweb/v0.3/#didtdw-version-changelog:
        //              Use multihash in the SCID to differentiate the different hash function outputs.
        //              See https://www.ietf.org/archive/id/draft-multiformats-multibase-08.html#name-base-58-bitcoin-encoding

        // multihash is an implementation of the multihash specification (https://www.w3.org/TR/controller-document/#multihash).
        // Its output is a hash of the input using the associated <hash algorithm>, prefixed with a hash algorithm identifier and the hash size.
        // Multihash Identifier	Multihash Header	Description
        // sha2-256	            0x12	            SHA-2 with 256 bits (32 bytes) of output, as defined by [RFC6234].
        let multihash_header: &[u8] = &[
            0x12u8,             // hash algorithm (sha2-256) identifier
            digest.len() as u8, // hash size (in bytes)
        ];

        [multihash_header, digest.as_slice()].concat()
    }

    /// The UniFFI-compliant wrapper of [`Self::base58btc_encode_multihash_json_value`] method
    #[inline]
    pub fn base58btc_encode_multihash(&self, json: &str) -> Result<String, DidSidekicksError> {
        let json_value: JsonValue = json_from_str(json).map_err(|err| {
            JscHashingFailed(format!(
                "Failed to base58btc-encode SHA2-256 multihash of canonical JSON UTF-8 string: {err}"
            ))
        })?;

        (Self {
            hasher: self.hasher.to_owned(),
        })
        .base58btc_encode_multihash_json_value(&json_value)
        .map_err(|err| {
            JscHashingFailed(format!(
                "Failed to base58btc-encode SHA2-256 multihash of canonical JSON UTF-8 string: {err}"
            ))
        })
    }

    /// Serialize the given data structure as a JCS UTF-8 string and calculate SHA2-256 multihash out of it.
    /// The multihash encoded in base58btc format is returned
    #[inline]
    pub fn base58btc_encode_multihash_json_value(
        &mut self,
        json_value: &JsonValue,
    ) -> serde_json::Result<String> {
        // WORKAROUND (":ff" -> ":") in case of numeric json properties (e.g. witnessThreshold)
        let multihash_sha256 =
            self.encode_multihash(jcs_to_string(json_value)?.replace(":ff", ":"));

        //
        // Since v0.3 (https://identity.foundation/trustdidweb/v0.3/#didtdw-version-changelog):
        //            Change base32 encoding with base58btc, as it offers a better expansion rate.
        // More here: https://identity.foundation/trustdidweb/v0.3/#generate-scid
        //            To generate the required [[ref: SCID]] for a did:tdw DID, the DID Controller MUST execute the following function:
        //            base58btc(multihash(JCS(preliminary log entry with placeholders), <hash algorithm>))
        Ok(base58_encode(multihash_sha256)
            .with_alphabet(Alphabet58::BITCOIN) // it is the default alphabet, but still (to ensure spec conformity)
            .into_string())
    }

    /// This helper calculates the hash string as `base58btc(multihash(multikey))`, where:
    /// - `multikey` is the multikey representation of a public key
    /// - `multihash` is an implementation of the <a href="https://www.w3.org/TR/controller-document/#multihash">multihash</a> specification.
    ///   Its output is a hash of the input using the associated `<hash algorithm>`
    /// - `<hash algorithm>` is the hash algorithm used by the DID Controller.
    ///   The hash algorithm MUST be one listed in the parameters defined by the version of a `did:*`
    ///   (e.g. `did:webvh`) specification being used by the DID Controller
    /// - `base58btc` is an implementation of the base58btc function (converts data to a `base58` encoding).
    ///   Its output is the base58 encoded string of its input
    ///
    /// As such, the helper can be used out-of-the-box for the purpose of
    /// <a href="https://identity.foundation/didwebvh/v1.0/#pre-rotation-key-hash-generation-and-verification">pre-rotation-key-hash-generation-and-verification</a>.
    #[inline]
    pub fn base58btc_encode_multihash_multikey(&mut self, multikey: &str) -> String {
        base58_encode(self.encode_multihash(multikey.to_owned()))
            .with_alphabet(Alphabet58::BITCOIN) // it is the default alphabet, but still (to ensure spec conformity)
            .into_string()
    }
}

impl Default for JcsSha256Hasher {
    #[inline]
    fn default() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex::encode as hex_encode;
    use rstest::rstest;

    #[rstest]
    #[case(
        // Example taken from https://multiformats.io/multihash/#sha2-256---256-bits-aka-sha256
        "Merkle\u{2013}Damg\u{e5}rd", // "Merkle–Damgård",
        "122041dd7b6443542e75701aa98a0c235951a28a0d851b11564d20022ab11d2589a8"
    )]
    fn test_encode_multihash(#[case] input: &str, #[case] expected: &str) {
        let hash = hex_encode(JcsSha256Hasher::default().encode_multihash(input.to_owned()));
        assert_eq!(hash, expected);
    }

    #[rstest]
    #[case(
        // Example taken from https://identity.foundation/didwebvh/v0.3/#log-file-for-version-2
        "z82Lkvgj5NKYhoFh4hWzax9WicQaVDphN8MMzR3JZhontVfHaoGd9JbC4QRpDvmjQH3BLeQ",
        "QmcbM5bppyT4yyaL35TQQJ2XdSrSNAhH5t6f4ZcuyR4VSv"
    )]
    #[case(
        // Example taken from https://github.com/affinidi/affinidi-tdk-rs/blob/main/crates/affinidi-tdk/common/affinidi-secrets-resolver/src/secrets.rs#L456
        "z6MkgfFvvWA7sw8WkNWyK3y74kwNVvWc7Qrs5tWnsnqMfLD3",
        "QmY1kaguPMgjndEh1sdDZ8kdjX4Uc1SW4vziMfgWC6ndnJ"
    )]
    #[case(
        // Example taken from https://raw.githubusercontent.com/decentralized-identity/didwebvh-rs/refs/heads/main/tests/test_vectors/pre-1_0-spec.jsonl
        "z6Mkk7qfjoovyci2wpD1GZPvkngtWBjLr4bVdYeZfdWHDkEu",
        "QmPyrGjbkwKPbDE33StNmA6v9uwNWB9NWgmxMiQ7tV1uJx"
    )]
    #[case(
        // Example taken from https://raw.githubusercontent.com/decentralized-identity/didwebvh-rs/refs/heads/main/tests/test_vectors/pre-1_0-spec.jsonl
        "z6MkmpTLDBwKi8qWC6J8jz4sGR9zn1oLTizNt6XbYxDEkFQS",
        "QmWZg7NR5vyjxHFjNLzyUdpHKXFr6MWM7pQJE8wdKrDZwV"
    )]
    #[case(
        // Example taken from https://raw.githubusercontent.com/decentralized-identity/didwebvh-rs/refs/heads/main/tests/test_vectors/revoked-did.jsonl
        "z6Mkr7XVfuk77YmHG9WWX3rxhLRzK2z7oEia7D75fpZC6dzG",
        "QmeLTcLUJ9A2TTHeWdo2xx6yd52E4aPrLoEDnmCbUEhYUi"
    )]
    #[case(
        // Example taken from https://raw.githubusercontent.com/decentralized-identity/didwebvh-rs/refs/heads/main/tests/test_vectors/revoked-did.jsonl
        "z6MkiwKu88uSsuNP5tYVvcaQSc7ZVpe1248zefnQXtbeHcxE",
        "QmejLZab9j1DuA8fD5593XXGS2WXUgKsh3jYGY8ctaSdyC"
    )]
    fn test_base58btc_encode_multihash_multikey(#[case] multikey: &str, #[case] expected: &str) {
        let hash = JcsSha256Hasher::default().base58btc_encode_multihash_multikey(multikey);
        assert_eq!(hash, expected);
    }
}
