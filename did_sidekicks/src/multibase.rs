// SPDX-License-Identifier: MIT

use crate::errors::DidSidekicksError;
use bs58::{decode as base58_decode, encode as base58_encode, Alphabet as Alphabet58};
use core::cmp::PartialEq;

/// See https://www.ietf.org/archive/id/draft-multiformats-multibase-08.html#appendix-D.1
pub const BASE58BTC_MULTIBASE_IDENTIFIER: &str = "z";

/// The trait describes type conversion w.r.t [Multibase Data Format](https://www.ietf.org/archive/id/draft-multiformats-multibase-08.html)
///
/// Raw binary data is often encoded using a mechanism that enables the data to be included in human-readable text-based formats.
/// This mechanism is often referred to as "base-encoding the data" and is often used when expressing binary data in hyperlinks,
/// cryptographic keys in web pages, or security tokens in application software.
///
/// There are a variety of base-encodings, such as base32, base58, and base64.
/// To be able to differentiate one base-encoding from another, a multibase-encoded value always
/// starts with a single character header, which identifies the base and encoding alphabet used to encode a binary value,
/// followed by the encoded binary value (using that base and alphabet).
pub trait MultiBaseConvertible {
    /// The multibase-encoding method.
    fn to_multibase(&self) -> String;
    /// The type constructor from a multibase-encoded value.
    ///
    /// # Errors
    ///
    /// If a supplied string value is not multibase-encoded as specified by
    /// [The Multibase Data Format](https://www.ietf.org/archive/id/draft-multiformats-multibase-08.html)
    fn from_multibase(multibase: &str) -> Result<Self, DidSidekicksError>
    where
        Self: Sized;
}

/// See https://www.ietf.org/archive/id/draft-multiformats-multibase-08.html#appendix-D.1
#[derive(PartialEq, Eq, Debug)]
#[expect(
    clippy::exhaustive_enums,
    reason = "further enum variants may be added in the future"
)]
pub enum MultibaseAlgorithm {
    /// Base58 bitcoin
    Base58btc,
}

/// A helper capable of encoding/decoding data in Multibase format according to
/// https://www.ietf.org/archive/id/draft-multiformats-multibase-08.html
pub struct MultibaseEncoderDecoder {
    algorithm: MultibaseAlgorithm,
    alphabet: &'static Alphabet58,
}

impl Default for MultibaseEncoderDecoder {
    /// The default constructor featuring [`MultibaseAlgorithm::Base58btc`] algorithm.
    #[inline]
    fn default() -> Self {
        Self {
            algorithm: MultibaseAlgorithm::Base58btc,
            alphabet: Alphabet58::BITCOIN,
        }
    }
}

impl MultibaseEncoderDecoder {
    /// The UniFFI-compliant default constructor featuring [`MultibaseAlgorithm::Base58btc`] algorithm.
    #[inline]
    fn build() -> Self {
        Self::default()
    }

    /// Encode bytes into a new owned string using the alphabet supplied earlier.
    #[inline]
    #[expect(clippy::panic, reason = "sanity guard")]
    pub fn encode_base58btc(&self, data: &[u8]) -> String {
        // sanity guard
        if self.algorithm != MultibaseAlgorithm::Base58btc {
            panic!("Unsupported multibase algorithm {:?}", self.algorithm);
        }

        let encoded = base58_encode(data)
            .with_alphabet(self.alphabet)
            .into_string();
        // See https://www.ietf.org/archive/id/draft-multiformats-multibase-08.html#name-base-58-bitcoin-encoding
        format!("{BASE58BTC_MULTIBASE_IDENTIFIER}{encoded}")
    }

    /// Decode into the given buffer.
    ///
    /// If the buffer is resizeable it will be extended and the new data will be written to the end
    /// of it.
    ///
    /// If the buffer is not resizeable bytes will be written from the beginning and bytes after
    /// the final encoded byte will not be touched.
    #[inline]
    #[expect(clippy::panic_in_result_fn, reason = "..")]
    #[expect(clippy::panic, reason = "sanity guard")]
    pub fn decode_base58_onto(
        &self,
        multibase: &str,
        result: &mut [u8],
    ) -> Result<(), DidSidekicksError> {
        // sanity guard
        if self.algorithm != MultibaseAlgorithm::Base58btc {
            panic!("Unsupported multibase algorithm {:?}", self.algorithm);
        }

        if !multibase.starts_with(BASE58BTC_MULTIBASE_IDENTIFIER) {
            return Err(DidSidekicksError::DeserializationFailed(format!(
                "Invalid multibase algorithm identifier '{:?}'",
                self.algorithm
            )));
        }

        // get rid of the multibase identifier
        let to_decode = multibase.chars().skip(1).collect::<String>();

        // decode into the given buffer
        match base58_decode(to_decode)
            .with_alphabet(self.alphabet)
            .onto(result)
        {
            Ok(_) => Ok(()),
            Err(err) => Err(DidSidekicksError::DeserializationFailed(format!("{err}"))),
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "unwrap calls are panic-safe as long as test case setup is correct"
)]
mod test {
    use super::*;
    use crate::errors::*;
    use rstest::rstest;
    use std::vec;

    #[rstest]
    fn test_multibase_conversion() {
        let multibase = MultibaseEncoderDecoder::default();
        let encoded = multibase.encode_base58btc(b"helloworld"); // == "z6sBRWyteSSzHrs"

        let mut buff = vec![0; 16];
        multibase
            .decode_base58_onto(encoded.as_str(), &mut buff)
            .unwrap();
        let decoded = String::from_utf8_lossy(&buff).to_string();
        assert!(decoded.starts_with("helloworld"));
        //assert_eq!(decoded, "helloworld");
    }

    #[rstest]
    fn test_multibase_conversion_invalid_multibase() {
        let multibase = MultibaseEncoderDecoder::default();
        let encoded = multibase.encode_base58btc(b"helloworld"); // == "z6sBRWyteSSzHrs"

        // Now, to induce error, just get rid of the multibase code (prefix char 'z')
        let encoded_without_multibase = encoded.chars().skip(1).collect::<String>();
        let mut buff = vec![0; 16];
        let res = multibase.decode_base58_onto(encoded_without_multibase.as_str(), &mut buff);
        assert!(res.is_err());
        let err = res.unwrap_err(); // panic-safe unwrap call (see the previous line)
        assert_eq!(err.kind(), DidSidekicksErrorKind::DeserializationFailed);
        assert!(err
            .to_string()
            .contains("Invalid multibase algorithm identifier 'Base58btc'"));
    }

    #[rstest]
    fn test_multibase_conversion_buffer_too_small() {
        let multibase = MultibaseEncoderDecoder::default();
        let encoded = multibase.encode_base58btc(b"helloworld"); // == "z6sBRWyteSSzHrs"

        // all it takes to reproduce the behaviour
        let mut buff = vec![0; 8]; // empirical size for "helloworld" (encoded)

        let res = multibase.decode_base58_onto(encoded.as_str(), &mut buff);
        assert!(res.is_err());
        let err = res.unwrap_err(); // panic-safe unwrap call (see the previous line)
        assert_eq!(err.kind(), DidSidekicksErrorKind::DeserializationFailed);
        assert!(err
            .to_string()
            .contains("buffer provided to decode base58 encoded string into was too small"));
    }
}
