// SPDX-License-Identifier: MIT

use std::str::FromStr;

use did_sidekicks::errors::DidResolverError;
use serde::{Deserialize, Serialize, de};

#[expect(clippy::exhaustive_structs, reason = "..")]
#[derive(Debug, Clone)]
pub struct DidLogVersion {
    pub hash: String,
    pub id: String,
    pub index: usize,
}

impl DidLogVersion {
    /// Creates a DidLogVersion with empty hash and index that serializes to the provides hash.
    ///
    /// The returned value should ONLY be used for serialization as the index and hash property are
    /// not filled correctly.
    #[inline]
    pub fn new_forced(version: String) -> Self {
        Self {
            id: version,
            index: 0,
            hash: String::new(),
        }
    }
}

impl FromStr for DidLogVersion {
    type Err = DidResolverError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some(split) = s.split_once('-') else {
            return Err(DidResolverError::DeserializationFailed(
                "Expected version id to contain '-'".into(),
            ));
        };
        let index: usize = match split.0.parse() {
            Ok(index) => index,
            Err(err) => {
                return Err(DidResolverError::DeserializationFailed(format!(
                    "Version id must start with an integer: {}",
                    err
                )));
            }
        };

        if split.1.is_empty() {
            return Err(DidResolverError::DeserializationFailed(
                "EntryHash must not be empty.".into(),
            ));
        }

        Ok(Self {
            id: s.to_owned(),
            index,
            hash: split.1.to_owned(),
        })
    }
}

impl Serialize for DidLogVersion {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.id)
    }
}

#[expect(clippy::missing_trait_methods, reason = "..")]
impl<'de> Deserialize<'de> for DidLogVersion {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct DidLogVersionVisitor;

        #[expect(clippy::missing_trait_methods, reason = "..")]
        impl<'de> de::Visitor<'de> for DidLogVersionVisitor {
            type Value = DidLogVersion;

            #[inline]
            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("a versionId in the format '<version number>-<entryHash>'")
            }

            #[inline]
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                DidLogVersion::from_str(v).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(DidLogVersionVisitor)
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use rstest::rstest;
    use serde::{Deserialize, Serialize};

    use crate::did_webvh::version_id::DidLogVersion;

    #[test]
    fn parse_version_id_from_json() {
        let version_id = "1-hash";
        let raw_json = r#"{"version_id": "1-hash"}"#;
        #[derive(Deserialize, Serialize)]
        struct Foo {
            version_id: DidLogVersion,
        }

        let parsed_json: Foo = serde_json::from_str(raw_json).unwrap();
        assert_eq!(version_id, parsed_json.version_id.id)
    }

    #[rstest]
    #[case("", Err("to contain '-'"))]
    #[case("Hello World", Err("to contain '-'"))]
    #[case("-", Err("must start with an integer"))]
    #[case("0-", Err("EntryHash must not be empty"))]
    #[case("-10-{SCID}", Err("must start with an integer"))]
    #[case("0-{SCID}", Ok((0, "{SCID}")))]
    #[case("1-QmdFXCA7RgH2NszV3WgnbemHqLxpXeE66FswLjpTC2hcvV", Ok((1, "QmdFXCA7RgH2NszV3WgnbemHqLxpXeE66FswLjpTC2hcvV")))]
    fn version_id_from_str(#[case] version_id: &str, #[case] result: Result<(usize, &str), &str>) {
        let version = DidLogVersion::from_str(version_id);
        match (version, result) {
            (Ok(version), Ok((index, hash))) => {
                assert_eq!(index, version.index);
                assert_eq!(hash, version.hash);
            }
            (Err(err), Err(message)) => {
                assert!(
                    err.to_string().contains(message),
                    "Expected err to contain '{}': {}",
                    message,
                    err.to_string()
                );
            }
            (Ok(_), Err(_)) => panic!("Expected parsing of {} to fail.", version_id),
            (Err(err), Ok(_)) => panic!(
                "Parsing of {} unexpectedly failed with: {}",
                version_id,
                err.to_string()
            ),
        }
    }
}
