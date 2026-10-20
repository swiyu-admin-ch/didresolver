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
    /// # Safety
    /// The returned value should ONLY be used for serialization as the index and hash property are
    /// not filled correctly.
    #[inline]
    pub unsafe fn new_forced(version: String) -> Self {
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
                    "VersionID must start with an integer: {}",
                    err
                )));
            }
        };
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
                formatter.write_str("a versionId in the format '<version_index>-<hash>'")
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

// TODO@MP write tests for parsing versionID
