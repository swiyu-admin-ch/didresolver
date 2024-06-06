use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PublicKey {
    pub id: String,
    #[serde(rename = "type")]
    pub key_type: String,
    pub controller: String,
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: Option<String>,
    #[serde(rename = "publicKeyJwk")]
    pub public_key_jwk: Option<Jwk>,
}
