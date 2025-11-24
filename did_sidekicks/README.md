# DID sidekicks

This crate features a set of various Rust modules required while implementing either of 
[did:tdw (v0.3)](https://identity.foundation/didwebvh/v0.3/) and [did:webvh (v1.0)](https://identity.foundation/didwebvh/v1.0) specifications.
However, the modules are neither closely related nor specific to any of these specs and may be freely used elsewhere, for other purposes.

More specifically, each of the Rust modules has its own purpose and implements rather partially one of the [referenced specifications](https://identity.foundation/didwebvh/v1.0/#references),
such as:
- [Data Integrity EdDSA Cryptosuites v1.0](https://www.w3.org/TR/vc-di-eddsa)
- [Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-core/)
- [Multiformats](https://datatracker.ietf.org/doc/draft-multiformats-multibase/08/)
- [JSON Canonicalization Scheme (JCS)](https://www.rfc-editor.org/rfc/rfc8785)
- etc.

## Crate's hierarchical structure

Such structure may be easily obtained by simply running `cargo-modules structure --lib --package did_sidekicks`:

```text
crate did_sidekicks
├── mod custom_jsonschema_keywords: pub
│   ├── struct DidLogEntryKeyword: pub
│   │   ├── fn factory: pub
│   │   ├── fn is_valid: pub(self)
│   │   └── fn validate: pub(self)
│   └── struct DidVersionTimeKeyword: pub
│       ├── fn factory: pub
│       ├── fn is_valid: pub(self)
│       └── fn validate: pub(self)
├── mod did_doc: pub
│   ├── struct DidDoc: pub
│   │   ├── fn from_json: pub
│   │   ├── fn get_assertion_method: pub
│   │   ├── fn get_authentication: pub
│   │   ├── fn get_capability_delegation: pub
│   │   ├── fn get_capability_invocation: pub
│   │   ├── fn get_context: pub
│   │   ├── fn get_controller: pub
│   │   ├── fn get_deactivated: pub
│   │   ├── fn get_id: pub
│   │   ├── fn get_key: pub
│   │   ├── fn get_verification_method: pub
│   │   └── fn to_json: pub
│   ├── struct DidDocExtended: pub
│   │   ├── fn get_did_doc: pub
│   │   ├── fn get_did_doc_obj: pub
│   │   ├── fn get_did_method_parameters: pub
│   │   └── const fn new: pub
│   ├── struct DidDocNormalized: pub
│   │   └── fn to_did_doc: pub
│   ├── struct Jwk: pub
│   ├── struct VerificationMethod: pub
│   │   └── const fn new: pub
│   ├── enum VerificationType: pub
│   └── fn get_key_from_did_doc: pub
├── mod did_jsonschema: pub
│   ├── trait DidLogEntryJsonSchema: pub
│   ├── struct DidLogEntryValidator: pub
│   │   ├── fn validate: pub
│   │   └── fn validate_str: pub
│   ├── enum DidLogEntryValidatorError: pub
│   │   └── const fn kind: pub
│   └── enum DidLogEntryValidatorErrorKind: pub
├── mod did_method_parameters: pub
│   └── struct DidMethodParameter: pub
│       ├── const fn get_bool_value: pub
│       ├── const fn get_f64_value: pub
│       ├── const fn get_i64_value: pub
│       ├── fn get_json_text: pub
│       ├── fn get_name: pub
│       ├── fn get_string_array_value: pub
│       ├── fn get_string_value: pub
│       ├── const fn get_u64_value: pub
│       ├── const fn is_array: pub
│       ├── const fn is_bool: pub
│       ├── const fn is_empty_array: pub
│       ├── const fn is_f64: pub
│       ├── const fn is_i64: pub
│       ├── const fn is_null: pub
│       ├── const fn is_object: pub
│       ├── const fn is_string: pub
│       ├── const fn is_string_array: pub
│       ├── const fn is_u64: pub
│       ├── fn new: pub(self)
│       ├── fn new_bool: pub
│       ├── fn new_bool_from_option: pub
│       ├── fn new_false: pub
│       ├── fn new_number_from_option: pub
│       ├── fn new_string: pub
│       ├── fn new_string_array_from_option: pub
│       ├── fn new_string_from_option: pub
│       └── fn new_true: pub
├── mod did_resolver: pub
│   └── trait DidResolver: pub
├── mod ed25519: pub
│   ├── struct Ed25519KeyPair: pub
│   │   ├── fn from: pub
│   │   ├── fn generate: pub
│   │   ├── fn get_signing_key: pub
│   │   ├── fn get_verifying_key: pub
│   │   └── fn sign: pub
│   ├── struct Ed25519Signature: pub
│   │   ├── fn from_multibase: pub(self)
│   │   └── fn to_multibase: pub(self)
│   ├── struct Ed25519SigningKey: pub
│   │   ├── fn from_multibase: pub(self)
│   │   ├── const fn new: pub
│   │   ├── fn sign: pub
│   │   ├── fn sign_bytes: pub
│   │   └── fn to_multibase: pub(self)
│   ├── struct Ed25519VerifyingKey: pub
│   │   ├── fn from_multibase: pub(self)
│   │   ├── const fn new: pub
│   │   └── fn to_multibase: pub(self)
│   └── trait MultiBaseConverter: pub
├── mod errors: pub
│   ├── enum DidResolverError: pub
│   │   └── const fn kind: pub
│   ├── enum DidResolverErrorKind: pub
│   ├── enum DidSidekicksError: pub
│   │   └── const fn kind: pub
│   └── enum DidSidekicksErrorKind: pub
├── mod jcs_sha256_hasher: pub
│   └── struct JcsSha256Hasher: pub
│       ├── fn base58btc_encode_multihash: pub
│       ├── fn base58btc_encode_multihash_multikey: pub
│       ├── fn encode_hex: pub
│       └── fn encode_multihash: pub
├── mod multibase: pub
│   ├── enum MultibaseAlgorithm: pub
│   └── struct MultibaseEncoderDecoder: pub
│       ├── fn decode_base58_onto: pub
│       ├── const fn default: pub(crate)
│       └── fn encode_base58btc: pub
└── mod vc_data_integrity: pub
    ├── struct CryptoSuiteProofOptions: pub
    │   ├── fn default: pub(crate)
    │   └── fn new: pub
    ├── enum CryptoSuiteType: pub
    ├── struct DataIntegrityProof: pub
    │   ├── fn extract_update_key: pub
    │   ├── fn from: pub
    │   └── fn json_value: pub
    ├── struct EddsaJcs2022Cryptosuite: pub
    │   ├── fn add_proof: pub(self)
    │   └── fn verify_proof: pub(self)
    └── trait VCDataIntegrity: pub
```
