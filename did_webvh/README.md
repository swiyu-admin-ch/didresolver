# DID WEBVH

**⚠️ PARTIAL IMPLEMENTATION ⚠️**

*Beware, this Rust library implements [DID Web + Verifiable History (did:webvh) v1.0 specification](https://identity.foundation/didwebvh/v1.0/)
only partially while focusing solely on [DID resolution](https://identity.foundation/didwebvh/v1.0/#read-resolve).*

## Crate's hierarchical structure

Such structure may be easily obtained by simply running `cargo-modules structure --lib --package did_webvh`:

```text
crate did_webvh
├── mod did_webvh: pub
│   ├── struct DidLogEntry: pub
│   │   ├── fn build_original_scid: pub(self)
│   │   ├── fn calculate_entry_hash: pub
│   │   ├── fn is_key_authorized_for_update: pub(self)
│   │   ├── fn new: pub
│   │   ├── fn to_log_entry_line: pub(self)
│   │   ├── fn verify_data_integrity_proof: pub
│   │   └── fn verify_version_id_integrity: pub
│   ├── struct DidLogVersion: pub
│   │   ├── fn deserialize: pub(self)
│   │   ├── fn new: pub(self)
│   │   └── fn serialize: pub(self)
│   ├── struct DidLogVersionVisitor: pub
│   │   ├── type Value: pub(self)
│   │   ├── fn expecting: pub(self)
│   │   └── fn visit_str: pub(self)
│   ├── struct WebVerifiableHistory: pub
│   │   ├── fn collect_did_method_parameters_map: pub(self)
│   │   ├── fn get_did: pub
│   │   ├── fn get_did_doc: pub
│   │   ├── fn get_did_doc_obj: pub(self)
│   │   ├── fn get_did_doc_obj: pub(self)
│   │   ├── fn get_did_doc_obj_thread_safe: pub
│   │   ├── fn get_did_log: pub
│   │   ├── fn get_did_method_parameters: pub
│   │   ├── fn get_did_method_parameters_obj: pub(self)
│   │   └── fn resolve: pub
│   ├── struct WebVerifiableHistoryDidLog: pub
│   │   ├── fn get_did_method_parameters: pub
│   │   ├── fn validate: pub
│   │   └── fn validate_with_scid: pub
│   └── struct WebVerifiableHistoryId: pub
│       ├── fn get_scid: pub
│       ├── fn get_url: pub
│       └── fn parse_did_webvh: pub
├── mod did_webvh_jsonschema: pub
│   ├── enum WebVerifiableHistoryDidLogEntryJsonSchema: pub
│   │   └── fn get_json_schema: pub(self)
│   └── struct WebVerifiableHistoryDidLogJsonSchemaEmbedFolder: pub(self)
├── mod did_webvh_method_parameters: pub
│   ├── struct WebVerifiableHistoryDidMethodParameters: pub
│   │   ├── fn deactivate: pub
│   │   ├── const fn empty: pub
│   │   ├── fn for_genesis_did_doc: pub
│   │   ├── fn from_json: pub
│   │   ├── fn get_scid: pub
│   │   ├── fn get_scid_option: pub
│   │   ├── fn get_update_keys: pub
│   │   ├── const fn is_deactivated: pub
│   │   ├── fn is_key_pre_rotation_active: pub
│   │   ├── fn merge_from: pub
│   │   └── fn validate_initial: pub
│   ├── struct Witness: pub
│   └── const fn is_zero: pub(self)
└── mod errors: pub
    ├── enum WebVerifiableHistoryIdResolutionError: pub
    │   └── const fn kind: pub
    └── enum WebVerifiableHistoryIdResolutionErrorKind: pub
```

## Benchmarks

All the relevant reports are available [here](criterion/README.md).

Start browsing the crate's relevant reports [here](https://raw.githack.com/swiyu-admin-ch/didresolver/main/criterion/did_webvh/report/index.html) (or [here](https://htmlpreview.github.io/?https://raw.githubusercontent.com/swiyu-admin-ch/didresolver/main/criterion/did_webvh/report/index.html)).
