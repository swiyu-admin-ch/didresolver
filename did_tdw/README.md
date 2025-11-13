# DID TDW

**⚠️ PARTIAL IMPLEMENTATION ⚠️**

*Beware, this Rust library implements historical [Trust DID Web - did:tdw - v0.3 specification](https://identity.foundation/didwebvh/v0.3)
only partially while focusing solely on [DID resolution](https://identity.foundation/didwebvh/v0.3/#read-resolve).*

Although the library is still required by [DID Resolver](https://github.com/swiyu-admin-ch/didresolver), it will be kept
in the future as legacy and solely for the sake of backward compatibility, as [newer version of the specifications](https://identity.foundation/didwebvh/v1.0) is currently being implemented.

## Crate's hierarchical structure

Such structure may be easily obtained by simply running `cargo-modules structure --lib --package did_tdw`:

```text
crate did_tdw
├── mod did_tdw: pub
│   ├── struct DidLogEntry: pub
│   │   ├── fn build_original_scid: pub(self)
│   │   ├── fn build_version_id: pub
│   │   ├── fn is_key_authorized_for_update: pub(self)
│   │   ├── fn new: pub
│   │   ├── fn to_log_entry_line: pub(self)
│   │   ├── fn verify_data_integrity_proof: pub
│   │   └── fn verify_version_id_integrity: pub
│   ├── struct TrustDidWeb: pub
│   │   ├── fn collect_did_method_parameters_map: pub(self)
│   │   ├── fn get_did: pub
│   │   ├── fn get_did_doc: pub
│   │   ├── fn get_did_doc_obj: pub(self)
│   │   ├── fn get_did_doc_obj: pub(self)
│   │   ├── fn get_did_doc_obj_thread_safe: pub
│   │   ├── fn get_did_log: pub
│   │   ├── fn get_did_method_parameters: pub
│   │   ├── fn get_did_method_parameters_obj: pub(self)
│   │   ├── fn read: pub
│   │   └── fn resolve: pub
│   ├── struct TrustDidWebDidLog: pub
│   │   ├── fn get_did_method_parameters: pub
│   │   ├── fn validate: pub
│   │   └── fn validate_with_scid: pub
│   └── struct TrustDidWebId: pub
│       ├── fn get_scid: pub
│       ├── fn get_url: pub
│       └── fn parse_did_tdw: pub
├── mod did_tdw_jsonschema: pub
│   ├── struct DidLogJsonSchemaEmbedFolder: pub(self)
│   └── enum TrustDidWebDidLogEntryJsonSchema: pub
│       └── fn get_json_schema: pub(self)
├── mod did_tdw_method_parameters: pub
│   └── struct TrustDidWebDidMethodParameters: pub
│       ├── fn deactivate: pub
│       ├── const fn empty: pub
│       ├── fn for_genesis_did_doc: pub
│       ├── fn from_json: pub
│       ├── fn get_scid: pub
│       ├── fn get_scid_option: pub
│       ├── fn get_update_keys: pub
│       ├── const fn is_deactivated: pub
│       ├── fn merge_from: pub
│       └── fn validate_initial: pub
└── mod errors: pub
    ├── enum TrustDidWebError: pub
    │   └── const fn kind: pub
    ├── enum TrustDidWebErrorKind: pub
    ├── enum TrustDidWebIdResolutionError: pub
    │   └── const fn kind: pub
    └── enum TrustDidWebIdResolutionErrorKind: pub
```

## Benchmarks

All the relevant reports are available [here](../criterion/README.md).

Start browsing the crate's relevant reports [here](https://raw.githack.com/swiyu-admin-ch/didresolver/main/criterion/did_tdw/report/index.html) (or [here](https://htmlpreview.github.io/?https://raw.githubusercontent.com/swiyu-admin-ch/didresolver/main/criterion/did_tdw/report/index.html)).
