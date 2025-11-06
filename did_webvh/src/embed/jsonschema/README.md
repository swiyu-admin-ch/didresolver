# [JSON schemata (Draft 2020-12)](https://json-schema.org/draft/2020-12) for [didwebvh](https://identity.foundation/didwebvh)

[JSON schema (Draft 2020-12)](https://json-schema.org/draft/2020-12) is a declarative language for annotating and validating JSON documents' structure, constraints, and data types.
It helps standardize and define expectations for JSON data.

This directory features various [JSON schema (Draft 2020-12)](https://json-schema.org/draft/2020-12) designed for the sake of validating [didwebvh](https://identity.foundation/didwebvh) DID logs:

- [`V1_0EidConform`](did_log_jsonschema_v_0_3_eid_conform.json), as defined by both [did:webvh:1.0](https://identity.foundation/didwebvh/v1.0) and (eID-conformity) addendum:
    - https://confluence.bit.admin.ch/x/r_0EMw (DID Log Conformity Check)
    - https://confluence.bit.admin.ch/x/3e0EMw (DID Doc Conformity Check)
- [`V1_0`](did_log_jsonschema_v_0_3.json), as (strictly) specified by [did:webvh:1.0](https://identity.foundation/didwebvh/v0.3)

Both these schemata are indeed different, not substantially, though.
To a certain extent, the [`V1_0EidConform`](did_log_jsonschema_v_1_0_eid_conform.json) might also be considered a (validation rule) subset of [`V1_0`](did_log_jsonschema_v_1_0.json). 
To explore their differences, feel free to run either:
- [`delta -s *.json`](https://github.com/dandavison/delta) or
- [`difft    *.json`](https://github.com/Wilfred/difftastic)

## Implementation Detail

[`jsonschema`](https://docs.rs/jsonschema/latest/jsonschema) is a high-performance JSON Schema validator for Rust.
Among many advanced features, it also allows you to extend its functionality by implementing custom validation logic through [`custom keywords`](https://docs.rs/jsonschema/latest/jsonschema/index.html#custom-keywords).
This feature is particularly useful when you need to validate against domain-specific rules that aren’t covered by the standard JSON Schema keywords.
Furthermore, both [`V1_0EidConform`](did_log_jsonschema_v_1_0_eid_conform.json) and [`V1_0`](did_log_jsonschema_v_1_0.json) 
schemata feature several such (custom, hence non-standard) keywords such as:
- `did-version-time`.

## The Features Unsupported By [`V1_0EidConform`](did_log_jsonschema_v_1_0_eid_conform.json)

Beware of the following unsupported features by the [`V1_0EidConform`](did_log_jsonschema_v_1_0_eid_conform.json) schema:

- [DID Witnesses](https://identity.foundation/didwebvh/v1.0/#did-witnesses) won't be supported as they are not needed from the current point of view.
As the DIDs are published on a central base registry the DID controller and the hoster are different actors and the chance that both are compromised is minimized.
It would add complexity to the resolving of a DID and the base registry would need to also host `did-witness.json` file.

- [DID Portability](https://identity.foundation/didwebvh/v1.0/#did-portability) won't be supported as it is not intended that a did can be ported from the swiss trust infrastructure
to another infrastructure or that the did is ported to the swiss trust infrastructure.

- [DID Document properties](https://www.w3.org/TR/did-1.0/#verification-method-properties) like:
  - [`controller`](https://www.w3.org/TR/did-1.0/#dfn-controller)
  - [`alsoKnownAs`](https://www.w3.org/TR/did-1.0/#dfn-alsoknownas)
  - [`service`](https://www.w3.org/TR/did-1.0/#dfn-service)

- [Verification Method properties](https://www.w3.org/TR/did-1.0/#verification-method-properties) like:
  - [`verificationMethod`](https://www.w3.org/TR/cid-1.0/#verification-methods) → [`controller`](https://www.w3.org/TR/did-1.0/#dfn-controller)
  - [`verificationMethod`](https://www.w3.org/TR/cid-1.0/#verification-methods) → [`publicKeyMultibase`](https://www.w3.org/TR/did-1.0/#dfn-publickeymultibase)
