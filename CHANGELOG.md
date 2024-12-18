# DID resolver changelog

| Version | Description                                                                                                                                                                       |
|---------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 0.0.6   | **IMPROVEMENT/FIX** Ensured conformity with [Trust DID Web - did:tdw - v0.3](https://identity.foundation/trustdidweb/v0.3/)                                                       |
| 0.0.5   | **BUGFIX** Large `*.jsonl` files handled properly                                                                                                                                 |
| 0.0.4   | **BREAKING CHANGE** `TrustDidWebProcessor` discontinued. <br/>Signature of the `resolve` method now requires a DID log (as string). <br/>It may also throw new `TrustDidWebError` |
| 0.0.3   | Upgrade didresolver dependency to version 0.0.2 to add missing jwk model properties                                                                                               |


