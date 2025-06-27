![Public Beta banner](https://github.com/swiyu-admin-ch/swiyu-admin-ch.github.io/blob/main/assets/images/github-banner.jpg)

# DID resolver

> Latest version of the DID methods might not be supported yet

An official Swiss Government project made by the [Federal Office of Information Technology, Systems and Telecommunication FOITT](https://www.bit.admin.ch/)
as part of the electronic identity (e-ID) project.

This project contains a DID resolver which allows to resolve the following methods:
- [did:web](https://w3c-ccg.github.io/did-method-web/)
- [did:tdw/did:webvh](https://bcgov.github.io/trustdidweb/#create-register)

## Table of contents

- [Overview](#overview)
- [Using the library](#using-the-library)
- [Example](#example)
- [Internal dependencies](#internal-dependencies)
- [Known Issues](#known-issues)
- [Contributions and feedback](#contributions-and-feedback)
- [License](#license)

## Overview

This repository is part of the ecosystem developed for the future official Swiss e-ID.
The goal of this repository is to engage with the community and collaborate on developing the Swiss ecosystem for e-ID and other credentials.
We warmly encourage you to engage with us by creating an issue in the repository.

For more information about the project please visit the [introduction for the Public Beta](https://www.eid.admin.ch/de/public-beta) or the [Open Source Community](https://github.com/swiyu-admin-ch/community) repository.

## Using the library

The library can be used either directly in rust as is or through the different built bindings which are published in different submodules

### Rust

The library can be used directly in rust by adding the following dependency to your `Cargo.toml`:
````toml
[dependencies]
# Alternatively, feel free to so use tag=<ANY_EXISTING_VERSION> instead of branch="main"
didresolver = { git="https://github.com/swiyu-admin-ch/didresolver.git", branch="main" }
ureq = "3.0.12"

# Optional: For manipulating the json content in the example
serde_json = "1.0.215"
````

### Additional language bindings

> General information how the bindings are generated can be found in the [UniFFI user guide](https://mozilla.github.io/uniffi-rs/latest/)

The library is also available in other languages. Please consult the documentation of the subsequent repositories for more information:
- [Examples](https://github.com/swiyu-admin-ch/didresolver-examples)
- [Kotlin / Java](https://github.com/swiyu-admin-ch/didresolver-kotlin)
- [Kotlin for android](https://github.com/swiyu-admin-ch/didresolver-kotlin-android)
- [Swift](https://github.com/swiyu-admin-ch/didresolver-swift)

## Example

In the example the following steps are shown:
1. Convert supplied DID string into the standard did representation, if possible
2. Fetch a raw DID log, using the url embedded in the did object created previously, if available 
3. Try resolving the raw DOD log into a DID doc
4. Get different parts from the DID doc w.r.t. [data model](#models)
```rust
use didresolver::did::Did;

fn main() {
    let did = Did::new(String::from("did:tdw:QmRjT8JCbQkEffVBWSbQd8nbMVNfAxiXStLPmqkQUWcsfv:gist.githubusercontent.com:vst-bit:32b64cfac9075b2a3ab7301b772bcdef:raw:4775dd76799b35e99322bf738fafd6c10f421ed7"))
        .expect("invalid DID supplied");

    let url = match did.get_url() {
        Ok(url) => url,
        Err(reason) => panic!(
            "invalid (unsupported or malformed) DID supplied: {}",
            reason
        ),
    };

    let did_log_raw = ureq::get(&url)
        .call()
        .expect("Failed to call did url")
        .into_body()
        .read_to_string()
        .expect("Failed to read DID to string");

    let did_doc = match did.resolve(did_log_raw) {
        Ok(did_doc) => did_doc,
        Err(reason) => panic!("Error occurred during resolution: {}", reason),
    };

    did_doc.get_verification_method().iter().for_each(|method| {
        println!(
            "id: {}, publicKey: {:?}, publicKeyJwk: {:?}",
            method.id, method.public_key_multibase, method.public_key_jwk
        )
    });
}
```

## Internal dependencies

![Dependencies](/images/dependencies.png)

The graph is also available in other layouts: [circo](/images/dependencies-circo.png), [dot](/images/dependencies-dot.png), [fdp](/images/dependencies-dot.fdp), [neato](/images/dependencies-neato.png), [sfdp](/images/dependencies-sfdp.png), [twopi](/images/dependencies-twopi.png)  

## Known Issues

The swiyu Public Beta Trust Infrastructure was deliberately released at an early stage to enable future ecosystem participants. There may still be minor bugs or security vulnerabilities in the test system. We publish them as [KnownIssues](https://github.com/swiyu-admin-ch/didresolver/issues?q=is%3Aissue%20state%3Aopen%20type%3AKnownIssue) in this repository.

## Contributions and feedback

We welcome any feedback on the code regarding both the implementation and security aspects. Please follow the guidelines for contributing found in [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

This project is licensed under the terms of the MIT license. See the [LICENSE](LICENSE.md) file for details.
