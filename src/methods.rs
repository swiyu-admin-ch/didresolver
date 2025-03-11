// SPDX-License-Identifier: MIT

use crate::did::{Did, DidResolveError};
use didtoolbox::did_tdw::{TrustDidWeb, TrustDidWebId};
use didtoolbox::didtoolbox::DidDoc;
use serde_json::from_str as json_from_str;

pub fn resolve_did_tdw(did: &Did, did_log_raw: String) -> Result<DidDoc, DidResolveError> {
    match TrustDidWebId::parse_did(did.to_string()) {
        Ok(_) => {
            let did_doc_json = match TrustDidWeb::read_log(did.to_string(), did_log_raw) {
                Ok(tdw) => tdw.get_did_doc(),
                Err(e) => return Err(DidResolveError::InvalidDidLog(e.to_string())),
            };

            // NOTE Calling unwrap is fully legit here, as TrustDidWeb::read(...) already ensures it is all well with the DID doc.
            Ok(json_from_str::<DidDoc>(&did_doc_json).unwrap())
        }
        Err(e) => Err(DidResolveError::DidNotSupported(e.to_string())),
    }
}
