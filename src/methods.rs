// SPDX-License-Identifier: MIT
use didtoolbox::didtoolbox::DidDoc;
use didtoolbox::did_tdw::{TrustDidWebId, TrustDidWeb};
use serde_json::from_str as json_from_str;
use crate::did::{Did, DidResolveError};

pub fn resolve_did_tdw(did: &Did, did_log_raw: String) -> Result<DidDoc, DidResolveError> {
    match TrustDidWebId::parse_did_tdw(did.to_string(), Some(false)) {
        Ok(tdw_id) => {
            let did_doc_json = match TrustDidWeb::read(tdw_id.get_scid(), did_log_raw) {
                Ok(tdw) => tdw.get_did_doc(),
                Err(e) => return Err(DidResolveError::InvalidDidLog(e.to_string())),
            };

            // NOTE Calling unwrap is fully legit here, as TrustDidWeb::read(...) already ensures it is all well with the DID doc.
            Ok(json_from_str::<DidDoc>(&did_doc_json).unwrap())
        }
        Err(e) => {
            //eprintln!("{e}");
            Err(DidResolveError::DidNotSupported(e.to_string()))
        },
    }
}
