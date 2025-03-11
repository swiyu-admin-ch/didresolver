// SPDX-License-Identifier: MIT

use crate::did::{Did, DidResolveError};
use didtoolbox::did_tdw::{TrustDidWeb, TrustDidWebId};
use didtoolbox::didtoolbox::DidDoc;
use std::sync::Arc;

pub fn resolve_did_tdw(did: &Did, did_log_raw: String) -> Result<Arc<DidDoc>, DidResolveError> {
    match TrustDidWebId::parse_did_tdw(did.to_string()) {
        Ok(_) => match TrustDidWeb::read(did.to_string(), did_log_raw) {
            Ok(tdw) => match tdw.get_did_doc_obj() {
                Ok(doc) => Ok(doc),
                Err(e) => Err(DidResolveError::InvalidDidLog(e.to_string())),
            },
            Err(e) => Err(DidResolveError::InvalidDidLog(e.to_string())),
        },
        Err(e) => Err(DidResolveError::DidNotSupported(e.to_string())),
    }
}
