// SPDX-License-Identifier: MIT
use didtoolbox::didtoolbox::DidDoc;
use didtoolbox::did_tdw::{TrustDidWebId, TrustDidWeb, DidMethodOperation};

use crate::did::{Did, DidResolveError};

#[derive(PartialEq)]
pub enum DidMethod {
    WEB,
    TDW,
    UNKNOWN,
}

pub fn resolve_did_tdw(did: &Did, did_log_raw: String) -> Result<DidDoc, DidResolveError> {
    let full_did = did.parts.join(":");
    match TrustDidWebId::parse_did_tdw(full_did, Some(false)) {
        Ok(tdw_id) => {
            let scid = tdw_id.get_scid();

            let did_doc_json = match TrustDidWeb::read(scid, did_log_raw) {
                Ok(tdw) => tdw.get_did_doc(),
                Err(e) => return Err(DidResolveError::InvalidDidLog(e.to_string())),
            };

            match serde_json::from_str::<DidDoc>(&did_doc_json) {
                Ok(doc) => Ok(doc),
                Err(e) => {
                    println!("Error parsing DID tdw document: {:?}", e);
                    Err(DidResolveError::HttpError(500, String::from("Error parsing DID tdw document")))
                }
            }
        }
        Err(e) => Err(DidResolveError::DidNotSupported(e.to_string())),
    }
}

pub fn resolve_did_web(did: &Did) -> Result<DidDoc, DidResolveError> {
    let mut url = format!("https://{}", did.parts[2].replace("%3A", ":"));

    if did.parts.len() > 3 {
        let f = format!("/{}/did.json", did.parts[3..].join("/"));
        url += &f;
    } else {
        url += "/.well-known/did.json";
    }

    let res = reqwest::blocking::get(url);

    if !res.is_ok() {
        let reqwest_error = res.err().unwrap();
        return Err(DidResolveError::HttpError(
            reqwest_error.status().unwrap().as_u16(),
            reqwest_error.to_string(),
        ));
    }

    let res = res.unwrap();

    match res.error_for_status() {
        Ok(_res) => {
            let text = _res.text().unwrap();

            let did_doc: DidDoc = serde_json::from_str(text.as_str()).unwrap();

            Ok(did_doc.into())
        }
        Err(err) => Err(DidResolveError::HttpError(
            err.status().unwrap().as_u16(),
            err.to_string(),
        )),
    }
}
