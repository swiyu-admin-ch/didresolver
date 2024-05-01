use std::sync::Arc;

use crate::did::{Did, DidDoc, DidResolveError};

#[derive(PartialEq)]
pub enum DidMethod {
    WEB,
    UNKOWN,
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

            Ok(did_doc)
        }
        Err(err) => Err(DidResolveError::HttpError(
            err.status().unwrap().as_u16(),
            err.to_string(),
        )),
    }
}
