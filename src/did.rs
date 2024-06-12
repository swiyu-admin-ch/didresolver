use thiserror::Error;
use crate::methods::{resolve_did_tdw, resolve_did_web, DidMethod};
use didtoolbox::didtoolbox::DidDoc;

#[derive(Error, Debug, PartialEq)]
pub enum DidResolveError {
    #[error("the provided did is not supported. Only did:web is supported")]
    DidNotSupported,
    #[error("a http error occured while trying to read the did")]
    HttpError(u16, String),
}
pub struct Did {
    pub parts: Vec<String>,
    method: DidMethod,
}

impl Did {
    pub fn new(text: String) -> Self {
        let mut method = DidMethod::UNKOWN;
        let splitted_did: Vec<String> = text.split(":").map(|x| x.to_string()).collect();

        if splitted_did[0] == "did"  {
            method = match splitted_did[1].as_str() {
                "web" => DidMethod::WEB,
                "tdw" => DidMethod::TDW,
                _ => DidMethod::UNKOWN,
            };
        }

        return Did {
            parts: splitted_did,
            method: method,
        };
    }

    pub fn resolve(&self) -> Result<DidDoc, DidResolveError> {
        match self.method {
            DidMethod::WEB => resolve_did_web(self),
            DidMethod::TDW => resolve_did_tdw(self),
            DidMethod::UNKOWN => Err(DidResolveError::DidNotSupported),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::did::DidResolveError;
    use super::Did;

    #[test]
    fn resolve_did_tdw() {
        let did_url = "did:tdw:raw.githubusercontent.com:frithjofhoppebit:sample_did_tdw:main:gfstmoddgyywmmtfgbswmntemrrdezdegmzdiojzgi3wgmruga4wkztdgfrtayjxheztendbmrstintdgbsggmzyhe3wgzryhbqwmma=";
        let did = Did::new(did_url.to_string());
        let did_doc = did.resolve().unwrap();
        assert_eq!(did_doc.id, did_url);
    }

    #[test]
    fn resolve() {
        let did_url = "did:web:gist.githubusercontent.com:bit-jniestroj:7fb3cce550db5a239b543035298429fe:raw:5e5540c6f67ffe30cca2dfc4bb950a68f412c406";

        let did = Did::new(did_url.to_string());

        did.resolve().unwrap();
    }

    #[test]
    fn resolve_bbs() {
        let did_url = "did:web:gist.githubusercontent.com:bit-jniestroj:f23a80ba382f94fdb93436424f6e4e01:raw:d1bfa1f6c0bfee7687e9fc4ca6f86c2340c6b6f5";

        let did = Did::new(did_url.to_string());

        did.resolve().unwrap();
    }

    #[test]
    fn resolve_did_jwk() {
        let did_url = "did:jwk:ansjdasd";

        let did = Did::new(did_url.to_string());

        let resolved = did.resolve();

        assert_eq!(resolved.is_err(), true);
        assert_eq!(resolved.err().unwrap(), DidResolveError::DidNotSupported);
    }

    #[test]
    fn resolve_did_wrong_url() {
        let did_url = "did:web:example.com";

        let did = Did::new(did_url.to_string());

        let resolved = did.resolve();

        assert_eq!(resolved.is_err(), true);
        assert_eq!(
            resolved.err().unwrap(),
            DidResolveError::HttpError(500, "HTTP status server error (500 Internal Server Error) for url (https://example.com/.well-known/did.json)".to_string())
        );
    }
}
