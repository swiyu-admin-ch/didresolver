use crate::did::*;
use didtoolbox::didtoolbox::DidDoc;

pub mod did;
pub mod methods;

uniffi::include_scaffolding!("did");
