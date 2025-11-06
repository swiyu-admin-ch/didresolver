// SPDX-License-Identifier: MIT

#[allow(unused_imports, reason = "required by the UniFFI compiler!")]
#[expect(clippy::allow_attributes, reason = "..")]
use crate::did::*;

pub mod did;

#[allow(unused_imports, reason = "required by the UniFFI compiler!")]
#[expect(clippy::allow_attributes, reason = "..")]
use did_sidekicks::did_doc::{DidDoc, DidDocExtended};
//use did_sidekicks::errors::DidResolverError;

uniffi::include_scaffolding!("did");
