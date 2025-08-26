// SPDX-License-Identifier: MIT

// IGNORE the 'Unused import' warning - it is required by the UniFFI compiler!
use crate::did::*;
use did_sidekicks::did_doc::DidDoc;
use did_sidekicks::did_doc::DidDocExtended;

pub mod did;

uniffi::include_scaffolding!("did");
