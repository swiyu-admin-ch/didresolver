// SPDX-License-Identifier: MIT

// IGNORE the 'Unused import' warning - it is required by the UniFFI compiler!
use crate::did::*;
// IGNORE the 'Unused import' warning - it is required by the UniFFI compiler!
use did_sidekicks::did_doc::DidDoc;

pub mod did;

uniffi::include_scaffolding!("did");
