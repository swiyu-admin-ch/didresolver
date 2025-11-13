// SPDX-License-Identifier: MIT

use crate::did_doc::DidDoc;
use crate::did_method_parameters::DidMethodParameter;
use crate::errors::DidResolverError;
use std::collections::HashMap;
use std::sync::Arc;

/// A simple model of a generic `DID` resolver regardless of specification.
///
/// The trait is `dyn` compatible, as elaborated at https://doc.rust-lang.org/reference/items/traits.html#dyn-compatibility
pub trait DidResolver {
    // CAUTION Beware of "dyn" compatibility for traits,
    //         as elaborated at https://doc.rust-lang.org/reference/items/traits.html#dyn-compatibility

    /// The getter for a [`DidDoc`] object collected during the resolution process.
    fn get_did_doc_obj(&self) -> DidDoc;

    /// The method aims at returning a map of all [`DidMethodParameter`] collected during resolution process.
    fn collect_did_method_parameters_map(
        &self,
    ) -> Result<HashMap<String, Arc<DidMethodParameter>>, DidResolverError>;
}
