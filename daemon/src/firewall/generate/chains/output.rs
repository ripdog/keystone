//! Output chain generation for nftables
//!
//! This module handles generation of the output chain which controls
//! traffic originating from the router itself. By default this is permissive.

use crate::firewall::generate::FILTER_TABLE;
use nftables::{
    batch::Batch,
    schema::{Chain, NfListObject},
    types::{NfChainPolicy, NfChainType, NfFamily, NfHook},
};
use std::borrow::Cow;

/// Generate the output chain (traffic from the router - permissive by default)
pub fn generate_output_chain(batch: &mut Batch<'static>) {
    batch.add(NfListObject::Chain(Chain {
        family: NfFamily::INet,
        table: Cow::Borrowed(FILTER_TABLE),
        name: Cow::Borrowed("output"),
        _type: Some(NfChainType::Filter),
        hook: Some(NfHook::Output),
        prio: Some(0),
        policy: Some(NfChainPolicy::Accept),
        ..Default::default()
    }));
}
