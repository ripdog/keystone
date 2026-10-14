//! Chain objects for the nftables ruleset. Each chain's rules come from the
//! shared model in `firewall::rules`; this module only adds the chain header
//! (type, hook, priority and policy) and emits the rules in order.
//!
//! The output chain is permissive and has no user rules; see `output`.

pub mod output;

use crate::firewall::generate::emit;
use crate::firewall::rules::{ChainSpec, Verdict};
use nftables::{
    batch::Batch,
    schema::{Chain, NfListObject},
    types::{NfChainPolicy, NfChainType, NfFamily, NfHook},
};
use std::borrow::Cow;

/// Add a chain object to `batch`, followed by its rules.
pub(crate) fn add_chain(
    batch: &mut Batch<'static>,
    table: &'static str,
    spec: &ChainSpec,
    chain_type: NfChainType,
    hook: NfHook,
    priority: i32,
) {
    batch.add(NfListObject::Chain(Chain {
        family: NfFamily::INet,
        table: Cow::Borrowed(table),
        name: Cow::Borrowed(spec.name),
        _type: Some(chain_type),
        hook: Some(hook),
        prio: Some(priority),
        policy: chain_policy(spec.policy),
        ..Default::default()
    }));
    for rule in &spec.rules {
        batch.add(NfListObject::Rule(emit::rule_object(
            rule, table, spec.name,
        )));
    }
}

/// Only drop and accept are valid chain policies; the model never uses others.
fn chain_policy(policy: Option<Verdict>) -> Option<NfChainPolicy> {
    match policy {
        Some(Verdict::Drop) => Some(NfChainPolicy::Drop),
        Some(Verdict::Accept) => Some(NfChainPolicy::Accept),
        Some(
            Verdict::Reject | Verdict::Dnat { .. } | Verdict::Masquerade | Verdict::Redirect { .. },
        )
        | None => None,
    }
}
