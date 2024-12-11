// Having `#[expect(dead_code)]` declared directly on `reason` attributes results in
// `unfulfilled_lint_expectations` false positive warning.
// Declaring this for the whole module as a temporary workaround. Using `expect` here triggers
// the same warning.
// TODO(Grandine Team): consider removing this workaround when upgrading from Rust 1.82.0.
//
// `ExplainedProposerSlashing.reason` is used for logging through the `Debug` impl.
// `ExplainedAttesterSlashing.reason` is used for logging through the `Debug` impl.
// Implementing `Display` might be more appropriate but also more verbose.
#![allow(
    dead_code,
    reason = "Explained*Slashing.reason is used for logging through the `Debug` impl."
)]
use types::{
    phase0::containers::{AttesterSlashing, ProposerSlashing},
    preset::Preset,
};

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum ProposerSlashingReason {
    DoubleVote,
}

#[derive(Debug)]
pub struct ExplainedProposerSlashing {
    pub slashing: ProposerSlashing,
    pub reason: ProposerSlashingReason,
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum AttesterSlashingReason {
    DoubleVote,
    Surrounding,
    Surrounded,
}

#[derive(Debug)]
pub struct ExplainedAttesterSlashing<P: Preset> {
    pub slashing: AttesterSlashing<P>,
    pub reason: AttesterSlashingReason,
}
