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
    // `ExplainedProposerSlashing.reason` is used for logging through the `Debug` impl.
    // Implementing `Display` might be more appropriate but also more verbose.
    #[allow(dead_code)]
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
    // `ExplainedAttesterSlashing.reason` is used for logging through the `Debug` impl.
    // Implementing `Display` might be more appropriate but also more verbose.
    #[allow(dead_code)]
    pub reason: AttesterSlashingReason,
}
