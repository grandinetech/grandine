//! Fast Confirmation Rule (FCR) — isolated from the fork-choice `Store`.
//!
//! Entry points live on `FastConfirmationStore` in [`store`](self::store); all math helpers
//! are free functions in [`rules`](self::rules) operating on the pre-computed types defined in
//! [`types`](self::types).
//!
//! Spec: <https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.9/specs/phase0/fast-confirmation.md>

mod committees;
mod rules;
mod store;
mod types;

// `pub` here is equivalent to `pub(crate)` because `mod fast_confirmation` is crate-private
// at the crate root (see `lib.rs`). `Store::fcr_build_chain_info` and `fcr_build_ffg_data`
// reach these via the `fast_confirmation::NAME` shortcut; external crates never see them.
pub use self::committees::fcr_slot_committee_participants;
pub use self::rules::{
    compute_adversarial_weight, compute_proposer_score, estimate_committee_weight_between_slots,
    get_voting_source_epoch,
};
pub use self::types::{ChainInfo, FcrFfgData};

// `FastConfirmationStore` is re-exported to external crates through `crate::lib.rs`'s
// `pub use crate::fast_confirmation::FastConfirmationStore`.
pub use self::store::FastConfirmationStore;
