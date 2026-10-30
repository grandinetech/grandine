pub mod cache;
pub mod combined;
pub mod config;
pub mod nonstandard;
pub mod preset;
pub mod redacting_url;
#[cfg(not(target_os = "zkvm"))]
pub mod storage;
pub mod traits;

pub mod phase0 {
    #[cfg(not(target_os = "zkvm"))]
    pub mod balances_patch;
    pub mod beacon_state;
    pub mod consts;
    pub mod containers;
    pub mod primitives;
    #[cfg(not(target_os = "zkvm"))]
    pub mod storage;
    #[cfg(not(target_os = "zkvm"))]
    pub mod stored_validators;
    pub mod validator_list;
    #[cfg(not(target_os = "zkvm"))]
    pub mod validator_list_patch;

    mod container_impls;

    #[cfg(test)]
    mod spec_tests;
}

pub mod altair {
    pub mod beacon_state;
    pub mod consts;
    pub mod containers;
    #[cfg(not(target_os = "zkvm"))]
    pub mod participation_patch;
    pub mod primitives;
    #[cfg(not(target_os = "zkvm"))]
    pub mod storage;

    mod container_impls;

    #[cfg(test)]
    mod spec_tests;
}

pub mod bellatrix {
    pub mod beacon_state;
    pub mod containers;
    pub mod primitives;
    #[cfg(not(target_os = "zkvm"))]
    pub mod storage;

    mod container_impls;

    #[cfg(test)]
    mod spec_tests;
}

pub mod capella {
    pub mod beacon_state;
    pub mod consts;
    pub mod containers;
    pub mod primitives;
    #[cfg(not(target_os = "zkvm"))]
    pub mod storage;

    mod container_impls;

    #[cfg(test)]
    mod spec_tests;
}

pub mod deneb {
    pub mod beacon_state;
    pub mod consts;
    pub mod containers;
    pub mod primitives;
    #[cfg(not(target_os = "zkvm"))]
    pub mod storage;

    mod container_impls;

    #[cfg(test)]
    mod spec_tests;
}

pub mod electra {
    pub mod beacon_state;
    pub mod consts;
    pub mod containers;
    pub mod error;
    #[cfg(not(target_os = "zkvm"))]
    pub mod storage;

    mod container_impls;

    #[cfg(test)]
    mod spec_tests;
}

pub mod fulu {
    pub mod beacon_state;
    pub mod containers;
    pub mod primitives;
    #[cfg(not(target_os = "zkvm"))]
    pub mod storage;

    mod container_impls;

    #[cfg(test)]
    mod spec_tests;
}

pub mod gloas {
    pub mod beacon_state;
    #[cfg(not(target_os = "zkvm"))]
    pub mod builder_list_patch;
    pub mod consts;
    pub mod containers;
    pub mod primitives;
    #[cfg(not(target_os = "zkvm"))]
    pub mod ptc_patch;
    #[cfg(not(target_os = "zkvm"))]
    pub mod storage;
    pub mod validator_list;

    mod container_impls;

    #[cfg(test)]
    mod spec_tests;
}

pub use collections::{
    Balances, PayloadExpectedWithdrawals, PendingConsolidations, PendingDeposits,
    PendingPartialWithdrawals, ProposerLookahead, Ptc, PtcWindow, RandaoMixes, Validators,
};

mod collections;

mod unphased {
    pub mod consts;

    #[cfg(test)]
    pub mod spec_tests;
}
