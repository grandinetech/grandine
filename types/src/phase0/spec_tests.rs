use spec_test_utils::Case;
use test_generator::test_resources;

use crate::{
    preset::{Mainnet, Minimal},
    unphased::spec_tests,
};

mod tested_types {
    pub use crate::phase0::{beacon_state::BeaconState, containers::*};
}

macro_rules! tests_for_type {
    (
        $type: ident $(<_ $bracket: tt)?,
        $mainnet_glob: literal,
        $minimal_glob: literal,
    ) => {
        #[expect(non_snake_case)]
        mod $type {
            use super::*;

            #[test_resources($mainnet_glob)]
            fn mainnet(case: Case) {
                spec_tests::run_spec_test_case::<tested_types::$type$(<Mainnet $bracket)?>(case);
            }

            #[test_resources($minimal_glob)]
            fn minimal(case: Case) {
                spec_tests::run_spec_test_case::<tested_types::$type$(<Minimal $bracket)?>(case);
            }
        }
    };
}

// We do not run `consensus-spec-tests/tests/*/phase0/ssz_static/Eth1Block/*/*`.
// `Eth1Block` as defined in `consensus-specs` is meant as an example (an "abstract object").
// For whatever reason there are tests for it anyway.

tests_for_type! {
    AggregateAndProof<_>,
    "consensus-spec-tests/tests/mainnet/phase0/ssz_static/AggregateAndProof/*/*",
    "consensus-spec-tests/tests/minimal/phase0/ssz_static/AggregateAndProof/*/*",
}

tests_for_type! {
    Attestation<_>,
    "consensus-spec-tests/tests/mainnet/phase0/ssz_static/Attestation/*/*",
    "consensus-spec-tests/tests/minimal/phase0/ssz_static/Attestation/*/*",
}

tests_for_type! {
    AttestationData,
    "consensus-spec-tests/tests/mainnet/phase0/ssz_static/AttestationData/*/*",
    "consensus-spec-tests/tests/minimal/phase0/ssz_static/AttestationData/*/*",
}

tests_for_type! {
    AttesterSlashing<_>,
    "consensus-spec-tests/tests/mainnet/phase0/ssz_static/AttesterSlashing/*/*",
    "consensus-spec-tests/tests/minimal/phase0/ssz_static/AttesterSlashing/*/*",
}

tests_for_type! {
    BeaconBlock<_>,
    "consensus-spec-tests/tests/mainnet/phase0/ssz_static/BeaconBlock/*/*",
    "consensus-spec-tests/tests/minimal/phase0/ssz_static/BeaconBlock/*/*",
}

tests_for_type! {
    BeaconBlockBody<_>,
    "consensus-spec-tests/tests/mainnet/phase0/ssz_static/BeaconBlockBody/*/*",
    "consensus-spec-tests/tests/minimal/phase0/ssz_static/BeaconBlockBody/*/*",
}

tests_for_type! {
    BeaconBlockHeader,
    "consensus-spec-tests/tests/mainnet/phase0/ssz_static/BeaconBlockHeader/*/*",
    "consensus-spec-tests/tests/minimal/phase0/ssz_static/BeaconBlockHeader/*/*",
}

tests_for_type! {
    BeaconState<_>,
    "consensus-spec-tests/tests/mainnet/phase0/ssz_static/BeaconState/*/*",
    "consensus-spec-tests/tests/minimal/phase0/ssz_static/BeaconState/*/*",
}

tests_for_type! {
    Checkpoint,
    "consensus-spec-tests/tests/mainnet/phase0/ssz_static/Checkpoint/*/*",
    "consensus-spec-tests/tests/minimal/phase0/ssz_static/Checkpoint/*/*",
}

tests_for_type! {
    Deposit,
    "consensus-spec-tests/tests/mainnet/phase0/ssz_static/Deposit/*/*",
    "consensus-spec-tests/tests/minimal/phase0/ssz_static/Deposit/*/*",
}

tests_for_type! {
    DepositData,
    "consensus-spec-tests/tests/mainnet/phase0/ssz_static/DepositData/*/*",
    "consensus-spec-tests/tests/minimal/phase0/ssz_static/DepositData/*/*",
}

tests_for_type! {
    DepositMessage,
    "consensus-spec-tests/tests/mainnet/phase0/ssz_static/DepositMessage/*/*",
    "consensus-spec-tests/tests/minimal/phase0/ssz_static/DepositMessage/*/*",
}

tests_for_type! {
    Eth1Data,
    "consensus-spec-tests/tests/mainnet/phase0/ssz_static/Eth1Data/*/*",
    "consensus-spec-tests/tests/minimal/phase0/ssz_static/Eth1Data/*/*",
}

tests_for_type! {
    Fork,
    "consensus-spec-tests/tests/mainnet/phase0/ssz_static/Fork/*/*",
    "consensus-spec-tests/tests/minimal/phase0/ssz_static/Fork/*/*",
}

tests_for_type! {
    ForkData,
    "consensus-spec-tests/tests/mainnet/phase0/ssz_static/ForkData/*/*",
    "consensus-spec-tests/tests/minimal/phase0/ssz_static/ForkData/*/*",
}

tests_for_type! {
    HistoricalBatch<_>,
    "consensus-spec-tests/tests/mainnet/phase0/ssz_static/HistoricalBatch/*/*",
    "consensus-spec-tests/tests/minimal/phase0/ssz_static/HistoricalBatch/*/*",
}

tests_for_type! {
    IndexedAttestation<_>,
    "consensus-spec-tests/tests/mainnet/phase0/ssz_static/IndexedAttestation/*/*",
    "consensus-spec-tests/tests/minimal/phase0/ssz_static/IndexedAttestation/*/*",
}

tests_for_type! {
    PendingAttestation<_>,
    "consensus-spec-tests/tests/mainnet/phase0/ssz_static/PendingAttestation/*/*",
    "consensus-spec-tests/tests/minimal/phase0/ssz_static/PendingAttestation/*/*",
}

tests_for_type! {
    ProposerSlashing,
    "consensus-spec-tests/tests/mainnet/phase0/ssz_static/ProposerSlashing/*/*",
    "consensus-spec-tests/tests/minimal/phase0/ssz_static/ProposerSlashing/*/*",
}

tests_for_type! {
    SignedAggregateAndProof<_>,
    "consensus-spec-tests/tests/mainnet/phase0/ssz_static/SignedAggregateAndProof/*/*",
    "consensus-spec-tests/tests/minimal/phase0/ssz_static/SignedAggregateAndProof/*/*",
}

tests_for_type! {
    SignedBeaconBlock<_>,
    "consensus-spec-tests/tests/mainnet/phase0/ssz_static/SignedBeaconBlock/*/*",
    "consensus-spec-tests/tests/minimal/phase0/ssz_static/SignedBeaconBlock/*/*",
}

tests_for_type! {
    SignedBeaconBlockHeader,
    "consensus-spec-tests/tests/mainnet/phase0/ssz_static/SignedBeaconBlockHeader/*/*",
    "consensus-spec-tests/tests/minimal/phase0/ssz_static/SignedBeaconBlockHeader/*/*",
}

tests_for_type! {
    SignedVoluntaryExit,
    "consensus-spec-tests/tests/mainnet/phase0/ssz_static/SignedVoluntaryExit/*/*",
    "consensus-spec-tests/tests/minimal/phase0/ssz_static/SignedVoluntaryExit/*/*",
}

tests_for_type! {
    SigningData,
    "consensus-spec-tests/tests/mainnet/phase0/ssz_static/SigningData/*/*",
    "consensus-spec-tests/tests/minimal/phase0/ssz_static/SigningData/*/*",
}

tests_for_type! {
    Validator,
    "consensus-spec-tests/tests/mainnet/phase0/ssz_static/Validator/*/*",
    "consensus-spec-tests/tests/minimal/phase0/ssz_static/Validator/*/*",
}

tests_for_type! {
    VoluntaryExit,
    "consensus-spec-tests/tests/mainnet/phase0/ssz_static/VoluntaryExit/*/*",
    "consensus-spec-tests/tests/minimal/phase0/ssz_static/VoluntaryExit/*/*",
}
