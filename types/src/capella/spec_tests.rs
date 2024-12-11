use spec_test_utils::Case;
use test_generator::test_resources;

use crate::{
    preset::{Mainnet, Minimal},
    unphased::spec_tests,
};

mod tested_types {
    pub use crate::{
        altair::containers::{
            ContributionAndProof, SignedContributionAndProof, SyncAggregate,
            SyncAggregatorSelectionData, SyncCommittee, SyncCommitteeContribution,
            SyncCommitteeMessage,
        },
        bellatrix::containers::PowBlock,
        capella::{beacon_state::BeaconState, containers::*},
        phase0::containers::{
            AggregateAndProof, Attestation, AttestationData, AttesterSlashing, BeaconBlockHeader,
            Checkpoint, Deposit, DepositData, DepositMessage, Eth1Data, Fork, ForkData,
            HistoricalBatch, IndexedAttestation, PendingAttestation, ProposerSlashing,
            SignedAggregateAndProof, SignedBeaconBlockHeader, SignedVoluntaryExit, SigningData,
            Validator, VoluntaryExit,
        },
    };
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

// We do not run `consensus-spec-tests/tests/*/capella/ssz_static/Eth1Block/*/*`.
// `Eth1Block` as defined in `consensus-specs` is meant as an example (an "abstract object").
// For whatever reason there are tests for it anyway.

tests_for_type! {
    AggregateAndProof<_>,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/AggregateAndProof/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/AggregateAndProof/*/*",
}

tests_for_type! {
    Attestation<_>,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/Attestation/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/Attestation/*/*",
}

tests_for_type! {
    AttestationData,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/AttestationData/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/AttestationData/*/*",
}

tests_for_type! {
    AttesterSlashing<_>,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/AttesterSlashing/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/AttesterSlashing/*/*",
}

tests_for_type! {
    BeaconBlock<_>,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/BeaconBlock/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/BeaconBlock/*/*",
}

tests_for_type! {
    BeaconBlockBody<_>,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/BeaconBlockBody/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/BeaconBlockBody/*/*",
}

tests_for_type! {
    BeaconBlockHeader,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/BeaconBlockHeader/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/BeaconBlockHeader/*/*",
}

tests_for_type! {
    BeaconState<_>,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/BeaconState/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/BeaconState/*/*",
}

tests_for_type! {
    BlsToExecutionChange,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/BLSToExecutionChange/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/BLSToExecutionChange/*/*",
}

tests_for_type! {
    Checkpoint,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/Checkpoint/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/Checkpoint/*/*",
}

tests_for_type! {
    ContributionAndProof<_>,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/ContributionAndProof/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/ContributionAndProof/*/*",
}

tests_for_type! {
    Deposit,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/Deposit/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/Deposit/*/*",
}

tests_for_type! {
    DepositData,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/DepositData/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/DepositData/*/*",
}

tests_for_type! {
    DepositMessage,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/DepositMessage/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/DepositMessage/*/*",
}

tests_for_type! {
    Eth1Data,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/Eth1Data/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/Eth1Data/*/*",
}

tests_for_type! {
    ExecutionPayload<_>,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/ExecutionPayload/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/ExecutionPayload/*/*",
}

tests_for_type! {
    ExecutionPayloadHeader<_>,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/ExecutionPayloadHeader/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/ExecutionPayloadHeader/*/*",
}

tests_for_type! {
    Fork,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/Fork/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/Fork/*/*",
}

tests_for_type! {
    ForkData,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/ForkData/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/ForkData/*/*",
}

tests_for_type! {
    HistoricalBatch<_>,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/HistoricalBatch/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/HistoricalBatch/*/*",
}

tests_for_type! {
    HistoricalSummary,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/HistoricalSummary/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/HistoricalSummary/*/*",
}

tests_for_type! {
    IndexedAttestation<_>,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/IndexedAttestation/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/IndexedAttestation/*/*",
}

tests_for_type! {
    LightClientBootstrap<_>,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/LightClientBootstrap/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/LightClientBootstrap/*/*",
}

tests_for_type! {
    LightClientFinalityUpdate<_>,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/LightClientFinalityUpdate/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/LightClientFinalityUpdate/*/*",
}

tests_for_type! {
    LightClientHeader<_>,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/LightClientHeader/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/LightClientHeader/*/*",
}

tests_for_type! {
    LightClientOptimisticUpdate<_>,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/LightClientOptimisticUpdate/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/LightClientOptimisticUpdate/*/*",
}

tests_for_type! {
    LightClientUpdate<_>,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/LightClientUpdate/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/LightClientUpdate/*/*",
}

tests_for_type! {
    PendingAttestation<_>,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/PendingAttestation/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/PendingAttestation/*/*",
}

tests_for_type! {
    PowBlock,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/PowBlock/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/PowBlock/*/*",
}

tests_for_type! {
    ProposerSlashing,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/ProposerSlashing/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/ProposerSlashing/*/*",
}

tests_for_type! {
    SignedAggregateAndProof<_>,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/SignedAggregateAndProof/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/SignedAggregateAndProof/*/*",
}

tests_for_type! {
    SignedBeaconBlock<_>,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/SignedBeaconBlock/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/SignedBeaconBlock/*/*",
}

tests_for_type! {
    SignedBeaconBlockHeader,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/SignedBeaconBlockHeader/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/SignedBeaconBlockHeader/*/*",
}

tests_for_type! {
    SignedBlsToExecutionChange,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/SignedBLSToExecutionChange/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/SignedBLSToExecutionChange/*/*",
}

tests_for_type! {
    SignedContributionAndProof<_>,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/SignedContributionAndProof/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/SignedContributionAndProof/*/*",
}

tests_for_type! {
    SignedVoluntaryExit,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/SignedVoluntaryExit/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/SignedVoluntaryExit/*/*",
}

tests_for_type! {
    SigningData,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/SigningData/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/SigningData/*/*",
}

tests_for_type! {
    SyncAggregate<_>,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/SyncAggregate/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/SyncAggregate/*/*",
}

tests_for_type! {
    SyncAggregatorSelectionData,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/SyncAggregatorSelectionData/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/SyncAggregatorSelectionData/*/*",
}

tests_for_type! {
    SyncCommittee<_>,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/SyncCommittee/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/SyncCommittee/*/*",
}

tests_for_type! {
    SyncCommitteeContribution<_>,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/SyncCommitteeContribution/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/SyncCommitteeContribution/*/*",
}

tests_for_type! {
    SyncCommitteeMessage,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/SyncCommitteeMessage/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/SyncCommitteeMessage/*/*",
}

tests_for_type! {
    Validator,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/Validator/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/Validator/*/*",
}

tests_for_type! {
    VoluntaryExit,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/VoluntaryExit/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/VoluntaryExit/*/*",
}

tests_for_type! {
    Withdrawal,
    "consensus-spec-tests/tests/mainnet/capella/ssz_static/Withdrawal/*/*",
    "consensus-spec-tests/tests/minimal/capella/ssz_static/Withdrawal/*/*",
}
