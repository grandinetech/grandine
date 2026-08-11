use core::future::Future;

use anyhow::Result;
use http_api_utils::ValidatorAttesterDutyResponse;
use p2p::BeaconCommitteeSubscription;
use types::{
    nonstandard::OwnAttestation,
    phase0::{
        containers::AttestationData,
        primitives::{CommitteeIndex, Epoch, H256, Slot, ValidatorIndex},
    },
    preset::Preset,
};

pub struct AttesterDuties {
    pub dependent_root: H256,
    pub duties: Vec<ValidatorAttesterDutyResponse>,
}

/// A beacon node the validator can perform duties against.
pub trait BeaconNodeApi<P: Preset> {
    // A remote beacon node reports the dependent root only alongside duties, so `validator_index`
    // names the one validator whose duties are requested to obtain it. The built-in node derives
    // the root without asking anything and is given `None`.
    fn dependent_root(
        &self,
        epoch: Epoch,
        validator_index: Option<ValidatorIndex>,
    ) -> impl Future<Output = Result<H256>> + Send;

    /// <https://ethereum.github.io/beacon-APIs/#/Validator/getAttesterDuties>
    fn attester_duties(
        &self,
        epoch: Epoch,
        validator_indices: &[ValidatorIndex],
    ) -> impl Future<Output = Result<AttesterDuties>> + Send;

    /// <https://ethereum.github.io/beacon-APIs/#/Validator/produceAttestationData>
    fn attestation_data(
        &self,
        slot: Slot,
        committee_index: CommitteeIndex,
    ) -> impl Future<Output = Result<AttestationData>> + Send;

    /// <https://ethereum.github.io/beacon-APIs/#/Beacon/submitPoolAttestationsV2>
    fn publish_singular_attestations(
        &self,
        attestations: &[OwnAttestation<P>],
    ) -> impl Future<Output = Result<()>> + Send;

    /// <https://ethereum.github.io/beacon-APIs/#/Validator/prepareBeaconCommitteeSubnet>
    fn subscribe_to_beacon_committees(
        &self,
        current_slot: Slot,
        subscriptions: &[BeaconCommitteeSubscription],
    ) -> impl Future<Output = Result<()>> + Send;
}
