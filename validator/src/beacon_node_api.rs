use core::future::Future;

use anyhow::Result;
use types::{
    nonstandard::OwnAttestation,
    phase0::{
        containers::AttestationData,
        primitives::{CommitteeIndex, Slot},
    },
    preset::Preset,
};

/// A beacon node the validator can perform duties against.
///
/// Implementors also implement `Display`, which names them in logs.
pub trait BeaconNodeApi<P: Preset> {
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
}
