use core::{
    sync::atomic::{AtomicU8, Ordering},
    time::Duration,
};
use std::sync::Arc;

use anyhow::{Error as AnyhowError, Result, bail, ensure};
use derive_more::Display;
use helper_functions::misc;
use http_api_utils::{ETH_CONSENSUS_VERSION, EthResponse, ValidatorAttesterDutyResponse};
use logging::{debug_with_peers, info_with_peers, warn_with_peers};
use p2p::BeaconCommitteeSubscription;
use reqwest::{Client, Response, StatusCode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use ssz::SszHash as _;
use thiserror::Error;
use types::{
    combined::{Attestation, SignedAggregateAndProof},
    config::Config as ChainConfig,
    electra::containers::Attestation as ElectraAttestation,
    gloas::containers::Attestation as GloasAttestation,
    nonstandard::{OwnAttestation, Phase},
    phase0::containers::Attestation as Phase0Attestation,
    phase0::{
        containers::AttestationData,
        primitives::{CommitteeIndex, Epoch, H256, Slot, ValidatorIndex, Version},
    },
    preset::Preset,
    redacting_url::RedactingUrl,
};

use crate::{
    beacon_node_api::{AttesterDuties, BeaconNodeApi},
    health::Health,
};

const REQUEST_TIMEOUT_QUOTIENT: u32 = 4;

#[derive(Debug, Error)]
enum Error {
    #[error(
        "beacon node at {url} is on a different network \
         (expected genesis fork version {expected:?}, received {actual:?})"
    )]
    NetworkMismatch {
        url: String,
        expected: Version,
        actual: Version,
    },
    #[error(
        "beacon node returned an aggregate covering committees {actual:?} \
         where only committee {expected} was requested"
    )]
    UnexpectedCommittees {
        expected: CommitteeIndex,
        actual: Vec<CommitteeIndex>,
    },
    #[error("beacon node reported {reported} data where {expected} was expected")]
    UnexpectedVersion { expected: Phase, reported: Phase },
    #[error("request to beacon node at {url} failed with status {status}: {body}")]
    Response {
        url: String,
        status: StatusCode,
        body: String,
    },
}

#[derive(Deserialize)]
struct Genesis {
    genesis_fork_version: Version,
}

/// The request body of `getAttesterDuties`, whose indices are quoted in JSON.
#[derive(Serialize)]
#[serde(transparent)]
struct ValidatorIndices(
    #[serde(with = "serde_utils::string_or_native_sequence")] Vec<ValidatorIndex>,
);

// `head_slot` and `sync_distance` are ignored: neither separates a node that has fallen behind
// from a chain with missed slots.
#[derive(Deserialize)]
struct SyncingStatus {
    is_syncing: bool,
    #[serde(default)]
    is_optimistic: bool,
    #[serde(default)]
    el_offline: bool,
}

pub enum NetworkCheck {
    Matches,
    Mismatch(AnyhowError),
    Unreachable(AnyhowError),
}

/// A beacon node reached over <https://ethereum.github.io/beacon-APIs/>.
#[derive(Display)]
#[display("{url}")]
pub struct RemoteBeaconNode {
    chain_config: Arc<ChainConfig>,
    client: Client,
    url: RedactingUrl,
    /// A [`Health`] discriminant. Atomic because it is read on the duty path.
    health: AtomicU8,
}

impl RemoteBeaconNode {
    #[must_use]
    pub const fn new(chain_config: Arc<ChainConfig>, client: Client, url: RedactingUrl) -> Self {
        Self {
            chain_config,
            client,
            url,
            health: AtomicU8::new(Health::Unknown.as_u8()),
        }
    }

    #[must_use]
    pub fn health(&self) -> Health {
        Health::from_u8(self.health.load(Ordering::Relaxed))
    }

    pub async fn refresh_health(&self) {
        let previous = self.health();
        let health = self.poll_health().await;

        if health != previous {
            info_with_peers!("beacon node at {} is now {health:?}", self.url);
        }

        self.health.store(health.as_u8(), Ordering::Relaxed);
    }

    async fn poll_health(&self) -> Health {
        match self.check_network().await {
            NetworkCheck::Matches => {}
            NetworkCheck::Mismatch(error) => {
                warn_with_peers!(
                    "beacon node at {} is on a different network: {error:?}",
                    self.url,
                );

                return Health::Incompatible;
            }
            NetworkCheck::Unreachable(error) => {
                debug_with_peers!(
                    "beacon node at {} could not be reached: {error:?}",
                    self.url,
                );

                return Health::Unreachable;
            }
        }

        match self.syncing_status().await {
            Ok(status) => Health::from_syncing_status(
                status.el_offline,
                status.is_syncing,
                status.is_optimistic,
            ),
            Err(error) => {
                debug_with_peers!(
                    "beacon node at {} did not report its sync status: {error:?}",
                    self.url,
                );

                Health::Unreachable
            }
        }
    }

    async fn syncing_status(&self) -> Result<SyncingStatus> {
        let url = self.endpoint("/eth/v1/node/syncing")?;

        let response = self
            .client
            .get(url.into_url())
            .timeout(self.request_timeout())
            .send()
            .await?;

        self.parse_data(response).await
    }

    /// Short enough that a node that does not answer leaves time to try another within the slot.
    fn request_timeout(&self) -> Duration {
        self.chain_config
            .slot_duration_ms
            .checked_div(REQUEST_TIMEOUT_QUOTIENT)
            .expect("REQUEST_TIMEOUT_QUOTIENT is not zero")
    }

    // The two failure modes are separated because they warrant different responses.
    pub async fn check_network(&self) -> NetworkCheck {
        match self.ensure_same_network().await {
            Ok(()) => NetworkCheck::Matches,
            Err(error) => {
                if matches!(error.downcast_ref(), Some(Error::NetworkMismatch { .. })) {
                    NetworkCheck::Mismatch(error)
                } else {
                    NetworkCheck::Unreachable(error)
                }
            }
        }
    }

    fn endpoint(&self, path: &str) -> Result<RedactingUrl> {
        self.url.join(path).map_err(Into::into)
    }

    /// Checked once. Prevents producing attestations signed under the wrong domain.
    async fn ensure_same_network(&self) -> Result<()> {
        let url = self.endpoint("/eth/v1/beacon/genesis")?;

        let response = self
            .client
            .get(url.into_url())
            .timeout(self.request_timeout())
            .send()
            .await?;

        let genesis = self.parse_data::<Genesis>(response).await?;
        let expected = self.chain_config.genesis_fork_version;

        ensure!(
            genesis.genesis_fork_version == expected,
            Error::NetworkMismatch {
                url: self.url.to_string(),
                expected,
                actual: genesis.genesis_fork_version,
            },
        );

        Ok(())
    }

    async fn parse_data<T: DeserializeOwned>(&self, response: Response) -> Result<T> {
        let response = self.check_status(response).await?;
        Ok(response.json::<EthResponse<T>>().await?.into_data())
    }

    async fn parse_versioned_data<T: DeserializeOwned>(
        &self,
        response: Response,
        expected: Phase,
    ) -> Result<T> {
        let response = self.check_status(response).await?;

        let (data, reported) = response
            .json::<EthResponse<T>>()
            .await?
            .into_data_and_version();

        check_version(expected, reported)?;

        Ok(data)
    }

    async fn check_status(&self, response: Response) -> Result<Response> {
        let status = response.status();

        if status.is_success() {
            return Ok(response);
        }

        let body = response.text().await.unwrap_or_default();

        bail!(Error::Response {
            url: self.url.to_string(),
            status,
            body,
        })
    }
}

impl<P: Preset> BeaconNodeApi<P> for RemoteBeaconNode {
    async fn dependent_root(
        &self,
        epoch: Epoch,
        validator_index: Option<ValidatorIndex>,
    ) -> Result<H256> {
        <Self as BeaconNodeApi<P>>::attester_duties(self, epoch, validator_index.as_slice())
            .await
            .map(|duties| duties.dependent_root)
    }

    async fn attester_duties(
        &self,
        epoch: Epoch,
        validator_indices: &[ValidatorIndex],
    ) -> Result<AttesterDuties> {
        let url = self.endpoint(format!("/eth/v1/validator/duties/attester/{epoch}").as_str())?;

        let response = self
            .client
            .post(url.into_url())
            .json(&ValidatorIndices(validator_indices.to_vec()))
            .timeout(self.request_timeout())
            .send()
            .await?;

        let response = self.check_status(response).await?;

        let (duties, dependent_root) = response
            .json::<EthResponse<Vec<ValidatorAttesterDutyResponse>>>()
            .await?
            .into_data_and_dependent_root();

        let dependent_root = dependent_root.ok_or_else(|| {
            AnyhowError::msg(format!(
                "beacon node at {} did not report a dependent root for attester duties",
                self.url,
            ))
        })?;

        debug_with_peers!(
            "{} produced {} attester duties for epoch {epoch}",
            self.url,
            duties.len(),
        );

        Ok(AttesterDuties {
            dependent_root,
            duties,
        })
    }

    async fn attestation_data(
        &self,
        slot: Slot,
        committee_index: CommitteeIndex,
    ) -> Result<AttestationData> {
        let url = self.endpoint(
            format!(
                "/eth/v1/validator/attestation_data?slot={slot}&committee_index={committee_index}"
            )
            .as_str(),
        )?;

        let response = self
            .client
            .get(url.into_url())
            .timeout(self.request_timeout())
            .send()
            .await?;

        self.parse_data(response).await
    }

    async fn aggregate_attestation(
        &self,
        data: AttestationData,
        committee_index: CommitteeIndex,
    ) -> Result<Attestation<P>> {
        let url = self.endpoint(&aggregate_attestation_path(data, committee_index))?;

        let response = self
            .client
            .get(url.into_url())
            .timeout(self.request_timeout())
            .send()
            .await?;

        // Electra and Gloas attestations have the same fields, so untagged deserialization would
        // always read a Gloas one as Electra.
        let phase = self.chain_config.phase_at_slot::<P>(data.slot);

        let attestation = if phase < Phase::Electra {
            self.parse_versioned_data::<Phase0Attestation<P>>(response, phase)
                .await
                .map(Attestation::Phase0)?
        } else if phase < Phase::Gloas {
            self.parse_versioned_data::<ElectraAttestation<P>>(response, phase)
                .await
                .map(Attestation::Electra)?
        } else {
            self.parse_versioned_data::<GloasAttestation<P>>(response, phase)
                .await
                .map(Attestation::Gloas)?
        };

        ensure_requested_committee(&attestation, committee_index)?;

        Ok(attestation)
    }

    async fn publish_singular_attestations(
        &self,
        attestations: &[OwnAttestation<P>],
    ) -> Result<()> {
        let Some(first) = attestations.first() else {
            return Ok(());
        };

        let phase = self
            .chain_config
            .phase_at_slot::<P>(first.attestation.data().slot);

        // `combined::Attestation` serializes untagged, so this is a `SingleAttestation` from Electra
        // on and a phase 0 `Attestation` before it, exactly as the endpoint expects.
        let bodies = attestations
            .iter()
            .map(|own_attestation| &own_attestation.attestation)
            .collect::<Vec<_>>();

        let url = self.endpoint("/eth/v2/beacon/pool/attestations")?;

        let response = self
            .client
            .post(url.into_url())
            .header(ETH_CONSENSUS_VERSION, phase.as_ref())
            .json(&bodies)
            .timeout(self.request_timeout())
            .send()
            .await?;

        self.check_status(response).await?;

        debug_with_peers!("published {} attestations to {}", bodies.len(), self.url);

        Ok(())
    }

    async fn publish_aggregates_and_proofs(
        &self,
        aggregates_and_proofs: &[Arc<SignedAggregateAndProof<P>>],
    ) -> Result<()> {
        let Some(first) = aggregates_and_proofs.first() else {
            return Ok(());
        };

        let phase = self.chain_config.phase_at_slot::<P>(first.slot());
        let url = self.endpoint("/eth/v2/validator/aggregate_and_proofs")?;

        let response = self
            .client
            .post(url.into_url())
            .header(ETH_CONSENSUS_VERSION, phase.as_ref())
            .json(&aggregates_and_proofs)
            .timeout(self.request_timeout())
            .send()
            .await?;

        self.check_status(response).await?;

        debug_with_peers!(
            "published {} aggregates and proofs to {}",
            aggregates_and_proofs.len(),
            self.url,
        );

        Ok(())
    }

    async fn subscribe_to_beacon_committees(
        &self,
        _current_slot: Slot,
        subscriptions: &[BeaconCommitteeSubscription],
    ) -> Result<()> {
        let url = self.endpoint("/eth/v1/validator/beacon_committee_subscriptions")?;

        let response = self
            .client
            .post(url.into_url())
            .json(&subscriptions)
            .timeout(self.request_timeout())
            .send()
            .await?;

        self.check_status(response).await?;

        debug_with_peers!(
            "subscribed to {} beacon committees on {}",
            subscriptions.len(),
            self.url,
        );

        Ok(())
    }
}

// Aggregation bits from Electra on span every committee in `committee_bits`, so a position in the
// requested committee only indexes them when that is the sole committee covered.
fn ensure_requested_committee<P: Preset>(
    attestation: &Attestation<P>,
    committee_index: CommitteeIndex,
) -> Result<()> {
    let Some(committee_bits) = attestation.committee_bits() else {
        return Ok(());
    };

    let actual = misc::get_committee_indices::<P>(committee_bits).collect::<Vec<_>>();

    ensure!(
        actual == [committee_index],
        Error::UnexpectedCommittees {
            expected: committee_index,
            actual,
        },
    );

    Ok(())
}

fn check_version(expected: Phase, reported: Option<Phase>) -> Result<()> {
    if let Some(reported) = reported {
        ensure!(
            reported == expected,
            Error::UnexpectedVersion { expected, reported },
        );
    }

    Ok(())
}

fn aggregate_attestation_path(data: AttestationData, committee_index: CommitteeIndex) -> String {
    format!(
        "/eth/v2/validator/aggregate_attestation?attestation_data_root={:?}\
         &slot={}&committee_index={committee_index}",
        data.hash_tree_root(),
        data.slot,
    )
}

#[cfg(test)]
mod tests {
    use bls::{
        AggregateSignatureBytes, PublicKeyBytes, SignatureBytes, traits::SignatureBytes as _,
    };
    use serde_json::json;
    use ssz::BitVector;
    use types::{
        combined::Attestation,
        electra::containers::{
            AggregateAndProof as ElectraAggregateAndProof, Attestation as ElectraAttestation,
            SignedAggregateAndProof as ElectraSignedAggregateAndProof, SingleAttestation,
        },
        phase0::primitives::H256,
        preset::Mainnet,
    };

    use super::*;

    // The endpoint takes a bare array of quoted validator indices.
    #[test]
    fn serializes_attester_duties_request_body() -> Result<()> {
        let body = serde_json::to_value(ValidatorIndices(vec![1, 2]))?;

        assert_eq!(body, json!(["1", "2"]));

        Ok(())
    }

    // The dependent root lives in the response envelope rather than the duties themselves.
    #[test]
    fn parses_attester_duties_response() -> Result<()> {
        let response = json!({
            "dependent_root":
                "0x0404040404040404040404040404040404040404040404040404040404040404",
            "execution_optimistic": false,
            "data": [{
                "pubkey": PublicKeyBytes::zero(),
                "validator_index": "1",
                "committee_index": "2",
                "committee_length": "3",
                "committees_at_slot": "4",
                "validator_committee_index": "5",
                "slot": "6",
            }],
        });

        let (duties, dependent_root) =
            serde_json::from_value::<EthResponse<Vec<ValidatorAttesterDutyResponse>>>(response)?
                .into_data_and_dependent_root();

        assert_eq!(dependent_root, Some(H256::repeat_byte(4)));

        assert_eq!(
            duties,
            [ValidatorAttesterDutyResponse {
                committee_index: 2,
                committee_length: 3,
                committees_at_slot: 4,
                pubkey: PublicKeyBytes::zero(),
                slot: 6,
                validator_committee_index: 5,
                validator_index: 1,
            }],
        );

        Ok(())
    }

    // The node names itself by URL, so logging it must not leak credentials.
    #[test]
    fn display_is_the_redacted_url() -> Result<()> {
        let node = RemoteBeaconNode::new(
            Arc::new(ChainConfig::mainnet()),
            Client::new(),
            "http://user:password@localhost:5052/".parse()?,
        );

        assert_eq!(node.to_string(), "http://*:*@localhost:5052/");

        Ok(())
    }

    // A request must end early enough to leave time for another node.
    #[test]
    fn request_timeout_is_a_quarter_of_a_slot() -> Result<()> {
        let node = RemoteBeaconNode::new(
            Arc::new(ChainConfig::mainnet()),
            Client::new(),
            "http://localhost:5052/".parse()?,
        );

        assert_eq!(node.request_timeout(), Duration::from_secs(3));

        Ok(())
    }

    #[test]
    fn parses_genesis_response() -> Result<()> {
        let response = json!({
            "data": {
                "genesis_time": "1590832934",
                "genesis_validators_root":
                    "0x0000000000000000000000000000000000000000000000000000000000000000",
                "genesis_fork_version": "0x00000001",
            },
        });

        let data = serde_json::from_value::<EthResponse<Genesis>>(response)?.into_data();

        assert_eq!(data.genesis_fork_version, Version::from([0, 0, 0, 1]));

        Ok(())
    }

    #[test]
    fn parses_attestation_data_response() -> Result<()> {
        let response = json!({
            "data": {
                "slot": "1",
                "index": "1",
                "beacon_block_root":
                    "0x0101010101010101010101010101010101010101010101010101010101010101",
                "source": {
                    "epoch": "2",
                    "root": "0x0202020202020202020202020202020202020202020202020202020202020202",
                },
                "target": {
                    "epoch": "3",
                    "root": "0x0303030303030303030303030303030303030303030303030303030303030303",
                },
            },
        });

        let data = serde_json::from_value::<EthResponse<AttestationData>>(response)?.into_data();

        assert_eq!(data.slot, 1);
        assert_eq!(data.index, 1);
        assert_eq!(data.beacon_block_root, H256::repeat_byte(1));
        assert_eq!(data.source.epoch, 2);
        assert_eq!(data.target.epoch, 3);

        Ok(())
    }

    // The publication body is the bare attestation, not an enveloped or tagged one.
    #[test]
    fn serializes_single_attestation_body() -> Result<()> {
        let attestation = Attestation::<Mainnet>::from(SingleAttestation {
            committee_index: 4,
            attester_index: 5,
            data: AttestationData::default(),
            signature: SignatureBytes::empty(),
        });

        let body = serde_json::to_value([&attestation])?;

        assert_eq!(body[0]["committee_index"], json!("4"));
        assert_eq!(body[0]["attester_index"], json!("5"));
        assert_eq!(body[0]["data"]["slot"], json!("0"));

        Ok(())
    }

    fn electra_aggregate_body() -> serde_json::Value {
        json!({
            "aggregation_bits": "0x07",
            "data": {
                "slot": "6",
                "index": "0",
                "beacon_block_root": H256::zero(),
                "source": { "epoch": "0", "root": H256::zero() },
                "target": { "epoch": "0", "root": H256::zero() },
            },
            "signature": AggregateSignatureBytes::empty(),
            "committee_bits": "0x0100000000000000",
        })
    }

    // Why `aggregate_attestation` parses by phase instead of letting serde choose: Electra and
    // Gloas attestations have the same fields, so an untagged read of either yields Electra.
    #[test]
    fn a_gloas_attestation_is_untagged_as_electra() -> Result<()> {
        let attestation = serde_json::from_value::<Attestation<Mainnet>>(electra_aggregate_body())?;

        assert!(matches!(attestation, Attestation::Electra(_)));

        Ok(())
    }

    // The phases that `deny_unknown_fields` does separate stay separated.
    #[test]
    fn an_electra_aggregate_is_not_a_phase0_one() -> Result<()> {
        let body = electra_aggregate_body();

        serde_json::from_value::<ElectraAttestation<Mainnet>>(body.clone())?;
        serde_json::from_value::<GloasAttestation<Mainnet>>(body.clone())?;

        serde_json::from_value::<Phase0Attestation<Mainnet>>(body)
            .expect_err("committee bits should not fit a phase 0 attestation");

        Ok(())
    }

    // Reading a position in the requested committee against bits covering other committees would
    // silently pick the wrong validator.
    #[test]
    fn rejects_an_aggregate_covering_other_committees() -> Result<()> {
        let aggregate = |indices: &[usize]| {
            let mut committee_bits = BitVector::default();

            for index in indices {
                committee_bits.set(*index, true);
            }

            Attestation::<Mainnet>::Electra(ElectraAttestation {
                committee_bits,
                ..ElectraAttestation::default()
            })
        };

        ensure_requested_committee(&aggregate(&[3]), 3)?;

        ensure_requested_committee(&aggregate(&[2]), 3)
            .expect_err("an aggregate for another committee should be rejected");

        ensure_requested_committee(&aggregate(&[2, 3]), 3)
            .expect_err("an aggregate covering several committees should be rejected");

        ensure_requested_committee(&aggregate(&[]), 3)
            .expect_err("an aggregate covering no committee should be rejected");

        Ok(())
    }

    // A phase 0 aggregate has no committee bits; its committee is fixed by the data root.
    #[test]
    fn accepts_a_phase0_aggregate() -> Result<()> {
        let aggregate = Attestation::<Mainnet>::Phase0(Phase0Attestation::default());

        ensure_requested_committee(&aggregate, 3)
    }

    // A node that reports no version is taken at its word; one that disagrees is not.
    #[test]
    fn check_version_rejects_only_a_disagreeing_node() -> Result<()> {
        check_version(Phase::Electra, None)?;
        check_version(Phase::Electra, Some(Phase::Electra))?;

        check_version(Phase::Electra, Some(Phase::Gloas))
            .expect_err("a node reporting another phase should be rejected");

        Ok(())
    }

    // The root goes into the query in full; `Display` would abbreviate it.
    #[test]
    fn aggregate_attestation_path_spells_out_the_root() {
        let data = AttestationData {
            slot: 6,
            ..AttestationData::default()
        };

        let path = aggregate_attestation_path(data, 3);

        let root = path
            .split("attestation_data_root=")
            .nth(1)
            .and_then(|rest| rest.split('&').next())
            .expect("path contains the attestation data root");

        assert!(root.starts_with("0x"));
        assert_eq!(root.len(), 66);
        assert!(path.ends_with("&slot=6&committee_index=3"));
    }

    // The publication body is the bare aggregate and proof, not an `Arc`-wrapped one.
    #[test]
    fn serializes_aggregate_and_proof_body() -> Result<()> {
        let aggregate_and_proof = Arc::new(SignedAggregateAndProof::<Mainnet>::from(
            ElectraSignedAggregateAndProof {
                message: ElectraAggregateAndProof {
                    aggregator_index: 6,
                    aggregate: ElectraAttestation::default(),
                    selection_proof: SignatureBytes::empty(),
                },
                signature: SignatureBytes::empty(),
            },
        ));

        let body = serde_json::to_value([&aggregate_and_proof])?;

        assert_eq!(body[0]["message"]["aggregator_index"], json!("6"));
        assert_eq!(body[0]["message"]["aggregate"]["data"]["slot"], json!("0"));

        Ok(())
    }

    // The endpoint takes a bare array of subscriptions with quoted numbers.
    #[test]
    fn serializes_beacon_committee_subscription_body() -> Result<()> {
        let body = serde_json::to_value([BeaconCommitteeSubscription {
            validator_index: 1,
            committee_index: 2,
            committees_at_slot: 3,
            slot: 4,
            is_aggregator: true,
        }])?;

        assert_eq!(body[0]["validator_index"], json!("1"));
        assert_eq!(body[0]["committee_index"], json!("2"));
        assert_eq!(body[0]["committees_at_slot"], json!("3"));
        assert_eq!(body[0]["slot"], json!("4"));
        assert_eq!(body[0]["is_aggregator"], json!(true));

        Ok(())
    }
}
