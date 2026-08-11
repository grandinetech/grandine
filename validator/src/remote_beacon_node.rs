use core::{
    sync::atomic::{AtomicU8, Ordering},
    time::Duration,
};
use std::sync::Arc;

use anyhow::{Error as AnyhowError, Result, bail, ensure};
use derive_more::Display;
use http_api_utils::{ETH_CONSENSUS_VERSION, EthResponse, ValidatorAttesterDutyResponse};
use logging::{debug_with_peers, info_with_peers, warn_with_peers};
use p2p::BeaconCommitteeSubscription;
use reqwest::{Client, Response, StatusCode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
use types::{
    config::Config as ChainConfig,
    nonstandard::OwnAttestation,
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

#[cfg(test)]
mod tests {
    use bls::{PublicKeyBytes, SignatureBytes, traits::SignatureBytes as _};
    use serde_json::json;
    use types::{
        combined::Attestation, electra::containers::SingleAttestation, phase0::primitives::H256,
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
