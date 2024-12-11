use std::{
    collections::{hash_map::Entry, HashMap},
    sync::Arc,
};

use anyhow::Result;
use arc_swap::{ArcSwap, Guard};
use bls::{PublicKeyBytes, SecretKey, Signature};
use doppelganger_protection::DoppelgangerProtection;
use futures::{
    lock::Mutex,
    stream::{FuturesUnordered, TryStreamExt as _},
    try_join, TryFutureExt as _,
};
use helper_functions::misc;
use itertools::{izip, Itertools as _};
use log::{info, warn};
use prometheus_metrics::Metrics;
use rayon::iter::{IntoParallelIterator as _, ParallelIterator as _};
use reqwest::Client;
use slashing_protection::{Attestation, BlockProposal, SlashingProtector};
use std_ext::ArcExt as _;
use thiserror::Error;
use types::{
    combined::BeaconState,
    phase0::primitives::{Slot, H256},
    preset::Preset,
    redacting_url::RedactingUrl,
};

use crate::{
    types::{ForkInfo, SigningMessage, SigningTriple},
    web3signer::{FetchedKeys, Web3Signer},
    Web3SignerConfig,
};

#[derive(Debug, Error)]
enum Error {
    #[error("Cannot sign due to missing credentials for a public key: {public_key:?}")]
    MissingCredentials { public_key: PublicKeyBytes },
}

#[derive(Clone, Copy)]
pub enum KeyOrigin {
    KeymanagerAPI,
    LocalFileSystem,
    Web3Signer,
}

#[derive(Clone)]
enum SignMethod {
    SecretKey(Arc<SecretKey>, KeyOrigin),
    Web3Signer(RedactingUrl),
}

pub struct Signer {
    snapshot: ArcSwap<Snapshot>,
}

impl Signer {
    pub fn new(
        validator_keys: impl IntoIterator<Item = (PublicKeyBytes, Arc<SecretKey>, KeyOrigin)>,
        client: Client,
        web3signer_config: Web3SignerConfig,
        metrics: Option<Arc<Metrics>>,
    ) -> Self {
        let sign_methods = validator_keys
            .into_iter()
            .map(|(public_key, secret_key, origin)| {
                (public_key, SignMethod::SecretKey(secret_key, origin))
            })
            .collect();

        let snapshot = ArcSwap::from_pointee(Snapshot {
            sign_methods,
            web3signer: Web3Signer::new(client, web3signer_config, metrics),
            doppelganger_protection: None,
        });

        Self { snapshot }
    }

    pub fn enable_doppelganger_protection(
        &self,
        doppelganger_protection: &Arc<DoppelgangerProtection>,
    ) {
        self.update(|snapshot| {
            let mut snapshot = snapshot.as_ref().clone();

            snapshot.enable_doppelganger_protection(doppelganger_protection.clone_arc());

            snapshot
        });
    }

    pub async fn load_keys_from_web3signer(&self) {
        let keys = self.load().fetch_keys_from_web3signer().await;

        self.update(|snapshot| {
            let mut snapshot = snapshot.as_ref().clone();

            snapshot.save_fetched_keys_from_web3signer(&keys);

            snapshot
        });

        for (url, remote_keys) in keys {
            match remote_keys {
                Some(keys) => {
                    info!(
                        "loaded {} validator key(s) from Web3Signer at {}",
                        keys.len(),
                        url,
                    );
                }
                None => {
                    warn!(
                        "Web3Signer at {} did not return any validator keys. It will retry to fetch keys again in the next epoch.",
                        url,
                    );
                }
            }
        }
    }

    #[must_use]
    pub fn load(&self) -> Guard<Arc<Snapshot>> {
        self.snapshot.load()
    }

    pub fn update<R, F>(&self, f: F) -> Arc<Snapshot>
    where
        F: FnMut(&Arc<Snapshot>) -> R,
        R: Into<Arc<Snapshot>>,
    {
        self.snapshot.rcu(f)
    }

    pub fn update_doppelganger_protection_pubkeys<P: Preset>(
        &self,
        beacon_state: &BeaconState<P>,
        current_slot: Slot,
    ) {
        let snapshot = self.load();
        let public_keys = snapshot.keys().copied();

        if let Some(doppelganger_protection) = &snapshot.doppelganger_protection {
            doppelganger_protection.add_tracked_validators(public_keys, beacon_state, current_slot);
        }
    }
}

#[derive(Clone)]
pub struct Snapshot {
    sign_methods: HashMap<PublicKeyBytes, SignMethod>,
    web3signer: Web3Signer,
    doppelganger_protection: Option<Arc<DoppelgangerProtection>>,
}

impl Snapshot {
    pub fn enable_doppelganger_protection(
        &mut self,
        doppelganger_protection: Arc<DoppelgangerProtection>,
    ) {
        self.doppelganger_protection = Some(doppelganger_protection);
    }

    #[must_use]
    pub fn has_key(&self, public_key: PublicKeyBytes) -> bool {
        self.sign_methods.contains_key(&public_key)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sign_methods.is_empty()
    }

    pub fn keys(&self) -> impl ExactSizeIterator<Item = &PublicKeyBytes> {
        self.sign_methods.keys()
    }

    pub fn keys_with_origin(&self) -> impl Iterator<Item = (PublicKeyBytes, KeyOrigin)> + '_ {
        self.sign_methods
            .iter()
            .map(|(pubkey, sign_method)| match sign_method {
                SignMethod::SecretKey(_, origin) => (*pubkey, *origin),
                SignMethod::Web3Signer(_) => (*pubkey, KeyOrigin::Web3Signer),
            })
    }

    pub fn web3signer_keys(&self) -> impl Iterator<Item = (PublicKeyBytes, RedactingUrl)> + '_ {
        self.sign_methods
            .iter()
            .filter_map(|(pubkey, sign_method)| match sign_method {
                SignMethod::SecretKey(_, _) => None,
                SignMethod::Web3Signer(url) => Some((*pubkey, url.clone())),
            })
    }

    #[must_use]
    pub const fn client(&self) -> &Client {
        self.web3signer.client()
    }

    pub fn append_keys(
        &mut self,
        keys: impl IntoIterator<Item = (PublicKeyBytes, Arc<SecretKey>)>,
    ) {
        for (public_key, secret_key) in keys {
            self.sign_methods
                .entry(public_key)
                .or_insert(SignMethod::SecretKey(secret_key, KeyOrigin::KeymanagerAPI));
        }
    }

    pub fn append_remote_key(&mut self, public_key: PublicKeyBytes, url: RedactingUrl) -> bool {
        match self.sign_methods.entry(public_key) {
            Entry::Occupied(_) => false,
            Entry::Vacant(vacant) => {
                vacant.insert(SignMethod::Web3Signer(url));
                true
            }
        }
    }

    pub fn delete_key(&mut self, public_key: PublicKeyBytes) {
        self.sign_methods.remove(&public_key);
    }

    pub async fn fetch_keys_from_web3signer(&self) -> FetchedKeys {
        self.web3signer.fetch_public_keys().await
    }

    #[must_use]
    pub fn no_keys(&self) -> bool {
        self.sign_methods.is_empty()
    }

    pub fn save_fetched_keys_from_web3signer(&mut self, keys: &FetchedKeys) {
        for (url, remote_keys) in keys {
            if let Some(keys) = remote_keys {
                for public_key in keys {
                    self.sign_methods
                        .entry(*public_key)
                        .or_insert_with(|| SignMethod::Web3Signer(url.clone()));
                }

                self.web3signer.mark_keys_loaded_from(url.clone());
            }
        }
    }

    pub async fn sign_without_slashing_protection<'block, P: Preset>(
        &self,
        message: SigningMessage<'block, P>,
        signing_root: H256,
        fork_info: Option<ForkInfo<P>>,
        public_key: PublicKeyBytes,
    ) -> Result<Signature> {
        let signature = match self.sign_method(public_key)? {
            SignMethod::SecretKey(secret_key, _) => secret_key.sign(signing_root),
            SignMethod::Web3Signer(url) => self
                .web3signer
                .sign(url, message, signing_root, fork_info, public_key)
                .await?
                .try_into()?,
        };

        Ok(signature)
    }

    #[expect(clippy::too_many_lines)]
    pub async fn sign_triples<P: Preset>(
        &self,
        triples: impl IntoIterator<Item = SigningTriple<'_, P>> + Send,
        beacon_state: &BeaconState<P>,
        slashing_protector: Arc<Mutex<SlashingProtector>>,
    ) -> Result<impl Iterator<Item = Option<Signature>>> {
        let mut message_indices = vec![];
        let mut block_proposal_indices = vec![];
        let mut attestation_indices = vec![];
        let mut block_messages = vec![];
        let mut attestation_triples = vec![];
        let mut attestations = vec![];
        let mut block_proposals = vec![];
        let mut signable_messages = vec![];

        let fork_info = ForkInfo::from(beacon_state);
        let mut signing_triples_count = 0;

        let doppelganger_protection = self
            .doppelganger_protection
            .as_deref()
            .map(DoppelgangerProtection::load);

        for (index, triple) in triples.into_iter().enumerate() {
            let SigningTriple {
                message,
                signing_root,
                public_key,
            } = triple;

            if let Some(doppelganger_protection) = &doppelganger_protection {
                if !doppelganger_protection.is_validator_active(public_key) {
                    warn!(
                        "Doppelganger protection prevented validator {public_key:?} from signing a message \
                         since not enough time has passed to ensure there are no duplicate validators participating on network",
                    );
                    continue;
                }
            }

            match message {
                SigningMessage::Attestation(attestation_data) => {
                    attestation_triples.push((message, signing_root, public_key));
                    attestation_indices.push(index);

                    attestations.push((
                        Attestation {
                            source_epoch: attestation_data.source.epoch,
                            target_epoch: attestation_data.target.epoch,
                            signing_root: Some(signing_root),
                        },
                        public_key,
                    ));
                }
                SigningMessage::BeaconBlock(ref signing_block) => {
                    let slot = signing_block.slot();
                    let proposal = BlockProposal {
                        slot,
                        signing_root: Some(signing_root),
                    };

                    block_messages.push((message, signing_root, public_key));
                    block_proposal_indices.push(index);
                    block_proposals.push((
                        proposal,
                        public_key,
                        misc::compute_epoch_at_slot::<P>(slot),
                    ));
                }
                SigningMessage::AggregationSlot { .. }
                | SigningMessage::AggregateAndProof(_)
                | SigningMessage::RandaoReveal { .. }
                | SigningMessage::SyncCommitteeMessage { .. }
                | SigningMessage::SyncAggregatorSelectionData(_)
                | SigningMessage::ContributionAndProof(_)
                | SigningMessage::ValidatorRegistration(_)
                | SigningMessage::VoluntaryExit(_) => {
                    signable_messages.push(SigningTriple {
                        message,
                        signing_root,
                        public_key,
                    });
                    message_indices.push(index);
                }
            }

            signing_triples_count += 1;
        }

        let mut protector = slashing_protector.lock().await;

        let slashing_outcome =
            protector.validate_and_store_own_attestations(beacon_state, attestations)?;

        for (outcome, data, index) in izip!(
            slashing_outcome.iter(),
            attestation_triples,
            attestation_indices
        ) {
            let (message, signing_root, public_key) = data;

            if outcome.is_some() {
                signable_messages.push(SigningTriple {
                    message,
                    signing_root,
                    public_key,
                });
                message_indices.push(index);
            }
        }

        for ((proposal, pubkey, current_epoch), (message, signing_root, public_key), index) in izip!(
            block_proposals.into_iter(),
            block_messages,
            block_proposal_indices
        ) {
            let control_flow =
                protector.validate_and_store_own_block_proposal(proposal, pubkey, current_epoch)?;

            if control_flow.is_continue() {
                signable_messages.push(SigningTriple {
                    message,
                    signing_root,
                    public_key,
                });

                message_indices.push(index);
            }
        }

        let signed_messages = self
            .sign_triples_without_slashing_protection(signable_messages, Some(fork_info))
            .await?;

        let mut answer = vec![None; signing_triples_count];
        for (signed_message, index) in signed_messages.zip(message_indices) {
            answer[index] = Some(signed_message);
        }

        Ok(answer.into_iter())
    }

    pub async fn sign_triples_without_slashing_protection<P: Preset>(
        &self,
        triples: impl IntoIterator<Item = SigningTriple<'_, P>> + Send,
        fork_info: Option<ForkInfo<P>>,
    ) -> Result<impl Iterator<Item = Signature>> {
        let mut sign_locally = vec![];
        let mut sign_remotely = vec![];

        for (index, triple) in triples.into_iter().enumerate() {
            let SigningTriple {
                message,
                signing_root,
                public_key,
            } = triple;

            match self.sign_method(public_key)? {
                SignMethod::SecretKey(secret_key, _) => {
                    sign_locally.push((index, signing_root, secret_key.clone_arc()));
                }
                SignMethod::Web3Signer(_) => {
                    sign_remotely.push((index, message, signing_root, public_key))
                }
            }
        }

        let sign_locally_future = tokio::task::spawn_blocking(|| {
            sign_locally
                .into_par_iter()
                .map(|(index, signing_root, secret_key)| {
                    let signature = secret_key.sign(signing_root);
                    (index, signature)
                })
                .collect::<Vec<_>>()
        })
        .map_err(Into::into);

        let sign_remotely_future = async {
            sign_remotely
                .into_iter()
                .map(|(index, message, signing_root, public_key)| async move {
                    self.sign_without_slashing_protection(
                        message,
                        signing_root,
                        fork_info,
                        public_key,
                    )
                    .await
                    .map(|signature| (index, signature))
                })
                .collect::<FuturesUnordered<_>>()
                .try_collect::<Vec<_>>()
                .await
        };

        let (local, remote) = try_join!(sign_locally_future, sign_remotely_future)?;

        Ok(local
            .into_iter()
            .chain(remote)
            .sorted_by_key(|(index, _)| *index)
            .map(|(_, signature)| signature))
    }

    fn sign_method(&self, public_key: PublicKeyBytes) -> Result<&SignMethod> {
        self.sign_methods
            .get(&public_key)
            .ok_or(Error::MissingCredentials { public_key })
            .map_err(Into::into)
    }
}
