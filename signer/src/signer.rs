use core::sync::atomic::{AtomicBool, Ordering};
use std::{
    collections::{HashMap, hash_map::Entry},
    path::Path,
    sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use anyhow::{Error as AnyhowError, Result};
use arc_swap::{ArcSwap, Guard};
use bls::{PublicKeyBytes, SecretKey, Signature, traits::SecretKey as _};
use doppelganger_protection::DoppelgangerProtection;
use futures::{
    StreamExt as _, TryFutureExt as _,
    lock::Mutex,
    stream::{self, TryStreamExt as _},
    try_join,
};
use helper_functions::misc;
use itertools::{Itertools as _, izip};
use logging::{info_with_peers, warn_with_peers};
use prometheus_metrics::Metrics;
use rayon::iter::{IntoParallelIterator as _, IntoParallelRefIterator as _, ParallelIterator as _};
use reqwest::Client;
use slashing_protection::{Attestation, BlockProposal, SlashingProtector};
use std_ext::ArcExt as _;
use thiserror::Error;
use tokio::sync::Notify;
use tracing::instrument;
use types::{
    phase0::primitives::{Epoch, H256, Slot},
    preset::Preset,
    redacting_url::RedactingUrl,
};

use xmss::{LeafIndex, PUBLIC_PARAMETER_SIZE, XmssSignature};

use crate::{
    VrfStateArtifact, Web3SignerConfig, XmssCacheRecord,
    pq::{self, PqKey, PqKeys},
    types::{ForkInfo, SigningMessage, SigningTriple},
    web3signer::{FetchedKeys, Web3Signer},
};

// Whole epochs of selection proofs and registrations are signed at once, which would otherwise
// open thousands of requests to a Web3Signer.
const MAX_CONCURRENT_WEB3SIGNER_REQUESTS: usize = 32;

#[derive(Debug, Error)]
enum Error {
    #[error("Cannot sign due to missing credentials for a public key: {public_key:?}")]
    MissingCredentials { public_key: PublicKeyBytes },
    #[error("Cannot sign with XMSS due to a missing PQ key for a public key: {public_key:?}")]
    MissingPqKey { public_key: PublicKeyBytes },
}

#[derive(Clone, Copy)]
pub enum KeyOrigin {
    /// A key Grandine manages itself: the `keystores.json` blob or a keystore under the validator
    /// directory. Deletable via the API.
    Internal,
    /// A key from outside the validator directory (`--keystore-dir`, interop/CLI). Read-only to the API.
    External,
    /// A remote Web3Signer key, managed via the remotekeys API.
    Web3Signer,
}

#[derive(Clone)]
enum SignMethod {
    SecretKey(Arc<SecretKey>, KeyOrigin),
    Web3Signer(RedactingUrl),
}

pub struct Signer {
    snapshot: ArcSwap<Snapshot>,
    keys_changed: Notify,
    // Keyed by the BLS public key of the local key the PQ key was derived from.
    pq_keys: RwLock<PqKeys>,
    precomputing_vrf_proofs: AtomicBool,
}

impl Signer {
    pub fn new(
        validator_keys: impl IntoIterator<Item = (PublicKeyBytes, Arc<SecretKey>, KeyOrigin)>,
        web3signer_client: Client,
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
            web3signer: Web3Signer::new(web3signer_client, web3signer_config, metrics),
            doppelganger_protection: None,
        });

        Self {
            snapshot,
            keys_changed: Notify::new(),
            pq_keys: RwLock::default(),
            precomputing_vrf_proofs: AtomicBool::new(false),
        }
    }

    /// Derives the PQ keys of the local keys that do not have them yet, caching their VRF trees
    /// in `cache_directory`. Building a VRF tree takes minutes.
    ///
    /// Do not call on an async executor thread.
    pub fn load_pq_keys(
        &self,
        cache_directory: Option<&Path>,
        xmss_caches: &HashMap<PublicKeyBytes, XmssCacheRecord>,
    ) -> Result<()> {
        let local_keys = self
            .load()
            .sign_methods
            .iter()
            .filter_map(|(public_key, sign_method)| match sign_method {
                SignMethod::SecretKey(secret_key, _) => Some((*public_key, secret_key.clone_arc())),
                // TODO(PQ): Sign with XMSS through Web3Signer.
                SignMethod::Web3Signer(_) => None,
            })
            .filter(|(public_key, _)| !self.pq_keys_read().contains_key(public_key))
            .collect_vec();

        for (public_key, secret_key) in local_keys {
            let pq_key = PqKey::load(
                public_key,
                &secret_key,
                cache_directory,
                xmss_caches.get(&public_key),
            )?;

            info_with_peers!(
                "loaded PQ key for validator {public_key:?} (XMSS public key: {:?})",
                pq_key.xmss_public_key(),
            );

            self.pq_keys_write().insert(public_key, Arc::new(pq_key));
        }

        Ok(())
    }

    /// Builds the trees the XMSS keys sign attestations of `epoch` and duties of `slot` at, which
    /// signing would otherwise build first. Takes seconds per key.
    ///
    /// Do not call on an async executor thread.
    pub fn prepare_pq_keys(&self, epoch: Epoch, slot: Slot) -> Result<()> {
        let leaves = [
            helper_functions::pq::compute_xmss_attestation_leaf_index(epoch)?,
            helper_functions::pq::compute_xmss_leaf_index(slot, 0)?,
        ]
        .into_iter()
        .map(LeafIndex::try_from)
        .collect::<Result<Vec<_>, _>>()?;

        let pq_keys = self.pq_keys_read().values().cloned().collect_vec();

        pq_keys.into_par_iter().try_for_each(|pq_key| {
            leaves
                .iter()
                .try_for_each(|leaf_index| pq_key.xmss().prepare(*leaf_index))
        })?;

        Ok(())
    }

    /// The public parameters of the XMSS keys [`Self::load_pq_keys`] would derive, which find their
    /// XMSS cache records. Cheap.
    #[must_use]
    pub fn pq_public_parameters(&self) -> Vec<(PublicKeyBytes, [u8; PUBLIC_PARAMETER_SIZE])> {
        self.load()
            .sign_methods
            .iter()
            .filter_map(|(public_key, sign_method)| match sign_method {
                SignMethod::SecretKey(secret_key, _) => Some((*public_key, secret_key)),
                SignMethod::Web3Signer(_) => None,
            })
            .filter(|(public_key, _)| !self.pq_keys_read().contains_key(public_key))
            .map(|(public_key, secret_key)| (public_key, pq::xmss_public_parameter(secret_key)))
            .collect()
    }

    /// Takes the VRF trees the loaded PQ keys do not have yet from `artifact`, in parallel.
    /// Returns how many it loaded. Keys it has no valid record for are left to
    /// [`Self::build_missing_vrf_trees`].
    ///
    /// Do not call on an async executor thread.
    pub fn load_vrf_trees_from_artifact(&self, artifact: &VrfStateArtifact) -> usize {
        let missing = self
            .pq_keys_read()
            .iter()
            .filter(|(_, pq_key)| !pq_key.has_vrf_tree())
            .map(|(public_key, pq_key)| (*public_key, pq_key.clone_arc()))
            .collect_vec();

        missing
            .into_par_iter()
            .filter(
                |(public_key, pq_key)| match pq_key.load_vrf_tree_from_artifact(artifact) {
                    Ok(()) => true,
                    Err(error) => {
                        warn_with_peers!(
                            "no usable VRF state for validator {public_key:?}: {error:?}",
                        );
                        false
                    }
                },
            )
            .count()
    }

    /// Builds the VRF trees the loaded PQ keys do not have yet, one at a time. Takes minutes per
    /// key. Until its tree is built, a validator cannot propose.
    ///
    /// Do not call on an async executor thread.
    pub fn build_missing_vrf_trees(&self) -> Result<()> {
        let missing = self
            .pq_keys_read()
            .iter()
            .filter(|(_, pq_key)| !pq_key.has_vrf_tree())
            .map(|(public_key, pq_key)| (*public_key, pq_key.clone_arc()))
            .collect_vec();

        for (index, (public_key, pq_key)) in missing.iter().enumerate() {
            info_with_peers!(
                "building VRF tree {} of {} (validator: {public_key:?})",
                index.saturating_add(1),
                missing.len(),
            );

            pq_key.build_vrf_tree()?;
        }

        Ok(())
    }

    /// Computes the RANDAO reveals of `proposals` (BLS public key and slot) ahead of time, in
    /// parallel. Skipped while an earlier call is still running.
    ///
    /// Do not call on an async executor thread.
    pub fn precompute_vrf_proofs(&self, proposals: &[(PublicKeyBytes, Slot)], current_slot: Slot) {
        if self.precomputing_vrf_proofs.swap(true, Ordering::Acquire) {
            return;
        }

        proposals.par_iter().for_each(|(public_key, slot)| {
            let Some(pq_key) = self.pq_key(*public_key) else {
                return;
            };

            if let Err(error) = pq_key.precompute_vrf_proof(*slot, current_slot) {
                warn_with_peers!(
                    "failed to compute the RANDAO reveal of {public_key:?} for slot {slot}: \
                     {error:?}",
                );
            }
        });

        self.precomputing_vrf_proofs.store(false, Ordering::Release);
    }

    /// The BLS public key of the local key whose PQ key a PQ state holds as `state_public_key`.
    #[must_use]
    pub fn bls_public_key_of(&self, state_public_key: PublicKeyBytes) -> Option<PublicKeyBytes> {
        self.pq_keys_read()
            .iter()
            .find(|(_, pq_key)| pq_key.state_public_key() == state_public_key)
            .map(|(public_key, _)| *public_key)
    }

    #[must_use]
    pub fn pq_key(&self, public_key: PublicKeyBytes) -> Option<Arc<PqKey>> {
        self.pq_keys_read().get(&public_key).cloned()
    }

    /// Signs each signing root with the XMSS key derived from the BLS public key at its leaf,
    /// after recording the leaf in `slashing_protector`.
    ///
    /// A leaf that already holds a different signing root is not signed again, and its entry is
    /// `None`. Signing it would let anyone forge signatures at that leaf.
    pub async fn sign_pq(
        &self,
        requests: Vec<(PublicKeyBytes, u64, H256)>,
        slashing_protector: &Mutex<SlashingProtector>,
    ) -> Result<Vec<Option<XmssSignature>>> {
        let reservations = slashing_protector
            .lock()
            .await
            .reserve_xmss_leaves(requests.iter().copied())?;

        let to_sign = izip!(requests, reservations)
            .map(|((public_key, leaf_index, signing_root), reservation)| {
                if !reservation.may_sign() {
                    warn_with_peers!(
                        "refusing to sign at XMSS leaf {leaf_index} of {public_key:?} again \
                         ({reservation:?}, signing root: {signing_root:?})",
                    );

                    return Ok(None);
                }

                let pq_key = self
                    .pq_key(public_key)
                    .ok_or(Error::MissingPqKey { public_key })?;

                Ok(Some((
                    pq_key,
                    LeafIndex::try_from(leaf_index)?,
                    signing_root,
                )))
            })
            .collect::<Result<Vec<_>>>()?;

        tokio::task::spawn_blocking(move || {
            to_sign
                .into_par_iter()
                .map(|request| {
                    request
                        .map(|(pq_key, leaf_index, signing_root)| {
                            pq_key
                                .xmss()
                                .sign(signing_root.as_fixed_bytes(), leaf_index)
                        })
                        .transpose()
                        .map_err(Into::into)
                })
                .collect()
        })
        .await?
    }

    fn pq_keys_read(&self) -> RwLockReadGuard<'_, PqKeys> {
        self.pq_keys.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn pq_keys_write(&self) -> RwLockWriteGuard<'_, PqKeys> {
        self.pq_keys.write().unwrap_or_else(PoisonError::into_inner)
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
                    info_with_peers!(
                        "loaded {} validator key(s) from Web3Signer at {url}",
                        keys.len(),
                    );
                }
                None => {
                    warn_with_peers!(
                        "Web3Signer at {url} did not return any validator keys. \
                        It will retry to fetch keys again in the next epoch.",
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
        let previous = self.snapshot.rcu(f);
        let current = self.snapshot.load();

        let keys_changed = previous.sign_methods.len() != current.sign_methods.len()
            || previous
                .sign_methods
                .keys()
                .any(|public_key| !current.sign_methods.contains_key(public_key));

        if keys_changed {
            // Unlike `notify_waiters`, this keeps a permit for a waiter that comes later.
            self.keys_changed.notify_one();
        }

        previous
    }

    #[must_use]
    pub const fn keys_changed(&self) -> &Notify {
        &self.keys_changed
    }

    pub fn update_doppelganger_protection_pubkeys(&self, current_slot: Slot) {
        let snapshot = self.load();
        let public_keys = snapshot.keys().copied();

        if let Some(doppelganger_protection) = &snapshot.doppelganger_protection {
            doppelganger_protection.add_tracked_validators(public_keys, current_slot);
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
    pub fn is_web3signer_key(&self, public_key: PublicKeyBytes) -> bool {
        matches!(
            self.sign_methods.get(&public_key),
            Some(SignMethod::Web3Signer(_)),
        )
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

    pub fn append_keys(
        &mut self,
        keys: impl IntoIterator<Item = (PublicKeyBytes, Arc<SecretKey>)>,
    ) {
        for (public_key, secret_key) in keys {
            self.sign_methods
                .entry(public_key)
                .or_insert(SignMethod::SecretKey(secret_key, KeyOrigin::Internal));
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

    pub async fn sign_without_slashing_protection<P: Preset>(
        &self,
        message: SigningMessage<'_, P>,
        signing_root: H256,
        fork_info: Option<ForkInfo>,
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
    #[instrument(level = "debug", skip_all)]
    pub async fn sign_triples<P: Preset>(
        &self,
        triples: impl IntoIterator<Item = SigningTriple<'_, P>> + Send,
        fork_info: ForkInfo,
        current_epoch: Epoch,
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

        let mut signing_triples_count: usize = 0;

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

            if let Some(doppelganger_protection) = &doppelganger_protection
                && !doppelganger_protection.is_validator_active(public_key)
            {
                warn_with_peers!(
                    "Doppelganger protection prevented validator {public_key:?} from signing a message \
                         since not enough time has passed to ensure there are no duplicate validators participating on network",
                );
                continue;
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
                | SigningMessage::ExecutionPayloadEnvelope(_)
                | SigningMessage::RandaoReveal { .. }
                | SigningMessage::SyncCommitteeMessage { .. }
                | SigningMessage::SyncAggregatorSelectionData(_)
                | SigningMessage::ContributionAndProof(_)
                | SigningMessage::ValidatorRegistration(_)
                | SigningMessage::VoluntaryExit(_)
                | SigningMessage::ProposerPreferences(_)
                | SigningMessage::BuilderRequestAuth(_)
                | SigningMessage::PayloadAttestation(_) => {
                    signable_messages.push(SigningTriple {
                        message,
                        signing_root,
                        public_key,
                    });
                    message_indices.push(index);
                }
            }

            signing_triples_count = signing_triples_count.saturating_add(1);
        }

        let mut protector = slashing_protector.lock().await;

        tokio::task::block_in_place(|| {
            let slashing_outcome =
                protector.validate_and_store_own_attestations(current_epoch, attestations)?;

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
                let control_flow = protector.validate_and_store_own_block_proposal(
                    proposal,
                    pubkey,
                    current_epoch,
                )?;

                if control_flow.is_continue() {
                    signable_messages.push(SigningTriple {
                        message,
                        signing_root,
                        public_key,
                    });

                    message_indices.push(index);
                }
            }

            Ok::<_, AnyhowError>(())
        })?;

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
        fork_info: Option<ForkInfo>,
    ) -> Result<impl Iterator<Item = Signature>> {
        self.sign_triples_with_request_limit(triples, fork_info, usize::MAX)
            .await
    }

    pub async fn sign_triples_throttled_without_slashing_protection<P: Preset>(
        &self,
        triples: impl IntoIterator<Item = SigningTriple<'_, P>> + Send,
        fork_info: Option<ForkInfo>,
    ) -> Result<impl Iterator<Item = Signature>> {
        self.sign_triples_with_request_limit(triples, fork_info, MAX_CONCURRENT_WEB3SIGNER_REQUESTS)
            .await
    }

    async fn sign_triples_with_request_limit<P: Preset>(
        &self,
        triples: impl IntoIterator<Item = SigningTriple<'_, P>> + Send,
        fork_info: Option<ForkInfo>,
        max_concurrent_requests: usize,
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
            let requests = sign_remotely
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
                .collect_vec();

            stream::iter(requests)
                .buffer_unordered(max_concurrent_requests)
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

#[cfg(test)]
mod tests {
    use bls::SecretKeyBytes;
    use futures::FutureExt as _;
    use hex_literal::hex;
    use std_ext::ArcExt;

    use super::*;

    const PUBLIC_KEY: PublicKeyBytes = PublicKeyBytes(hex!(
        "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81"
    ));

    const SECRET_KEY: [u8; 32] =
        hex!("47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138");

    // The index resolver waits on the notification, so it must fire on a key change and only then.
    #[test]
    fn update_notifies_only_when_the_key_set_changes() -> Result<()> {
        let signer = Signer::new([], Client::new(), Web3SignerConfig::default(), None);

        let secret_key: Arc<SecretKey> = Arc::new(SecretKeyBytes::from(SECRET_KEY).try_into()?);

        signer.update(ArcExt::clone_arc);
        assert!(signer.keys_changed().notified().now_or_never().is_none());

        signer.update(|snapshot| {
            let mut snapshot = snapshot.as_ref().clone();
            snapshot.append_keys([(PUBLIC_KEY, secret_key.clone_arc())]);
            snapshot
        });
        assert!(signer.keys_changed().notified().now_or_never().is_some());

        signer.update(ArcExt::clone_arc);
        assert!(signer.keys_changed().notified().now_or_never().is_none());

        signer.update(|snapshot| {
            let mut snapshot = snapshot.as_ref().clone();
            snapshot.delete_key(PUBLIC_KEY);
            snapshot
        });
        assert!(signer.keys_changed().notified().now_or_never().is_some());

        Ok(())
    }
}
