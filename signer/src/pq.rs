//! PQ key material derived from the BLS secret keys the signer already holds.

use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, PoisonError},
};

use anyhow::{Result, anyhow, ensure};
use bls::{PublicKeyBytes, SecretKey, traits::SecretKey as _};
use fs_err as fs;
use helper_functions::vrf_tree::{VrfTree, compute_vrf_seed_leaf};
use logging::warn_with_peers;
use sha2::{Digest as _, Sha256};
use ssz::H256;
use types::pq::{primitives::VrfProof, validator_list::padded_pubkey};
use xmss::{PUBLIC_KEY_SIZE, PUBLIC_PARAMETER_SIZE, XmssPublicKey, XmssSecretKey};

use crate::{vrf_state::VrfStateArtifact, xmss_cache::XmssCacheRecord};
use zeroize::Zeroizing;

pub type PqKeys = HashMap<PublicKeyBytes, Arc<PqKey>>;

/// The XMSS key and the VRF tree of a validator.
pub struct PqKey {
    xmss: XmssSecretKey,
    xmss_cache_path: Option<PathBuf>,
    vrf_seed: H256,
    // Building a tree takes minutes, so it is built after the key is in use. Only proposals need it.
    vrf_tree: OnceLock<VrfTree>,
    vrf_tree_path: Option<PathBuf>,
    // Proofs of upcoming proposals, computed ahead because a proof takes about a second.
    vrf_proofs: Mutex<BTreeMap<u64, VrfProof>>,
}

impl PqKey {
    /// Loads the XMSS key from `cache_directory` or `xmss_cache` if either matches, deriving it
    /// from `secret_key` otherwise, and loads the VRF tree if it was saved in `cache_directory`.
    /// Takes about a second without a cache.
    ///
    /// Do not call on an async executor thread.
    pub fn load(
        public_key: PublicKeyBytes,
        secret_key: &SecretKey,
        cache_directory: Option<&Path>,
        xmss_cache: Option<&XmssCacheRecord>,
    ) -> Result<Self> {
        let (xmss_seed, vrf_seed) = derive_seeds(secret_key);

        let xmss_cache_path =
            cache_directory.map(|directory| xmss_cache_path(directory, public_key));

        let saved_xmss = xmss_cache_path
            .as_deref()
            .filter(|path| path.exists())
            .and_then(|path| {
                let xmss = read_xmss_cache(path, &xmss_seed);

                if xmss.is_none() {
                    warn_with_peers!(
                        "XMSS cache {} does not match the key of validator {public_key:?}",
                        path.display(),
                    );
                }

                xmss
            });

        let loaded_from_disk = saved_xmss.is_some();

        let cached_xmss = saved_xmss.or_else(|| {
            xmss_cache.and_then(|record| {
                let xmss =
                    XmssSecretKey::from_cache_bytes(&xmss_seed, record.public_key, &record.bytes);

                if xmss.is_none() {
                    warn_with_peers!(
                        "the XMSS cache record for validator {public_key:?} does not match its key",
                    );
                }

                xmss
            })
        });

        let pq_key = Self {
            xmss: cached_xmss.unwrap_or_else(|| XmssSecretKey::from_seed(&xmss_seed)),
            xmss_cache_path,
            vrf_seed,
            vrf_tree: OnceLock::new(),
            vrf_tree_path: cache_directory.map(|directory| {
                directory.join(format!("{}.vrf", hex::encode(public_key.as_bytes())))
            }),
            vrf_proofs: Mutex::default(),
        };

        if !loaded_from_disk {
            pq_key.save_xmss_cache()?;
        }

        if let Some(path) = pq_key.vrf_tree_path.as_deref().filter(|path| path.exists()) {
            let bytes = fs::read(path)?;

            let (nodes, remainder) = bytes.as_chunks::<32>();

            ensure!(
                remainder.is_empty(),
                "VRF tree cache {} is truncated",
                path.display(),
            );

            let nodes = nodes.iter().copied().map(H256).collect();

            let vrf_tree = VrfTree::from_cached_nodes(vrf_seed, nodes)?;
            pq_key.vrf_tree.get_or_init(|| vrf_tree);
        }

        Ok(pq_key)
    }

    /// Builds the VRF tree and saves it in the cache directory unless it is already there. Takes
    /// minutes.
    ///
    /// Do not call on an async executor thread.
    pub fn build_vrf_tree(&self) -> Result<()> {
        if self.vrf_tree.get().is_some() {
            return Ok(());
        }

        let vrf_tree = VrfTree::build(self.vrf_seed);

        if let Some((path, cached_nodes)) =
            self.vrf_tree_path.as_deref().zip(vrf_tree.cached_nodes())
        {
            if let Some(directory) = path.parent() {
                fs::create_dir_all(directory)?;
            }

            let bytes = cached_nodes
                .iter()
                .flat_map(H256::as_bytes)
                .copied()
                .collect::<Vec<_>>();

            fs::write(path, bytes)?;
        }

        self.vrf_tree.get_or_init(|| vrf_tree);

        Ok(())
    }

    /// Takes the VRF tree from the slot 0 branch in `artifact`, checked against `state_vrf_root`,
    /// the validator's VRF root in the state, or else against the artifact's own root. Cheap.
    pub fn load_vrf_tree_from_artifact(
        &self,
        artifact: &VrfStateArtifact,
        state_vrf_root: Option<H256>,
    ) -> Result<()> {
        if self.has_vrf_tree() {
            return Ok(());
        }

        let (artifact_root, branch) = artifact.record(compute_vrf_seed_leaf(self.vrf_seed, 1))?;
        let root = state_vrf_root.unwrap_or(artifact_root);
        let vrf_tree = VrfTree::from_slot_zero_branch(self.vrf_seed, root, branch)?;

        self.vrf_tree.get_or_init(|| vrf_tree);

        Ok(())
    }

    /// Saves the XMSS public key and the trees the key has built in the cache directory, for
    /// [`Self::load`] to skip building them.
    pub fn save_xmss_cache(&self) -> Result<()> {
        let Some(path) = self.xmss_cache_path.as_deref() else {
            return Ok(());
        };

        if let Some(directory) = path.parent() {
            fs::create_dir_all(directory)?;
        }

        let mut bytes = self.xmss_public_key().as_ref().to_vec();
        bytes.extend(self.xmss.cache_to_bytes());

        fs::write(path, bytes)?;

        Ok(())
    }

    #[must_use]
    pub fn has_vrf_tree(&self) -> bool {
        self.vrf_tree.get().is_some()
    }

    #[must_use]
    pub const fn xmss(&self) -> &XmssSecretKey {
        &self.xmss
    }

    #[must_use]
    pub const fn xmss_public_key(&self) -> XmssPublicKey {
        self.xmss.public_key()
    }

    /// The validator's key as a PQ state holds it: `XMSS_DEPOSIT_PREFIX` followed by the XMSS
    /// public key.
    #[must_use]
    pub fn state_public_key(&self) -> PublicKeyBytes {
        padded_pubkey(self.xmss_public_key())
    }

    #[must_use]
    pub fn vrf_root(&self) -> Option<H256> {
        self.vrf_tree.get().map(VrfTree::root)
    }

    /// The RANDAO reveal for `slot`: the one [`Self::precompute_vrf_proof`] computed, or else built
    /// now, which takes about a second.
    ///
    /// Do not call on an async executor thread.
    pub fn vrf_proof(&self, slot: u64) -> Result<VrfProof> {
        if let Some(proof) = self.vrf_proofs().remove(&slot) {
            return Ok(proof);
        }

        self.compute_vrf_proof(slot)
    }

    /// Computes the RANDAO reveal for an upcoming proposal at `slot`, and drops the ones before
    /// `current_slot`. Does nothing until the VRF tree is built.
    ///
    /// Do not call on an async executor thread.
    pub fn precompute_vrf_proof(&self, slot: u64, current_slot: u64) -> Result<()> {
        self.vrf_proofs()
            .retain(|proof_slot, _| *proof_slot >= current_slot);

        if !self.has_vrf_tree() || self.vrf_proofs().contains_key(&slot) {
            return Ok(());
        }

        let proof = self.compute_vrf_proof(slot)?;

        self.vrf_proofs().insert(slot, proof);

        Ok(())
    }

    fn vrf_proofs(&self) -> std::sync::MutexGuard<'_, BTreeMap<u64, VrfProof>> {
        self.vrf_proofs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn compute_vrf_proof(&self, slot: u64) -> Result<VrfProof> {
        self.vrf_tree
            .get()
            .ok_or_else(|| {
                anyhow!(
                    "the VRF tree of {:?} is not built yet",
                    self.xmss_public_key()
                )
            })?
            .proof(slot)
    }
}

/// Where [`PqKey::save_xmss_cache`] saves the XMSS cache of `public_key` in `cache_directory`.
#[must_use]
pub fn xmss_cache_path(cache_directory: &Path, public_key: PublicKeyBytes) -> PathBuf {
    cache_directory.join(format!("{}.xmss", hex::encode(public_key.as_bytes())))
}

// The XMSS public key, then the trees as leanVM's `cache_to_bytes` writes them.
fn read_xmss_cache(path: &Path, xmss_seed: &[u8; 32]) -> Option<XmssSecretKey> {
    let bytes = fs::read(path).ok()?;
    let (public_key, cache) = bytes.split_at_checked(PUBLIC_KEY_SIZE)?;
    let public_key = XmssPublicKey::from_slice(public_key).ok()?;

    XmssSecretKey::from_cache_bytes(xmss_seed, public_key, cache)
}

/// The public parameter of the XMSS key derived from `secret_key`. Cheap.
#[must_use]
pub fn xmss_public_parameter(secret_key: &SecretKey) -> [u8; PUBLIC_PARAMETER_SIZE] {
    let (xmss_seed, _) = derive_seeds(secret_key);
    XmssSecretKey::public_parameter(&xmss_seed)
}

// The spec leaves the XMSS key seed and the VRF seed to the validator. These match the pq-devnet-0
// genesis tool (`ethpandaops/eth-beacon-genesis@ff42fce`), which derives both from the BLS secret
// key.
fn derive_seeds(secret_key: &SecretKey) -> (Zeroizing<[u8; 32]>, H256) {
    // Zeroized on drop.
    let secret_key_bytes = secret_key.to_bytes();

    let xmss_seed = Zeroizing::new(
        Sha256::new()
            .chain_update(b"leanxmss-seed")
            .chain_update(secret_key_bytes.as_ref())
            .finalize()
            .into(),
    );

    let vrf_seed = H256(
        Sha256::new()
            .chain_update(b"vrf-seed")
            .chain_update(secret_key_bytes.as_ref())
            .finalize()
            .into(),
    );

    (xmss_seed, vrf_seed)
}

#[cfg(test)]
mod tests {
    use bls::SecretKeyBytes;
    use hex_literal::hex;

    use super::*;

    // Keys `m/12381/3600/i/0/0` of the mnemonic the pq-devnet-0 genesis tool tests with
    // ("rare observe fox ..."), derived with EIP-2333. The tool (`ethpandaops/eth-beacon-genesis@ff42fce`,
    // `validators/mnemonic_test.go`) pins the BLS key of index 0 and the XMSS key of index 5. It uses
    // a separate XMSS implementation, so matching it checks the seed derivation and the key
    // generation together.
    const SECRET_KEY_0: [u8; 32] =
        hex!("5eb078c8fa64fffb66e17ea3ca4a6b2d5ea55ca44423895b2b38f53ea82b36d9");
    const SECRET_KEY_5: [u8; 32] =
        hex!("2892f3ba475c3640a67fe730798ad9c4eed3a6d934db85f91c41cfc837ce8834");

    #[test]
    fn keys_match_the_genesis_tool() -> Result<()> {
        let secret_key_0 = SecretKey::try_from(SecretKeyBytes::from(SECRET_KEY_0))?;

        assert_eq!(
            PublicKeyBytes::from(secret_key_0.to_public_key()),
            PublicKeyBytes(hex!(
                "a72ce460a5ab6bea347e59b17ee349bebf6adfa0a240993ed70a5be0da9638b6e2dc7bbdd19e24a8292c1c7b30f23c9e"
            )),
        );

        let secret_key_5 = SecretKey::try_from(SecretKeyBytes::from(SECRET_KEY_5))?;
        let (xmss_seed, _) = derive_seeds(&secret_key_5);

        assert_eq!(
            H256::from(XmssSecretKey::from_seed(&xmss_seed).public_key()),
            H256(hex!(
                "155a29b971da2b771fdf52c768af63fa03f78f25487e3e0ed03d012b7039d88b"
            )),
        );

        Ok(())
    }
}
