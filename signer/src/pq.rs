//! PQ key material derived from the BLS secret keys the signer already holds.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
};

use anyhow::{Result, anyhow, ensure};
use bls::{PublicKeyBytes, SecretKey, traits::SecretKey as _};
use fs_err as fs;
use helper_functions::vrf_tree::VrfTree;
use sha2::{Digest as _, Sha256};
use ssz::H256;
use types::pq::{primitives::VrfProof, validator_list::padded_pubkey};
use xmss::{XmssPublicKey, XmssSecretKey};
use zeroize::Zeroizing;

pub type PqKeys = HashMap<PublicKeyBytes, Arc<PqKey>>;

/// The XMSS key and the VRF tree of a validator.
pub struct PqKey {
    xmss: XmssSecretKey,
    vrf_seed: H256,
    // Building a tree takes minutes, so it is built after the key is in use. Only proposals need it.
    vrf_tree: OnceLock<VrfTree>,
    vrf_tree_path: Option<PathBuf>,
}

impl PqKey {
    /// Derives the XMSS key from `secret_key`, and loads the VRF tree if it was saved in
    /// `cache_directory`. Takes about a second.
    ///
    /// Do not call on an async executor thread.
    pub fn load(
        public_key: PublicKeyBytes,
        secret_key: &SecretKey,
        cache_directory: Option<&Path>,
    ) -> Result<Self> {
        let (xmss_seed, vrf_seed) = derive_seeds(secret_key);

        let pq_key = Self {
            xmss: XmssSecretKey::from_seed(&xmss_seed),
            vrf_seed,
            vrf_tree: OnceLock::new(),
            vrf_tree_path: cache_directory.map(|directory| {
                directory.join(format!("{}.vrf", hex::encode(public_key.as_bytes())))
            }),
        };

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

        if let Some(path) = self.vrf_tree_path.as_deref() {
            if let Some(directory) = path.parent() {
                fs::create_dir_all(directory)?;
            }

            let bytes = vrf_tree
                .cached_nodes()
                .iter()
                .flat_map(H256::as_bytes)
                .copied()
                .collect::<Vec<_>>();

            fs::write(path, bytes)?;
        }

        self.vrf_tree.get_or_init(|| vrf_tree);

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

    /// The RANDAO reveal for `slot`. Rebuilds a subtree, which takes a fraction of a second.
    ///
    /// Do not call on an async executor thread.
    pub fn vrf_proof(&self, slot: u64) -> Result<VrfProof> {
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

// The spec leaves the XMSS key seed and the VRF seed to the validator. These match the genesis
// tooling, which derives both from the BLS secret key.
//
// TODO(PQ): Confirm the derivation against the pq-devnet-0 genesis tool.
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
