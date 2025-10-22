use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Result;
use dedicated_executor::DedicatedExecutor;
use features::Feature;
use logging::warn_with_peers;
use ssz::{SszHash as _, SszWrite as _};
use types::{
    combined::{Attestation, BeaconState, SignedAggregateAndProof, SignedBeaconBlock},
    deneb::containers::BlobSidecar,
    phase0::primitives::H256,
    preset::Preset,
    traits::{BeaconState as _, SignedBeaconBlock as _},
};

const DUMP_DIR: &str = "dump";

pub struct DataDumper {
    inner: Option<Inner>,
}

impl DataDumper {
    pub fn new(config_name: &str) -> Result<Self> {
        let inner = dump_enabled()
            .then(|| Inner::new(config_name))
            .transpose()?;

        Ok(Self { inner })
    }

    pub fn dump_beacon_state<P: Preset>(&self, state: Arc<BeaconState<P>>, block_root: H256) {
        if let Some(inner) = &self.inner {
            inner.dump_beacon_state(state, block_root);
        }
    }

    pub fn dump_blob_sidecar<P: Preset>(&self, blob_sidecar: Arc<BlobSidecar<P>>) {
        if let Some(inner) = &self.inner {
            inner.dump_blob_sidecar(blob_sidecar);
        }
    }

    pub fn dump_signed_aggregate_and_proof<P: Preset>(
        &self,
        aggregate: Arc<SignedAggregateAndProof<P>>,
    ) {
        if let Some(inner) = &self.inner {
            inner.dump_signed_aggregate_and_proof(aggregate);
        }
    }

    pub fn dump_signed_beacon_block<P: Preset>(&self, signed_block: Arc<SignedBeaconBlock<P>>) {
        if let Some(inner) = &self.inner {
            inner.dump_signed_beacon_block(signed_block);
        }
    }
}

struct Inner {
    dedicated_executor: DedicatedExecutor,
    dump_dir: PathBuf,
}

impl Inner {
    fn new(config_name: &str) -> Result<Self> {
        let dedicated_executor =
            DedicatedExecutor::new("de-data-dump", (num_cpus::get() / 4).max(1), Some(19), None);
        let dump_dir = [DUMP_DIR, config_name].into_iter().collect();

        fs_err::create_dir_all(&dump_dir)?;

        Ok(Self {
            dedicated_executor,
            dump_dir,
        })
    }

    fn dump_beacon_state<P: Preset>(&self, state: Arc<BeaconState<P>>, block_root: H256) {
        if !Feature::DumpBeaconStates.is_enabled() {
            return;
        }

        let dump_dir = self.dump_dir.clone();

        self.dedicated_executor
            .spawn(async move {
                if let Err(error) = try_dump_beacon_state(&dump_dir, &state, block_root) {
                    warn_with_peers!("failed to dump beacon state to disk: {error:?}");
                }
            })
            .detach();
    }

    fn dump_blob_sidecar<P: Preset>(&self, blob_sidecar: Arc<BlobSidecar<P>>) {
        if !Feature::DumpBlobSidecars.is_enabled() {
            return;
        }

        let dump_dir = self.dump_dir.clone();

        self.dedicated_executor
            .spawn(async move {
                if let Err(error) = try_dump_blob_sidecar(&dump_dir, &blob_sidecar) {
                    warn_with_peers!("failed to dump blob sidecar to disk: {error:?}");
                }
            })
            .detach();
    }

    fn dump_signed_aggregate_and_proof<P: Preset>(
        &self,
        aggregate: Arc<SignedAggregateAndProof<P>>,
    ) {
        if !Feature::DumpAggregateAttestations.is_enabled() {
            return;
        }

        let dump_dir = self.dump_dir.clone();

        self.dedicated_executor
            .spawn(async move {
                if let Err(error) =
                    try_dump_aggregate_attestation(&dump_dir, &aggregate.aggregate())
                {
                    warn_with_peers!("failed to dump aggregate attestation to disk: {error:?}");
                }
            })
            .detach();
    }

    fn dump_signed_beacon_block<P: Preset>(&self, signed_block: Arc<SignedBeaconBlock<P>>) {
        if !Feature::DumpBeaconBlocks.is_enabled() {
            return;
        }

        let dump_dir = self.dump_dir.clone();

        self.dedicated_executor
            .spawn(async move {
                if let Err(error) = try_dump_signed_block(&dump_dir, &signed_block) {
                    warn_with_peers!("failed to dump signed beacon block to disk: {error:?}");
                }
            })
            .detach();
    }
}

fn dump_enabled() -> bool {
    Feature::DumpAggregateAttestations.is_enabled()
        || Feature::DumpBeaconBlocks.is_enabled()
        || Feature::DumpBeaconStates.is_enabled()
        || Feature::DumpBlobSidecars.is_enabled()
}

fn try_dump_aggregate_attestation<P: Preset>(
    dump_dir: &Path,
    attestation: &Attestation<P>,
) -> Result<()> {
    let slot = attestation.data().slot;
    let root = attestation.hash_tree_root();
    let file_name = format!("attestation_slot_{slot:08}_root_{root:?}.ssz");

    fs_err::write(dump_dir.join(file_name), attestation.to_ssz()?)?;

    Ok(())
}

fn try_dump_beacon_state<P: Preset>(
    dump_dir: &Path,
    state: &BeaconState<P>,
    block_root: H256,
) -> Result<()> {
    let slot = state.slot();
    let file_name = format!("beacon_state_slot_{slot:08}_root_{block_root:?}.ssz");

    fs_err::write(dump_dir.join(file_name), state.to_ssz()?)?;

    Ok(())
}

fn try_dump_blob_sidecar<P: Preset>(dump_dir: &Path, blob_sidecar: &BlobSidecar<P>) -> Result<()> {
    let slot = blob_sidecar.slot();
    let block_root = blob_sidecar.signed_block_header.message.hash_tree_root();
    let index = blob_sidecar.index;
    let file_name = format!("blob_sidecar_slot_{slot:08}_root_{block_root:?}_index_{index}.ssz");

    fs_err::write(dump_dir.join(file_name), blob_sidecar.to_ssz()?)?;

    Ok(())
}

fn try_dump_signed_block<P: Preset>(
    dump_dir: &Path,
    signed_block: &SignedBeaconBlock<P>,
) -> Result<()> {
    let block_root = signed_block.message().hash_tree_root();
    let slot = signed_block.message().slot();
    let file_name = format!("beacon_block_slot_{slot:08}_root_{block_root:?}.ssz");

    fs_err::write(dump_dir.join(file_name), signed_block.to_ssz()?)?;

    Ok(())
}
