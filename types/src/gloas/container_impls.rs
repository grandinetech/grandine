use core::fmt;

use ssz::ContiguousList;

use crate::{
    deneb::primitives::{KzgCommitment, KzgProof},
    gloas::containers::DataColumnSidecar,
    preset::Preset,
};

impl<P: Preset> DataColumnSidecar<P> {
    #[must_use]
    pub fn full() -> Self {
        Self {
            column: ContiguousList::full(Box::default()),
            kzg_commitments: ContiguousList::full(KzgCommitment::repeat_byte(u8::MAX)),
            kzg_proofs: ContiguousList::full(KzgProof::repeat_byte(u8::MAX)),
            ..Default::default()
        }
    }
}

#[expect(clippy::missing_fields_in_debug)]
impl<P: Preset> fmt::Debug for DataColumnSidecar<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataColumnSidecar")
            .field("index", &self.index)
            .field("beacon_block_root", &self.beacon_block_root)
            .field("kzg_commitments", &self.kzg_commitments)
            .finish()
    }
}
