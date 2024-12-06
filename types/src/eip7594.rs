use core::fmt;

use serde::{Deserialize, Serialize};
use ssz::{ByteVector, ContiguousList, ContiguousVector, Ssz, SszHash as _, H256};
use typenum::{Prod, U128, U4, U64};

use crate::{
    deneb::{
        consts::BytesPerFieldElement,
        primitives::{KzgCommitment, KzgProof},
    },
    phase0::containers::SignedBeaconBlockHeader,
    preset::Preset,
};

// const
pub type NumberOfColumns = U128;
type FieldElementsPerCell = U64;
type KzgCommitmentsInclusionProofDepth = U4;
type BytesPerCell = Prod<BytesPerFieldElement, FieldElementsPerCell>;

// primitives
pub type CellIndex = u64;
pub type RowIndex = u64;
pub type ColumnIndex = u64;
pub type Cell = Box<ByteVector<BytesPerCell>>;
type DataColumn<P> = ContiguousList<Cell, <P as Preset>::MaxBlobCommitmentsPerBlock>;
pub type BlobCommitmentsInclusionProof = ContiguousVector<H256, KzgCommitmentsInclusionProofDepth>;

pub const DATA_COLUMN_SIDECAR_SUBNET_COUNT: u64 = 128;

// container
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct DataColumnIdentifier {
    pub block_root: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub index: ColumnIndex,
}

#[derive(Clone, Default, PartialEq, Eq, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct DataColumnSidecar<P: Preset> {
    #[serde(with = "serde_utils::string_or_native")]
    pub index: ColumnIndex,
    pub column: DataColumn<P>,
    pub kzg_commitments: ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock>,
    pub kzg_proofs: ContiguousList<KzgProof, P::MaxBlobCommitmentsPerBlock>,
    pub signed_block_header: SignedBeaconBlockHeader,
    pub kzg_commitments_inclusion_proof: BlobCommitmentsInclusionProof,
}

// container_impl
impl<P: Preset> DataColumnSidecar<P> {
    #[must_use]
    pub const fn slot(&self) -> u64 {
        self.signed_block_header.message.slot
    }

    #[must_use]
    pub fn full() -> Self {
        Self {
            column: DataColumn::<P>::full(Box::default()),
            kzg_commitments: ContiguousList::full(KzgCommitment::repeat_byte(u8::MAX)),
            kzg_proofs: ContiguousList::full(KzgProof::repeat_byte(u8::MAX)),
            ..Default::default()
        }
    }
}

#[allow(clippy::missing_fields_in_debug)]
impl<P: Preset> fmt::Debug for DataColumnSidecar<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataColumnSidecar")
            .field("index", &self.index)
            .field(
                "kzg_commitments_inclusion_proof",
                &self.kzg_commitments_inclusion_proof,
            )
            .field("signed_block_header", &self.signed_block_header)
            .field("kzg_commitments", &self.kzg_commitments)
            .finish()
    }
}

impl<P: Preset> From<&DataColumnSidecar<P>> for DataColumnIdentifier {
    fn from(sidecar: &DataColumnSidecar<P>) -> Self {
        let DataColumnSidecar {
            index,
            signed_block_header,
            ..
        } = *sidecar;

        let block_header = signed_block_header.message;
        let block_root = block_header.hash_tree_root();

        Self { block_root, index }
    }
}

#[cfg(test)]
mod tests {
    use spec_test_utils::Case;
    use test_generator::test_resources;

    use crate::{
        preset::{Mainnet, Minimal},
        unphased::spec_tests,
    };

    macro_rules! tests_for_type {
        (
            $type: ident $(<_ $bracket: tt)?,
            $mainnet_glob: literal,
            $minimal_glob: literal,
        ) => {
            #[allow(non_snake_case)]
            mod $type {
                use super::*;

                #[test_resources($mainnet_glob)]
                fn mainnet(case: Case) {
                    spec_tests::run_spec_test_case::<crate::eip7594::$type$(<Mainnet $bracket)?>(case);
                }

                #[test_resources($minimal_glob)]
                fn minimal(case: Case) {
                    spec_tests::run_spec_test_case::<crate::eip7594::$type$(<Minimal $bracket)?>(case);
                }
            }
        };
    }

    tests_for_type! {
        DataColumnIdentifier,
        "consensus-spec-tests/tests/mainnet/eip7594/ssz_static/DataColumnIdentifier/*/*",
        "consensus-spec-tests/tests/minimal/eip7594/ssz_static/DataColumnIdentifier/*/*",
    }

    tests_for_type! {
        DataColumnSidecar<_>,
        "consensus-spec-tests/tests/mainnet/eip7594/ssz_static/DataColumnSidecar/*/*",
        "consensus-spec-tests/tests/minimal/eip7594/ssz_static/DataColumnSidecar/*/*",
    }
}
