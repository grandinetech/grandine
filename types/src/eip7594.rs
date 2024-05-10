use core::fmt;

use serde::{Deserialize, Serialize};
use ssz::{ByteVector, ContiguousList, ContiguousVector, Ssz, SszHash as _, H256};
use typenum::{Prod, U4, U64};

use crate::{
    deneb::{
        consts::BytesPerFieldElement,
        primitives::{KzgCommitment, KzgProof},
    },
    phase0::containers::SignedBeaconBlockHeader,
    preset::Preset,
};

type FieldElementsPerCell = U64;
type BytesPerCell = Prod<BytesPerFieldElement, FieldElementsPerCell>;

pub type ColumnIndex = u64;
pub type Cell = Box<ByteVector<BytesPerCell>>;

type DataColumn<P> = ContiguousList<Cell, <P as Preset>::MaxBlobCommitmentsPerBlock>;

pub type KzgCommitmentsInclusionProofDepth = U4;

pub type BlobCommitmentsInclusionProof = ContiguousVector<H256, KzgCommitmentsInclusionProofDepth>;

pub const DATA_COLUMN_SIDECAR_SUBNET_COUNT: u64 = 32;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct DataColumnIdentifier {
    block_root: H256,
    #[serde(with = "serde_utils::string_or_native")]
    index: ColumnIndex,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize, Ssz)]
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

impl<P: Preset> DataColumnSidecar<P> {
    pub fn slot(&self) -> u64 {
        self.signed_block_header.message.slot
    }
}

impl<P: Preset> fmt::Debug for DataColumnSidecar<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataColumnSidecar")
            .field("index", &self.index)
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
