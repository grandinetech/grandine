use core::fmt;

use primitive_types::H384;
use serde::{Deserialize, Serialize};
use ssz::{ContiguousList, ContiguousVector, Ssz, H256};
use typenum::{U48, U6};

use crate::{phase0::containers::SignedBeaconBlockHeader, preset::Preset};

pub type ColumnIndex = u64;

type MaxBlobCommitmentsPerBlock = U6;
type DataColumn = ContiguousList<ContiguousList<u8, U48>, U6>;

#[derive(PartialEq, Eq, Debug, Deserialize, Serialize, Ssz)]
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
    pub column: DataColumn,
    pub kzg_commitments: ContiguousList<H384, P::MaxBlobCommitmentsPerBlock>,
    pub kzg_proofs: ContiguousList<ContiguousList<u8, U48>, MaxBlobCommitmentsPerBlock>,
    pub signed_block_header: SignedBeaconBlockHeader,
    pub kzg_commitments_inclusion_proof:
        ContiguousVector<H256, P::KzgCommitmentInclusionProofDepth>,
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
