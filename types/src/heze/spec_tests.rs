use spec_test_utils::Case;
use test_generator::test_resources;

use crate::{
    preset::{Mainnet, Minimal},
    unphased::spec_tests,
};

mod tested_types {
    pub use crate::heze::containers::*;
}

macro_rules! tests_for_type {
    (
        $type: ident $(<_ $bracket: tt)?,
        $mainnet_glob: literal,
        $minimal_glob: literal,
    ) => {
        #[expect(non_snake_case)]
        mod $type {
            use super::*;

            #[test_resources($mainnet_glob)]
            fn mainnet(case: Case) {
                spec_tests::run_spec_test_case::<tested_types::$type$(<Mainnet $bracket)?>(case);
            }

            #[test_resources($minimal_glob)]
            fn minimal(case: Case) {
                spec_tests::run_spec_test_case::<tested_types::$type$(<Minimal $bracket)?>(case);
            }
        }
    };
}

tests_for_type! {
    InclusionList<_>,
    "consensus-spec-tests/tests/mainnet/heze/ssz_static/InclusionList/*/*",
    "consensus-spec-tests/tests/minimal/heze/ssz_static/InclusionList/*/*",
}

tests_for_type! {
    SignedInclusionList<_>,
    "consensus-spec-tests/tests/mainnet/heze/ssz_static/SignedInclusionList/*/*",
    "consensus-spec-tests/tests/minimal/heze/ssz_static/SignedInclusionList/*/*",
}
