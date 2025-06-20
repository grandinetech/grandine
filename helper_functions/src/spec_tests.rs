use std::sync::Arc;

use bls::{
    traits::PublicKey as _, AggregatePublicKey, AggregatePublicKeyBytes, PublicKey, PublicKeyBytes,
    SignatureBytes,
};
use serde::Deserialize;
use spec_test_utils::Case;
use ssz::H256;
use tap::Conv as _;
use test_generator::test_resources;

use crate::{
    error::SignatureKind,
    verifier::{SingleVerifier, Verifier as _},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EthAggregatePubkeysData {
    input: Vec<PublicKeyBytes>,
    output: Option<AggregatePublicKeyBytes>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FastAggregateVerifyInput {
    pubkeys: Vec<PublicKeyBytes>,
    message: H256,
    signature: SignatureBytes,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FastAggregateVerifyData {
    input: FastAggregateVerifyInput,
    output: bool,
}

#[test_resources("consensus-spec-tests/tests/general/altair/bls/eth_aggregate_pubkeys/*/*")]
fn eth_aggregate_pubkeys(case: Case) {
    let EthAggregatePubkeysData { input, output } = case.yaml("data");

    #[rustfmt::skip]
    let result = itertools::process_results(
        input.into_iter().map(|bytes| PublicKey::try_from(bytes).map(Arc::new)),
        |public_keys| AggregatePublicKey::aggregate_nonempty(public_keys),
    );

    if let Some(expected_output) = output {
        let actual_output = result
            .expect("decompression should succeed")
            .expect("aggregation should succeed")
            .conv::<AggregatePublicKeyBytes>();

        assert_eq!(actual_output, expected_output);
    } else {
        result
            .and_then(core::convert::identity)
            .expect_err("either decompression or aggregation should fail");
    }
}

#[test_resources("consensus-spec-tests/tests/general/*/bls/eth_fast_aggregate_verify/*/*")]
fn eth_fast_aggregate_verify(case: Case) {
    let FastAggregateVerifyData { input, output } = case.yaml("data");

    let FastAggregateVerifyInput {
        pubkeys,
        message,
        signature,
    } = input;

    let result = pubkeys
        .into_iter()
        .map(|bytes| PublicKey::try_from(bytes).map(Arc::new))
        .collect::<Result<Vec<_>, _>>()
        .map(|public_keys| {
            SingleVerifier.verify_aggregate_allowing_empty(
                message,
                signature,
                public_keys,
                SignatureKind::SyncAggregate,
            )
        });

    if output {
        result
            .expect("decompression should succeed")
            .expect("verification should succeed");
    } else {
        result
            .map_err(Into::into)
            .and_then(core::convert::identity)
            .expect_err("either decompression or verification should fail");
    }
}
