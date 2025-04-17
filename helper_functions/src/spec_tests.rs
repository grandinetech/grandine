use bls::{
    error::Error,
    SecretKeyTrait as _, SignatureTrait as _,
    AggregatePublicKey, AggregatePublicKeyBytes, AggregateSignature, AggregateSignatureBytes,
    PublicKey, PublicKeyBytes, SecretKey, SecretKeyBytes, Signature, SignatureBytes,
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

// We do not run `consensus-spec-tests/tests/general/phase0/bls/aggregate_verify/*/*`.
// The currently stable parts of `consensus-specs` do not use `AggregateVerify`.

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AggregateData {
    input: Vec<SignatureBytes>,
    output: Option<AggregateSignatureBytes>,
}

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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignInput {
    privkey: SecretKeyBytes,
    message: H256,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignData {
    input: SignInput,
    output: Option<SignatureBytes>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyInput {
    pubkey: PublicKeyBytes,
    message: H256,
    signature: SignatureBytes,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyData {
    input: VerifyInput,
    output: bool,
}

#[test_resources("consensus-spec-tests/tests/general/*/bls/aggregate/*/*")]
fn aggregate(case: Case) {
    let AggregateData { input, output } = case.yaml("data");

    let actual_output = input
        .into_iter()
        .map(|bytes| {
            bytes
                .try_into()
                .expect("every aggregate test case contains a valid signature")
        })
        .reduce(AggregateSignature::aggregate)
        .map(Into::into);

    assert_eq!(actual_output, output);
}

#[test_resources("consensus-spec-tests/tests/general/altair/bls/eth_aggregate_pubkeys/*/*")]
fn eth_aggregate_pubkeys(case: Case) {
    let EthAggregatePubkeysData { input, output } = case.yaml("data");

    #[rustfmt::skip]
    let result = itertools::process_results(
        input.into_iter().map(PublicKey::try_from),
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
        .map(PublicKey::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map(|public_keys| {
            SingleVerifier.verify_aggregate_allowing_empty(
                message,
                signature,
                public_keys.iter(),
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

#[test_resources("consensus-spec-tests/tests/general/*/bls/fast_aggregate_verify/*/*")]
fn fast_aggregate_verify(case: Case) {
    let FastAggregateVerifyData { input, output } = case.yaml("data");

    let FastAggregateVerifyInput {
        pubkeys,
        message,
        signature,
    } = input;

    let run = || -> Result<_, Error> {
        let public_keys = pubkeys
            .into_iter()
            .map(PublicKey::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        let signature = Signature::try_from(signature)?;

        Ok(signature.fast_aggregate_verify(message, public_keys.iter()))
    };

    if output {
        assert!(
            run().expect("decompression should succeed"),
            "verification should succeed",
        );
    } else {
        assert!(
            !run().unwrap_or_default(),
            "either decompression or verification should fail",
        );
    }
}

#[test_resources("consensus-spec-tests/tests/general/*/bls/sign/*/*")]
fn sign(case: Case) {
    let SignData {
        input: SignInput { privkey, message },
        output,
    } = case.yaml("data");

    let secret_key = SecretKey::try_from(privkey);

    if let Some(expected_output) = output {
        let actual_output = secret_key
            .expect("every sign test case with output contains a valid secret key")
            .sign(message)
            .conv::<SignatureBytes>();

        assert_eq!(actual_output, expected_output);
    } else {
        secret_key.expect_err("every sign test case without output contains an invalid secret key");
    }
}

#[test_resources("consensus-spec-tests/tests/general/*/bls/verify/*/*")]
fn verify(case: Case) {
    let VerifyData { input, output } = case.yaml("data");

    let VerifyInput {
        pubkey,
        message,
        signature,
    } = input;

    let run = || -> Result<_, Error> {
        let public_key = PublicKey::try_from(pubkey)?;
        let signature = Signature::try_from(signature)?;
        Ok(signature.verify(message, public_key))
    };

    if output {
        assert!(
            run().expect("decompression should succeed"),
            "verification should succeed",
        );
    } else {
        assert!(
            !run().unwrap_or_default(),
            "either decompression or verification should fail",
        );
    }
}
