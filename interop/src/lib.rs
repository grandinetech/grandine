use core::num::NonZeroU64;

use anyhow::Result;
use bls::{SecretKey, SecretKeyBytes};
use deposit_tree::DepositTree;
use genesis::Incremental;
use helper_functions::{misc, signing::SignForAllForks};
use hex_literal::hex;
use num_bigint::BigUint;
use ssz::SszHash as _;
use types::{
    combined::BeaconState as CombinedBeaconState,
    config::Config,
    phase0::{
        containers::{DepositData, DepositMessage},
        primitives::{UnixSeconds, ValidatorIndex, H256},
    },
    preset::Preset,
    traits::BeaconState,
};

/// <https://github.com/ethereum/eth2.0-pm/tree/b7c76e7a9d036ce73ca6aa0b7065db92f7728f41/interop/mocked_start#create-genesis-state>
const QUICK_START_ETH1_BLOCK_HASH: H256 = H256([0x42; 32]);

/// <https://github.com/ethereum/eth2.0-pm/tree/b7c76e7a9d036ce73ca6aa0b7065db92f7728f41/interop/mocked_start#create-genesis-state>
///
/// This is defined in the standard but effectively never used because the genesis time derived from
/// this is replaced by the one passed in as a parameter.
const QUICK_START_ETH1_BLOCK_TIMESTAMP: UnixSeconds = 1 << 40;

/// <https://github.com/ethereum/eth2.0-pm/tree/b7c76e7a9d036ce73ca6aa0b7065db92f7728f41/interop/mocked_start#pubkeyprivkey-generation>
///
/// Encoded in binary to avoid parsing a decimal string at runtime.
const CURVE_ORDER: &[u8] =
    &hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");

/// <https://github.com/ethereum/eth2.0-pm/tree/b7c76e7a9d036ce73ca6aa0b7065db92f7728f41/interop/mocked_start#quick-start-genesis>
pub fn quick_start_beacon_state<P: Preset>(
    config: &Config,
    genesis_time: UnixSeconds,
    validator_count: NonZeroU64,
) -> Result<(CombinedBeaconState<P>, DepositTree)> {
    let mut incremental = Incremental::new(config);

    incremental.set_eth1_timestamp(QUICK_START_ETH1_BLOCK_TIMESTAMP);

    for index in 0..validator_count.get() {
        let deposit_data = quick_start_deposit_data::<P>(config, &secret_key(index));
        incremental.add_deposit_data(deposit_data, index)?;
    }

    // > Clients must not run is_valid_genesis_state as this state is already considered valid.
    // > Specifically, we do not check nor care about MIN_GENESIS_TIME in these coordinated starts.

    let (mut genesis_state, deposit_tree) =
        incremental.finish(QUICK_START_ETH1_BLOCK_HASH, None)?;

    *genesis_state.genesis_time_mut() = genesis_time;

    Ok((genesis_state, deposit_tree))
}

/// <https://github.com/ethereum/eth2.0-pm/tree/b7c76e7a9d036ce73ca6aa0b7065db92f7728f41/interop/mocked_start#pubkeyprivkey-generation>
#[must_use]
pub fn secret_key(validator_index: ValidatorIndex) -> SecretKey {
    let index_hash = hashing::hash_256(validator_index.hash_tree_root());
    let curve_order = BigUint::from_bytes_be(CURVE_ORDER);
    let secret_key_uint = BigUint::from_bytes_le(index_hash.as_bytes()) % &curve_order;
    let unpadded = secret_key_uint.to_bytes_be();
    let mut padded = SecretKeyBytes::default();
    padded.as_mut()[size_of::<SecretKeyBytes>() - unpadded.len()..]
        .copy_from_slice(unpadded.as_slice());
    padded
        .try_into()
        .expect("the algorithm given in the standard should produce valid secret keys")
}

/// <https://github.com/ethereum/eth2.0-pm/tree/b7c76e7a9d036ce73ca6aa0b7065db92f7728f41/interop/mocked_start#generate-deposits>
#[must_use]
pub fn quick_start_deposit_data<P: Preset>(config: &Config, secret_key: &SecretKey) -> DepositData {
    let public_key = secret_key.to_public_key();
    let pubkey = public_key.into();
    let withdrawal_credentials = misc::bls_withdrawal_credentials(pubkey);
    let amount = P::MAX_EFFECTIVE_BALANCE;

    let deposit_message = DepositMessage {
        pubkey,
        withdrawal_credentials,
        amount,
    };

    let signature = deposit_message.sign(config, secret_key).into();

    DepositData {
        pubkey,
        withdrawal_credentials,
        amount,
        signature,
    }
}

#[cfg(test)]
mod tests {
    use bls::PublicKeyBytes;

    use super::*;

    #[test]
    fn curve_order_matches_standard() {
        assert_eq!(
            BigUint::from_bytes_be(CURVE_ORDER).to_string(),
            "52435875175126190479447740508185965837690552500527637822603658699938581184513",
        );
    }

    // See the following:
    // - <https://github.com/ethereum/eth2.0-pm/tree/b7c76e7a9d036ce73ca6aa0b7065db92f7728f41/interop/mocked_start#test-vectors>
    // - <https://github.com/ethereum/eth2.0-pm/blob/b7c76e7a9d036ce73ca6aa0b7065db92f7728f41/interop/mocked_start/keygen_10_validators.yaml>
    #[test]
    fn keypairs_match_standard() {
        let expected_keypairs = [
            (
                hex!("25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866"),
                hex!("a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c"),
            ),
            (
                hex!("51d0b65185db6989ab0b560d6deed19c7ead0e24b9b6372cbecb1f26bdfad000"),
                hex!("b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b"),
            ),
            (
                hex!("315ed405fafe339603932eebe8dbfd650ce5dafa561f6928664c75db85f97857"),
                hex!("a3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b"),
            ),
            (
                hex!("25b1166a43c109cb330af8945d364722757c65ed2bfed5444b5a2f057f82d391"),
                hex!("88c141df77cd9d8d7a71a75c826c41a9c9f03c6ee1b180f3e7852f6a280099ded351b58d66e653af8e42816a4d8f532e"),
            ),
            (
                hex!("3f5615898238c4c4f906b507ee917e9ea1bb69b93f1dbd11a34d229c3b06784b"),
                hex!("81283b7a20e1ca460ebd9bbd77005d557370cabb1f9a44f530c4c4c66230f675f8df8b4c2818851aa7d77a80ca5a4a5e"),
            ),
            (
                hex!("055794614bc85ed5436c1f5cab586aab6ca84835788621091f4f3b813761e7a8"),
                hex!("ab0bdda0f85f842f431beaccf1250bf1fd7ba51b4100fd64364b6401fda85bb0069b3e715b58819684e7fc0b10a72a34"),
            ),
            (
                hex!("1023c68852075965e0f7352dee3f76a84a83e7582c181c10179936c6d6348893"),
                hex!("9977f1c8b731a8d5558146bfb86caea26434f3c5878b589bf280a42c9159e700e9df0e4086296c20b011d2e78c27d373"),
            ),
            (
                hex!("3a941600dc41e5d20e818473b817a28507c23cdfdb4b659c15461ee5c71e41f5"),
                hex!("a8d4c7c27795a725961317ef5953a7032ed6d83739db8b0e8a72353d1b8b4439427f7efa2c89caa03cc9f28f8cbab8ac"),
            ),
            (
                hex!("066e3bdc0415530e5c7fed6382d5c822c192b620203cf669903e1810a8c67d06"),
                hex!("a6d310dbbfab9a22450f59993f87a4ce5db6223f3b5f1f30d2c4ec718922d400e0b3c7741de8e59960f72411a0ee10a7"),
            ),
            (
                hex!("2b3b88a041168a1c4cd04bdd8de7964fd35238f95442dc678514f9dadb81ec34"),
                hex!("9893413c00283a3f9ed9fd9845dda1cea38228d22567f9541dccc357e54a2d6a6e204103c92564cbc05f4905ac7c493a"),
            ),
        ];

        for ((sk_bytes, pk_bytes), validator_index) in expected_keypairs.iter().copied().zip(0..) {
            let expected_secret_key = SecretKeyBytes::from(sk_bytes)
                .try_into()
                .expect("every secret key given in the standard should be valid");
            let expected_public_key = PublicKeyBytes::from(pk_bytes)
                .try_into()
                .expect("every public key given in the standard should be valid");

            let actual_secret_key = secret_key(validator_index);
            let actual_public_key = actual_secret_key.to_public_key();

            assert_eq!(actual_secret_key, expected_secret_key);
            assert_eq!(actual_public_key, expected_public_key);
        }
    }
}
