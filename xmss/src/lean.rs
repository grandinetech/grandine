use core::panic::AssertUnwindSafe;
use std::panic::catch_unwind;

use lean_xmss::{
    LeanXmssExpandedSecretKey, LeanXmssPublicKey, LeanXmssSignature,
    internals::{public_param, scheme_seed},
};

use crate::{
    Error, LeafIndex, MESSAGE_SIZE, PUBLIC_KEY_SIZE, PUBLIC_PARAMETER_SIZE, SEED_SIZE,
    SIGNATURE_SIZE,
};

const _: () = assert!(lean_xmss::PUB_KEY_SIZE == PUBLIC_KEY_SIZE);
const _: () = assert!(lean_xmss::SIG_SIZE == SIGNATURE_SIZE);
const _: () = assert!(lean_xmss::SECRET_KEY_LEN == SEED_SIZE);
const _: () = assert!(lean_xmss::MESSAGE_LEN == MESSAGE_SIZE);

pub struct ExpandedKey(LeanXmssExpandedSecretKey);

pub fn key_gen(seed: &[u8; SEED_SIZE]) -> (ExpandedKey, [u8; PUBLIC_KEY_SIZE]) {
    let (secret_key, public_key) = lean_xmss::key_gen(seed);
    (ExpandedKey(secret_key), public_key.to_bytes())
}

pub fn public_parameter(seed: &[u8; SEED_SIZE]) -> [u8; PUBLIC_PARAMETER_SIZE] {
    public_param(&scheme_seed(seed))
}

pub fn from_cache_bytes(
    seed: &[u8; SEED_SIZE],
    public_key: &[u8; PUBLIC_KEY_SIZE],
    bytes: &[u8],
) -> Option<ExpandedKey> {
    // Upstream indexes with `unwrap` in places.
    catch_unwind(AssertUnwindSafe(|| {
        LeanXmssExpandedSecretKey::from_cache_bytes(
            seed,
            &LeanXmssPublicKey::from_bytes(public_key),
            bytes,
        )
    }))
    .ok()
    .flatten()
    .map(ExpandedKey)
}

pub fn cache_to_bytes(key: &ExpandedKey) -> Vec<u8> {
    key.0.cache_to_bytes()
}

// Upstream panics instead of returning errors (for example, on a poisoned cache lock).
pub fn prepare(key: &ExpandedKey, leaf_index: LeafIndex) -> Result<(), Error> {
    catch_unwind(AssertUnwindSafe(|| key.0.prepare(leaf_index))).map_err(|_| Error::SigningFailed)
}

pub fn sign(
    key: &ExpandedKey,
    _public_key: &[u8; PUBLIC_KEY_SIZE],
    message: &[u8; MESSAGE_SIZE],
    leaf_index: LeafIndex,
) -> Result<[u8; SIGNATURE_SIZE], Error> {
    catch_unwind(AssertUnwindSafe(|| {
        lean_xmss::sign(&key.0, message, leaf_index).to_bytes()
    }))
    .map_err(|_| Error::SigningFailed)
}

pub fn verify(
    public_key: &[u8; PUBLIC_KEY_SIZE],
    message: &[u8; MESSAGE_SIZE],
    signature: &[u8; SIGNATURE_SIZE],
) -> bool {
    lean_xmss::verify(
        &LeanXmssPublicKey::from_bytes(public_key),
        message,
        &LeanXmssSignature::from_bytes(signature),
    )
}
