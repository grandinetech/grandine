//! An insecure stand-in for leanXMSS. Anyone can sign for any public key, but a signature only
//! verifies for the key, leaf index and message it was made for:
//!
//! - public key: `sha256("fake-xmss-pk" ‖ seed)`
//! - signature: `leaf_index (u32 LE) ‖ sha256(public key ‖ leaf_index (u32 LE) ‖ message)`,
//!   zero-padded

use sha2::{Digest as _, Sha256};

use crate::{
    Error, LEAF_INDEX_SIZE, LeafIndex, MESSAGE_SIZE, PUBLIC_KEY_SIZE, SEED_SIZE, SIGNATURE_SIZE,
};

const PUBLIC_KEY_DOMAIN: &[u8] = b"fake-xmss-pk";

pub struct ExpandedKey;

pub fn key_gen(seed: &[u8; SEED_SIZE]) -> (ExpandedKey, [u8; PUBLIC_KEY_SIZE]) {
    let public_key = Sha256::new()
        .chain_update(PUBLIC_KEY_DOMAIN)
        .chain_update(seed)
        .finalize();

    (ExpandedKey, public_key.into())
}

#[expect(clippy::unnecessary_wraps)]
pub const fn prepare(_key: &ExpandedKey, _leaf_index: LeafIndex) -> Result<(), Error> {
    Ok(())
}

fn fake_signature(
    public_key: &[u8; PUBLIC_KEY_SIZE],
    message: &[u8; MESSAGE_SIZE],
    leaf_index: LeafIndex,
) -> [u8; SIGNATURE_SIZE] {
    let leaf_bytes = leaf_index.to_le_bytes();

    let digest = Sha256::new()
        .chain_update(public_key)
        .chain_update(leaf_bytes)
        .chain_update(message)
        .finalize();

    let mut signature = [0; SIGNATURE_SIZE];
    signature[..LEAF_INDEX_SIZE].copy_from_slice(&leaf_bytes);
    signature[LEAF_INDEX_SIZE..][..digest.len()].copy_from_slice(&digest);
    signature
}

#[expect(clippy::unnecessary_wraps)]
pub fn sign(
    _key: &ExpandedKey,
    public_key: &[u8; PUBLIC_KEY_SIZE],
    message: &[u8; MESSAGE_SIZE],
    leaf_index: LeafIndex,
) -> Result<[u8; SIGNATURE_SIZE], Error> {
    Ok(fake_signature(public_key, message, leaf_index))
}

pub fn verify(
    public_key: &[u8; PUBLIC_KEY_SIZE],
    message: &[u8; MESSAGE_SIZE],
    signature: &[u8; SIGNATURE_SIZE],
) -> bool {
    let mut leaf_bytes = [0; LEAF_INDEX_SIZE];
    leaf_bytes.copy_from_slice(&signature[..LEAF_INDEX_SIZE]);
    let leaf_index = LeafIndex::from_le_bytes(leaf_bytes);

    fake_signature(public_key, message, leaf_index) == *signature
}
