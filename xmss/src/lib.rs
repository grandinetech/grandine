//! leanXMSS signatures for the PQ fork (`specs/_features/pq`).
//!
//! A key signs at `2^32` one-time leaves. Signing two different messages at one leaf breaks the
//! key. Nothing here tracks used leaves: callers pick the leaf (the spec schedules them) and must
//! never reuse one.
//!
//! The scheme is `lean_xmss` from leanVM, pinned to one revision in the workspace manifest. All
//! nodes of a network must agree on it.

use core::{
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    num::NonZeroU64,
    str::FromStr,
};

use nonzero_ext::nonzero;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use ssz::{H256, MerkleTree, ReadError, Size, SszHash, SszRead, SszSize, SszWrite};
use thiserror::Error;
use typenum::{U1, U7};
use zeroize::Zeroizing;

#[cfg(feature = "fake_crypto")]
use fake as backend;
#[cfg(not(feature = "fake_crypto"))]
use lean as backend;

#[cfg(feature = "fake_crypto")]
mod fake;
#[cfg(not(feature = "fake_crypto"))]
mod lean;

pub const PUBLIC_KEY_SIZE: usize = 32;
/// The public parameter ends the public key.
pub const PUBLIC_PARAMETER_SIZE: usize = 16;
pub const SIGNATURE_SIZE: usize = 2404;
pub const SEED_SIZE: usize = 32;
pub const MESSAGE_SIZE: usize = 32;

/// Whether this build uses the insecure `fake_crypto` stand-in.
pub const FAKE_CRYPTO: bool = cfg!(feature = "fake_crypto");

/// The spec's `Uint64` leaf indices must fit in this.
pub type LeafIndex = u32;

/// Leaves per tree. [`XmssSecretKey::prepare`] builds the tree of one such aligned range.
pub const LEAVES_PER_TREE: NonZeroU64 = nonzero!(1_u64 << 16);

const LEAF_INDEX_SIZE: usize = size_of::<LeafIndex>();

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("invalid hex: {0}")]
    InvalidHex(#[from] hex::FromHexError),
    #[error("signing failed")]
    SigningFailed,
}

/// The spec's `XMSSPubkey`: the Merkle root followed by the public parameter.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct XmssPublicKey([u8; PUBLIC_KEY_SIZE]);

/// The spec's `XMSSSignature`: the leaf index (little-endian `u32`) followed by one signature per
/// layer.
///
/// Boxed so that containers holding one stay small enough to move around cheaply.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct XmssSignature(Box<[u8; SIGNATURE_SIZE]>);

impl Default for XmssSignature {
    fn default() -> Self {
        Self::empty()
    }
}

impl XmssPublicKey {
    #[must_use]
    pub const fn from_array(bytes: [u8; PUBLIC_KEY_SIZE]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_array(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.0
    }

    #[must_use]
    pub fn public_parameter(&self) -> [u8; PUBLIC_PARAMETER_SIZE] {
        let (_, public_parameter) = self.0.split_last_chunk().unwrap_or((&[], &[0; _]));
        *public_parameter
    }

    #[must_use]
    pub const fn empty() -> Self {
        Self([0; PUBLIC_KEY_SIZE])
    }
}

impl XmssSignature {
    #[must_use]
    pub fn from_array(bytes: [u8; SIGNATURE_SIZE]) -> Self {
        Self(Box::new(bytes))
    }

    #[must_use]
    pub fn as_array(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.0
    }

    /// The all-zero signature, which the spec requires of self-built bids.
    #[must_use]
    pub fn empty() -> Self {
        Self::from_array([0; SIGNATURE_SIZE])
    }

    /// The leaf index the signature claims (the spec's `GetLeafIndex`).
    #[must_use]
    pub fn leaf_index(&self) -> LeafIndex {
        let mut leaf_index = [0; LEAF_INDEX_SIZE];
        leaf_index.copy_from_slice(&self.0[..LEAF_INDEX_SIZE]);
        LeafIndex::from_le_bytes(leaf_index)
    }
}

macro_rules! impl_bytes {
    ($type: ident, $size: expr) => {
        impl $type {
            pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
                <[u8; $size]>::try_from(bytes)
                    .map(Self::from_array)
                    .map_err(|_| Error::InvalidLength {
                        expected: $size,
                        actual: bytes.len(),
                    })
            }

            #[must_use]
            pub fn is_empty(&self) -> bool {
                *self.as_array() == [0; $size]
            }
        }

        impl From<[u8; $size]> for $type {
            fn from(bytes: [u8; $size]) -> Self {
                Self::from_array(bytes)
            }
        }

        impl AsRef<[u8]> for $type {
            fn as_ref(&self) -> &[u8] {
                self.as_array()
            }
        }

        impl Display for $type {
            fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
                write!(formatter, "0x{}", hex::encode(self.as_array()))
            }
        }

        impl Debug for $type {
            fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
                Display::fmt(self, formatter)
            }
        }

        impl FromStr for $type {
            type Err = Error;

            fn from_str(string: &str) -> Result<Self, Self::Err> {
                let digits = string.strip_prefix("0x").unwrap_or(string);
                Self::from_slice(&hex::decode(digits)?)
            }
        }

        impl Serialize for $type {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let string = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
                string.parse().map_err(D::Error::custom)
            }
        }

        impl SszSize for $type {
            const SIZE: Size = Size::Fixed { size: $size };
        }

        impl<C> SszRead<C> for $type {
            fn from_ssz_unchecked(_context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
                Self::from_slice(bytes).map_err(|_| ReadError::FixedSizeMismatch {
                    expected: $size,
                    actual: bytes.len(),
                })
            }
        }

        impl SszWrite for $type {
            fn write_fixed(&self, bytes: &mut [u8]) {
                bytes.copy_from_slice(self.as_array());
            }
        }
    };
}

impl_bytes!(XmssPublicKey, PUBLIC_KEY_SIZE);
impl_bytes!(XmssSignature, SIGNATURE_SIZE);

impl SszHash for XmssPublicKey {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        H256(self.0)
    }
}

impl SszHash for XmssSignature {
    type PackingFactor = U1;

    // 2404 bytes are 76 chunks, padded to 128 = 2^7.
    fn hash_tree_root(&self) -> H256 {
        MerkleTree::<U7>::merkleize_bytes(self.as_array())
    }
}

impl From<H256> for XmssPublicKey {
    fn from(hash: H256) -> Self {
        Self(hash.0)
    }
}

impl From<XmssPublicKey> for H256 {
    fn from(public_key: XmssPublicKey) -> Self {
        Self(public_key.0)
    }
}

/// A leanXMSS secret key expanded from its seed.
///
/// Deliberately not `Clone`: two live copies of a stateful key are how leaves get reused.
pub struct XmssSecretKey {
    public_key: XmssPublicKey,
    expanded: backend::ExpandedKey,
}

impl Debug for XmssSecretKey {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        formatter
            .debug_struct("XmssSecretKey")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl XmssSecretKey {
    /// Expensive with the real scheme (about a second, a few MiB). Do not call on an async
    /// executor thread.
    #[must_use]
    pub fn from_seed(seed: &[u8; SEED_SIZE]) -> Self {
        let (expanded, public_key) = backend::key_gen(seed);

        Self {
            public_key: XmssPublicKey(public_key),
            expanded,
        }
    }

    /// The key `public_key` from the cache of its trees (leanVM `cache_to_bytes`), which saves
    /// building them. The cache is checked against `public_key`, so it needs no trust. `None` if
    /// it does not match.
    ///
    /// Recomputes part of each tree, which takes a fraction of a second. Do not call on an async
    /// executor thread.
    #[must_use]
    pub fn from_cache_bytes(
        seed: &[u8; SEED_SIZE],
        public_key: XmssPublicKey,
        bytes: &[u8],
    ) -> Option<Self> {
        backend::from_cache_bytes(seed, &public_key.0, bytes).map(|expanded| Self {
            public_key,
            expanded,
        })
    }

    /// The trees the key has built, for [`Self::from_cache_bytes`].
    #[must_use]
    pub fn cache_to_bytes(&self) -> Vec<u8> {
        backend::cache_to_bytes(&self.expanded)
    }

    /// The public parameter of the key `seed` generates. Cheap, unlike generating the key, so it
    /// can find a key's entry among public keys.
    #[must_use]
    pub fn public_parameter(seed: &[u8; SEED_SIZE]) -> [u8; PUBLIC_PARAMETER_SIZE] {
        backend::public_parameter(seed)
    }

    pub fn from_seed_slice(seed: &[u8]) -> Result<Self, Error> {
        let seed = Zeroizing::new(<[u8; SEED_SIZE]>::try_from(seed).map_err(|_| {
            Error::InvalidLength {
                expected: SEED_SIZE,
                actual: seed.len(),
            }
        })?);

        Ok(Self::from_seed(&seed))
    }

    #[must_use]
    pub const fn public_key(&self) -> XmssPublicKey {
        self.public_key
    }

    /// Builds the tree of the [`LEAVES_PER_TREE`]-leaf range containing `leaf_index` ahead of
    /// signing.
    #[cfg_attr(feature = "fake_crypto", expect(clippy::missing_const_for_fn))]
    pub fn prepare(&self, leaf_index: LeafIndex) -> Result<(), Error> {
        backend::prepare(&self.expanded, leaf_index)
    }

    /// The spec's `Sign`. Deterministic.
    pub fn sign(
        &self,
        message: &[u8; MESSAGE_SIZE],
        leaf_index: LeafIndex,
    ) -> Result<XmssSignature, Error> {
        backend::sign(&self.expanded, &self.public_key.0, message, leaf_index)
            .map(XmssSignature::from_array)
    }
}

/// The spec's `Verify`: `signature` is `public_key`'s signature of `message` at exactly
/// `leaf_index`.
#[must_use]
pub fn verify(
    public_key: &XmssPublicKey,
    leaf_index: LeafIndex,
    message: &[u8; MESSAGE_SIZE],
    signature: &XmssSignature,
) -> bool {
    signature.leaf_index() == leaf_index && backend::verify(&public_key.0, message, &signature.0)
}

/// [`verify`] with the spec's `Uint64` leaf index. Leaves past `u32::MAX` never verify.
#[must_use]
pub fn verify_u64(
    public_key: &XmssPublicKey,
    leaf_index: u64,
    message: &[u8; MESSAGE_SIZE],
    signature: &XmssSignature,
) -> bool {
    LeafIndex::try_from(leaf_index)
        .is_ok_and(|leaf_index| verify(public_key, leaf_index, message, signature))
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "fake_crypto"))]
    use serde::Deserialize;

    use ssz::SszReadDefault as _;

    use super::*;

    const LEAF: LeafIndex = (1 << 15) + 7;

    #[test]
    fn signature_root_matches_byte_vector_merkleization() {
        let signature = XmssSignature::from_array(core::array::from_fn(|index| {
            u8::try_from(index % 251).expect("remainder fits in u8")
        }));

        let byte_vector = ssz::ByteVector::<
            typenum::Sum<
                typenum::Sum<
                    typenum::Sum<typenum::Sum<typenum::U2048, typenum::U256>, typenum::U64>,
                    typenum::U32,
                >,
                typenum::U4,
            >,
        >::try_from(signature.as_ref())
        .expect("length matches");

        assert_eq!(signature.hash_tree_root(), byte_vector.hash_tree_root());
    }

    #[test]
    fn ssz_and_serde_round_trip() -> Result<(), Box<dyn core::error::Error>> {
        let signature = XmssSignature::from_array([0xcd; SIGNATURE_SIZE]);
        let bytes = signature.to_ssz()?;

        assert_eq!(XmssSignature::from_ssz_default(&bytes)?, signature);
        XmssSignature::from_ssz_default(&bytes[1..]).expect_err("one byte short");

        let public_key = XmssPublicKey::from_array([0xab; PUBLIC_KEY_SIZE]);
        let json = serde_json::to_string(&public_key)?;

        assert_eq!(json, format!("\"0x{}\"", "ab".repeat(32)));
        assert_eq!(serde_json::from_str::<XmssPublicKey>(&json)?, public_key);

        Ok(())
    }

    #[test]
    fn keys_load_from_their_cache_only() -> Result<(), Error> {
        let seed = [3; SEED_SIZE];
        let key = XmssSecretKey::from_seed(&seed);
        let public_key = key.public_key();

        assert_eq!(
            XmssSecretKey::public_parameter(&seed),
            public_key.public_parameter(),
        );

        key.prepare(LEAF)?;

        let cache = key.cache_to_bytes();
        let loaded = XmssSecretKey::from_cache_bytes(&seed, public_key, &cache)
            .expect("a key loads from its own cache");
        let message = [5; MESSAGE_SIZE];

        assert_eq!(loaded.sign(&message, LEAF)?, key.sign(&message, LEAF)?);

        let other_public_key = XmssSecretKey::from_seed(&[4; SEED_SIZE]).public_key();

        assert!(XmssSecretKey::from_cache_bytes(&seed, other_public_key, &cache).is_none());

        if !FAKE_CRYPTO {
            assert!(XmssSecretKey::from_cache_bytes(&seed, public_key, &cache[1..]).is_none());
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_bind_key_leaf_and_message() -> Result<(), Error> {
        let secret_key = XmssSecretKey::from_seed(&[1; SEED_SIZE]);
        let public_key = secret_key.public_key();
        let signature = secret_key.sign(&[2; MESSAGE_SIZE], LEAF)?;

        assert_eq!(signature.leaf_index(), LEAF);
        assert!(verify(&public_key, LEAF, &[2; MESSAGE_SIZE], &signature));
        assert_eq!(secret_key.sign(&[2; MESSAGE_SIZE], LEAF)?, signature);

        assert!(!verify(&public_key, LEAF, &[3; MESSAGE_SIZE], &signature));
        assert!(!verify(
            &public_key,
            LEAF + 1,
            &[2; MESSAGE_SIZE],
            &signature
        ));

        let other_key = XmssSecretKey::from_seed(&[9; SEED_SIZE]).public_key();

        assert!(!verify(&other_key, LEAF, &[2; MESSAGE_SIZE], &signature));

        let mut relabelled = *signature.as_array();
        relabelled[..LEAF_INDEX_SIZE].copy_from_slice(&(LEAF + 1).to_le_bytes());

        assert!(!verify(
            &public_key,
            LEAF + 1,
            &[2; MESSAGE_SIZE],
            &XmssSignature::from_array(relabelled),
        ));

        Ok(())
    }

    #[cfg(not(feature = "fake_crypto"))]
    #[derive(Deserialize)]
    struct Kat {
        seed: String,
        leaf_index: LeafIndex,
        message: String,
        pubkey: String,
        signature: String,
    }

    // The pyspec's known-answer test (ethlib leanXMSS). Real scheme only.
    #[cfg(not(feature = "fake_crypto"))]
    #[test]
    fn pyspec_known_answer() -> Result<(), Box<dyn core::error::Error>> {
        let kat = serde_json::from_str::<Kat>(include_str!("xmss_kat.json"))?;
        let seed = <[u8; SEED_SIZE]>::try_from(hex::decode(kat.seed)?.as_slice())?;
        let message = <[u8; MESSAGE_SIZE]>::try_from(hex::decode(kat.message)?.as_slice())?;
        let expected_public_key = kat.pubkey.parse::<XmssPublicKey>()?;
        let expected_signature = kat.signature.parse::<XmssSignature>()?;

        let secret_key = XmssSecretKey::from_seed(&seed);

        assert_eq!(secret_key.public_key(), expected_public_key);
        assert_eq!(
            secret_key.sign(&message, kat.leaf_index)?,
            expected_signature
        );
        assert!(verify(
            &expected_public_key,
            kat.leaf_index,
            &message,
            &expected_signature,
        ));

        Ok(())
    }
}
