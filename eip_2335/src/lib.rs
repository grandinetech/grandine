//! Implementation of [EIP-2335](https://eips.ethereum.org/EIPS/eip-2335).

use core::fmt::{Display, Formatter, Result as FmtResult};

use aes::Aes128;
use anyhow::{ensure, Result};
use bls::{PublicKeyBytes, SecretKeyBytes};
use ctr::{
    cipher::{KeyIvInit as _, StreamCipher as _},
    Ctr32BE,
};
use derive_more::AsRef;
use hex::{FromHex, ToHex};
use hmac::Hmac;
use rand::Rng as _;
use scrypt::Params;
use serde::{
    de::{Error as DeserializeError, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use serde_utils::FromHexTrait;
use serde_with::As;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization as _;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// EIP-2335 does not specify an exact value for this, but it must be at least 32.
// The test vectors and other implementations use this exact number as well.
const DERIVED_KEY_LENGTH: usize = 32;
const PURPOSE: usize = 12381;
const VERSION: usize = 4;

type DerivedKey = Zeroizing<[u8; DERIVED_KEY_LENGTH]>;
type ScryptCost = u64;

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Keystore {
    crypto: Crypto<SecretKeyBytes>,
    description: Option<String>,
    // Without the attribute this would use the `Deserialize` impl of `PublicKeyBytes`,
    // which accepts strings prefixed with `0x`.
    #[serde(with = "As::<Option<FromHexTrait>>")]
    pubkey: Option<PublicKeyBytes>,
    path: Eip2334Path,
    uuid: Uuid,
    version: Version,
}

impl Keystore {
    #[must_use]
    pub const fn uuid(&self) -> Uuid {
        self.uuid
    }

    pub fn decrypt(self, normalized_password: &str) -> Result<SecretKeyBytes> {
        self.crypto.decrypt(normalized_password)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(
    bound(
        serialize = "for <'t> &'t T: ToHex",
        deserialize = "T: FromHex<Error: Display>",
    ),
    deny_unknown_fields
)]
pub struct Crypto<T> {
    kdf: Module<Kdf, KdfMessage>,
    // This may have to be redesigned if other checksum algorithms are added.
    checksum: Module<Checksum, ChecksumMessage>,
    cipher: Module<Cipher, T>,
}

impl<T> Crypto<T> {
    pub fn encrypt(message: T, password: &str) -> Result<Self>
    where
        T: AsRef<[u8]> + AsMut<[u8]>,
    {
        let mut crypto = Self::new(message);

        let encryption_key = crypto.kdf.function.derive_key(password)?;
        let (first_half, second_half) = encryption_key.split_at(DERIVED_KEY_LENGTH / 2);

        // Borrow the `Cipher` to avoid copying `iv` out of it.
        match &crypto.cipher.function {
            Cipher::Aes128Ctr { iv } => {
                let mut cipher = Ctr32BE::<Aes128>::new(first_half.into(), iv.as_ref().into());
                cipher.apply_keystream(crypto.cipher.message.as_mut());
            }
        }

        match crypto.checksum.function {
            Checksum::Sha256 {} => {
                Sha256::new()
                    .chain_update(second_half)
                    .chain_update(crypto.cipher.message.as_ref())
                    .finalize_into(crypto.checksum.message.bytes.as_mut().into());
            }
        }

        Ok(crypto)
    }

    pub fn decrypt(mut self, password: &str) -> Result<T>
    where
        T: AsRef<[u8]> + AsMut<[u8]>,
    {
        let decryption_key = self.kdf.function.derive_key(password)?;
        let (first_half, second_half) = decryption_key.split_at(DERIVED_KEY_LENGTH / 2);

        match self.checksum.function {
            Checksum::Sha256 {} => {
                let mut checksum = ChecksumMessage::default();

                Sha256::new()
                    .chain_update(second_half)
                    .chain_update(self.cipher.message.as_ref())
                    .finalize_into(checksum.bytes.as_mut().into());

                ensure!(checksum == self.checksum.message, Error::ChecksumMismatch);
            }
        }

        // Borrow the `Cipher` to avoid copying `iv` out of it.
        match &self.cipher.function {
            Cipher::Aes128Ctr { iv } => {
                let mut cipher = Ctr32BE::<Aes128>::new(first_half.into(), iv.into());
                cipher.apply_keystream(self.cipher.message.as_mut());
            }
        }

        Ok(self.cipher.message)
    }

    fn new(message: T) -> Self {
        // `ThreadRng` is cryptographically secure.
        let mut rng = rand::thread_rng();

        let salt = rng.gen();
        let iv = rng.gen();

        Self {
            kdf: Module {
                function: Kdf::Scrypt {
                    dklen: DerivedKeyLength,
                    n: 1 << 18, // 262_144
                    p: 1,
                    r: 8,
                    salt: Salt { bytes: salt },
                },
                message: KdfMessage,
            },
            checksum: Module {
                function: Checksum::Sha256 {},
                message: ChecksumMessage::default(),
            },
            cipher: Module {
                function: Cipher::Aes128Ctr { iv },
                message,
            },
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(
    bound(
        serialize = "F: Serialize, for <'m> &'m M: ToHex",
        deserialize = "F: Deserialize<'de>, M: FromHex<Error: Display>",
    ),
    deny_unknown_fields
)]
struct Module<F, M> {
    #[serde(flatten)]
    function: F,
    #[serde(with = "hex::serde")]
    message: M,
}

/// Key derivation function.
#[derive(Zeroize, ZeroizeOnDrop, Deserialize, Serialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "lowercase",
    tag = "function",
    content = "params"
)]
enum Kdf {
    Pbkdf2 {
        c: u32,
        dklen: DerivedKeyLength,
        prf: PseudoRandomFunction,
        salt: Salt,
    },
    Scrypt {
        dklen: DerivedKeyLength,
        n: ScryptCost,
        p: u32,
        r: u32,
        salt: Salt,
    },
}

impl Kdf {
    fn derive_key(&self, password: &str) -> Result<DerivedKey> {
        let mut decryption_key = DerivedKey::default();

        match self {
            Self::Pbkdf2 {
                c,
                prf: PseudoRandomFunction::HmacSha256,
                salt,
                ..
            } => pbkdf2::pbkdf2::<Hmac<Sha256>>(
                password.as_bytes(),
                &salt.bytes,
                *c,
                decryption_key.as_mut(),
            )?,
            Self::Scrypt { n, p, r, salt, .. } => {
                let log_n = n
                    .checked_ilog2()
                    .ok_or(Error::ScryptCostZero)?
                    .try_into()
                    .expect("binary logarithm of u64 should fit in u8");

                let scrypt_params = Params::new(log_n, *r, *p, DERIVED_KEY_LENGTH)?;

                scrypt::scrypt(
                    password.as_bytes(),
                    &salt.bytes,
                    &scrypt_params,
                    decryption_key.as_mut(),
                )?
            }
        }

        Ok(decryption_key)
    }
}

#[derive(Zeroize, ZeroizeOnDrop, Deserialize, Serialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "lowercase",
    tag = "function",
    content = "params"
)]
enum Checksum {
    // The empty braces affect the generated Serde impls.
    #[allow(clippy::empty_enum_variants_with_brackets)]
    Sha256 {},
}

#[derive(Zeroize, ZeroizeOnDrop, Deserialize, Serialize)]
#[serde(deny_unknown_fields, tag = "function", content = "params")]
enum Cipher {
    #[serde(rename = "aes-128-ctr")]
    Aes128Ctr {
        #[serde(with = "hex::serde")]
        iv: [u8; 16],
    },
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct DerivedKeyLength;

impl Serialize for DerivedKeyLength {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        DERIVED_KEY_LENGTH.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DerivedKeyLength {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let actual_dklen = usize::deserialize(deserializer)?;

        if actual_dklen != DERIVED_KEY_LENGTH {
            return Err(D::Error::custom(format!(
                "expected dklen to be {DERIVED_KEY_LENGTH}, found {actual_dklen}",
            )));
        }

        Ok(Self)
    }
}

#[derive(Zeroize, ZeroizeOnDrop, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PseudoRandomFunction {
    HmacSha256,
}

#[derive(Zeroize, ZeroizeOnDrop, Deserialize, Serialize)]
#[serde(transparent)]
struct Salt {
    // EIP-2335 does not specify salt lengths, but the test vectors and other implementations use
    // salts of 32 bytes.
    #[serde(with = "hex::serde")]
    bytes: [u8; 32],
}

/// An empty message.
#[derive(Zeroize, ZeroizeOnDrop)]
struct KdfMessage;

impl AsRef<[u8]> for KdfMessage {
    fn as_ref(&self) -> &[u8] {
        &[]
    }
}

impl FromHex for KdfMessage {
    type Error = Error;

    fn from_hex<T: AsRef<[u8]>>(bytes: T) -> Result<Self, Self::Error> {
        if !bytes.as_ref().is_empty() {
            return Err(Error::KdfMessageNotEmpty);
        }

        Ok(Self)
    }
}

#[derive(PartialEq, Eq, Default, AsRef, Zeroize, ZeroizeOnDrop, Serialize)]
#[as_ref(forward)]
struct ChecksumMessage {
    bytes: [u8; 32],
}

impl FromHex for ChecksumMessage {
    type Error = <[u8; core::mem::size_of::<Self>()] as FromHex>::Error;

    fn from_hex<T: AsRef<[u8]>>(digits: T) -> Result<Self, Self::Error> {
        let bytes = FromHex::from_hex(digits)?;
        Ok(Self { bytes })
    }
}

/// BLS12-381 key path as defined by [EIP-2334](https://eips.ethereum.org/EIPS/eip-2334).
enum Eip2334Path {
    UnknownOrIrrelevant,
    #[allow(dead_code)]
    Known {
        coin_type: usize,
        account: usize,
        // `use` is a keyword in Rust.
        use_levels: Vec<usize>,
    },
}

impl<'de> Deserialize<'de> for Eip2334Path {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PathVisitor;

        impl<'de> Visitor<'de> for PathVisitor {
            type Value = Eip2334Path;

            fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
                formatter.write_str("EIP-2334 path as a string")
            }

            fn visit_str<E: DeserializeError>(self, string: &str) -> Result<Self::Value, E> {
                if string.is_empty() {
                    return Ok(Eip2334Path::UnknownOrIrrelevant);
                }

                let mut levels = string.split('/');

                let first_level = levels
                    .next()
                    .expect("core::str::Split should always yield at least one item");

                if first_level != "m" {
                    return Err(E::custom(format!(
                        "expected path to start with master node, found {first_level:?}",
                    )));
                }

                let mut levels = levels.map(|level_string| level_string.parse().map_err(E::custom));

                let actual_purpose = levels
                    .next()
                    .ok_or_else(|| E::custom("path ends before purpose level"))??;

                if actual_purpose != PURPOSE {
                    return Err(E::custom(format!(
                        "expected path to have purpose {PURPOSE}, found {actual_purpose}",
                    )));
                }

                let coin_type = levels
                    .next()
                    .ok_or_else(|| E::custom("path ends before coin_type level"))??;

                let account = levels
                    .next()
                    .ok_or_else(|| E::custom("path ends before account level"))??;

                let use_levels = levels.collect::<Result<Vec<_>, _>>()?;

                if use_levels.is_empty() {
                    return Err(E::custom("path has no use levels"));
                }

                Ok(Eip2334Path::Known {
                    coin_type,
                    account,
                    use_levels,
                })
            }
        }

        deserializer.deserialize_str(PathVisitor)
    }
}

struct Version;

impl<'de> Deserialize<'de> for Version {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let actual_version = usize::deserialize(deserializer)?;

        if actual_version != VERSION {
            return Err(D::Error::custom(format!(
                "expected version {VERSION}, found version {actual_version}",
            )));
        }

        Ok(Self)
    }
}

#[derive(Debug, Error)]
enum Error {
    #[error("KDF message is not empty")]
    KdfMessageNotEmpty,
    #[error("scrypt cost is zero")]
    ScryptCostZero,
    #[error("derived key does not match checksum")]
    ChecksumMismatch,
}

pub fn normalize_password(bytes: impl AsRef<[u8]>) -> Result<Zeroizing<String>> {
    let string = core::str::from_utf8(bytes.as_ref())?;
    let normalized_chars = string.nfkd().filter(|character| !character.is_control());
    let normalized_length = normalized_chars.clone().map(char::len_utf8).sum();
    let mut normalized_string = Zeroizing::new(String::with_capacity(normalized_length));
    normalized_string.extend(normalized_chars);
    assert_eq!(normalized_string.len(), normalized_length);
    Ok(normalized_string)
}

#[cfg(test)]
mod tests {
    use bls::SecretKey;
    use hex_literal::hex;
    use tap::{Conv as _, TryConv as _};
    use test_case::test_case;

    use super::*;

    /// Checks that [`char::is_control`] behaves as required by [EIP-2335].
    ///
    /// [EIP-2335]: https://eips.ethereum.org/EIPS/eip-2335#control-codes-removal
    #[test]
    fn char_is_control_matches_eip_2335() {
        for character in '\0'..=char::MAX {
            let expected = matches!(character, '\0'..='\x1f' | '\x7f'..='\u{9f}');
            assert_eq!(character.is_control(), expected);
        }
    }

    #[test_case(
        r#"
            {
                "crypto": {
                    "kdf": {
                        "function": "pbkdf2",
                        "params": {
                            "dklen": 32,
                            "c": 262144,
                            "prf": "hmac-sha256",
                            "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                        },
                        "message": ""
                    },
                    "checksum": {
                        "function": "sha256",
                        "params": {},
                        "message": "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"
                    },
                    "cipher": {
                        "function": "aes-128-ctr",
                        "params": {
                            "iv": "264daa3f303d7259501c93d997d84fe6"
                        },
                        "message": "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad"
                    }
                },
                "description": "This is a test keystore that uses PBKDF2 to secure the secret.",
                "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
                "path": "m/12381/60/0/0",
                "uuid": "64625def-3331-4eea-ab6f-782f3ed16a83",
                "version": 4
            }
        "#;
        "PBKDF2 test vector from EIP-2335"
    )]
    #[test_case(
        r#"
            {
                "crypto": {
                    "kdf": {
                        "function": "scrypt",
                        "params": {
                            "dklen": 32,
                            "n": 262144,
                            "p": 1,
                            "r": 8,
                            "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                        },
                        "message": ""
                    },
                    "checksum": {
                        "function": "sha256",
                        "params": {},
                        "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484"
                    },
                    "cipher": {
                        "function": "aes-128-ctr",
                        "params": {
                            "iv": "264daa3f303d7259501c93d997d84fe6"
                        },
                        "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f"
                    }
                },
                "description": "This is a test keystore that uses scrypt to secure the secret.",
                "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
                "path": "m/12381/60/3141592653/589793238",
                "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
                "version": 4
            }
        "#;
        "scrypt test vector from EIP-2335"
    )]
    fn successfully_decrypts(keystore_json: &str) -> Result<()> {
        let expected_secret_key =
            hex!("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                .conv::<SecretKeyBytes>()
                .try_conv::<SecretKey>()?;

        let normalized_password = normalize_password("𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑")?;

        let actual_secret_key = serde_json::from_str::<Keystore>(keystore_json)?
            .decrypt(normalized_password.as_str())?
            .try_conv::<SecretKey>()?;

        assert_eq!(actual_secret_key, expected_secret_key);

        Ok(())
    }
}
