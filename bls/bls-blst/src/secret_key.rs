use bls_core::{
    consts::DOMAIN_SEPARATION_TAG, error::Error, impl_secret_key,
    traits::SecretKey as SecretKeyTrait,
};
use blst::min_pk::SecretKey as RawSecretKey;

use super::{
    public_key::PublicKey,
    secret_key_bytes::{SecretKeyBytes, SIZE},
    signature::Signature,
};

// `RawSecretKey` already implements `Zeroize` (with `zeroize(drop)`):
// <https://github.com/supranational/blst/blob/v0.3.10/bindings/rust/src/lib.rs#L458-L460>
impl_secret_key!(
    SecretKeyTrait<SIZE>,
    SecretKey,
    RawSecretKey,
    SecretKeyBytes,
    PublicKey,
    Signature
);

impl TryFrom<SecretKeyBytes> for SecretKey {
    type Error = Error;

    #[inline]
    fn try_from(secret_key_bytes: SecretKeyBytes) -> Result<Self, Self::Error> {
        RawSecretKey::from_bytes(secret_key_bytes.as_ref())
            .map(Self)
            .map_err(|_| Error::InvalidSecretKey)
    }
}

impl SecretKeyTrait<SIZE> for SecretKey {
    type SecretKeyBytes = SecretKeyBytes;
    type PublicKey = PublicKey;
    type Signature = Signature;

    #[inline]
    #[must_use]
    fn to_bytes(&self) -> SecretKeyBytes {
        SecretKeyBytes {
            bytes: self.as_raw().to_bytes(),
        }
    }

    #[inline]
    fn to_public_key(&self) -> PublicKey {
        self.as_raw().sk_to_pk().into()
    }

    #[inline]
    fn sign(&self, message: impl AsRef<[u8]>) -> Signature {
        self.as_raw()
            .sign(message.as_ref(), DOMAIN_SEPARATION_TAG, &[])
            .into()
    }
}
