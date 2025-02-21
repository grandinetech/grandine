use bls_core::impl_secret_key_bytes;

use crate::secret_key::SecretKey;

pub const SIZE: usize = size_of::<SecretKey>();

impl_secret_key_bytes!(SecretKeyBytes, SIZE);
