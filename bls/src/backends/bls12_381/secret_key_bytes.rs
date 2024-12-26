use crate::impl_secret_key_bytes;

use super::secret_key::SecretKey;

pub const SIZE: usize = size_of::<SecretKey>();

impl_secret_key_bytes!(SecretKeyBytes, SIZE);
