use bls::PublicKeyBytes;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("Doppelganger validators detected on the network (public keys: {public_keys:?})")]
    DoppelgangersDetected { public_keys: Vec<PublicKeyBytes> },
}
