pub use crate::{
    signer::{KeyOrigin, Signer},
    types::{ForkInfo, SigningMessage, SigningTriple},
    web3signer::Config as Web3SignerConfig,
};

mod signer;
mod types;
mod web3signer {
    pub use api::{Config, FetchedKeys, Web3Signer};

    mod api;
    mod types;
}
