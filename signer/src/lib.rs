pub use crate::{
    signer::{KeyOrigin, Signer, Snapshot},
    types::{ForkInfo, SigningMessage, SigningTriple},
    web3signer::{
        Config as Web3SignerConfig, UrlPolicy as Web3SignerUrlPolicy, Web3SignerClientOptions,
        build_web3signer_client,
    },
};

mod signer;
mod types;
mod web3signer {
    pub use api::{
        ClientOptions as Web3SignerClientOptions, Config, FetchedKeys, UrlPolicy, Web3Signer,
        build_client as build_web3signer_client,
    };

    mod api;
    mod types;
}
