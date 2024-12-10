#[cfg(feature = "embed")]
mod embed_api;
#[cfg(feature = "embed")]
pub use embed_api::*;

#[cfg(not(feature = "embed"))]
mod http_api;
#[cfg(not(feature = "embed"))]
pub use http_api::*;
