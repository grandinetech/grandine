use anyhow::Result;
use std::path::Path;

#[cfg(feature = "risc0")]
mod risc0;
#[cfg(feature = "risc0")]
pub use risc0::*;

#[cfg(feature = "sp1")]
mod sp1;
#[cfg(feature = "sp1")]
pub use sp1::*;

#[cfg(feature = "pico")]
mod pico;
#[cfg(feature = "pico")]
pub use pico::*;

#[derive(Clone, Copy, Debug)]
pub enum ConfigKind {
    Mainnet = 0,
    PectraDevnet6 = 1,
}

pub trait ReportTrait {
    fn cycles(&self) -> u64;
}

pub trait ProofTrait {
    fn verify(&self) -> bool;

    fn save(&self, path: impl AsRef<Path>) -> Result<()>;
}

pub trait VmBackend: Sized {
    type Report: ReportTrait;
    type Proof: ProofTrait;

    fn new() -> Result<Self>;

    fn execute(
        &self,
        config: ConfigKind,
        state_ssz: Vec<u8>,
        block_ssz: Vec<u8>,
        cache_ssz: Vec<u8>,
        phase_bytes: Vec<u8>,
    ) -> Result<(Vec<u8>, Self::Report)>;

    fn prove(
        &self,
        config: ConfigKind,
        state_ssz: Vec<u8>,
        block_ssz: Vec<u8>,
        cache_ssz: Vec<u8>,
        phase_bytes: Vec<u8>,
    ) -> Result<(Vec<u8>, Self::Proof)>;
}
