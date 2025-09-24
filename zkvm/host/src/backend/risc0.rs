use super::{ConfigKind, ProofTrait, ReportTrait, VmBackend};
use anyhow::Result;
use borsh::BorshSerialize;
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt, SessionStats};
use std::{fs::File, io::BufWriter};
use zkvm_guest_risc0::{RISC0_GRANDINE_STATE_TRANSITION_ELF, RISC0_GRANDINE_STATE_TRANSITION_ID};

pub struct Vm;

pub struct Report(SessionStats);

impl ReportTrait for Report {
    fn cycles(&self) -> u64 {
        self.0.total_cycles
    }
}

pub struct Proof(Receipt);

impl ProofTrait for Proof {
    fn verify(&self) -> bool {
        self.0.verify(RISC0_GRANDINE_STATE_TRANSITION_ID).is_ok()
    }

    fn save(&self, path: impl AsRef<std::path::Path>) -> Result<()> {
        let mut writer = BufWriter::new(File::create(path)?);
        BorshSerialize::serialize(&self.0, &mut writer)?;

        Ok(())
    }
}

impl VmBackend for Vm {
    type Report = Report;

    type Proof = Proof;

    fn new() -> Result<Self> {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
            .init();
        Ok(Self)
    }

    fn execute(
        &self,
        config: ConfigKind,
        state_ssz: Vec<u8>,
        block_ssz: Vec<u8>,
        cache_ssz: Vec<u8>,
        phase_bytes: Vec<u8>,
    ) -> Result<(Vec<u8>, Self::Report)> {
        let prover = default_prover();

        let env = ExecutorEnv::builder()
            .write(&(config as u8))?
            .write(&state_ssz.len())?
            .write(&block_ssz.len())?
            .write(&cache_ssz.len())?
            .write(&phase_bytes.len())?
            .write_slice(&state_ssz)
            .write_slice(&block_ssz)
            .write_slice(&cache_ssz)
            .write_slice(&phase_bytes)
            .build()?;

        let elf = RISC0_GRANDINE_STATE_TRANSITION_ELF;

        let prove_info = prover.prove(env, elf)?;
        let receipt = prove_info.receipt;

        Ok((receipt.journal.bytes, Report(prove_info.stats)))
    }

    fn prove(
        &self,
        config: ConfigKind,
        state_ssz: Vec<u8>,
        block_ssz: Vec<u8>,
        cache_ssz: Vec<u8>,
        phase_bytes: Vec<u8>,
    ) -> Result<(Vec<u8>, Self::Proof)> {
        let prover = default_prover();

        let env = ExecutorEnv::builder()
            .write(&(config as u8))?
            .write(&state_ssz.len())?
            .write(&block_ssz.len())?
            .write(&cache_ssz.len())?
            .write(&phase_bytes.len())?
            .write_slice(&state_ssz)
            .write_slice(&block_ssz)
            .write_slice(&cache_ssz)
            .write_slice(&phase_bytes)
            .build()?;

        let elf = RISC0_GRANDINE_STATE_TRANSITION_ELF;

        let prove_info = prover.prove(env, elf)?;
        let receipt = prove_info.receipt;

        Ok((receipt.journal.bytes.clone(), Proof(receipt)))
    }
}
