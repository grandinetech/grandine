use super::{ConfigKind, ProofTrait, ReportTrait, VmBackend};
use anyhow::Result;
use sp1_sdk::{
    include_elf, ExecutionReport, Prover, ProverClient, SP1ProofWithPublicValues, SP1Stdin,
    SP1VerifyingKey,
};
use std::path::Path;

const STATE_TRANSITION_ELF: &[u8] = include_elf!("zkvm_guest_sp1");

pub struct Report(ExecutionReport);

impl ReportTrait for Report {
    fn cycles(&self) -> u64 {
        self.0.total_instruction_count()
    }
}

pub struct Proof(SP1VerifyingKey, SP1ProofWithPublicValues);

impl ProofTrait for Proof {
    fn verify(&self) -> bool {
        let prover = ProverClient::builder().cpu().build();

        prover.verify(&self.1, &self.0).is_ok()
    }

    fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        self.1.save(path)
    }
}

pub struct Vm;

impl VmBackend for Vm {
    type Report = Report;

    type Proof = Proof;

    fn new() -> Result<Self> {
        sp1_sdk::utils::setup_logger();

        Ok(Vm)
    }

    fn execute(
        &self,
        config: ConfigKind,
        state_ssz: Vec<u8>,
        block_ssz: Vec<u8>,
        cache_ssz: Vec<u8>,
        phase_bytes: Vec<u8>,
    ) -> Result<(Vec<u8>, Self::Report)> {
        let client = ProverClient::from_env();
        let mut stdin = SP1Stdin::new();

        stdin.write(&(config as u8));
        stdin.write_slice(&state_ssz);
        stdin.write_slice(&block_ssz);
        stdin.write_slice(&cache_ssz);
        stdin.write_slice(&phase_bytes);

        let (output, report) = client.execute(STATE_TRANSITION_ELF, &stdin).run()?;

        Ok((output.as_slice().to_vec(), Report(report)))
    }

    fn prove(
        &self,
        config: ConfigKind,
        state_ssz: Vec<u8>,
        block_ssz: Vec<u8>,
        cache_ssz: Vec<u8>,
        phase_bytes: Vec<u8>,
    ) -> Result<(Vec<u8>, Self::Proof)> {
        let client = ProverClient::builder().network().build();

        let (pk, vk) = client.setup(STATE_TRANSITION_ELF);

        let mut stdin = SP1Stdin::new();

        stdin.write(&(config as u8));
        stdin.write_slice(&state_ssz);
        stdin.write_slice(&block_ssz);
        stdin.write_slice(&cache_ssz);
        stdin.write_slice(&phase_bytes);

        let proof = client
            .prove(&pk, &stdin)
            .skip_simulation(true)
            .cycle_limit(10_000_000_000)
            .groth16()
            .run()?;

        Ok((proof.public_values.as_slice().to_vec(), Proof(vk, proof)))
    }
}
