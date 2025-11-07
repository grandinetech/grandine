use super::{ConfigKind, ProofTrait, ReportTrait, VmBackend};
use anyhow::Result;
use std::path::Path;
use zkm_sdk::{ProverClient, ZKMProofWithPublicValues, ZKMStdin, include_elf};

const STATE_TRANSITION_ELF: &[u8] = include_elf!("zkvm_guest_ziren");

pub struct Report(zkm_sdk::ExecutionReport);

impl ReportTrait for Report {
    fn cycles(&self) -> u64 {
        self.0.total_instruction_count()
    }
}

pub struct Proof(zkm_sdk::ZKMVerifyingKey, ZKMProofWithPublicValues);

impl ProofTrait for Proof {
    fn verify(&self) -> bool {
        let client = ProverClient::new();

        client.verify(&self.1, &self.0).is_ok()
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
        zkm_sdk::utils::setup_logger();

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
        let client = ProverClient::new();
        let mut stdin = ZKMStdin::new();

        stdin.write(&(config as u8));
        stdin.write_slice(&state_ssz);
        stdin.write_slice(&block_ssz);
        stdin.write_slice(&cache_ssz);
        stdin.write_slice(&phase_bytes);

        let (output, report) = client.execute(STATE_TRANSITION_ELF, stdin).run()?;

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
        let client = ProverClient::new();

        let (pk, vk) = client.setup(STATE_TRANSITION_ELF);

        let mut stdin = ZKMStdin::new();

        stdin.write(&(config as u8));
        stdin.write_slice(&state_ssz);
        stdin.write_slice(&block_ssz);
        stdin.write_slice(&cache_ssz);
        stdin.write_slice(&phase_bytes);

        let proof = client.prove(&pk, stdin).run()?;

        Ok((proof.public_values.as_slice().to_vec(), Proof(vk, proof)))
    }
}
