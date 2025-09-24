use super::{ConfigKind, ProofTrait, ReportTrait, VmBackend};
use anyhow::{anyhow, Context, Result};
use pico_sdk::{client::DefaultProverClient, init_logger};
use pico_vm::{
    configs::stark_config::KoalaBearPoseidon2,
    instances::configs::embed_kb_config::KoalaBearBn254Poseidon2, machine::proof::MetaProof,
};
use std::{
    env,
    fs::{self, File},
    io::{BufWriter, Write},
    path::Path,
};

type PicoProofSet = (
    MetaProof<KoalaBearPoseidon2>,
    MetaProof<KoalaBearBn254Poseidon2>,
);

// Refer to Pico client code for the prove return type:
// https://github.com/brevis-network/pico/blob/b52a89e4551b3f28086f7aae49505631845bf961/sdk/sdk/src/client.rs#L123
// We save the prover here so verify() action can be performed later.
pub struct Proof {
    prover: DefaultProverClient,
    proof_set: PicoProofSet,
}

impl ProofTrait for Proof {
    fn verify(&self) -> bool {
        match self.prover.verify(&self.proof_set) {
            Ok(()) => true,
            Err(err) => {
                println!("proof verification failed: {err}");
                false
            }
        }
    }

    fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let mut writer = BufWriter::new(File::create(path)?);

        serde_json::to_writer(&mut writer, &self.proof_set.0)?;
        writer.write_all(b"\n")?;
        serde_json::to_writer(&mut writer, &self.proof_set.1)?;
        writer.flush()?;

        Ok(())
    }
}

pub struct Report(u64);

impl ReportTrait for Report {
    fn cycles(&self) -> u64 {
        self.0
    }
}

const ZKVM_GUEST_PICO_SUFFIX: &str = "elf/zkvm-guest-pico.elf";

pub struct Vm;
impl VmBackend for Vm {
    type Proof = Proof;
    type Report = Report;

    fn new() -> Result<Self> {
        init_logger();
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
        // Load the ELF file
        let out_dir = env!("OUT_DIR");
        let zkvm_guest_path = Path::new(&out_dir).join(ZKVM_GUEST_PICO_SUFFIX);
        let elf = fs::read(&zkvm_guest_path).with_context(|| {
            format!("Failed to load ELF file from {}", zkvm_guest_path.display())
        })?;

        // Initialize the prover client
        let prover = DefaultProverClient::new(&elf);

        // Set up input
        let mut stdin_builder = prover.new_stdin_builder();

        stdin_builder.write(&(config as u8));
        stdin_builder.write_slice(&state_ssz);
        stdin_builder.write_slice(&block_ssz);
        stdin_builder.write_slice(&cache_ssz);
        stdin_builder.write_slice(&phase_bytes);

        // zkVM emulation
        println!("zkvm_host: emulation starts.");
        let (cycle, output) = prover.emulate(stdin_builder);
        println!("zkvm_host: emulation ends.");

        Ok((output, Report(cycle)))
    }

    fn prove(
        &self,
        config: ConfigKind,
        state_ssz: Vec<u8>,
        block_ssz: Vec<u8>,
        cache_ssz: Vec<u8>,
        phase_bytes: Vec<u8>,
    ) -> Result<(Vec<u8>, Self::Proof)> {
        // Load the ELF file
        let out_dir = env!("OUT_DIR");
        let zkvm_guest_path = Path::new(&out_dir).join(ZKVM_GUEST_PICO_SUFFIX);
        let elf = fs::read(&zkvm_guest_path).map_err(|err| {
            anyhow!(format!(
                "Failed to load ELF file from {}: {}",
                zkvm_guest_path.display(),
                err
            ))
        })?;

        // Initialize the prover client
        let prover = DefaultProverClient::new(&elf);

        // Set up input
        let mut stdin_builder = prover.new_stdin_builder();

        stdin_builder.write(&(config as u8));
        stdin_builder.write_slice(&state_ssz);
        stdin_builder.write_slice(&block_ssz);
        stdin_builder.write_slice(&cache_ssz);
        stdin_builder.write_slice(&phase_bytes);

        println!("zkvm_host: proving starts.");

        let proof_set = prover
            .prove(stdin_builder)
            .context("Failed to generate proof")?;

        println!("zkvm_host: proving ends.");

        let output = proof_set
            .0
            .pv_stream
            .clone()
            .context("Reading proof_set error")?;

        Ok((output, Proof { prover, proof_set }))
    }
}
