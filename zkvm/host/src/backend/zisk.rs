use super::{ConfigKind, ProofTrait, ReportTrait, VmBackend};
use anyhow::Result;
use serde::{Deserialize, Serialize};

use std::env;
use std::path::Path;
use std::process::Command;

pub struct Report;

impl ReportTrait for Report {
    fn cycles(&self) -> u64 {
        1
    }
}

pub struct Proof;

impl ProofTrait for Proof {
    fn verify(&self) -> bool {
        true
    }

    fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VMGuestInput {
    config: u8,
    state_ssz: Vec<u8>,
    block_ssz: Vec<u8>,
    cache_ssz: Vec<u8>,
    phase_bytes: Vec<u8>,
}

pub struct Vm;

impl VmBackend for Vm {
    type Report = Report;
    type Proof = Proof;

    fn new() -> Result<Self> {
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
        let serialized_data = bincode::serialize(&VMGuestInput {
            config: config as u8,
            state_ssz,
            block_ssz,
            cache_ssz,
            phase_bytes,
        })
        .unwrap();

        // Generating the zkVM guest input data
        let output_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../guest/zisk/build");
        if !output_dir.exists() {
            std::fs::create_dir_all(&output_dir)?;
        }
        let input_path = output_dir.join("input.bin");
        std::fs::write(&input_path, &serialized_data)?;

        let zisk_guest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../guest/zisk");

        println!("Building the guest program");

        // First, build the guest program ELF file.
        let build_output = Command::new("cargo-zisk")
            .arg("build")
            .arg("--release")
            .current_dir(&zisk_guest_dir)
            .output()?;

        if !build_output.status.success() {
            let stderr = String::from_utf8_lossy(&build_output.stderr);
            return Err(anyhow::anyhow!(
                "Failed to build zisk guest program. Stderr: {}",
                stderr
            ));
        }

        println!("Using ziskemu to execute the guest program");

        // Second, execute the ELF file using ziskemu with a high step count.
        let elf_path =
            zisk_guest_dir.join("target/riscv64ima-zisk-zkvm-elf/release/zkvm_guest_zisk");
        let input_path = zisk_guest_dir.join("build/input.bin");

        let output = Command::new("ziskemu")
            .env("RUST_BACKTRACE", "full")
            .arg("-e")
            .arg(elf_path)
            .arg("-i")
            .arg(input_path)
            .arg("--max-steps")
            .arg("100000000000000")
            .arg("-X")
            .current_dir(&zisk_guest_dir)
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!(
                "Failed to execute ziskemu command. Stderr:\n{}",
                stderr
            ));
        }

        let stdout = String::from_utf8(output.stdout)?;
        println!("VM guest stdout:\n{stdout}");

        // Gather the last set_output() from the VM guest output back
        let state_root_str = stdout
            .lines()
            .map(|line| line.trim())
            .filter(|trimmed| trimmed.len() == 8)
            .fold(String::new(), |acc, line| acc + line);

        let state_root = hex::decode(state_root_str).expect("Invalid state root");

        if state_root.len() != 32 {
            return Err(anyhow::anyhow!(
                "Expect 32 bytes state root from guest output, but got {:?}",
                state_root
            ));
        }

        Ok((state_root, Report))
    }

    fn prove(
        &self,
        _config: ConfigKind,
        _state_ssz: Vec<u8>,
        _block_ssz: Vec<u8>,
        _cache_ssz: Vec<u8>,
        _phase_bytes: Vec<u8>,
    ) -> Result<(Vec<u8>, Self::Proof)> {
        Ok((vec![], Proof))
    }
}
