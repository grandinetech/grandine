use super::{ConfigKind, ProofTrait, ReportTrait, VmBackend};
use anyhow::Result;
use ssz::{SszHash as _, SszRead as _, SszWrite as _, H256};

use std::env;
use std::path::Path;
use std::process::Command;
use std::str::FromStr;

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

        println!("entering execute");

        let serialized_data =
            bincode::serialize(&(config, state_ssz, block_ssz, cache_ssz, phase_bytes)).unwrap();

        let output_dir =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../guest/zisk/build");
        if !output_dir.exists() {
            std::fs::create_dir_all(&output_dir)?;
        }

        let input_path = output_dir.join("input.bin");
        std::fs::write(&input_path, &serialized_data)?;

        let zisk_guest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../guest/zisk");

        println!("building the guest program");

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
        let elf_path = zisk_guest_dir
            .join("../../../target/riscv64ima-zisk-zkvm-elf/release/zkvm_guest_zisk");
        let output = Command::new("ziskemu")
            .arg("-e")
            .arg(elf_path)
            .arg("-i")
            .arg(input_path)
            .arg("--max-steps")
            .arg("100000000000000")
            .current_dir(&zisk_guest_dir)
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!(
                "Failed to execute ziskemu command. Stderr: {}",
                stderr
            ));
        }

        let stdout = String::from_utf8(output.stdout)?;
        let mut big_endian_hex = String::with_capacity(64);

        // Process only the lines that are valid 8-character hex strings,
        // ignoring any other output like compiler messages.
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.len() == 8 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
                // This is a valid hex chunk, process it.
                // Reverse bytes to convert from little-endian hex to big-endian hex.
                for byte in trimmed.as_bytes().chunks(2).rev() {
                    big_endian_hex.push_str(std::str::from_utf8(byte)?);
                }
            }
        }

        if big_endian_hex.len() != 64 {
            return Err(anyhow::anyhow!(
                "Expected 64 hex characters from guest output, but got {}. Full output:\n{}",
                big_endian_hex.len(),
                stdout
            ));
        }

        let state_root = H256::from_str(&big_endian_hex)
            .map_err(|e| anyhow::anyhow!("Failed to parse combined hex string: {}", e))?;
        Ok((state_root.as_bytes().to_vec(), Report))
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
