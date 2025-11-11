use super::{ConfigKind, ProofTrait, ReportTrait, VmBackend};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use std::env;
use std::path::Path;
use std::process::Command;

pub struct Report(u64);

impl ReportTrait for Report {
    fn cycles(&self) -> u64 {
        self.0
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

impl Vm {
    fn generate_input(&self, config: ConfigKind, state_ssz: Vec<u8>, block_ssz: Vec<u8>, cache_ssz: Vec<u8>, phase_bytes: Vec<u8>) -> Result<String>
    {
        let serialized_data = bincode::serialize(&VMGuestInput {
            config: config as u8,
            state_ssz,
            block_ssz,
            cache_ssz,
            phase_bytes,
        })?;

        // Generating the zkVM guest input data
        let output_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../guest/zisk/build");
        if !output_dir.exists() {
            std::fs::create_dir_all(&output_dir)?;
        }
        let input_path = output_dir.join("input.bin");
        std::fs::write(&input_path, &serialized_data)?;

        Ok(input_path)
    }
}

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
        let input_path = self.generate_input(config, state_ssz, block_ssz, cache_ssz, phase_bytes)?;
        let zisk_guest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../guest/zisk");

        println!("Building the zkVM guest program");

        // First, build the guest program ELF file.
        let build_output = Command::new("cargo-zisk")
            .arg("build")
            .arg("--release")
            .current_dir(&zisk_guest_dir)
            .output()?;

        if !build_output.status.success() {
            let stderr = String::from_utf8_lossy(&build_output.stderr);
            return Err(anyhow!("Failed to build zisk guest program. Stderr:\n{}", stderr));
        }

        println!("Executing the zkVM guest program with ziskemu");

        // Second, execute the ELF file using ziskemu with a high step count.
        let elf_path =
            zisk_guest_dir.join("target/riscv64ima-zisk-zkvm-elf/release/zkvm_guest_zisk");

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
            return Err(anyhow!(
                "Failed to execute ziskemu command. Stderr:\n{}",
                stderr
            ));
        }

        let stdout = String::from_utf8(output.stdout)?;
        println!("VM guest stdout:\n{stdout}");

        let cycles: u64 = stdout
            .lines()
            .find(|line| line.starts_with("STEPS")) // the cycle line starts with `STEPS`
            .map(|line|
                line
                    .chars()
                    .filter(|c| c.is_ascii_digit())
                    .collect::<String>()
                    .parse::<u64>()
                    .expect("Couldn't parse the execution cycle.")
            )
            .ok_or(anyhow!("Expect having a line starting with STEPS from Zisk output."))?;

        // Gather the last set_output() from the VM guest output back
        let state_root_str = stdout
            .lines()
            .map(|line| line.trim())
            .filter(|trimmed| trimmed.len() == 8)
            .fold(String::new(), |acc, line| acc + line);

        let state_root = hex::decode(state_root_str)?;

        if state_root.len() != 32 {
            return Err(anyhow::anyhow!(
                "Expect 32 bytes state root from guest output, but got {:?}",
                state_root
            ));
        }

        Ok((state_root, Report(cycles)))
    }

    fn prove(
        &self,
        _config: ConfigKind,
        _state_ssz: Vec<u8>,
        _block_ssz: Vec<u8>,
        _cache_ssz: Vec<u8>,
        _phase_bytes: Vec<u8>,
    ) -> Result<(Vec<u8>, Self::Proof)> {
        // Refer to https://0xpolygonhermez.github.io/zisk/getting_started/writing_programs.html#prove
        // 1. Run cmd for program setup
        //   cargo-zisk rom-setup -e target/riscv64ima-zisk-zkvm-elf/release/zkvm_guest_zisk
        // 2. Generate proof
        //   LIB_EXT=$([[ "$(uname)" == "Darwin" ]] && echo "dylib" || echo "so")
        //   cargo-zisk prove -e target/riscv64ima-zisk-zkvm-elf/release/zkvm_guest_zisk -i build/input.bin -o ./ -a
        // 3. Verify proof
        //   cargo-zisk verify -p ./proofs/vadcop_final_proof.bin
        let input_path = self.generate_input(config, state_ssz, block_ssz, cache_ssz, phase_bytes)?;
        let zisk_guest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../guest/zisk");
        let zisk_elf_path = zisk_guest_dir

        let setup_output = Command::new("cargo-zisk")
            .arg("rom-setup")
            .arg("-e")
            .arg(zisk_elf_path)
            .current_dir(&zisk_guest_dir)
            .output()?;

        if !build_output.status.success() {
            let stderr = String::from_utf8_lossy(&build_output.stderr);
            return Err(anyhow!("Failed to build zisk guest program. Stderr:\n{}", stderr));
        }



        Ok((vec![], Proof))
    }
}
