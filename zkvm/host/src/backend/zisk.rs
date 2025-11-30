use super::{ConfigKind, ProofTrait, ReportTrait, VmBackend};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use std::env;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

const ELF_PATH_SUFFIX: &str = "target/riscv64ima-zisk-zkvm-elf/release/zkvm_guest_zisk";

pub struct Report(u64);

impl ReportTrait for Report {
    fn cycles(&self) -> u64 {
        self.0
    }
}

pub struct Proof;

impl ProofTrait for Proof {
    fn verify(&self) -> bool {
        // Verify proof, run the command:
        //   cargo-zisk verify -p ./proofs/vadcop_final_proof.bin
        let zisk_guest_dir = Vm::get_guest_dir();
        let proofs_path = Vm::get_guest_dir()
            .join("proofs")
            .join("vadcop_final_proof.bin");

        let verify_output = run_cmd(
            Command::new("cargo-zisk")
                .arg("verify")
                .arg("-p")
                .arg(&proofs_path)
                .current_dir(&zisk_guest_dir),
        );

        let Ok((exit_status, _)) = verify_output else {
            return false;
        };

        exit_status.success()
    }

    fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let zisk_guest_dir = Vm::get_guest_dir();
        let proofs_path = Vm::get_guest_dir()
            .join("proofs")
            .join("vadcop_final_proof.bin");

        let output = run_cmd(
            Command::new("cp")
                .arg(&proofs_path)  // src
                .arg(path.as_ref())  // destination
                .current_dir(&zisk_guest_dir),
        )?;

        let (exit_status, output_bytes) = output;
        if !exit_status.success() {
            return Err(anyhow!(
                "Copy file failed. stderr:\n{}",
                String::from_utf8_lossy(&output_bytes)
            ));
        }

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
    fn generate_input_file(
        config: ConfigKind,
        state_ssz: Vec<u8>,
        block_ssz: Vec<u8>,
        cache_ssz: Vec<u8>,
        phase_bytes: Vec<u8>,
    ) -> Result<PathBuf> {
        let serialized_data = bincode::serialize(&VMGuestInput {
            config: config as u8,
            state_ssz,
            block_ssz,
            cache_ssz,
            phase_bytes,
        })?;

        // Generating the zkVM guest input data
        let output_dir = Self::get_guest_dir().join("build");
        if !output_dir.exists() {
            std::fs::create_dir_all(&output_dir)?;
        }
        let input_path = output_dir.join("input.bin");
        std::fs::write(&input_path, &serialized_data)?;

        Ok(input_path)
    }

    fn get_guest_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../guest/zisk")
    }

    fn extract_cycles(stdout: &str) -> Result<u64> {
        stdout
            .lines()
            .find(|line| line.starts_with("STEPS")) // the cycle line starts with `STEPS`
            .map(|line| line
                .chars()
                .filter(|c| c.is_ascii_digit())
                .collect::<String>()
                .parse::<u64>()
                .expect("Couldn't parse the execution cycle.")
            )
            .ok_or(anyhow!("Expect having a line starting with STEPS from Zisk output."))
    }

    fn collect_result(stdout: &str) -> Result<Vec<u8>> {
        let state_root_str = stdout
            .lines()
            .map(|line| line.trim())
            .filter(|trimmed| trimmed.len() == 8)
            .fold(String::new(), |acc, line| acc + line);

        let state_root = hex::decode(state_root_str)?;

        if state_root.len() != 32 {
            return Err(anyhow!(
                "Expect 32 bytes state root from guest output, but got {:?}",
                state_root
            ));
        }

        Ok(state_root)
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
        let input_path =
            Vm::generate_input_file(config, state_ssz, block_ssz, cache_ssz, phase_bytes)?;
        let zisk_guest_dir = Vm::get_guest_dir();

        println!("🛠️ Building the zkVM guest program...");

        // First, build the guest program ELF file.
        let build_output = run_cmd(
            Command::new("cargo-zisk")
                .arg("build")
                .arg("--release")
                .current_dir(&zisk_guest_dir),
        )?;

        if !build_output.0.success() {
            return Err(anyhow!(
                "Failed to build zisk guest program. Stderr:\n{}",
                String::from_utf8_lossy(&build_output.1)
            ));
        }

        println!("🛠️ Executing the zkVM guest program with ziskemu...");

        // Second, execute the ELF file using ziskemu with a high step count.
        let elf_path = zisk_guest_dir.join(ELF_PATH_SUFFIX);
        let execute_output = run_cmd(
            Command::new("ziskemu")
                .env("RUST_BACKTRACE", "full")
                .arg("-e")
                .arg(elf_path)
                .arg("-i")
                .arg(input_path)
                .arg("--max-steps")
                .arg("100000000000000")
                .arg("-X")
                .current_dir(&zisk_guest_dir),
        )?;

        let (exit_status, output_bytes) = execute_output;
        let output = String::from_utf8_lossy(&output_bytes);

        if !exit_status.success() {
            return Err(anyhow!(
                "Failed to execute ziskemu command. Stderr:\n{output}"
            ));
        }

        // Extract the execution cycle from the output.
        let cycles: u64 = Self::extract_cycles(&output)?;

        // Gather back the last set_output() from the VM guest output.
        let state_root = Self::collect_result(&output)?;
        Ok((state_root, Report(cycles)))
    }

    fn prove(
        &self,
        config: ConfigKind,
        state_ssz: Vec<u8>,
        block_ssz: Vec<u8>,
        cache_ssz: Vec<u8>,
        phase_bytes: Vec<u8>,
    ) -> Result<(Vec<u8>, Self::Proof)> {
        // Refer to https://0xpolygonhermez.github.io/zisk/getting_started/writing_programs.html#prove
        // 1. Run cmd for program setup
        //   cargo-zisk rom-setup -e target/riscv64ima-zisk-zkvm-elf/release/zkvm_guest_zisk
        // 2. Generate proof
        //   LIB_EXT=$([[ "$(uname)" == "Darwin" ]] && echo "dylib" || echo "so")
        //   cargo-zisk prove -e target/riscv64ima-zisk-zkvm-elf/release/zkvm_guest_zisk -i build/input.bin -o ./ -a
        let zisk_guest_dir = Self::get_guest_dir();
        let input_path =
            Self::generate_input_file(config, state_ssz, block_ssz, cache_ssz, phase_bytes)?;
        let elf_path = zisk_guest_dir.join(ELF_PATH_SUFFIX);

        println!("🛠️ Running program setup `cargo-zisk rom-setup`...");

        // 1. Run cmd for program setup
        let setup_output = run_cmd(
            Command::new("cargo-zisk")
                .arg("rom-setup")
                .arg("-e")
                .arg(&elf_path)
                .current_dir(&zisk_guest_dir),
        )?;

        if !setup_output.0.success() {
            return Err(anyhow!(
                "Failed to setup zisk proving. Stderr:\n{}",
                String::from_utf8_lossy(&setup_output.1)
            ));
        }

        // 2. Generate proof
        println!("🛠️ Proving `cargo-zisk prove`...");

        let prove_output = run_cmd(
            Command::new("cargo-zisk")
                .arg("prove")
                .arg("-e")
                .arg(&elf_path)
                .arg("-i")
                .arg(&input_path)
                .arg("-o")
                .arg(&zisk_guest_dir)
                .arg("-a") // aggregation, indicates that a final aggregated proof should be produced
                .current_dir(&zisk_guest_dir),
        )?;

        let (exit_status, output_bytes) = prove_output;
        let output = String::from_utf8_lossy(&output_bytes);

        if !exit_status.success() {
            return Err(anyhow!("Failed to generate proof. Stderr:\n{output}"));
        }

        // Gather back the last set_output() from the VM guest output.
        let state_root = Self::collect_result(&output)?;
        Ok((state_root, Proof))
    }
}

// This function runs the command, streaming the output to screen immediately while capuring the
// output and return it in a buffer.
fn run_cmd(cmd: &mut Command) -> Result<(ExitStatus, Vec<u8>)> {
    let mut child = cmd.stdout(Stdio::piped()).spawn()?;

    let mut buffer: Vec<u8> = Vec::new();
    let mut stdout = child
        .stdout
        .take()
        .ok_or(anyhow!("Failed to retrieve cmd stdout field"))?;
    let mut handle = io::stdout();

    let mut chunk = [0u8; 4096];
    loop {
        let n = stdout.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        handle.write_all(&chunk[..n])?; // stream to screen
        buffer.extend_from_slice(&chunk[..n]); // capture in buffer
    }

    let status = child.wait()?;

    Ok((status, buffer))
}
