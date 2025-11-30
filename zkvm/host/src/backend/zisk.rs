use super::{ConfigKind, ProofTrait, ReportTrait, VmBackend};
use anyhow::{Context, Result, anyhow};
use std::{
    env, fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
};
use tempfile::tempdir;

const ELF_PATH_SUFFIX: &str = "target/riscv64ima-zisk-zkvm-elf/release/zkvm_guest_zisk";

// Default generated proof filename
const PROOF_PATH_SUFFIX: &str = "vadcop_final_proof.bin";

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
        let proof_path = Vm::get_artifacts_dir().join(PROOF_PATH_SUFFIX);

        let verify_output = run_cmd(
            Command::new("cargo-zisk")
                .arg("verify")
                .arg("--proof")
                .arg(&proof_path),
        );

        let Ok((exit_status, _)) = verify_output else {
            return false;
        };

        exit_status.success()
    }

    fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let proof_path = Vm::get_artifacts_dir().join(PROOF_PATH_SUFFIX);

        let _ = fs::copy(&proof_path, path.as_ref()).context(format!(
            "Failed to copy file from {proof_path:?} to {:?}",
            path.as_ref()
        ))?;

        Ok(())
    }
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
        // Generating the zkVM guest input data
        let output_dir = Self::get_artifacts_dir();
        if !output_dir.exists() {
            fs::create_dir_all(&output_dir)?;
        }
        let input_path = output_dir.join("input.bin");
        let mut file = fs::File::create(&input_path)?;

        file.write_all(&[config as u8])?;

        file.write_all(&state_ssz.len().to_be_bytes())?;
        file.write_all(&state_ssz)?;

        file.write_all(&block_ssz.len().to_be_bytes())?;
        file.write_all(&block_ssz)?;

        file.write_all(&cache_ssz.len().to_be_bytes())?;
        file.write_all(&cache_ssz)?;

        file.write_all(&phase_bytes.len().to_be_bytes())?;
        file.write_all(&phase_bytes)?;

        file.sync_all()?;

        Ok(input_path)
    }

    fn get_guest_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("project cannot be at root directory")
            .join("guest/zisk")
    }

    fn get_artifacts_dir() -> PathBuf {
        Self::get_guest_dir().join("artifacts")
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

    fn compile_guest_program() -> Result<()> {
        println!("Building the zkVM guest program...");

        let build_output = run_cmd(
            Command::new("cargo-zisk")
                .arg("build")
                .arg("--release")
                .current_dir(Self::get_guest_dir()),
        )?;

        if !build_output.0.success() {
            return Err(anyhow!(
                "Failed to build zisk guest program. Stderr:\n{}",
                String::from_utf8_lossy(&build_output.1)
            ));
        }

        Ok(())
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
        Self::compile_guest_program()?;

        let input_path =
            Vm::generate_input_file(config, state_ssz, block_ssz, cache_ssz, phase_bytes)?;
        let zisk_guest_dir = Vm::get_guest_dir();

        println!("Executing the zkVM guest program with ziskemu...");

        // Second, execute the ELF file using ziskemu with a high step count.
        let elf_path = zisk_guest_dir.join(ELF_PATH_SUFFIX);
        let tempdir = tempdir()
            .map_err(|e| anyhow!("Couldn't create temp directory. Err:\n{}", e.to_string()))?;
        let output_path = tempdir.path().join("output");
        let execute_output = run_cmd(
            Command::new("ziskemu")
                .env("RUST_BACKTRACE", "full")
                .arg("--elf")
                .arg(elf_path)
                .arg("--inputs")
                .arg(input_path)
                .arg("--output")
                .arg(&output_path)
                .arg("--max-steps")
                .arg("100000000000000")
                .arg("--stats"), // showing stats
        )?;

        let (exit_status, output_bytes) = execute_output;
        let output = String::from_utf8_lossy(&output_bytes);

        if !exit_status.success() {
            return Err(anyhow!(
                "Failed to execute ziskemu command. See output error above."
            ));
        }

        // Extract the execution cycle from the output.
        let cycles: u64 = Self::extract_cycles(&output)?;

        // Read the public output from VM guest.
        let state_root = fs::read(&output_path).map_err(|e| {
            anyhow!(
                "Couldn't read from execution output. Error:\n{}",
                e.to_string()
            )
        })?;

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
        // Run `Self::execute()` anyway because:
        //   1. Zisk prove mode doesn't generate the public output
        //   2. We need to compile the guest program, which is run inside Self::execute()
        //   3. Input is serialized
        let (state_root, _) = self.execute(config, state_ssz, block_ssz, cache_ssz, phase_bytes)?;

        // Refer to https://0xpolygonhermez.github.io/zisk/getting_started/writing_programs.html#prove
        // 1. Run cmd for program setup
        //   cargo-zisk rom-setup -e target/riscv64ima-zisk-zkvm-elf/release/zkvm_guest_zisk
        // 2. Generate proof
        //   cargo-zisk prove -e target/riscv64ima-zisk-zkvm-elf/release/zkvm_guest_zisk \
        //   -i build/input.bin -o ./ -a
        let zisk_guest_dir = Self::get_guest_dir();
        let input_path = Self::get_artifacts_dir().join("input.bin");
        let elf_path = zisk_guest_dir.join(ELF_PATH_SUFFIX);

        println!("Running program setup...");

        // 1. Run cmd for program setup
        let setup_output = run_cmd(
            Command::new("cargo-zisk")
                .arg("rom-setup")
                .arg("--elf")
                .arg(&elf_path),
        )?;

        if !setup_output.0.success() {
            return Err(anyhow!(
                "Failed to setup zisk proving. Stderr:\n{}",
                String::from_utf8_lossy(&setup_output.1)
            ));
        }

        // 2. Generate proof
        println!("Proving...");

        let prove_output = run_cmd(
            Command::new("cargo-zisk")
                .arg("prove")
                .arg("--elf")
                .arg(&elf_path)
                .arg("--input")
                .arg(&input_path)
                .arg("--output-dir")
                .arg(Self::get_artifacts_dir())
                .arg("--final-snark")
                .arg("--aggregation"), // indicates that a final aggregated proof should be produced
        )?;

        let (exit_status, _) = prove_output;
        if !exit_status.success() {
            return Err(anyhow!("Failed to generate proof. See output error above."));
        }

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
