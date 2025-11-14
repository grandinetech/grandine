use std::path::Path;

use anyhow::Result;

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

#[cfg(feature = "risc0")]
mod risc0 {
    use super::{ConfigKind, ProofTrait, ReportTrait, VmBackend};
    use anyhow::Result;
    use borsh::BorshSerialize;
    use risc0_zkvm::{default_prover, ExecutorEnv, Receipt, SessionStats};
    use std::{fs::File, io::BufWriter};
    use zkvm_guest_risc0::{
        RISC0_GRANDINE_STATE_TRANSITION_ELF, RISC0_GRANDINE_STATE_TRANSITION_ID,
    };

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
}

#[cfg(feature = "risc0")]
pub use risc0::*;

#[cfg(feature = "sp1")]
mod sp1 {
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
}

#[cfg(feature = "sp1")]
pub use sp1::*;

#[cfg(feature = "ziren")]
mod ziren {
    use super::{ProofTrait, ReportTrait, VmBackend, ConfigKind};
    use anyhow::Result;
    use std::path::Path;
    use zkm_sdk::{include_elf, ProverClient, ZKMProofWithPublicValues, ZKMStdin};

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
            // ZKM SDK logger setup if available
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
}

#[cfg(feature = "ziren")]
pub use ziren::*;
