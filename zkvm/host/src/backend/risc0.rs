use super::{ConfigKind, ProofTrait, ReportTrait, VmBackend};
use anyhow::{Context, Result, anyhow};
use boundless_market::{Client, storage::StorageUploaderConfig};
use clap::{Args as _, FromArgMatches as _};
use risc0_zkvm::{ExecutorEnv, Journal, default_executor, default_prover, serde::to_vec};
use std::{
    fs::File,
    io::{BufWriter, Write},
    time::Duration,
};
use zkvm_guest_risc0::RISC0_GRANDINE_STATE_TRANSITION_ELF;

pub struct Vm;

pub struct Report(u64);

impl ReportTrait for Report {
    fn cycles(&self) -> u64 {
        self.0
    }
}

pub struct Proof(Vec<u8>);

impl ProofTrait for Proof {
    async fn verify(&self) -> bool {
        true
    }

    fn save(&self, path: impl AsRef<std::path::Path>) -> Result<()> {
        let mut writer = BufWriter::new(File::create(path)?);

        writer.write_all(&self.0)?;

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

    async fn execute(
        &self,
        config: ConfigKind,
        state_ssz: Vec<u8>,
        block_ssz: Vec<u8>,
        cache_ssz: Vec<u8>,
        phase_bytes: Vec<u8>,
    ) -> Result<(Vec<u8>, Self::Report)> {
        let prover = default_executor();

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

        let receipt = prover.execute(env, elf)?;

        let cycles = receipt.cycles();

        Ok((receipt.journal.bytes, Report(cycles)))
    }

    async fn prove(
        &self,
        config: ConfigKind,
        state_ssz: Vec<u8>,
        block_ssz: Vec<u8>,
        cache_ssz: Vec<u8>,
        phase_bytes: Vec<u8>,
    ) -> Result<(Vec<u8>, Self::Proof)> {
        if std::env::var_os("PROVER") == Some("boundless".into()) {
            println!("using network prover");

            let rpc_url =
                std::env::var("RPC_URL").context("invalid RPC_URL environment variable")?;

            let private_key =
                std::env::var("PRIVATE_KEY").context("invalid PRIVATE_KEY environment variable")?;

            let storage_config = {
                let cmd = StorageUploaderConfig::augment_args(clap::Command::new(""));

                let matches = cmd
                    .try_get_matches_from([""])
                    .context("invalid storage provider")?;

                StorageUploaderConfig::from_arg_matches(&matches)
                    .context("invalid storage provider")?
            };

            let client = Client::builder()
                .with_rpc_url(rpc_url.parse().context("invalid RPC_URL")?)
                .with_private_key_str(&private_key)
                .context("invalid PRIVATE_KEY environment variable")?
                .with_uploader_config(&storage_config)
                .await?
                .build()
                .await?;

            let mut stdin = Vec::new();
            stdin.extend_from_slice(bytemuck::cast_slice(&to_vec(&(config as u8))?));
            stdin.extend_from_slice(bytemuck::cast_slice(&to_vec(&state_ssz.len())?));
            stdin.extend_from_slice(bytemuck::cast_slice(&to_vec(&block_ssz.len())?));
            stdin.extend_from_slice(bytemuck::cast_slice(&to_vec(&cache_ssz.len())?));
            stdin.extend_from_slice(bytemuck::cast_slice(&to_vec(&phase_bytes.len())?));
            stdin.extend_from_slice(&state_ssz);
            stdin.extend_from_slice(&block_ssz);
            stdin.extend_from_slice(&cache_ssz);
            stdin.extend_from_slice(&phase_bytes);

            let request = client
                .new_request()
                .with_program(RISC0_GRANDINE_STATE_TRANSITION_ELF)
                .with_stdin(stdin);

            let (request_id, expires_at) = client
                .submit_onchain(request)
                .await
                .context("failed to submit onchain proof request")?;

            let fulfillment = client
                .wait_for_request_fulfillment(request_id, Duration::from_secs(10), expires_at)
                .await
                .context("failed to wait for fulfillment")?;

            let journal = Journal::new(
                fulfillment
                    .data()?
                    .journal()
                    .ok_or(anyhow!("no journal received"))?
                    .as_ref()
                    .to_vec(),
            );

            Ok::<(Vec<u8>, Self::Proof), anyhow::Error>((journal.bytes.clone(), Proof(Vec::new())))
        } else {
            println!("no PROVER=boundless environment variable found, using local prover");

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

            Ok((receipt.journal.bytes.clone(), Proof(Vec::new())))
        }
    }
}
