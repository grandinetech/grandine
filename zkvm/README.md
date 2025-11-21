# zkvm STF

## risc0 implementation

1. **Execute without proving:**

   ```sh
   RISC0_DEV_MODE=1 cargo run -p zkvm_host --features risc0 --release -- --test <test_case> execute
   ```
   Prefix command with `RUST_LOG=info` and/or `RISC0_INFO=1` to include enhanced usage stats.

   Replace `<test_case>` with needed test case:
   * `pectra-devnet-6 with epoch transition` - pectra epoch state transition, 100k validators.
   * `pectra-devnet-6 without epoch transition` - pectra state transition without epoch transition, 100k validators.
   * `mainnet without epoch transition` - pectra state transition without epoch, mainnet.
   * `consensus spec tests mainnet electra empty block transition` - an empty block transition from consensus spec tests.

2. **Prove using local prover:**

   ```sh
   RISC0_DEV_MODE=1 cargo run -p zkvm_host --features risc0 --release -- --test <test_case> prove
   ```

   Replace `<test_case>` with one of the four test cases mentioned above.

3. **Prove using network prover:**
   ```sh
   RISC0_DEV_MODE=0 BONSAI_API_URL=https://api.bonsai.xyz/ BONSAI_TIMEOUT_MS=30000000 BONSAI_API_KEY=<api_key> cargo run -p zkvm_host --features risc0 --release -- --test <test_case> prove
   ```
   As with execution, you can prefix command with `RUST_LOG=info` and/or `RISC0_INFO=1` to include enhanced usage stats. Replace `<test_case>` with needed test case, and `<api_key>` with your api key.

## sp1 implementation

1. **Execute without proving:**

   ```sh
   cargo run -p zkvm_host --features sp1 --release -- --test <test_case> execute
   ```
   Replace `<test_case>` with one of the four test cases mentioned above.

2. **Prove using local prover:**

   ```sh
   cargo run -p zkvm_host --features sp1 --release -- --test <test_case> prove
   ```

   Again, replace `<test_case>` with one of the four test cases mentioned above.

3. **Prove using network prover:**

   ```sh
   SP1_PROVER=network NETWORK_RPC_URL=https://rpc.production.succinct.xyz NETWORK_PRIVATE_KEY=<private_key> cargo run -p zkvm_host --features sp1 --release -- --test <test_case> prove
   ```
   Replace `<private_key>` with your generated private key.

## Brevis pico implementation

1. **Execute without proving:**

   ```sh
   cargo +nightly-2025-08-04 run -p zkvm_host --features pico --release -- --test <test_case> execute
   ```
   Replace `<test_case>` with one of the four test cases mentioned above.

   Compiling Brevis pico libraries require using nightly rust. Prefix command with `RUST_LOG=info` to include enhanced usage stats.

2. **Prove using local prover:**

   ```sh
   cargo +nightly-2025-08-04 run -p zkvm_host --features pico --release -- --test <test_case> prove
   ```
   Again, replace `<test_case>` with one of the four test cases mentioned above.

## Adding new zkvm

To add new zkvm, you need to:

* Update `zkvm/host/Cargo.toml` and add new feature flag with new zkvm name, just like `risc0` or `sp1`.
* Implement needed structs & traits for new zkvm host code in `zkvm/host/src/backend.rs`.
* Create zkvm guest crate in `zkvm/guest/<zkvm_name>` folder. Don't forget to add new crate to workspace `Cargo.toml` if possible.
* Add necessary patches/precompiles. Currently root `Cargo.toml` file contains patches for `sha2` and `bls12_381` crates, so don't forget to comment out these. They're defined in three places: in `[workspace.dependencies]` section, `[patch.crates-io]` and `[patch.'https://github.com/zkcrypto/bls12_381.git']`.
* Update Github workflow `.github/workflows/ci.yaml` to add your zkvm build and test inside.
