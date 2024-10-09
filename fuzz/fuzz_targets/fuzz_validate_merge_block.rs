#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;
use grandine::{
    fork_choice::validation,
    types::{
        bellatrix::containers::PowBlock,
        combined::SignedBeaconBlock,
        config::Config as ChainConfig,
        preset::Preset,
        traits::{PostBellatrixBeaconBlockBody, SignedBeaconBlock as _},
    },
    execution_engine::ExecutionEngine,
};

// Mock implementation of ExecutionEngine
struct MockExecutionEngine;

impl<P: Preset> ExecutionEngine<P> for MockExecutionEngine {
    const IS_NULL: bool = false;

    fn allow_optimistic_merge_block_validation(&self) -> bool {
        true
    }

    fn pow_block(&self, hash: [u8; 32]) -> Option<PowBlock> {
        // For simplicity, always return Some(PowBlock)
        Some(PowBlock {
            block_hash: hash,
            parent_hash: [0; 32],
            total_difficulty: 1000000.into(), // Arbitrary value
            // ... other fields ...
        })
    }

    // Implement other required methods...
}

// Mock implementation of PostBellatrixBeaconBlockBody
struct MockBeaconBlockBody;

impl<P: Preset> PostBellatrixBeaconBlockBody<P> for MockBeaconBlockBody {
    fn execution_payload(&self) -> &P::ExecutionPayload {
        unimplemented!("Mock implementation")
    }
    // Implement other required methods...
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }

    // Create ChainConfig from first 32 bytes
    let mut terminal_block_hash = [0u8; 32];
    terminal_block_hash.copy_from_slice(&data[..32]);
    let chain_config = ChainConfig {
        terminal_block_hash,
        terminal_block_hash_activation_epoch: 0,
        terminal_total_difficulty: 1000000.into(),
        // ... other fields ...
    };

    // Create SignedBeaconBlock from next 32 bytes
    let mut block_root = [0u8; 32];
    block_root.copy_from_slice(&data[32..64]);
    let block = Arc::new(SignedBeaconBlock::<Preset>::default()); // You'll need to implement this

    // Create mock objects
    let body = MockBeaconBlockBody;
    let execution_engine = MockExecutionEngine;

    // Call validate_merge_block
    let result = validation::validate_merge_block(
        &chain_config,
        &block,
        &body,
        execution_engine,
    );

    // Check the result
    match result {
        Ok(action) => {
            // You can add assertions here based on expected behavior
        },
        Err(e) => {
            // You can add assertions here for expected error cases
        },
    }
});#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
});


