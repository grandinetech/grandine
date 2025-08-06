# Grandine Codebase Structure

## Top-Level Organization

### Core Directories
- **`grandine/`**: Main binary crate containing the client entry point
- **`types/`**: Core Ethereum types and data structures
- **`consensus-spec-tests/`**: Ethereum consensus specification test suite
- **`transition_functions/`**: State transition logic implementation

### Networking & P2P
- **`eth2_libp2p/`**: Fork of Lighthouse's libp2p networking library
- **`p2p/`**: P2P networking implementation
- **`gossipsub/`**: Gossipsub protocol implementation

### Consensus Components
- **`fork_choice_store/`**: Fork choice rule implementation
- **`fork_choice_control/`**: Fork choice control logic
- **`attestation_verifier/`**: Attestation verification logic
- **`block_producer/`**: Block production functionality
- **`validator/`**: Validator client implementation

### Execution Layer
- **`execution_engine/`**: Execution engine interface
- **`eth1/`**: Eth1 chain integration
- **`eth1_api/`**: Eth1 API client

### Storage & Caching
- **`database/`**: Database abstraction and implementation
- **`state_cache/`**: State caching layer
- **`pubkey_cache/`**: Public key cache
- **`validator_key_cache/`**: Validator key caching

### Cryptography
- **`bls/`**: BLS signature implementation with multiple backends
- **`hashing/`**: Hashing utilities
- **`shuffling/`**: Validator shuffling algorithms
- **`kzg_utils/`**: KZG commitment utilities
- **`eip_7594/`**: EIP-7594 (PeerDAS) implementation

### APIs & Services
- **`http_api/`**: HTTP API implementation
- **`builder_api/`**: Builder API for MEV
- **`keymanager/`**: Key management API
- **`metrics/`**: Metrics collection
- **`prometheus_metrics/`**: Prometheus metrics export

### Utilities
- **`helper_functions/`**: Consensus spec helper functions
- **`factory/`**: Factory patterns for object creation
- **`runtime/`**: Runtime utilities
- **`logging/`**: Logging infrastructure
- **`clock/`**: Time and slot management

### Security & Protection
- **`slashing_protection/`**: Slashing protection database
- **`slasher/`**: Slasher implementation
- **`doppelganger_protection/`**: Doppelganger detection

### Development & Testing
- **`spec_test_utils/`**: Utilities for spec tests
- **`snapshot_test_utils/`**: Snapshot testing utilities
- **`benches/`**: Performance benchmarks
- **`scripts/`**: Build and CI scripts
- **`hive/`**: Hive testing integration

### Security Analysis Tool
- **`security-agent/`**: Python-based security analysis tool
  - Static code analyzer
  - AI-powered vulnerability assessment
  - Call graph generation

### Configuration
- **`.claude/`**: Claude Code configuration and commands
- **`.github/`**: GitHub workflows and CI configuration

## Key Implementation Details
- Workspace-based Cargo project with 50+ member crates
- Each major component is a separate crate for modularity
- Extensive use of Rust's type system for safety
- Plugin architecture for extensibility (e.g., BLS backends)
- Performance-optimized with careful memory management