# Suggested Commands for Grandine Development

## Build Commands
```bash
# Standard build with default networks
cargo build --profile compact --features default-networks

# Release build (faster build, larger binary)
cargo build --release --features default-networks

# Build with specific backend
cargo build --release --no-default-features --features default-networks,blst
```

## Testing Commands
```bash
# Run all tests
cargo test --release

# Run tests with specific backend
cargo test --release --no-default-features --features blst

# Run tests excluding network tests (useful on macOS)
cargo test --release --no-fail-fast --no-default-features --features blst -- --skip behaviour --skip common
```

## Code Quality Commands
```bash
# Format code
cargo fmt

# Check formatting
cargo fmt --check

# Run Clippy linter
scripts/ci/clippy.bash --deny warnings

# Type checking (implied with cargo build)
cargo check
```

## Security Agent Commands (Python)
```bash
# Install dependencies
uv sync

# Run static analyzer
uv run python -m utils.static_analyzer <path_to_repo> --verbose

# Generate call graphs (requires Graphviz)
cd outputs/callgraphs
dot -Tpng <contract>.call-graph.dot -o <contract>.png
dot -Tsvg all_contracts.call-graph.dot -o all_contracts.svg
```

## Docker Commands
```bash
# Build Docker image
docker build .

# Cross-compilation for amd64
cross build --bin grandine --target x86_64-unknown-linux-gnu --features default-networks --profile compact

# Cross-compilation for arm64
cross build --bin grandine --target aarch64-unknown-linux-gnu --features default-networks --profile compact
```

## System Commands (Darwin/macOS)
```bash
# Common utilities
ls, cd, grep, find, git

# File operations
mkdir, cp, mv, rm, chmod, chown

# Process management
ps, top, lsof

# Package management
brew (for macOS dependencies)
```