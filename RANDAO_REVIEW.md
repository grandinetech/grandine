# EIP-8321 consensus implementation

Baseline implementation: claude / 878e172fbad19297b60b3a3556b65d526fdd04ba.
Reference specification and generated vectors:
consensus-specs 12c8b24bc09b12f62688d439ba20ef00b1fdfe1f.

## Fixed during review

- Collect commitment-registration signatures in the real parallel block signature
  verifier. The processing path intentionally uses NullVerifier because signatures
  are checked separately; this previously omitted registration signatures.
- Use the pinned specification's registration domain 0x11000000.
- Use progressive commitment and registration lists. Enforce the 128-registration
  limit during processing, including when constructing a block programmatically.
- Match Heze/EIP-8321 active-field masks, omit legacy eth1/deposit fields from SSZ
  and JSON, and include the inherited inclusion-list bits in execution payload bids.
- Match Heze deposit processing: skip deposits creating new 0x00 validators,
  preserve top-ups, and align commitments when new validators are added.
- Remove obsolete eth1-data block/epoch processing in the experimental mode.
- Complete block constructors and expose grandine/eip8321 through runtime and
  block_producer, so the whole client can be checked with the mode enabled.
- Add read-only Rust runners for the generated reference fixtures, including
  verification of every block's Python-generated state root in the minimal
  registration lifecycle.

## Full state-transition coverage

The consensus-only scope includes every available state-transition vector in the
pinned generated archive: operations, epochs, rewards, slots, blocks, finality,
and Heze -> EIP-8321 upgrades. Run:

    bash scripts/test_randao.sh vectors-all

This mode executes 826 minimal and 751 mainnet cases (1,577 total), checking
positive post-state roots, negative rejection, full-epoch inputs when present,
and every supplied block's state root. Reports under test-vectors/reports account
for all 2,600 archive manifests. Two manifest-only RANDAO properties are executed
separately and are not counted as serialized vectors. The remaining 1,021
networking/fork-choice/fast-confirmation/light-client manifests are OUT_OF_SCOPE,
not passing. This follows the requested consensus-only implementation scope.

Additional fixes found by this broader suite:

- Freeze voluntary-exit signatures to the Capella domain for the EIP mode,
  independently of the state's new fork version.
- Settle the parent builder payment before processing execution requests.
- Deduct already queued withdrawals when calculating a builder's sweep balance.
- Clear all pending builder payments associated with a slashed proposer, including
  attester slashings, rather than only the equivocation's slot.
- Append an unset RANDAO commitment only when a deposit appends a validator.
  Epoch processing must not repair unrelated pre-existing list lengths.
- Add a separate Heze serialized pre-state and a callable upgrade_to_eip8321
  consensus upgrade. Its fork version is supplied by the caller; automatic client
  activation scheduling remains outside this change.

## Short checks

From the WSL checkout, with Rust available on PATH:

    bash scripts/test_randao.sh quick

Individual checks:

    bash scripts/test_randao.sh new
    bash scripts/test_randao.sh vectors
    bash scripts/test_randao.sh vectors-all
    bash scripts/test_randao.sh legacy
    bash scripts/test_randao.sh client

- quick: new + vectors consecutively, using the same Cargo feature set.
- new: 17 local RANDAO unit and regression tests, including valid/invalid real BLS
  signatures, activation boundaries, replay rejection, per-block limits, and
  multiple hash-chain reveals within one epoch.
- vectors: 144 official cases across minimal and mainnet: RANDAO (16), registration
  (20), pending commitments (10), pending deposits (97), and minimal lifecycle (1).
  The full generated EIP-8321 fixture directories are bundled in
  test-vectors/eip8321.tar.xz. On first use the script verifies SHA-256 and
  extracts to test-vectors/eip8321. Override with
  EIP8321_VECTORS_DIR=/path/to/reftests.
- legacy: 54 existing RANDAO-related tests and a separate 898-case Gloas operation
  regression check with the mode disabled. The filters overlap; counts are not
  added together as unique cases.
- client: cargo check for the complete client with eip8321 enabled.

These commands do not regenerate or modify Python test vectors. Vector checks
are ignored in ordinary cargo test runs because they require separately generated
fixtures; the vectors mode explicitly enables them and fails if fixtures are absent.
BLS Required/Optional/Ignored metadata follows the upstream test format. Independent
local regressions verify real signatures even when an optional reference fixture
does not require them.

## Verified results

- Full state-transition vectors: 1,577 passed, 0 failed (826 minimal, 751 mainnet).
- Additional manifest-only RANDAO properties: 2 passed, counted separately.

- Local unit/regression tests: 17 passed, 0 failed, 0.01 s execution.
- Official vector runners: 5 passed, covering 144 cases; 0.56 s execution.
- Legacy RANDAO reference tests: 54 passed, 0 failed, 0.07 s execution.
- Legacy Gloas operation tests: 898 passed, 0 failed, 0.42 s execution.
- Complete client cargo check with eip8321: passed.
- Rust formatting, shell syntax and git diff whitespace checks: passed.

Full state-transition execution took 28.28 s after compilation. Compilation
depends on the cache and selected features. The full workspace test suite
was not executed.

## Build and scope

    cargo check --locked --release -p grandine --features default-networks,eip8321

This is an experimental compile-time consensus mode on the existing Gloas dispatch,
not a new natively scheduled Heze/EIP-8321 phase in the multi-fork client. Feature-off
Gloas keeps its original schema. Feature-on fixtures must use the pinned EIP-8321
schema; original Gloas fixture tests are not compatible with that schema.

The consensus implementation can process supplied EIP-8321 blocks and the generated
lifecycle. Validator chain generation/storage, automatic registration submission,
gossip topics/pools, a fully configured private network and future-fork scheduling
are separate integration work. The block producer's default new fields support
the unregistered BLS path; it does not select secrets for registered validators.

The upstream mainnet lifecycle Python test still fails at its 256 <= 128 assertion.
It was not edited. The generated minimal lifecycle is used; no missing mainnet
lifecycle fixture is reported as passing.

Existing submodule working-tree differences were left untouched. Full tests were not run; the targeted checks do not establish absence of all
unrelated regressions.

## GitHub Actions

The dedicated workflow is `.github/workflows/eip8321.yml` (EIP-8321 consensus tests).
It runs on pushes to claude, pull requests, and manual workflow dispatch when
GitHub exposes the workflow on the default branch. It uses a fresh GitHub-hosted
Ubuntu 24.04 runner and the Rust version from rust-toolchain.toml.

The job checks out the committed Cargo submodules, installs native dependencies,
and downloads checksum-pinned v1.7.0-beta.1 legacy state-transition fixtures plus
v0.1.0 cryptography fixtures. Other legacy categories are not needed by the
selected test crates. Fixture preparation verifies all compile-time test globs;
this is necessary even when the execution filter selects only EIP tests.
The EIP-8321 archive is checked against its committed SHA-256.

Required steps run local RANDAO regressions, all 1,577 EIP consensus vector cases,
and feature-off legacy RANDAO/Gloas operation regressions. A final check validates
exact report counts and publishes a GitHub job summary. Logs and TSV reports are
uploaded as the eip8321-results-<commit> artifact even when a test fails. Failed
test commands propagate through tee; there is no continue-on-error.

The caches speed up downloads/compilation but are not required for correctness.
Release debug symbols are disabled in CI to reduce runner disk/memory use.
This workflow does not claim to regenerate the Python vectors or validate the
out-of-scope networking/fork-choice/fast-confirmation/light-client categories.
A successful local run is not a successful GitHub Actions run: use the green run
for the exact submitted commit as the assessment evidence.
