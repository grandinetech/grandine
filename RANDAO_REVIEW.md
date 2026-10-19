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

## Short checks

From the WSL checkout, with Rust available on PATH:

    bash scripts/test_randao.sh quick

Individual checks:

    bash scripts/test_randao.sh new
    bash scripts/test_randao.sh vectors
    bash scripts/test_randao.sh legacy
    bash scripts/test_randao.sh client

- quick: new + vectors consecutively, using the same Cargo feature set.
- new: 17 local RANDAO unit and regression tests, including valid/invalid real BLS
  signatures, activation boundaries, replay rejection, per-block limits, and
  multiple hash-chain reveals within one epoch.
- vectors: 144 official cases across minimal and mainnet: RANDAO (16), registration
  (20), pending commitments (10), pending deposits (97), and minimal lifecycle (1).
  Fixtures are read from ../consensus-specs/reftests by default. Override with
  EIP8321_VECTORS_DIR=/path/to/reftests.
- legacy: 54 existing randao-related reference tests with the mode disabled.
- client: cargo check for the complete client with eip8321 enabled.

These commands do not regenerate or modify Python test vectors. Vector checks
are ignored in ordinary cargo test runs because they require separately generated
fixtures; the vectors mode explicitly enables them and fails if fixtures are absent.
BLS Required/Optional/Ignored metadata follows the upstream test format. Independent
local regressions verify real signatures even when an optional reference fixture
does not require them.

## Verified results

- Local unit/regression tests: 17 passed, 0 failed, 0.01 s execution.
- Official vector runners: 5 passed, covering 144 cases; 0.56 s execution.
- Legacy reference tests: 54 passed, 0 failed, 0.08 s execution.
- Complete client cargo check with eip8321: passed, 30.14 s.
- Rust formatting, shell syntax and git diff whitespace checks: passed.

Compilation depends on the cache and selected features; the last local-test
compilation took 44.14 s. The full workspace test suite was not executed.

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

Existing submodule working-tree differences were left untouched. In particular,
the working eth2_libp2p points to eee0bdd while the reviewed commit pins 0eb8c4c.
Full tests were not run; the targeted checks do not establish absence of all
unrelated regressions.
