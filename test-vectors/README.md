# Bundled EIP-8321 reference vectors

Source: https://github.com/ethereum/consensus-specs.git
Source commit: 12c8b24bc09b12f62688d439ba20ef00b1fdfe1f
Generation command (executed in that repository):

    make test reftests=true fork=eip8321

The archive contains the complete generated minimal/eip8321 and mainnet/eip8321
directories: 34,289 files. Original fixture contents are unchanged. The original
generation run reported 2996 passed, 1 failed and 36237 skipped. The failed
mainnet registration lifecycle test attempts 256 registrations with a limit of
128. No upstream test was edited; no passing mainnet lifecycle is claimed.

## Run from a checkout of this branch

    bash scripts/test_randao.sh quick

Run every consensus state-transition vector (both presets):

    bash scripts/test_randao.sh vectors-all

Or only the 144 focused RANDAO/deposit vectors:

    bash scripts/test_randao.sh vectors

Extraction requires tar and xz (Ubuntu package xz-utils).

On the first run the script verifies the archive SHA-256 and extracts it into
test-vectors/eip8321. That generated directory is Git-ignored; the archive,
checksum and provenance are versioned. Subsequent runs reuse the extracted files.
A separate consensus-specs clone is not required to execute these Rust tests.

The full runner covers all 1,577 available consensus state-transition cases:
826 minimal and 751 mainnet. This includes operations, epoch processing (including
full-epoch inputs where supplied), rewards, slots, blocks, finality, and Heze to
EIP-8321 upgrades. Block cases verify intermediate block state roots as well as
the final post-state root. Invalid cases must be rejected.

Every one of the archive's 2,600 manifests is accounted for in the generated
TSV reports under test-vectors/reports/all-{minimal,mainnet}.tsv:

- PASS / FAIL: serialized state-transition vectors.
- PROPERTY_PASS: one upstream RANDAO property per preset emits no SSZ inputs.
  Its equivalent two-link property is executed separately using a fixture state;
  it is not counted as an official serialized vector.
- OUT_OF_SCOPE: 1,021 client/network manifests (fork choice, fast confirmation,
  networking, light client). These are not counted as passing.

Limit a diagnostic run to one category without regenerating anything:

    EIP8321_CATEGORY=operations/voluntary_exit bash scripts/test_randao.sh vectors-all

Filtered runs overwrite the reports, so run vectors-all without a filter to
restore the complete reports. The upstream mainnet lifecycle fixture is absent
because generation failed; it is not added to the vector count. See
RANDAO_REVIEW.md for implementation scope.

Override the extraction directory with already prepared external fixtures:

    EIP8321_VECTORS_DIR=/absolute/path/to/reftests bash scripts/test_randao.sh vectors

## Recreate the archive after generating the same reference version

From the Grandine repository root, assuming consensus-specs is its sibling:

    tar -c -C ../consensus-specs/reftests minimal/eip8321 mainnet/eip8321 \
      | xz -T2 -3 > test-vectors/eip8321.tar.xz
    (cd test-vectors && sha256sum eip8321.tar.xz > eip8321.sha256)

Archive bytes may differ with compression-tool versions even when fixture contents
are identical. Update the checksum when deliberately replacing the archive.

The upstream consensus-specs project declares CC0-1.0. SOURCE_COMMIT identifies
the exact source version for these generated fixtures.

## GitHub Actions evidence

The EIP-8321 consensus tests workflow runs the local regressions, complete
vectors-all suite and legacy regressions in a clean GitHub-hosted Ubuntu runner.
In the repository Actions tab, open the run for the submitted commit. Its job
summary lists both preset counts, and the eip8321-results-<commit> artifact
contains complete logs and per-case TSV reports, including OUT_OF_SCOPE entries.
The workflow definition is .github/workflows/eip8321.yml.
