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

Or only the official vectors:

    bash scripts/test_randao.sh vectors

Extraction requires tar and xz (Ubuntu package xz-utils).

On the first run the script verifies the archive SHA-256 and extracts it into
test-vectors/eip8321. That generated directory is Git-ignored; the archive,
checksum and provenance are versioned. Subsequent runs reuse the extracted files.
A separate consensus-specs clone is not required to execute these Rust tests.

The currently connected Rust runners cover 144 official cases, not every fixture
in the archive. See RANDAO_REVIEW.md for the categories and implementation scope.

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
