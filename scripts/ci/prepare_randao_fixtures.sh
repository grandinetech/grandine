#!/usr/bin/env bash
# Prepare only the upstream categories needed to compile/run consensus regression tests.
# EIP-8321 vectors are separately bundled and verified by test_randao.sh.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."

if [[ "${1:-}" != --check ]]; then
  staging="$(mktemp -d)"
  trap 'rm -rf -- "$staging"' EXIT
  mkdir -p consensus-spec-tests cryptography-spec-tests
  for preset in minimal mainnet; do
    archive="$staging/$preset.tar.gz"
    curl --fail --location --retry 3 --retry-delay 2 \
      "https://github.com/ethereum/consensus-specs/releases/download/v1.7.0-beta.1/$preset.tar.gz" \
      --output "$archive"
    case "$preset" in
      minimal) digest=8be17d6fc598adf0dfd6d74b5ef7be6441d1a4a7046128478a0785c84e128514 ;;
      mainnet) digest=c88212f45e73cba99b6671a47fb8cfb76c6c1202289357f517de1f06b46be899 ;;
    esac
    printf '%s  %s\n' "$digest" "$archive" | sha256sum --check
    tar -xzf "$archive" --directory consensus-spec-tests --wildcards \
      "tests/$preset/*/epoch_processing/*" "tests/$preset/*/operations/*" \
      "tests/$preset/*/rewards/*" "tests/$preset/*/sanity/*" \
      "tests/$preset/*/finality/*" "tests/$preset/*/random/*" \
      "tests/$preset/*/transition/*"
    rm -- "$archive"
  done
  archive="$staging/crypto.zip"
  curl --fail --location --retry 3 --retry-delay 2 \
    https://github.com/ethereum/cryptography-specs/releases/download/v0.1.0/tests.zip \
    --output "$archive"
  printf '%s  %s\n' eeb4893eb544f770810d9499007ebb0b9319431ea412bd54736e1c274da3d037 "$archive" | sha256sum --check
  unzip -q -o "$archive" -d cryptography-spec-tests
fi

# test-generator expands globs at compile time. Missing fixtures must fail early,
# rather than accidentally producing a successful run with fewer regression tests.
python3 - <<'PY'
import glob
import re
from pathlib import Path
patterns = set()
for directory in ("transition_functions/src", "bls", "kzg_utils"):
    for source in Path(directory).rglob("*.rs"):
        patterns.update(re.findall(r'"((?:consensus|cryptography)-spec-tests/[^"\n]*\*[^"\n]*)"', source.read_text()))
missing = sorted(pattern for pattern in patterns if not glob.glob(pattern))
if missing:
    raise SystemExit("Missing compile-time fixture globs:\n" + "\n".join(missing))
if len(patterns) < 400:
    raise SystemExit("Unexpectedly small compile-time fixture inventory")
print(f"Verified {len(patterns)} compile-time fixture globs")
PY
