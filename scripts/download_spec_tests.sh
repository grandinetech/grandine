#!/usr/bin/env bash
set -euo pipefail

SPEC_VERSION="${SPEC_VERSION:-v1.6.0}"
TESTS_DIR="consensus-spec-tests"
VERSION_FILE="${TESTS_DIR}/.version"
BASE_URL="https://github.com/ethereum/consensus-specs/releases/download/${SPEC_VERSION}"

# Tarballs to download
TARBALLS=("general" "minimal" "mainnet")

# Normalize paths on Windows Git Bash
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    TESTS_DIR=$(cygpath -m "$TESTS_DIR")
    VERSION_FILE=$(cygpath -m "$VERSION_FILE")
fi

# Check if tests already exist with the same version
if [[ -f "$VERSION_FILE" ]]; then
    EXISTING_VERSION=$(<"$VERSION_FILE")
    if [[ "$EXISTING_VERSION" == "$SPEC_VERSION" ]]; then
        echo "Consensus-spec-tests ${SPEC_VERSION} already exists."
        exit 0
    else
        echo "Found existing tests version ${EXISTING_VERSION}, updating to ${SPEC_VERSION}..."
        rm -rf "$TESTS_DIR"
    fi
fi

echo "Downloading consensus-spec-tests ${SPEC_VERSION}..."

# Create directory if it doesn't exist
mkdir -p "$TESTS_DIR"

# Function to download and extract a tarball
download_tarball() {
    local tarball_name="$1"
    local download_url="${BASE_URL}/${tarball_name}.tar.gz"

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$download_url" | tar -xz -C "$TESTS_DIR"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "$download_url" | tar -xz -C "$TESTS_DIR"
    else
        echo "Error: No download tool found. Please install curl or wget."
        exit 1
    fi

    echo "  ✓ ${tarball_name}.tar.gz extracted"
}

# Check if we can parallelize downloads
if command -v xargs >/dev/null 2>&1; then
    # Parallel downloads and extract using xargs
    echo "${TARBALLS[@]}" | tr ' ' '\n' | xargs -P 3 -I {} sh -c '
        tarball="$1"
        download_url="'"${BASE_URL}"'/${tarball}.tar.gz"
        echo "Downloading ${tarball}.tar.gz..."
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL "$download_url" | tar -xz -C "'"$TESTS_DIR"'"
        elif command -v wget >/dev/null 2>&1; then
            wget -qO- "$download_url" | tar -xz -C "'"$TESTS_DIR"'"
        else
            echo "Error: No download tool found. Please install curl or wget."
            exit 1
        fi
        echo "  ✓ ${tarball}.tar.gz extracted"
    ' _ {}
else
    # Fallback to sequential if xargs is not available
    for tarball in "${TARBALLS[@]}"; do
        download_tarball "$tarball"
    done
fi

# Save version file
echo "$SPEC_VERSION" > "$VERSION_FILE"

echo "Successfully downloaded and extracted all tests to ${TESTS_DIR}"
