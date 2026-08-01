#!/usr/bin/env bash
set -euo pipefail

SPEC_VERSION="${SPEC_VERSION:-v1.7.0-alpha.13}"
TESTS_DIR="consensus-spec-tests"
VERSION_FILE="${TESTS_DIR}/.version"
BASE_URL="https://github.com/ethereum/consensus-specs/releases/download/${SPEC_VERSION}"
MAX_RETRIES="${MAX_RETRIES:-3}"

# KZG and BLS test vectors were moved out of consensus-specs by
# <https://github.com/ethereum/consensus-specs/pull/5398> and now live in
# <https://github.com/ethereum/cryptography-specs>, which releases them as a
# single `tests.zip` containing `tests/kzg` and `tests/bls`.
CRYPTO_SPEC_VERSION="${CRYPTO_SPEC_VERSION:-v0.1.0}"
CRYPTO_TESTS_DIR="cryptography-spec-tests"
CRYPTO_VERSION_FILE="${CRYPTO_TESTS_DIR}/.version"
CRYPTO_URL="https://github.com/ethereum/cryptography-specs/releases/download/${CRYPTO_SPEC_VERSION}/tests.zip"

# Tarballs to download. "comptests" bundles the fork choice compliance tests
# that are now part of the consensus-spec release (run by compliance_tests.rs).
TARBALLS=("general" "minimal" "mainnet" "comptests")

# Normalize paths on Windows Git Bash
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    TESTS_DIR=$(cygpath -m "$TESTS_DIR")
    VERSION_FILE=$(cygpath -m "$VERSION_FILE")
    CRYPTO_TESTS_DIR=$(cygpath -m "$CRYPTO_TESTS_DIR")
    CRYPTO_VERSION_FILE=$(cygpath -m "$CRYPTO_VERSION_FILE")
fi

fetch_url() {
    local url="$1"
    local output="$2"

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$output"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$output" "$url"
    else
        echo "Error: No download tool found. Please install curl or wget."
        exit 1
    fi
}

# Map a tarball name to the relative directory used to verify its extraction.
# Most tarballs extract into tests/<name>, but comptests merges into the preset
# directories, so verify one of the compliance test paths it provides.
verify_subdir() {
    case "$1" in
        comptests) echo "tests/minimal/fulu/fork_choice_compliance" ;;
        *)         echo "tests/$1" ;;
    esac
}

# Function to verify tarball extraction was successful
verify_extraction() {
    local tarball_name="$1"
    local subdir
    subdir="$(verify_subdir "$tarball_name")"

    # Check if the extracted directory exists and contains files
    if [[ -d "${TESTS_DIR}/${subdir}" ]] && [[ -n "$(ls -A "${TESTS_DIR}/${subdir}" 2>/dev/null)" ]]; then
        return 0
    else
        return 1
    fi
}

# Function to download and extract a tarball
download_tarball() {
    local tarball_name="$1"
    local download_url="${BASE_URL}/${tarball_name}.tar.gz"
    local attempt=1
    local temp_file="${TESTS_DIR}/.${tarball_name}.tar.gz.tmp"

    while [[ $attempt -le $MAX_RETRIES ]]; do
        echo "Downloading ${tarball_name}.tar.gz (attempt ${attempt}/${MAX_RETRIES})..."

        # Download to temporary file first
        local download_success=false
        if fetch_url "$download_url" "$temp_file"; then
            download_success=true
        fi

        if [[ "$download_success" == true ]]; then
            # Verify the downloaded file is a valid gzip
            if gzip -t "$temp_file" 2>/dev/null; then
                # Extract the tarball
                if tar -xzf "$temp_file" -C "$TESTS_DIR"; then
                    rm -f "$temp_file"
                    # Verify extraction was successful
                    if verify_extraction "$tarball_name"; then
                        echo "  ✓ ${tarball_name}.tar.gz extracted and verified"
                        return 0
                    else
                        echo "  ✗ Extraction verification failed for ${tarball_name}.tar.gz"
                    fi
                else
                    echo "  ✗ Failed to extract ${tarball_name}.tar.gz"
                    rm -f "$temp_file"
                fi
            else
                echo "  ✗ Downloaded file is not a valid gzip archive"
                rm -f "$temp_file"
            fi
        else
            echo "  ✗ Download failed for ${tarball_name}.tar.gz"
        fi

        # Clean up any partial extraction
        rm -rf "${TESTS_DIR}/$(verify_subdir "$tarball_name")"

        if [[ $attempt -lt $MAX_RETRIES ]]; then
            echo "  Retrying in 2 seconds..."
            sleep 2
        fi

        attempt=$((attempt + 1))
    done

    echo "Error: Failed to download and extract ${tarball_name}.tar.gz after ${MAX_RETRIES} attempts"
    return 1
}

download_consensus_tests() {
    # Check if tests already exist with the same version
    if [[ -f "$VERSION_FILE" ]]; then
        local existing_version
        existing_version=$(<"$VERSION_FILE")
        if [[ "$existing_version" == "$SPEC_VERSION" ]]; then
            echo "Consensus-spec-tests ${SPEC_VERSION} already exists."
            return 0
        fi

        echo "Found existing tests version ${existing_version}, updating to ${SPEC_VERSION}..."
        rm -rf "$TESTS_DIR"
    fi

    echo "Downloading consensus-spec-tests ${SPEC_VERSION}..."

    # Create directory if it doesn't exist
    mkdir -p "$TESTS_DIR"

    # Check if we can parallelize downloads
    if command -v xargs >/dev/null 2>&1; then
        export -f download_tarball verify_extraction verify_subdir fetch_url
        export TESTS_DIR BASE_URL MAX_RETRIES

        # Parallel downloads using xargs
        if printf "%s\n" "${TARBALLS[@]}" | xargs -P 3 -I {} bash -c 'download_tarball "$@"' _ {}; then
            echo "All downloads completed successfully"
        else
            echo "Error: One or more downloads failed"
            exit 1
        fi
    else
        # Fallback to sequential if xargs is not available
        for tarball in "${TARBALLS[@]}"; do
            if ! download_tarball "$tarball"; then
                echo "Error: Download failed, aborting"
                exit 1
            fi
        done
    fi

    # Save version file
    echo "$SPEC_VERSION" > "$VERSION_FILE"

    echo "Successfully downloaded and extracted all tests to ${TESTS_DIR}"
}

extract_zip() {
    local archive="$1"
    local destination="$2"

    if command -v unzip >/dev/null 2>&1; then
        unzip -qo "$archive" -d "$destination"
    elif command -v bsdtar >/dev/null 2>&1; then
        bsdtar -xf "$archive" -C "$destination"
    elif command -v python3 >/dev/null 2>&1; then
        python3 -m zipfile -e "$archive" "$destination"
    else
        echo "Error: No unzip tool found. Please install unzip, bsdtar or python3."
        exit 1
    fi
}

download_cryptography_tests() {
    if [[ -f "$CRYPTO_VERSION_FILE" ]]; then
        local existing_version
        existing_version=$(<"$CRYPTO_VERSION_FILE")
        if [[ "$existing_version" == "$CRYPTO_SPEC_VERSION" ]]; then
            echo "Cryptography-spec-tests ${CRYPTO_SPEC_VERSION} already exists."
            return 0
        fi

        echo "Found existing cryptography tests version ${existing_version}, updating to ${CRYPTO_SPEC_VERSION}..."
    fi

    rm -rf "$CRYPTO_TESTS_DIR"
    mkdir -p "$CRYPTO_TESTS_DIR"

    echo "Downloading cryptography-spec-tests ${CRYPTO_SPEC_VERSION}..."

    local temp_file="${CRYPTO_TESTS_DIR}/.tests.zip.tmp"
    local attempt=1

    while [[ $attempt -le $MAX_RETRIES ]]; do
        echo "Downloading tests.zip (attempt ${attempt}/${MAX_RETRIES})..."

        if fetch_url "$CRYPTO_URL" "$temp_file"; then
            if extract_zip "$temp_file" "$CRYPTO_TESTS_DIR"; then
                rm -f "$temp_file"

                if [[ -n "$(ls -A "${CRYPTO_TESTS_DIR}/tests/kzg" 2>/dev/null)" ]]; then
                    echo "  ✓ tests.zip extracted and verified"
                    echo "$CRYPTO_SPEC_VERSION" > "$CRYPTO_VERSION_FILE"
                    echo "Successfully downloaded and extracted all tests to ${CRYPTO_TESTS_DIR}"
                    return 0
                fi

                echo "  ✗ Extraction verification failed for tests.zip"
            else
                echo "  ✗ Failed to extract tests.zip"
            fi
        else
            echo "  ✗ Download failed for tests.zip"
        fi

        # Clean up any partial download or extraction
        rm -rf "${CRYPTO_TESTS_DIR:?}/"*
        rm -f "$temp_file"

        if [[ $attempt -lt $MAX_RETRIES ]]; then
            echo "  Retrying in 2 seconds..."
            sleep 2
        fi

        attempt=$((attempt + 1))
    done

    echo "Error: Failed to download and extract tests.zip after ${MAX_RETRIES} attempts"
    return 1
}

download_consensus_tests
download_cryptography_tests
