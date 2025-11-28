#!/usr/bin/env bash
set -euo pipefail

SPEC_VERSION="${SPEC_VERSION:-v1.6.0}"
TESTS_DIR="consensus-spec-tests"
VERSION_FILE="${TESTS_DIR}/.version"
BASE_URL="https://github.com/ethereum/consensus-specs/releases/download/${SPEC_VERSION}"
MAX_RETRIES="${MAX_RETRIES:-3}"

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

# Function to verify tarball extraction was successful
verify_extraction() {
    local tarball_name="$1"

    # Check if the extracted directory exists and contains files
    if [[ -d "${TESTS_DIR}/tests/${tarball_name}" ]] && [[ -n "$(ls -A "${TESTS_DIR}/tests/${tarball_name}" 2>/dev/null)" ]]; then
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
        if command -v curl >/dev/null 2>&1; then
            if curl -fsSL "$download_url" -o "$temp_file"; then
                download_success=true
            fi
        elif command -v wget >/dev/null 2>&1; then
            if wget -qO "$temp_file" "$download_url"; then
                download_success=true
            fi
        else
            echo "Error: No download tool found. Please install curl or wget."
            rm -f "$temp_file"
            exit 1
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
        rm -rf "${TESTS_DIR}/tests/${tarball_name}"
        
        if [[ $attempt -lt $MAX_RETRIES ]]; then
            echo "  Retrying in 2 seconds..."
            sleep 2
        fi
        
        attempt=$((attempt + 1))
    done

    echo "Error: Failed to download and extract ${tarball_name}.tar.gz after ${MAX_RETRIES} attempts"
    return 1
}

# Check if we can parallelize downloads
if command -v xargs >/dev/null 2>&1; then
    export -f download_tarball verify_extraction
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
