#!/usr/bin/env bash

# Installs Nim for the `constantine` backend and adds it to `GITHUB_PATH`.
#
# `jiro4989/setup-nim-action` downloads from nim-lang.org, which often times out on GitHub runners.
# The nim-lang/nightlies release used here hosts the same official 2.0.2 archives on GitHub.
# The checksums below match the archives on nim-lang.org.

set -euo pipefail

NIM_VERSION=2.0.2
RELEASE_URL=https://github.com/nim-lang/nightlies/releases/download/2023-12-15-version-2-0-c4c44d10df8a14204a75c34e499def200589cb7c

case "$RUNNER_OS" in
    Linux)
        archive="nim-$NIM_VERSION-linux_x64.tar.xz"
        sha256=047dde8ff40b18628ac1188baa9ca992d05f1f45c5121d1d07a76224f06e1551
        ;;
    Windows)
        archive="nim-$NIM_VERSION-windows_x64.zip"
        sha256=948dbf8e3fdd1b5242e3d662fd25c50e9b2586e097be8a85c22d7db2bde70bad
        ;;
    *)
        echo "unsupported runner OS: $RUNNER_OS" >&2
        exit 1
        ;;
esac

cd "$RUNNER_TEMP"

curl --fail --silent --show-error --location \
    --connect-timeout 10 --max-time 300 --retry 5 --retry-all-errors \
    --output "$archive" "$RELEASE_URL/$archive"

echo "$sha256  $archive" | sha256sum --check

case "$archive" in
    *.zip) unzip -q "$archive" ;;
    *) tar xf "$archive" ;;
esac

rm "$archive"

nim_bin="$PWD/nim-$NIM_VERSION/bin"
nimble_bin="$HOME/.nimble/bin"
mkdir -p "$nimble_bin"

if [[ "$RUNNER_OS" == Windows ]]; then
    nim_bin=$(cygpath --windows "$nim_bin")
    nimble_bin=$(cygpath --windows "$nimble_bin")
fi

echo "$nim_bin" >> "$GITHUB_PATH"
echo "$nimble_bin" >> "$GITHUB_PATH"
