# grandine-nethermind integration

This crate contains grandine C# plugin, to integrate with nethermind.

## Building

Integration consists of two parts - nethermind plugin lib (Grandine.NethermindPlugin.dll file) and grandine dynamic lib (libgrandine.so/.dylib/.dll). Both of these files need to be copied into nethermind's plugins directory, in order to run embedded grandine.

### libgrandine.so

See README.md file in ./bindings/c directory for instructions on building `libgrandine.so`.

### Grandine.NethermindPlugin.dll

To build nethermind plugin, execute `nethermind-plugin` script from makefile:

```bash
make -B nethermind-plugin
```

### Packaging with nethermind

You can automatically download nethermind release and package it with grandine, using makefile:

```bash
# This script produces .zip archive with grandine-nethermind integration for linux x64, inside ./build directory:
#     ./build/grandine-0.1.15-nethermind-1.35.3-linux-x64.zip
# 
# Replace 1.35.3 with nethermind version, to be downloaded & packaged with grandine
# Replace 0.1.15 with grandine version, to be released
make -B grandine-nethermind-linux-x64 GRANDINE_VERSION=0.1.15 NETHERMIND_VERSION=1.35.3
```

Available targets are:

* linux-x64 - equivalent to `x86_64-unknown-linux-gnu` rust target triplet
* linux-arm64 - equivalent to `aarch64-unknown-linux-gnu` rust target triplet
* windows-x64 - equivalent to `x86_64-pc-windows-msvc` rust target triplet
* macos-x64 - equivalent to `x86_64-apple-darwin` rust target triplet
* macos-arm64 - equivalent to `aarch64-apple-darwin` rust target triplet

### Docker

You can also build docker images, containing grandine-nethermind integration. Build with makefile:

```bash
# This script produces docker multiarch image:
#      sifrai/grandine:unstable-0b83d87-nethermind-1.35.3
#      sifrai/grandine:unstable-arm64-0b83d87-nethermind-1.35.3
#      sifrai/grandine:unstable-amd64-0b83d87-nethermind-1.35.3
make -B nethermind-docker \
    DOCKER_LABEL=unstable \
    DOCKER_SUFFIX=0b83d87 \
    GRANDINE_VERSION=0.1.15 \
    NETHERMIND_VERSION=1.35.3
```

For this makefile script, you have several parameters:

* DOCKER_REPO - Docker repository. If not set, defaults to "sifrai/grandine".
* DOCKER_LABEL - Possible values: unstable/stable.
* DOCKER_SUFFIX - Optional. Can be used to add suffix to grandine version. Usually is set to short commit hash.
* GRANDINE_VERSION - Grandine version to release. Used only to set image tag. Can be anything, but usually follows semver (i.e. 1.0.0)
* NETHERMIND_VERSION - Valid nethermind version, to build integration from. Can be found among published [nethermind/nethermind](https://hub.docker.com/r/nethermind/nethermind) image tags. Note: chiseled nethermind variant is not supported yet.
