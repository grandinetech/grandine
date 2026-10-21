# Embeddable Grandine

Grandine can run inside another program instead of as its own process. The host program, usually an
execution client, starts Grandine in-process and serves Grandine's Engine API calls itself, as
ordinary function calls. There is no HTTP connection, no JWT secret and no JSON between the two.

This chapter is for developers who want to embed Grandine in their own project. If you only want to
run Grandine inside Nethermind, see [Grandine embedded in Nethermind](./nethermind_integration.md).

There are two ways to embed Grandine:

| Host language | Use | Built from |
| --- | --- | --- |
| Rust | The Grandine crates directly | `runtime` and `eth1_api` with the `embed` feature |
| Any language with a C FFI (C, C++, C#, Go, Java, ...) | The `libgrandine` C library | The `bindings/c` crate |

The Nethermind plugin is a complete example of the second way: it is a C# host built on
`libgrandine`.

## How embedding works

An embedded Grandine is a full beacon node. It keeps its own peer-to-peer networking, database,
Beacon Node API, metrics and, if it is given validator keys, its integrated validator client. Only
the connection to the execution layer changes:

```text
+---------------------------------------------------------------+
| Host process                                                  |
|                                                               |
|  +--------------------+   Engine API calls   +-------------+  |
|  | Grandine           | -------------------> | Adapter     |  |
|  |  beacon node       |                      |  (host      |  |
|  |  validator client  | <------------------- |   code)     |  |
|  +--------------------+      results         +-------------+  |
|                                                    |         |
|                                                    v         |
|                                     host's execution layer   |
+---------------------------------------------------------------+
```

The host does three things:

1. **Registers an adapter.** The adapter implements every Engine API method Grandine uses:
   `engine_newPayload`, `engine_forkchoiceUpdated`, `engine_getPayload`,
   `engine_getPayloadBodiesByHash`, `engine_getBlobs`, `engine_exchangeCapabilities` and
   `engine_getClientVersion`, in each version up to the current fork. Grandine calls the adapter
   wherever it would otherwise send an HTTP request to an execution client.
2. **Starts Grandine** with a list of command line options, the same ones the `grandine` binary
   takes. `--eth1-rpc-urls` and `--jwt-secret` are not needed.
3. **Stops Grandine** when the host shuts down. Grandine then saves its chain and returns.

### Rules for the host

These follow from how embedded mode is built:

- **One Grandine per process.** The adapter and the shutdown signal are process-wide. The adapter can
  be registered only once, and a second registration fails with an error.
- **Register the adapter before starting Grandine.** Until then, every Engine API call fails.
- **Starting blocks.** The start call returns only when Grandine stops, so run it on a thread of its
  own.
- **The host handles shutdown.** An embedded Grandine does not react to `SIGINT` or `SIGTERM`. Stop it
  with the shutdown call, and wait for the start call to return before the process exits, so that
  Grandine can save its chain. A Grandine that was stopped cannot be started again in the same
  process.
- **Mainnet preset only.** Embedded mode supports networks that use the mainnet preset: Mainnet,
  Sepolia and Hoodi, or a custom network with that preset.
- **The adapter must be thread-safe.** Grandine calls it from its own worker threads, and several
  calls can run at the same time.
- **Errors are returned, not thrown.** An adapter method reports a failure by returning an error.
  Grandine handles it as it handles an execution client that does not answer: the call fails, and
  Grandine counts the error and marks the execution layer as disconnected in its metrics. The
  `el_offline` field of `/eth/v1/node/syncing` is always `false` in embedded mode.

Besides the Engine API methods, the adapter has four methods for reading the deposit contract
(`eth_blockNumber`, `eth_getBlockByHash`, `eth_getBlockByNumber`, `eth_getLogs`). Since the Electra
upgrade, deposits reach the beacon chain through execution requests instead, and the Nethermind
plugin leaves these four unimplemented.

## Embedding in a Rust project

### Dependencies

The Grandine crates are not published on crates.io. Depend on them through Git, and pin a release
tag:

```toml
[dependencies]
anyhow = "1"
eth1_api = { git = "https://github.com/grandinetech/grandine", tag = "VERSION", features = ["embed"] }
execution_engine = { git = "https://github.com/grandinetech/grandine", tag = "VERSION" }
runtime = { git = "https://github.com/grandinetech/grandine", tag = "VERSION", features = ["embed", "network-mainnet", "network-hoodi"] }
types = { git = "https://github.com/grandinetech/grandine", tag = "VERSION" }
web3 = { git = "https://github.com/grandinetech/rust-web3.git", default-features = false }
# Select the cryptography backends, as the grandine binary does.
bls = { git = "https://github.com/grandinetech/grandine", tag = "VERSION", features = ["blst"] }
kzg_utils = { git = "https://github.com/grandinetech/grandine", tag = "VERSION", features = ["blst"] }
```

- `embed` on `eth1_api` replaces the HTTP Engine API client with the adapter, and on `runtime` it
  replaces signal handling with the shutdown call.
- The `network-*` features select the built-in networks the host can run: `network-mainnet`,
  `network-sepolia`, `network-hoodi`.
- `bls` and `kzg_utils` need a cryptography backend. `blst` is the one the official builds use; see
  [Building from source](./build_from_source.md#cryptography-backends) for the others.

Copy the `[patch]` sections from the end of Grandine's `Cargo.toml` (for the same tag) into your own
`Cargo.toml`. Cargo applies patches only from the top-level project, and Grandine depends on the
forked crates they point to.

Grandine's crates use the Rust 2024 edition and the toolchain pinned in Grandine's
`rust-toolchain.toml`. Build your project with that version or a newer one.

### Implementing the adapter and running Grandine

Implement `eth1_api::EmbedAdapter` for a type of yours, register it with `eth1_api::set_adapter`,
then start Grandine with `runtime::run`:

```rust
use std::{ffi::OsString, thread};

use anyhow::{Result, bail};
use eth1_api::{ClientVersionV1, EmbedAdapter, Eth1Block, RawForkChoiceUpdatedResponse};
use execution_engine::{ExecutionPayloadV3, ForkChoiceStateV1, PayloadAttributesV3, PayloadStatusV1};
use runtime::grandine_args::GrandineArgs;
use types::preset::Mainnet;
use web3::types::{BlockNumber, Filter, H256, Log};

/// Connects Grandine to the execution layer of the host application.
struct HostExecutionLayer;

impl EmbedAdapter for HostExecutionLayer {
    // Used only to read the deposit contract.
    fn eth_block_number(&self) -> Result<u64> {
        bail!("not supported")
    }

    fn eth_get_block_by_hash(&self, _hash: H256) -> Result<Option<Eth1Block>> {
        bail!("not supported")
    }

    fn eth_get_block_by_number(&self, _number: BlockNumber) -> Result<Option<Eth1Block>> {
        bail!("not supported")
    }

    fn eth_logs(&self, _filter: Filter) -> Result<Vec<Log>> {
        bail!("not supported")
    }

    fn engine_new_payload_v3(
        &self,
        payload: ExecutionPayloadV3<Mainnet>,
        versioned_hashes: Vec<H256>,
        parent_beacon_block_root: H256,
    ) -> Result<PayloadStatusV1> {
        // Validate and import the payload in the host's execution layer.
        todo!()
    }

    fn engine_forkchoice_updated_v3(
        &self,
        state: ForkChoiceStateV1,
        payload: Option<PayloadAttributesV3<Mainnet>>,
    ) -> Result<RawForkChoiceUpdatedResponse> {
        // Update the head and, if attributes are given, start building a payload.
        todo!()
    }

    fn engine_exchange_capabilities(&self, capabilities: &[&str]) -> Result<Vec<String>> {
        // Return the Engine API methods the host supports.
        todo!()
    }

    fn engine_get_client_version_v1(
        &self,
        own_version: ClientVersionV1,
    ) -> Result<Vec<ClientVersionV1>> {
        todo!()
    }

    // ... the other `engine_*` methods of the trait, in every version ...
}

fn main() -> Result<()> {
    // 1. Register the execution layer, once, before Grandine starts.
    eth1_api::set_adapter(Box::new(HostExecutionLayer))?;

    // 2. Parse the same options the grandine binary takes. The first item is the program name.
    let args = GrandineArgs::parse_strictly(
        ["my-node", "--network", "hoodi", "--data-dir", "/var/lib/my-node/grandine"]
            .map(OsString::from),
    )?;

    // 3. `run` blocks until Grandine stops, so give it a thread of its own.
    let grandine = thread::spawn(move || runtime::run(args));

    // ... the host application runs here ...

    // 4. Stop Grandine and wait until it has saved its chain.
    runtime::shutdown();
    grandine.join().expect("Grandine thread panicked")
}
```

The trait has one method per Engine API method and version, so the full implementation is longer
than shown here; the compiler lists the missing ones. The `CEmbedAdapter` implementation in
`bindings/c/src/lib.rs` is a complete example that forwards every method.

> **Note:** `runtime::run` installs Grandine's logger as the global `tracing` subscriber. Do not
> install your own global subscriber in the same process, or `run` panics. Grandine's log options,
> such as `GRANDINE_LOG`, apply as usual.

## Embedding through the C library

### Building libgrandine

`libgrandine` is built from the `bindings/c` crate, as a shared library (`libgrandine.so`,
`libgrandine.dylib` or `grandine.dll`) and as a static library:

```bash
make -B ./target/x86_64-unknown-linux-gnu/compact/libgrandine.so
```

`make -B x86_64-unknown-linux-gnu` builds the `grandine` binary and the library together. The other
targets are `aarch64-unknown-linux-gnu`, `x86_64-pc-windows-msvc`, `x86_64-apple-darwin` and
`aarch64-apple-darwin`. The library includes the Mainnet, Sepolia and Hoodi networks.

The build also writes a C header, `bindings/c/build/grandine.h`, generated from the Rust code. It
declares every function and type described below.

### The C interface

| Function | Purpose |
| --- | --- |
| `grandine_set_execution_layer_adapter(CEmbedAdapter adapter)` | Registers the adapter. Call it once, before `grandine_run`. |
| `grandine_run(uint64_t argc, const char *const *argv)` | Starts Grandine with command line options and blocks until it stops. Returns `0` on success and `1` on error. Unlike a C `main`, `argv` holds only the options, without a program name. |
| `grandine_shutdown(void)` | Asks Grandine to stop. `grandine_run` returns once the chain is saved. |
| `grandine_vec_alloc(CLayout layout, size_t size)` | Allocates memory for a vector that the host returns to Grandine. |
| `grandine_string(const char *str)` | Copies a string into memory owned by Grandine, for error messages and other strings the host returns. |
| `grandine_layout_*()` | Return the `CLayout` of each element type, to pass to `grandine_vec_alloc`. |

`CEmbedAdapter` is a struct of function pointers, one per Engine API method and version, for example
`engine_new_payload_v3`, `engine_forkchoice_updated_v3` and `engine_get_blobs_v2`. Each takes C
structs (`CExecutionPayloadV3`, `CForkChoiceStateV1`, ...) and returns a `CResult`:

- `code` is `GRANDINE_SUCCESS` (`0`) when the call succeeded, and `value` holds the result;
- any other code, such as `GRANDINE_ERROR_ENGINE_API` (`2`), reports a failure, with an explanation
  in `message`.

### Memory ownership

- **Grandine to host.** Pointers that Grandine passes to an adapter function are valid only during
  that call. Copy what you need to keep.
- **Host to Grandine.** Grandine frees what the host returns with its own allocator. Allocate every
  vector in a result with `grandine_vec_alloc` and every string with `grandine_string`, never with
  `malloc` or your language's allocator.

### Example: the Nethermind plugin

The Nethermind plugin (`bindings/csharp/Grandine.NethermindPlugin`) is a complete host built on
`libgrandine`, and a good template for other languages:

- `GrandineEngineApi.cs` implements each adapter method by converting the C structs to Nethermind's
  types and calling Nethermind's own Engine API module, for example `engine_newPayloadV3`.
- `GrandineClient.cs` turns these methods into C function pointers, fills `CEmbedAdapter` and calls
  `grandine_set_execution_layer_adapter`. It allows only one instance per process.
- `GrandineClient.Run` converts the options to C strings and calls `grandine_run` on a separate task.
  `DisposeAsync` calls `grandine_shutdown` and waits for that task to finish.
- `StartGrandine.cs` builds the option list from Nethermind's `Grandine.*` settings and starts the
  client once Nethermind has registered its Engine API module.

In C#, the delegates behind the function pointers must stay referenced for as long as Grandine runs,
or the garbage collector frees them. The plugin keeps them in fields of `GrandineClient` for this
reason.

The C# declarations of the native functions and types, `NativeMethods.impl.cs`, are generated from
`libgrandine` by the `bindings/csharp` crate with `csbindgen`. The plugin's settings, one per
Grandine command line option, are generated from Grandine's option definitions in the same build.
Build the plugin with:

```bash
make -B nethermind-plugin
```

See `bindings/c/README.md` and `bindings/csharp/README.md` in the repository for packaging the
library and the plugin with a Nethermind release or into Docker images.
