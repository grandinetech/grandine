# Runtime features

Runtime features are switches that change Grandine's behavior without a dedicated command line
option. Most are for debugging, testing or development. A few change behavior in ways that some
operators want. All are off by default unless this page says otherwise.

> **Warning:** Features are not a stable interface. They can change or disappear between releases.
> Some reduce validation or change how the node participates in the network. Do not enable a
> feature on a mainnet validator unless you know what it does.

## Enabling features

Pass feature names, comma-separated, to `--features`. Names are case-sensitive and written exactly
as in the tables below.

```bash
grandine --network hoodi --features LogHttpRequests,WarnOnFailedServiceHealthChecks ...
```

You can also repeat the option:

```bash
grandine --network hoodi --features LogHttpRequests --features LogHttpHeaders ...
```

`--features` is a general option. With `bn` and `vc` it goes after the subcommand, like every other
option:

```bash
grandine vc --features LogHttpRequests --beacon-node-urls http://BN-HOST:5052 ...
```

In an `--args-file`, use a list:

```yaml
features:
  - LogHttpRequests
  - WarnOnFailedServiceHealthChecks
```

### Viewing and changing features at runtime

The beacon node serves two Grandine-specific endpoints on the Beacon Node API:

```bash
# List every feature and whether it is enabled
curl -s http://127.0.0.1:5052/features

# Enable or disable features without a restart
curl -X PATCH http://127.0.0.1:5052/features \
  -H "Content-Type: application/json" \
  -d '{"LogHttpRequests": true, "DebugP2pMessages": false}'
```

Each change is logged as `feature NAME enabled` or `feature NAME disabled`. Changes last until the
process exits. Some features are read only once, at startup (noted below), so changing them at
runtime has no effect.

> **Warning:** These endpoints have no authentication. Anyone who can reach the Beacon Node API can
> change features. Keep the API on localhost or a private network. See
> [Security best practices](./security.md).

## Features for operators

| Feature | What it does | When to use it |
| --- | --- | --- |
| `PublishSyncCommitteeMessagesEarly` | When the slot's block arrives before the attestation deadline and Grandine attests early, also publishes sync committee messages at that moment. By default Grandine waits for the attestation tick to publish them, a deviation from the honest validator specification that tends to improve rewards. | If you want sync committee messages published as early as attestations. |
| `AlwaysPrepareExecutionPayload` | Asks the execution client to prepare a payload before every slot, not only before slots where a registered local validator proposes. | Testing block production, or a beacon node used by validator clients it does not know about. Costs execution client work. |
| `AlwaysPrepackAttestations` | Packs the attestations for the next block every slot, not only when a local validator proposes next. | Testing. Costs CPU. |
| `AggregateAllAttestations` | Aggregates attestations of all committees, not only those with local aggregators or upcoming local proposers. | Nodes that serve block production for others. Costs CPU and memory. |
| `SubscribeToAllAttestationSubnets` | Subscribes to every attestation subnet. Set by `--subscribe-all-subnets`. Read at startup. | Use `--subscribe-all-subnets` instead. |
| `SubscribeToAllSyncCommitteeSubnets` | Subscribes to every sync committee subnet. Set by `--subscribe-all-subnets`. | Use `--subscribe-all-subnets` instead. |
| `SubscribeToAllDataColumnSubnets` | Subscribes to every data column subnet. Set by `--supernode`. Read at startup. | Use `--supernode` instead. See [PeerDAS and blob data](./peerdas.md). |
| `ServeCostlyEndpoints` | Enables the Grandine-specific `/validator/statistics`, `/validator/registered` and `/validator/owned` endpoints, which are expensive to compute. | If you use these endpoints. See [Grandine-specific endpoints](./grandine_api.md). |
| `ServeLeakyEndpoints` | Enables `GET /system/stats`, which reveals information about the host. Also starts the metrics service without `--metrics`. Read at startup for the metrics service. | If you use `/system/stats` on a trusted network. |
| `WarnOnFailedServiceHealthChecks` | Warns when an internal service could not handle events for a long time (`SERVICE could not handle events for N ms`). | Diagnosing stalls and high load. |
| `WarnOnStateCacheSlotProcessing` | Warns with a backtrace when the node has to process empty slots to build a state it did not have cached, once synced. | Diagnosing CPU spikes. The backtrace is costly. |

## Features for debugging

These change logging or write extra data. They are safe in the sense that they do not change
consensus behavior, but they cost CPU, disk or log volume.

| Feature | What it does |
| --- | --- |
| `LogHttpRequests` | Logs each HTTP API request (method, URI, HTTP version, remote address) and its response status, on the Beacon Node API, the validator API and the metrics endpoint. |
| `LogHttpHeaders` | Logs HTTP request headers. Can log secrets such as the API token. |
| `LogHttpBodies` | Logs HTTP request and response bodies (except beacon states). Very verbose; can log secrets. Read at startup. |
| `DebugP2pMessages` | Records a short description of each gossip message for debug logging in the networking code. |
| `DebugEth1` | Logs details of reading deposit-contract blocks and errors from the execution client. |
| `DebugBlockProducer` | Logs details of block production steps. |
| `DebugAttestationPacker` | Logs how attestations are packed into blocks. Grandine enables this one itself when it runs a beacon node. |
| `LogBlockProcessingTime` | Logs how long block processing steps take, for example `block 0x… inserted in 63ms, processed in 52ms`. Grandine enables this one itself when it runs a beacon node. |
| `DumpBeaconBlocks` | Writes every new gossip or requested block to `dump/NETWORK/beacon_block_slot_..._root_....ssz` in the current working directory. |
| `DumpBlobSidecars` | Writes requested blob sidecars to `dump/NETWORK/blob_sidecar_slot_...ssz`. |
| `DumpAggregateAttestations` | Writes aggregate attestations received over gossip to `dump/NETWORK/attestation_slot_...ssz`. |
| `DumpBeaconStates` | Turns on the dump directory like the other `Dump*` features, but no code path writes states at the moment. |

The dumper is set up at startup only if at least one `Dump*` feature is enabled then; after that, each `Dump*` feature can be switched at runtime. The `Dump*` features can fill a disk quickly. The dump directory is relative to the working
directory of the process, not the data directory.

## Features for testing and development

These relax validation or change network behavior. They exist for tests, devnets and
investigations. Do not use them on a node that matters.

| Feature | What it does |
| --- | --- |
| `TrustOwnBlockSignatures` | Skips signature verification of blocks produced by this node. |
| `TrustOwnAttestationSignatures` | Skips signature verification of attestations produced by this node. |
| `TrustOwnAttesterSlashingSignatures` | Skips signature verification of attester slashings produced by this node. |
| `TrustOwnStateRoots` | Trusts the state root of blocks produced by this node instead of recomputing it. |
| `IgnoreAttestationsForUnknownBlocks` | Ignores attestations for blocks the node has not seen, instead of delaying them until the block arrives. |
| `IgnoreFutureAttestations` | Ignores attestations from future slots instead of delaying them. |
| `PatchHttpContentType` | Treats HTTP API requests without a `Content-Type` header as `application/json`. Read at startup. Meant for clients that leave the header out. |
| `DisableFinalizedRootCheck` | Keeps peers whose finalized block differs from ours at the same epoch, instead of disconnecting them. |
| `CacheTargetStates` | Uses cached checkpoint states, instead of computing target states, when validating aggregates and in the slasher. |
| `InhibitApplicationRestart` | Exits on a runtime error instead of restarting the runtime in-process. Enabled by default; pass `--force-application-restart` to disable it. |

By default Grandine fully validates even the objects it produces itself, which costs some CPU but
catches bugs. The `TrustOwn*` features turn that off.

## Internal and unused features

- `PrometheusMetrics` is set by `--metrics`. Use `--metrics` instead.
- `TrackMetrics` is not used by the code.
- `PublishAttestationsEarly` is deprecated and has no effect. Grandine publishes attestations at the
  normal time.

## Command line options

- `--features`: default none. Comma-separated list of runtime features to enable.

See [Command line reference](./cli_options.md) for the full list of options.
