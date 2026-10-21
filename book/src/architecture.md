# How Grandine works

This page explains the moving parts of an Ethereum node and how Grandine puts them together. You do not
need it to get started, but it helps when you plan a setup or read the logs.

## Concepts primer

### Execution layer and consensus layer

Since the Merge, an Ethereum node is made of two programs that work as a pair:

- The **execution client** (EL), such as Geth, Nethermind, Besu, Reth or Erigon, runs the EVM. It
  keeps account balances and contract storage, holds the transaction pool and executes the
  transactions in each block.
- The **consensus client** (CL), such as Grandine, runs proof of stake. It follows the beacon chain,
  decides which block is the head of the chain, talks to other consensus clients over a peer-to-peer
  network and drives the validators.

The two talk over the authenticated **Engine API**, usually on port 8551 of the execution client. Both
sides prove their identity with a shared secret, the **JWT secret**. The consensus client tells the
execution client which block to validate and which block is the head; the execution client tells the
consensus client whether a payload is valid and builds payloads for new blocks.

When Grandine is [embedded in Nethermind](./nethermind_integration.md), it runs inside the
Nethermind process and calls Nethermind's Engine API implementation directly, as native function
calls. There is no HTTP, JWT authentication or JSON encoding between the two clients, so this
communication has no overhead.

Neither half is useful alone. A consensus client without an execution client cannot check the
transactions in a block, and an execution client without a consensus client does not know which
chain to follow.

### Slots, epochs and finality

Time on the beacon chain is split into **slots** of 12 seconds on Mainnet. Each slot may hold one
block. 32 slots make an **epoch**, about 6.4 minutes.

Validators vote on the chain in every epoch. When two thirds of the stake agree on a checkpoint at an
epoch boundary, it becomes **justified**, and a justified checkpoint followed by another justified one
becomes **finalized**. A finalized block cannot be reverted without destroying at least one third of
all staked ether. Under normal conditions blocks finalize after about two epochs, roughly 13 minutes.

### Validator duties

A **validator** is 32 ether or more (up to 2048 after the Electra upgrade) staked with a BLS key pair.
Its key signs messages for these duties:

- **Attesting**: once per epoch, vote for the head of the chain and for the source and target
  checkpoints.
- **Proposing**: when selected, build and sign the block for a slot.
- **Aggregating**: when selected, collect attestations from a subnet and publish an aggregate.
- **Sync committee**: when selected for a sync committee (512 validators for about 27 hours), sign
  the head block in every slot to serve light clients.

Signing two conflicting messages for the same duty is a **slashable offense**. The validator loses part
of its stake and is ejected. Grandine guards against it with a
[slashing protection database](./slashing_protection.md) and optional
[doppelganger protection](./doppelganger_protection.md).

The software that holds the keys and performs duties is the **validator client** (VC). It needs a
beacon node to learn its duties, get blocks to sign and publish what it signs.

## The parts of Grandine

Grandine is one binary built from many crates. The main components of a running beacon node are:

| Component | Crate | What it does |
| --- | --- | --- |
| Fork choice | `fork_choice_store`, `fork_choice_control` | Keeps the block tree, applies the fork choice rule, tracks justification and finality, persists finalized data |
| State transition | `transition_functions`, `helper_functions` | Applies blocks and epochs to beacon states, per fork |
| Networking | `p2p`, `eth2_libp2p` | Gossip, peer discovery, request/response, range sync and back-sync |
| Execution layer | `eth1_api`, `execution_engine`, `eth1` | Engine API calls to the EL, deposit tracking, blob fetching from the EL |
| Beacon Node API | `http_api` | The standard REST API and Grandine-specific endpoints |
| Validator client | `validator`, `signer`, `slashing_protection`, `keymanager` | Duties, signing (local keys or Web3Signer), slashing protection, Keymanager API |
| Block production | `block_producer`, `operation_pools`, `builder_api` | Builds blocks, packs attestations, talks to external builders |
| Storage | `database` | Embedded `libmdbx` key-value database |
| Data availability | `eip_7594`, `kzg_utils` | PeerDAS data columns and KZG proofs |
| Liveness and doppelganger | `liveness_tracker`, `doppelganger_protection` | Detect whether validator keys are already active elsewhere |
| Metrics | `metrics`, `prometheus_metrics` | Prometheus metrics and remote monitoring |

The `runtime` crate parses the command line, sets up the components and connects them with message
channels.

## How the beacon node, validator client, EL and database interact

```text
             peers (libp2p: gossip, discovery, req/resp)
                              |
                              v
+--------------------------------------------------------+
| Grandine beacon node                                   |
|                                                        |
| p2p / sync ---> fork choice ---------> database        |
|                 (mutator thread)       (libmdbx)       |
|                    ^    |                              |
|                    |    | snapshots                    |
|                    |    v                              |
| Beacon API <--- controller ----------> execution ------+---> EL
| (port 5052)     (queries)              engine          |     (Engine API, JWT)
|     ^              ^                                   |
|     |              |                                   |
|     |       integrated validator client                |
|     |       (in-process, optional)                     |
+-----+--------------------------------------------------+
      |
      | Beacon Node API (HTTP)
      |
 separate validator client (grandine vc)
```

1. **Blocks arrive.** The networking service receives blocks, blobs, data columns and attestations by
   gossip, or requests them from peers while syncing.
2. **Fork choice processes them.** Objects are handed to the fork choice controller. A single
   *mutator* thread owns the fork choice store. Expensive work such as signature checks and state
   transitions runs in parallel on a thread pool, and the results come back to the mutator, which
   applies them in order.
3. **The EL validates payloads.** For each block, Grandine sends the execution payload to the
   execution client with `engine_newPayload`, and reports the new head with `engine_forkchoiceUpdated`.
   Until the EL confirms a payload, the block is *optimistic*.
4. **Readers use snapshots.** The Beacon API, the validator client and other components read from a
   recent snapshot of the store. They never wait for the mutator, and the mutator never waits for them.
5. **Finalized data goes to disk.** When a checkpoint finalizes, Grandine writes the newly finalized
   blocks, and states at the configured interval, to the database. What exactly it keeps depends on
   the [storage mode](./storage.md). On shutdown it saves the current chain, so a restart can
   continue where it stopped.

With `--eth1-rpc-urls` you can give more than one execution client endpoint. Grandine uses the first
and falls back to the others if it fails. See
[Connecting an execution client](./execution_client.md).

## The in-memory unfinalized chain

Most consensus clients keep recent states in a database or an on-disk cache. Grandine keeps the whole
unfinalized part of the chain in memory and uses the database mainly for finalized data, for loading
checkpoints at startup and for serving historical data through the API.

This is affordable because beacon states use **structural sharing**. A beacon state is built from
persistent data structures (trees). When a block changes a few balances, the new state shares every
unchanged subtree with the previous state instead of copying it. Hundreds of unfinalized states cost
little more memory than one, and Grandine avoids the cost of copying full states during block
processing.

On a healthy network the unfinalized part is about two epochs long, so memory use stays low. During a
long period without finality, the unfinalized chain grows. To bound memory, Grandine keeps full states
in memory for only the latest `--unfinalized-states-in-memory` slots (default 128) and recomputes older
ones from blocks when they are needed. See [Storage and database](./storage.md) and
[Performance and memory tuning](./performance_tuning.md).

## Integrated or separate validator client

Grandine can run in three modes:

| Command | Runs | Use it when |
| --- | --- | --- |
| `grandine` | Beacon node and, if you pass validator keys, the integrated validator client | The default and simplest setup for solo stakers |
| `grandine bn` | Beacon node only | You run validators elsewhere, or you run a node for its API only |
| `grandine vc` | Validator client only, against remote beacon nodes | You want to separate keys from the node, or use several beacon nodes |

### Beacon node only

`grandine bn` runs only the beacon node: networking, fork choice, the connection to the execution
client, the database and the Beacon Node API (port 5052 by default). It has no validator client and
holds no validator keys, so it refuses validator options such as `--keystore-dir` or
`--enable-validator-api`.

Use it when the validators run in a separate validator client, `grandine vc` or another client's,
that connects to this node through the standard Beacon Node API. If that validator client runs on
another host, bind the API with `--http-address` to an address the host can reach, and firewall it
so that only the validator client can connect. Set `--suggested-fee-recipient` on the node: it is
used for validators whose validator client does not send a fee recipient. See
[Validator client](./validator_client.md#running-the-beacon-node-and-the-validator-client-separately).

`grandine bn` also suits nodes that run for their API only, for example to serve applications,
explorers or other teams' validator clients.

### Integrated validator client (default)

When you start `grandine` with validator keys (`--keystore-dir`, or Web3Signer keys), the validator
client runs inside the beacon node process. It reads duties and head information directly from the
fork choice snapshot and hands signed messages straight to the node, without going through HTTP. This
is the fastest path and has the fewest moving parts.

Without keys, plain `grandine` behaves like a beacon node. You can still add keys later through the
[Keymanager API](./keymanager_api.md) if you enable it with `--enable-validator-api`.

### Separate validator client

`grandine vc` runs only the validator client. It performs duties through the standard Beacon Node API
of one or more beacon nodes given with `--beacon-node-urls`. The beacon nodes can be Grandine or any
other consensus client. Among the healthiest nodes, Grandine sends duties to the one with the newest
head, then to the first listed. By default it publishes every duty to every node
(`--publish-to-every-node`).

`grandine bn` and `grandine vc` reject options that do not apply to them. For example, `vc` refuses
`--checkpoint-sync-url`, and `bn` refuses `--keystore-dir`. Options must come after the command:
`grandine vc --network hoodi ...`, not `grandine --network hoodi vc ...`.

> **Warning:** Never run the same validator keys in two places at once, for example in an integrated
> validator client and in a `grandine vc`, or in Grandine and another client. This gets the validator
> slashed. Never point two validator clients at the same data directory. When you move keys, stop the
> old validator client first, move the slashing protection data with it, and see
> [Validator client](./validator_client.md) and [Migrating from another client](./migration.md).

For multiple beacon nodes and failover, see [Redundancy and fallback beacon nodes](./redundancy.md).

## Startup and shutdown

On startup, the beacon node:

1. Loads the network configuration and, on testnets, the genesis state (downloaded on first start
   and stored in the data directory).
2. Loads the latest finalized state from its database. If the database is empty and
   `--checkpoint-sync-url` is set, it downloads a recent finalized state from that beacon node instead
   (see [Checkpoint sync](./checkpoint_sync.md)).
3. Connects to the execution client, joins the peer-to-peer network and starts syncing forward.

On `SIGINT` (Ctrl+C) or `SIGTERM`, Grandine stops the fork choice, logs `saving current chain before
exit…`, writes the chain to the database (logging `chain saved`) and exits. Give it time to finish; see
[Running as a service](./running_as_a_service.md).

If a component fails at run time, Grandine logs `application runtime failed` and restarts its
runtime inside the same process. Some errors, such as detected doppelgangers or a validator startup
error, stop the process instead. The process exits with status 1 on failure and 2 on a command line
error.

## Optional components

- **Slasher**: the `slasher` crate watches for slashable offenses by other validators. It is currently
  not enabled from the command line. See [Slasher](./slasher.md).
- **Builder API**: with `--builder-url`, block production can use an external builder such as
  MEV-Boost. See [Builder API and MEV](./builder_api_and_mev.md).
- **Back-sync**: with `--back-sync`, a checkpoint-synced node downloads history backward. See
  [Back-sync and archive nodes](./historical_data.md).

## Command line options

- `--eth1-rpc-urls`: no default. Engine API URLs of the execution clients; the extra URLs are fallbacks.
- `--jwt-secret`: no default. File with the hex-encoded JWT secret shared with the EL.
- `--unfinalized-states-in-memory`: default `128`. Number of the latest unfinalized slots whose states stay in memory.
- `--keystore-dir`: no default. Validator keystores for the integrated or separate validator client.
- `--beacon-node-urls` (`vc` only): required. Beacon Node API URLs the validator client works against.
- `--publish-to-every-node` (`vc` only): default `all`. Duties published to every beacon node.

See the [Command line reference](./cli_options.md) for the full list.
