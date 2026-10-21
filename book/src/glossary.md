# Glossary

Terms used in this book, in alphabetical order. Where Grandine has an option or page for a term, it
is linked.

**Aggregate attestation**: Many validators' attestations for the same data, combined into one message with a single aggregate
BLS signature. Selected validators (aggregators) publish them.

**Anchor**: The block and state a beacon node starts from: the genesis state, or a finalized checkpoint loaded
by [checkpoint sync](./checkpoint_sync.md).

**Archive node**: A beacon node that keeps the full history: all blocks, blobs, and states at regular intervals.
Grandine runs as one with `--archive-storage` and `--back-sync`. See
[Back-sync and archive nodes](./historical_data.md).

**Attestation**: A validator's vote on the head of the chain and on the source and target checkpoints. Every active
validator attests once per epoch.

**Back-sync (backfill)**: Downloading blocks older than the anchor after a checkpoint sync. Enabled with `--back-sync`.

**Beacon chain**: The proof-of-stake consensus chain of Ethereum, run by consensus clients.

**Beacon Node API**: The standard HTTP API of a beacon node, used by validator clients and tools. Grandine serves it on
port `5052` by default. See [Beacon Node API](./beacon_node_api.md).

**Beacon node (BN)**: The part of a consensus client that follows the beacon chain, talks to peers, and drives the
execution client. In Grandine it runs with `grandine` or `grandine bn`.

**Blob (blob sidecar)**: Data attached to a block for layer 2 rollups (EIP-4844). Blobs are kept only for a limited window,
not forever.

**Blockprint graffiti**: A short client identifier that Grandine appends to block graffiti when there is room. Turned off
with `--disable-blockprint-graffiti`.

**BLS**: The signature scheme (BLS12-381) that validators use. BLS signatures can be aggregated.

**Builder (block builder)**: A third party that builds execution payloads and bids for the right to have them proposed. Reached
through the Builder API, usually via MEV-Boost. See [Builder API and MEV](./builder_api_and_mev.md).

**Builder boost factor**: How Grandine weighs a builder's bid against the locally built payload: the bid's value is scaled by this percentage first. Set with
`--default-builder-boost-factor` (default `100`).

**Checkpoint sync**: Starting a beacon node from a recent finalized state downloaded from a trusted beacon node, instead
of from genesis. Enabled with `--checkpoint-sync-url`.

**Circuit breaker**: Grandine's rule to stop using the builder and build blocks locally when too many blocks were missed
recently. Tuned with `--builder-max-skipped-slots` and `--builder-max-skipped-slots-per-epoch`.

**Consensus client (CL)**: Software that runs the beacon chain: a beacon node and a validator client. Grandine is a consensus
client.

**Custody group**: Under PeerDAS, a group of data columns that a node is responsible for storing and serving. See
[PeerDAS](./peerdas.md).

**Data column sidecar**: Under PeerDAS, one column of the erasure-coded blob data of a block. Nodes custody and sample
columns instead of downloading every blob.

**Deposit contract**: The execution-layer contract that receives validator deposits.

**discv5**: The UDP-based peer discovery protocol used by Ethereum consensus clients. Grandine uses UDP port
`9000` for it by default.

**Doppelganger protection**: A check that waits and watches the network before a validator starts signing, to detect the same
keys running elsewhere. Enabled with `--detect-doppelgangers`. See
[Doppelganger protection](./doppelganger_protection.md).

**EIP-2335 keystore**: The standard password-encrypted JSON file format for validator signing keys.

**EIP-3076 (interchange format)**: The standard JSON format for exporting and importing slashing protection data between clients. See
[Slashing protection](./slashing_protection.md).

**Engine API**: The authenticated JSON-RPC API between a consensus client and an execution client, usually on port
`8551`. Grandine connects to it with `--eth1-rpc-urls` and `--jwt-secret`.

**ENR (Ethereum Node Record)**: A signed record with a node's identity, IP addresses and ports, shared through discovery.

**Epoch**: 32 slots (6.4 minutes on mainnet). Duties, rewards and finality are organized by epoch.

**Execution client (EL)**: Software that runs the execution layer: transactions, state and the EVM. Examples are Geth,
Nethermind, Besu, Erigon and Reth. See [Connecting an execution client](./execution_client.md).

**Fee recipient**: The execution address that receives priority fees and MEV payments from blocks a validator proposes.
Set with `--suggested-fee-recipient` or per validator. See
[Fee recipient, graffiti and gas limit](./fee_recipient.md).

**Finality**: The point after which a block cannot be reverted without at least a third of all stake being
slashed. Normally reached after about two epochs.

**Fork choice**: The rule a beacon node uses to choose the head of the chain among competing blocks. Grandine keeps
the fork choice store in memory.

**Gas limit**: The maximum gas an execution block may use. Validators signal their preferred limit with
`--default-gas-limit` or per validator.

**Genesis state**: The first state of a beacon chain. For custom networks it is usually given as `genesis.ssz`.

**Genesis validators root**: A hash that identifies a beacon chain. Grandine uses it to check that remote beacon nodes and
slashing protection data belong to the right network.

**Graffiti**: Up to 32 bytes of free text that a proposer puts in a block. Set with `--graffiti`.

**JWT secret**: A shared 32-byte hex secret that authenticates the consensus client to the execution client's
Engine API.

**Keymanager API**: The standard HTTP API for listing, importing and deleting validator keys and remote keys at runtime.
Grandine serves it through the validator API (`--enable-validator-api`). See
[Keymanager API](./keymanager_api.md).

**KZG commitment**: A cryptographic commitment to blob data that lets nodes verify blobs and data columns. Grandine
selects a KZG library with `--kzg-backend`.

**libmdbx**: The embedded key-value database Grandine uses for its beacon database.

**libp2p**: The peer-to-peer networking stack used for gossip and requests between beacon nodes. Grandine uses
TCP port `9000` and QUIC on UDP port `9001` by default.

**MEV (maximal extractable value)**: Extra value a block producer can capture by ordering transactions. Validators usually access it
through MEV-Boost and relays.

**MEV-Boost**: Middleware that connects a beacon node to builder relays through the Builder API. Grandine connects
to it with `--builder-url`.

**Optimistic head**: A head block whose execution payload the execution client has not validated yet, typically while
the execution client syncs. Validators do not perform duties on an optimistic head.

**Peer ID**: A libp2p node identity derived from the node's private key, stored in `network/key`.

**PeerDAS**: Peer data availability sampling (EIP-7594, Fulu). Blob data is split into columns that are spread
across nodes. See [PeerDAS](./peerdas.md).

**Preset**: A set of constants fixed at compile time, such as slots per epoch. Networks use the `mainnet`
preset; some test networks use `minimal`.

**Prune mode**: Grandine's storage mode that keeps only a single checkpoint state and block. Enabled with
`--prune-storage`.

**QUIC**: A UDP-based transport that Grandine uses in libp2p as a fallback to TCP.

**Relay**: A service between builders and proposers that holds builder blocks in escrow until the proposer
signs the header.

**Slashing**: A penalty and forced exit for a validator that signs conflicting messages (a double proposal, a
double vote, or a surround vote).

**Slashing protection**: A local database of signed messages that a validator client checks before signing, to refuse
anything slashable. Grandine stores it in `validator/slashing_protection.sqlite`.

**Slot**: 12 seconds on mainnet. Each slot has one proposer and may contain one block.

**Subnet**: A gossip topic shard. Attestations, sync committee messages and data columns are split across
subnets so that each node handles only part of the traffic.

**Supernode**: A node that custodies all data columns (`--supernode`). A semi-supernode custodies half of them
(`--semi-supernode`).

**Sync committee**: A group of 512 validators that sign the head every slot for light clients. Members change every 256
epochs (about 27 hours).

**Validator API**: Grandine's validator client HTTP API, on port `5055` by default when enabled. It serves the
Keymanager API.

**Validator client (VC)**: The part of a consensus client that holds validator keys and performs duties: attesting,
proposing and aggregating. In Grandine it runs inside `grandine` or as `grandine vc`. See
[Validator client](./validator_client.md).

**validators.yml**: Grandine's file of validator definitions and per-validator settings, in the `validator` directory.
See [Validator definitions](./validator_definitions.md).

**Web3Signer**: A remote signing service that keeps validator keys outside the validator client. See
[Web3Signer](./web3signer.md).

**Weak subjectivity**: The property that a new node needs a recent trusted checkpoint to join the chain safely. Checkpoint
sync provides it.

**Withdrawal credentials**: The part of a validator's record that says where withdrawn funds go. `0x01` and `0x02` credentials
point to an execution address. See
[Voluntary exits, withdrawals and consolidations](./voluntary_exit.md).

