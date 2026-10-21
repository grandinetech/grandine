# Redundancy and fallback beacon nodes

A validator is only as available as the beacon node it uses. When that node restarts for an update, falls behind, loses its execution client or its peers, the validator misses duties. The safe way to add redundancy is to give one validator client several beacon nodes.

Grandine does this with the separate validator client, `grandine vc`, which accepts a list of beacon nodes in `--beacon-node-urls`. The integrated validator client always uses its own built-in beacon node. See [Validator client](./validator_client.md) for how to run the two parts separately.

## Never run duplicate validator clients

> **Warning:** Do not run two validator clients with the same keys "for redundancy", in any combination of clients, machines or data directories. Sooner or later the two sign different blocks or attestations for the same slot, which is a slashable offense. Each validator client only knows its own slashing protection database, so neither can stop the other. Slashing costs part of the stake and forces the validator out.

Redundancy belongs in the beacon node layer: several beacon nodes, one validator client. A missed attestation costs about as much as one attestation earns. A slashing costs far more. If the validator client itself has to fail over to another machine, do it by hand, following [Moving validators between machines](./key_management.md#moving-validators-between-machines), with [doppelganger protection](./doppelganger_protection.md) enabled on the new machine.

## Using several beacon nodes

List the beacon nodes, comma-separated, in order of preference:

```bash
grandine vc \
  --network mainnet \
  --beacon-node-urls http://BN-1:5052,http://BN-2:5052,http://BN-3:5052 \
  --keystore-dir /path/to/validator_keys \
  --keystore-password-file /path/to/password.txt \
  --suggested-fee-recipient 0xYOUR-EXECUTION-ADDRESS
```

The nodes can be Grandine (`grandine bn`). Other clients' beacon nodes should also work if they implement the standard Beacon Node API. Each needs its own execution client. Diversity helps: nodes on different hosts, with different execution clients, fail independently.

Every node must be on the same network. At startup the validator client asks each node for its genesis. Nodes that answer must agree on the genesis validators root, and for a predefined network it must be that network's. A node on a different network or chain stops the validator client with an error. Nodes that are down at startup are checked against the agreed genesis when they come back.

## How a node is chosen

### Health

Once per slot, the validator client polls every node and gives it one of these health levels, best first:

| Health | Meaning |
|---|---|
| Ready | Synced, its execution client online, its head verified by the execution client, and its head no more than `--max-empty-slots` slots (default `32`) behind the clock |
| Unknown | Not polled yet |
| Unusable | Reachable but syncing, optimistic, with its execution client offline, or with a stale head |
| Unreachable | The node did not answer |
| Incompatible | The node is on a different network. It is never used |

It also follows each node's head through the node's event stream (`/eth/v1/events`), and reconnects with a growing delay, up to one minute, when the stream drops.

Changes are logged:

```text
beacon node at http://BN-2:5052/ is now Unusable
beacon node at http://BN-2:5052/ is now Ready
```

### Order

For each duty, the validator client ranks the nodes by health first and by head second: among nodes of equal health, the one with the newest head goes first, and among nodes with equal heads, the one listed first in `--beacon-node-urls`. Incompatible nodes are left out. An unreachable node stays in the list as a last resort, because a failed poll does not mean the next request fails.

Requests for data then go to the nodes in that order until one succeeds: duties, attestation data, aggregates, sync committee data, validator indices and block production. A failure on one node falls back to the next one in the same slot, and is logged as a warning.

Some requests are special:

- **Block production.** A block is taken from the first node that builds on the head the other nodes agree on. A node with a different view of the head is passed over. If no node builds on that head, the first block produced is proposed anyway, because any block beats a missed slot.
- **Attesting on a new head.** When a node streams the slot's block as its new head before attestation time, the validator client attests to it without waiting for the attestation tick, and asks that node first, as it is the one known to have the block.
- **Doppelganger liveness.** Liveness is asked from every Ready node at once. A validator seen live by any of them counts as live.

### Publishing

Signed messages are published according to `--publish-to-every-node`:

- With the default, `all`, every message is sent to every usable node at the same time. Publishing succeeds as soon as one node accepts it, and the slow nodes still get it. This spreads each message into the network from several places, so a single node with poor peers does not delay it.
- A list of duties publishes only those to every node. The others are sent to one node at a time, in ranking order, until one accepts them.
- The flag with no value sends everything to the nodes one at a time, in ranking order, until one accepts it.

The duty names are `aggregates`, `attestations`, `blocks`, `payload-attestations`, `proposer-preferences`, `sync-committee-contributions` and `sync-committee-messages`:

```bash
# Broadcast attestations and blocks, send the rest to one node
--publish-to-every-node attestations,blocks

# Send everything to the first node that accepts it
--publish-to-every-node
```

Regardless of the flag:

- when blocks are sent to one node at a time, the node that produced the block is tried first, as it is known to accept it;
- a blinded block from the builder goes only to the node that produced it, because only that node can unblind it;
- beacon committee and sync committee subscriptions, proposer preparation and builder registrations are always sent to every usable node, so that whichever node serves a later duty is ready for it.

## Topologies

### One validator client, one beacon node

The basic split setup: `grandine bn` on one host and `grandine vc` on the same or another host. It has no redundancy, but the two can be restarted separately. A beacon node update stops duties only while the node restarts.

### One validator client, several beacon nodes

The recommended redundant setup. List two or three nodes. Keep the default `--publish-to-every-node all`. Update the beacon nodes one at a time, so that at least one is always Ready. Duties keep flowing while a node restarts, resyncs or loses its execution client.

```text
  EL-1           EL-2           EL-3
    |              |              |
  BN-1           BN-2           BN-3
    |              |              |
    +--------------+--------------+
                   |
          Beacon Node API (HTTP)
                   |
              grandine vc        (validator keys, slashing protection)
```

### Sentry nodes

The validator client runs on a host that is not reachable from the internet. It talks only to beacon nodes in a private network, and those nodes alone take part in the P2P network. This hides the validator's host from the network, and the redundant setup above protects against one sentry failing. Bind each node's Beacon Node API to its private address with `--http-address`, and firewall it so only the validator client can reach it.

### Remote signing with redundant beacon nodes

Combine several beacon nodes with a [Web3Signer](./web3signer.md), so that the keys live on a separate, locked-down signer. There is still exactly one validator client per key.

## What the beacon nodes need

- **HTTP API reachable by the validator client.** For a Grandine node, `--http-address` (default `127.0.0.1`) and `--http-port` (default `5052`). Never expose the Beacon Node API to the internet.
- **Liveness tracking for doppelganger protection.** A Grandine beacon node answers liveness requests only with `--track-liveness`. Start every node with it if the validator client uses `--detect-doppelgangers`.
- **A builder for MEV.** With `--use-builder` on the validator client, every node needs a builder configured, for a Grandine node with `--builder-url`. See [Builder API and MEV](./builder_api_and_mev.md).
- **Correct fee recipients.** The validator client sends each node the fee recipient of every validator that has one. Set `--suggested-fee-recipient` or per-validator fee recipients on the validator client. A validator without one is not prepared on the nodes, and each node pays its own default.

## Troubleshooting

- **`no remote beacon node is fully synced`**: no node is Ready. Duties are still attempted on the best node available, but its data may be outdated. Check each node's sync status, execution client and peers.
- **`no remote beacon node can serve duties`**: no node could be reached. Check the URLs, firewalls and `--http-address` on the nodes.
- **`beacon nodes at URL-1 and URL-2 are on different chains`**: the nodes disagree on genesis. One of them is on the wrong network.
- **`URL beacon node failed to ...`** warnings: a request failed on one node and was retried on the next one. Occasional warnings are normal. Constant ones point to a broken node.

## Command line options

- `--beacon-node-urls` (required for `vc`): comma-separated Beacon Node API URLs, in order of preference.
- `--publish-to-every-node` (default `all`): comma-separated duties to publish to every node. Without a value, everything is sent to the first node that accepts it.
- `--max-empty-slots` (default `32`): how many slots a node's head may lag behind the clock before the node counts as unusable.
- `--use-builder` (disabled): register validators with the builder behind the beacon nodes and accept builder payloads (until Gloas).
- `--detect-doppelgangers` (disabled): check, through the beacon nodes, that the keys are not live elsewhere before signing.

See [Command line reference](./cli_options.md) for the full list.
