# Event stream

The beacon node can push events to clients as they happen, so that tools do not have to poll. The
endpoint is `GET /eth/v1/events`, part of the standard [Beacon Node API](./beacon_node_api.md). It
uses [server-sent events](https://html.spec.whatwg.org/multipage/server-sent-events.html) (SSE):
the client opens one long-lived HTTP connection and the server writes a stream of text messages to
it.

Validator clients subscribe to `head` and `block` events to time their duties and to notice
reorganizations. Monitoring tools, block explorers and MEV software use the other topics.

## Subscribing

Pass the topics you want in the `topics` query parameter as a comma-separated list:

```bash
curl -N 'http://127.0.0.1:5052/eth/v1/events?topics=head,finalized_checkpoint'
```

`-N` turns off curl's output buffering so that each event appears as soon as it arrives. Each event
has an `event` line with the topic name and a `data` line with a JSON payload:

```text
event:head
data:{"slot":"12345678","block":"0x...","state":"0x...","epoch_transition":false,"previous_duty_dependent_root":"0x...","current_duty_dependent_root":"0x...","execution_optimistic":false}

event:finalized_checkpoint
data:{"block":"0x...","state":"0x...","epoch":"385802","execution_optimistic":false}
```

Grandine sends periodic keep-alive comments so that proxies do not close an idle connection.

A request without topics fails with `400 Bad Request`. An unknown topic name also makes the request
fail.

The stream is not affected by `--timeout`, because the timeout applies only to producing the
initial response.

## Supported topics

| Topic | When it fires | Payload |
| --- | --- | --- |
| `head` | The fork choice head changes. | `slot`, `block`, `state`, `epoch_transition`, `previous_duty_dependent_root`, `current_duty_dependent_root`, `execution_optimistic` |
| `block` | A block is imported into fork choice. | `slot`, `block`, `execution_optimistic`; after Gloas also `builder_index` and `block_hash` |
| `block_gossip` | A block received over gossip is accepted, or a block is published through the API. | `slot`, `block` |
| `chain_reorg` | The new head is not a descendant of the old head. | `slot`, `depth`, `old_head_block`, `new_head_block`, `old_head_state`, `new_head_state`, `epoch`, `execution_optimistic` |
| `finalized_checkpoint` | The finalized checkpoint advances. | `block`, `state`, `epoch`, `execution_optimistic` |
| `attestation` | An attestation that is not a single attestation (for example an aggregate) is accepted. | The attestation |
| `single_attestation` | A single attestation (the unaggregated format since Electra) is accepted. | The single attestation |
| `voluntary_exit` | A voluntary exit is accepted. | The signed exit |
| `proposer_slashing` | A proposer slashing is accepted. | The slashing |
| `attester_slashing` | An attester slashing is accepted. | The slashing |
| `bls_to_execution_change` | A BLS-to-execution credential change is accepted. | The signed change |
| `contribution_and_proof` | A sync committee contribution is accepted. | The signed contribution and proof |
| `blob_sidecar` | A blob sidecar is accepted. | `block_root`, `index`, `slot`, `kzg_commitment`, `versioned_hash` |
| `data_column_sidecar` | A data column sidecar is accepted (PeerDAS). | `block_root`, `index`, `slot`, and `kzg_commitments` when available |
| `payload_attributes` | The node prepares an execution payload for an upcoming proposal. | The proposer, parent block and payload attributes, with a `version` field |
| `head_v2` | Like `head`, with the payload status of the head (Gloas). | `version` and `data` with `slot`, `block`, `state`, `payload_status`, `epoch_transition`, `current_epoch_dependent_root`, `next_epoch_dependent_root`, `execution_optimistic` |
| `execution_payload` | An execution payload envelope is imported (Gloas). | `slot`, `builder_index`, `block_hash`, `block_root`, `execution_optimistic` |
| `execution_payload_gossip` | An execution payload envelope passes gossip validation (Gloas). | `slot`, `builder_index`, `block_hash`, `block_root` |
| `execution_payload_available` | The payload for a block becomes available (Gloas). | `slot`, `block_root` |
| `execution_payload_bid` | A builder's execution payload bid is accepted (Gloas). | The signed bid, with a `version` field |
| `payload_attestation_message` | A payload timeliness attestation is accepted (Gloas). | The message, with a `version` field |
| `proposer_preferences` | Signed proposer preferences are accepted (Gloas). | The signed preferences, with a `version` field |

Topics marked Gloas belong to the upcoming Gloas fork (enshrined proposer-builder separation) and
produce events only on networks where that fork is active. After Gloas, `head_v2` also fires a
second time for the same head when its payload becomes available.

Grandine sends the `block` event only after fork choice can return the block as part of its head,
so a client that reacts to a `block` event by querying the API sees consistent data.

The `payload_attributes` topic fires only when the next proposer is one of the validators that
registered through `POST /eth/v1/validator/prepare_beacon_proposer` (or the integrated validator
client), unless the `AlwaysPrepareExecutionPayload` runtime feature is enabled. External block
builders that need attributes for every slot should enable that feature. See
[Runtime features](./runtime_features.md).

## Buffering and slow clients

Each topic has its own in-memory buffer that holds up to `--max-events` events (default `100`).
Every subscriber reads from that buffer at its own pace.

- Events are produced only while at least one client is subscribed to the topic. A new subscriber
  receives only events that happen after it connects. There is no replay.
- If a client falls more than `--max-events` events behind on a topic, Grandine ends that client's
  stream. The client must reconnect, and it misses the events in between.

High-volume topics such as `attestation` and `single_attestation` can produce thousands of events
per slot on mainnet. If you subscribe to them, read the stream quickly, or raise the buffer:

```bash
grandine --network mainnet --max-events 10000
```

Each event topic has its own buffer of `--max-events` entries, rounded up to a power of two. The
buffers are allocated at startup, so a larger value uses more memory even when nothing subscribes.
Raise it only as far as your subscribers need.

> **Tip:** SSE clients should reconnect automatically when a stream ends. Most SSE libraries do. In
> scripts, wrap `curl` in a loop.

## Examples

Follow the chain head:

```bash
curl -sN 'http://127.0.0.1:5052/eth/v1/events?topics=head' \
  | grep --line-buffered '^data:' \
  | sed -u 's/^data://' \
  | jq -c '{slot, block}'
```

Watch for reorganizations and finality:

```bash
curl -N 'http://127.0.0.1:5052/eth/v1/events?topics=chain_reorg,finalized_checkpoint'
```

Watch for voluntary exits and slashings on the network:

```bash
curl -N 'http://127.0.0.1:5052/eth/v1/events?topics=voluntary_exit,proposer_slashing,attester_slashing'
```

Keep a stream open across disconnects:

```bash
while true; do
  curl -sN 'http://127.0.0.1:5052/eth/v1/events?topics=head,block'
  sleep 1
done
```

## Command line options

- `--max-events` (default: `100`): number of events buffered per topic; a subscriber that falls
  further behind is disconnected.
- `--http-address` (default: `127.0.0.1`) and `--http-port` (default: `5052`): where the API,
  including the event stream, listens.
- `--features AlwaysPrepareExecutionPayload` (default: off): prepare payloads, and emit
  `payload_attributes` events, for every proposer.

See [Command line reference](./cli_options.md) for all options.
