# grandine-builder

Standalone staked builder client for [Gloas](https://github.com/ethereum/consensus-specs/blob/master/specs/gloas/builder.md) (ePBS).

It runs as its own process next to a beacon node and an execution engine: it follows the chain over the beacon node's REST API and SSE stream, builds execution payloads through the Engine API, and signs bids and envelopes locally with its own keystores.

## Build

```sh
cargo build --release --bin grandine-builder -p builder
# or
make builder
```

## Run

```sh
grandine-builder \
    --beacon-node http://localhost:5052 \
    --execution-engine http://localhost:8551 \
    --jwt-secret /path/to/jwt.hex \
    --builder-keystore-dir /path/to/keystores \
    --builder-keystore-password-file /path/to/password.txt \
    --builder-fee-recipient 0x0000000000000000000000000000000000000000
```

Keystores are EIP-2335 files. Use `--builder-keystore-password-dir` instead of
`--builder-keystore-password-file` for per-keystore passwords matched by file name.
See `grandine-builder --help` for the full list of options.

The chain config, genesis and preset are fetched from the beacon node at startup, so
the builder does not take a network argument.

## How it works

Per slot, driven by the beacon node's SSE stream:

1. `payload_attributes` starts a payload build on the execution engine, with the configured
   `--builder-fee-recipient` and the proposer's `target_gas_limit` from `proposer_preferences`.
2. Late in the slot the payload is fetched from the engine and published as a signed
   `ExecutionPayloadBid` — once per builder key we control that is in the registry with enough
   balance to cover the bid. The bid pays the proposer the payload's full MEV.
3. `head` tells us whether one of our bids won. If it did, and we are still before
   `PAYLOAD_DUE_BPS` into the slot, the payload envelope is revealed. Past that deadline the
   reveal is skipped: the PTC would vote the payload absent anyway.

## Beacon node endpoints

| Endpoint | Use |
| --- | --- |
| `GET /eth/v1/beacon/genesis` | genesis time and validators root |
| `GET /eth/v1/config/spec` | chain config and preset |
| `GET /eth/v2/beacon/blocks/{block_id}` | head block (SSZ) |
| `POST /eth/v1/beacon/states/{state_id}/builders` | builder registry indices and balances |
| `GET /eth/v1/beacon/states/{state_id}/finality_checkpoints` | safe/finalized hashes for forkchoice updates |
| `POST /eth/v1/beacon/execution_payload_bids` | publish bids |
| `POST /eth/v1/beacon/execution_payload_envelopes` | publish envelopes |
| `GET /eth/v1/events` | `head`, `payload_attributes`, `proposer_preferences` |
