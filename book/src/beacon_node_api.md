# Beacon Node API

The Beacon Node API is the standard HTTP REST interface of an Ethereum consensus client. It is
defined by the [Ethereum Beacon APIs specification](https://ethereum.github.io/beacon-APIs/).
Validator clients, staking tools, block explorers, monitoring scripts and tools such as
[Vouch](https://github.com/attestantio/vouch) use it to read chain data and to submit blocks,
attestations and other messages.

Grandine serves this API from the beacon node. You need it when:

- you run a separate validator client (Grandine `grandine vc` or another client's VC) against
  Grandine,
- you want to check the node's sync status, peers or chain head from scripts or monitoring,
- you connect third-party tools that speak the Beacon API.

The integrated validator client (plain `grandine` with validator keys) talks to the beacon node
inside the same process and does not need the HTTP API. See
[How Grandine works](./architecture.md) for the difference between the two setups.

Grandine-specific endpoints that are not part of the specification are described in
[Grandine-specific endpoints](./grandine_api.md). The server-sent event stream at
`/eth/v1/events` has its own page: [Event stream](./event_stream.md).

## Enabling and binding the API

The API is enabled by default whenever Grandine runs a beacon node, that is, with plain
`grandine` and with `grandine bn`. It listens on `127.0.0.1:5052`, so by default only programs on
the same machine can reach it. A standalone validator client started with `grandine vc` does not
run a beacon node and does not serve this API. It has its own
[Keymanager API](./keymanager_api.md) instead.

When the server starts, Grandine logs the address it listens on. Check that the API is up:

```bash
curl -s http://127.0.0.1:5052/eth/v1/node/version
```

```json
{"data":{"version":"Grandine/VERSION-COMMIT/ARCH-OS"}}
```

To change the listen address or port:

```bash
grandine \
  --network mainnet \
  --eth1-rpc-urls http://EL-HOST:8551 \
  --jwt-secret /path/to/jwt.hex \
  --http-address 127.0.0.1 \
  --http-port 5052
```

To listen on all IPv4 interfaces, for example so that a validator client on another machine in
your private network can connect, use `--http-address 0.0.0.0`. Only do this behind a firewall.
See [Security exposure](#security-exposure).

To run a beacon node without the HTTP API, pass `--disable-http-api`. The integrated validator
client keeps working, because it does not use HTTP.

### Docker

Inside a container the API must listen on `0.0.0.0`, otherwise Docker cannot forward the port.
Publish the port on the host's loopback interface so it stays private to the host:

```bash
docker run \
  -p 9000:9000/tcp \
  -p 9000:9000/udp \
  -p 9001:9001/udp \
  -p 127.0.0.1:5052:5052/tcp \
  -v $HOME/.grandine:/root/.grandine \
  -v /path/to/jwt.hex:/root/.grandine/jwt.hex \
  sifrai/grandine:stable \
  --network mainnet \
  --checkpoint-sync-url CHECKPOINT-SYNC-URL \
  --eth1-rpc-urls http://EL-HOST:8551 \
  --jwt-secret /root/.grandine/jwt.hex \
  --http-address 0.0.0.0
```

The image's entry point is the `grandine` binary, so the options follow the image name directly.

## CORS

Browsers only let a web page call the API if the API answers with a matching
`Access-Control-Allow-Origin` header. By default Grandine allows a single origin: its own
listening URL, for example `http://127.0.0.1:5052`. Web dashboards served from other origins are
blocked by the browser.

Use `--http-allowed-origins` to allow other origins. It takes a comma-separated list:

```bash
grandine \
  --network mainnet \
  --http-allowed-origins http://localhost:3000,https://dashboard.example.com
```

The value `*` allows any origin. If you pass `*` together with other values, Grandine uses only
the wildcard and logs a warning.

> **Note:** CORS is a browser protection only. It does not stop `curl` or any other program that can
> reach the port. Use firewall rules to control who can connect.

## Security exposure

The Beacon Node API has no authentication. Anyone who can reach the port can:

- read everything the node knows, including which validators it serves (through duties and
  subscriptions),
- submit blocks, attestations, exits and other messages,
- request expensive operations such as full beacon states, which costs CPU, memory and bandwidth,
- change runtime behavior through the non-standard endpoints, such as `PATCH /features` and the log
  level endpoints (see [Grandine-specific endpoints](./grandine_api.md)).

Follow these rules:

- Keep the default `--http-address 127.0.0.1` unless another machine must connect.
- If a remote validator client needs access, allow only that machine with a firewall, or connect it
  over an SSH tunnel or a VPN such as WireGuard.
- Never expose port 5052 to the internet. If you must serve the API publicly, put a reverse proxy
  in front of it that adds TLS, authentication and rate limits, and that blocks the non-standard
  and debug endpoints.
- Grandine does not terminate TLS itself. Use a reverse proxy if you need HTTPS.

See [Security best practices](./security.md) for the wider picture.

## Timeouts

Each request must produce a response within `--timeout` milliseconds. The default is `1000000`
(1000 seconds). When a request takes longer, Grandine aborts it and answers with
`408 Request Timeout`. The timeout applies to producing the response, so long-lived
[event streams](./event_stream.md) are not cut off by it.

Grandine does not limit the size of request bodies.

## Response formats: JSON and SSZ

All endpoints return JSON by default. Some endpoints can also return SSZ, the compact binary
encoding used on the Ethereum peer-to-peer network. SSZ responses are smaller and faster to
produce and parse, which matters for large objects such as beacon states and blocks.

To ask for SSZ, include `application/octet-stream` in the `Accept` header:

```bash
curl -s -H 'Accept: application/octet-stream' \
  -o state.ssz \
  http://127.0.0.1:5052/eth/v2/debug/beacon/states/finalized
```

If the `Accept` header lists `application/octet-stream` anywhere, Grandine returns SSZ. Otherwise it
returns JSON. An SSZ response body is the bare `data` object. Metadata that JSON carries in the body,
such as `version`, is still sent in response headers.

These endpoints can return SSZ:

| Endpoint | Content |
| --- | --- |
| `GET /eth/v2/beacon/blocks/{block_id}` | Signed block |
| `GET /eth/v1/beacon/blinded_blocks/{block_id}` | Signed blinded block |
| `GET /eth/v1/beacon/blob_sidecars/{block_id}` | Blob sidecars |
| `GET /eth/v1/beacon/blobs/{block_id}` | Blobs |
| `GET /eth/v1/beacon/execution_payload_envelopes/{block_id}` | Execution payload envelope (Gloas) |
| `GET /eth/v1/beacon/pool/payload_attestations` | Payload attestations (Gloas) |
| `GET /eth/v1/beacon/states/{state_id}/pending_consolidations` | Pending consolidations |
| `GET /eth/v1/beacon/states/{state_id}/pending_deposits` | Pending deposits |
| `GET /eth/v1/beacon/states/{state_id}/pending_partial_withdrawals` | Pending partial withdrawals |
| `GET /eth/v1/beacon/states/{state_id}/proposer_lookahead` | Proposer lookahead |
| `GET /eth/v1/beacon/states/{state_id}/ptc` | Payload timeliness committee (Gloas) |
| `POST /eth/v1/beacon/states/{state_id}/validator_balances` | Validator balances |
| `POST /eth/v1/beacon/states/{state_id}/validator_identities` | Validator identities |
| `GET /eth/v1/debug/beacon/data_column_sidecars/{block_id}` | Data column sidecars |
| `GET /eth/v2/debug/beacon/states/{state_id}` | Full beacon state |
| `GET /eth/v1/validator/attestation_data` | Attestation data |
| `GET /eth/v2/validator/aggregate_attestation` | Aggregate attestation |
| `GET /eth/v1/validator/payload_attestation_data` | Payload attestation data (Gloas) |
| `GET /eth/v1/validator/execution_payload_envelopes/{slot}/{beacon_block_root}` | Execution payload envelope (Gloas) |
| `GET /eth/v2/validator/blocks/{slot}` | Unsigned block |
| `GET /eth/v3/validator/blocks/{slot}` | Unsigned block (full or blinded) |
| `POST /eth/v4/validator/blocks/{slot}` | Unsigned block (Gloas) |

### SSZ request bodies

These endpoints accept a request body in SSZ when you send `Content-Type: application/octet-stream`:

- `POST /eth/v1/beacon/blocks` and `POST /eth/v2/beacon/blocks`
- `POST /eth/v1/beacon/blinded_blocks` and `POST /eth/v2/beacon/blinded_blocks`
- `POST /eth/v2/beacon/pool/attestations`
- `POST /eth/v1/validator/aggregate_and_proofs` and `POST /eth/v2/validator/aggregate_and_proofs`
- `POST /eth/v1/beacon/pool/payload_attestations`
- `POST /eth/v1/beacon/execution_payload_bids`
- `POST /eth/v1/beacon/execution_payload_envelopes`
- `POST /eth/v1/validator/proposer_preferences`
- `POST /eth/v4/validator/blocks/{slot}`

All other request bodies must be JSON with `Content-Type: application/json`.

> **Tip:** Some validator clients send JSON requests without a `Content-Type` header. If yours does
> and its requests are rejected, enable the `PatchHttpContentType` runtime feature, which fills in
> `application/json` when the header is missing. See [Runtime features](./runtime_features.md).

## The Eth-Consensus-Version header

Objects such as blocks and states have a different shape in each fork. The header
`Eth-Consensus-Version` names the fork in lowercase: `phase0`, `altair`, `bellatrix`, `capella`,
`deneb`, `electra`, `fulu` or `gloas`.

- **Responses.** Endpoints that return fork-specific objects set `Eth-Consensus-Version` and also
  include a `version` field in JSON bodies. Block production endpoints also set
  `Eth-Consensus-Block-Value`, `Eth-Execution-Payload-Blinded` and `Eth-Execution-Payload-Value`.
- **Requests.** When you publish an SSZ body, you must send `Eth-Consensus-Version` so that Grandine
  knows how to decode it. The v2 endpoints (`POST /eth/v2/beacon/blocks`,
  `POST /eth/v2/beacon/blinded_blocks`, `POST /eth/v2/beacon/pool/attestations`,
  `POST /eth/v2/validator/aggregate_and_proofs`) require the header for JSON bodies too. The v1
  block publishing endpoints accept JSON without it.

## Responses during sync

`GET /eth/v1/node/health` returns `200 OK` when the node is synced and `206 Partial Content` while
it is syncing.

Most validator duty endpoints under `/eth/v1/validator/...` and `/eth/v2/validator/...` answer
`503 Service Unavailable` while the node is syncing, as the specification requires. Proposer duties,
`prepare_beacon_proposer`, and the v3 and v4 block production endpoints are served without this
check.

Responses about chain data include `execution_optimistic` and, where it applies, `finalized`. An
optimistic response means the execution client has not yet verified the payloads involved. Treat
such data as provisional.

## Supported endpoints

Grandine implements the endpoints below, grouped as in the specification. Path parameters:

- `{state_id}`: `head`, `genesis`, `finalized`, `justified`, a slot number, or a hex state root.
- `{block_id}`: `head`, `genesis`, `finalized`, a slot number, or a hex block root.
- `{validator_id}`: a validator index or a hex public key.

Endpoints marked Gloas belong to the upcoming Gloas fork (enshrined proposer-builder separation).
They are only useful on networks where that fork is active.

### Beacon

| Method | Path |
| --- | --- |
| GET | `/eth/v1/beacon/genesis` |
| GET | `/eth/v1/beacon/states/{state_id}/root` |
| GET | `/eth/v1/beacon/states/{state_id}/fork` |
| GET | `/eth/v1/beacon/states/{state_id}/finality_checkpoints` |
| GET, POST | `/eth/v1/beacon/states/{state_id}/validators` |
| GET | `/eth/v1/beacon/states/{state_id}/validators/{validator_id}` |
| POST | `/eth/v1/beacon/states/{state_id}/validator_identities` |
| GET, POST | `/eth/v1/beacon/states/{state_id}/validator_balances` |
| GET | `/eth/v1/beacon/states/{state_id}/committees` |
| GET | `/eth/v1/beacon/states/{state_id}/sync_committees` |
| GET | `/eth/v1/beacon/states/{state_id}/randao` |
| GET | `/eth/v1/beacon/states/{state_id}/pending_deposits` |
| GET | `/eth/v1/beacon/states/{state_id}/pending_partial_withdrawals` |
| GET | `/eth/v1/beacon/states/{state_id}/pending_consolidations` |
| GET | `/eth/v1/beacon/states/{state_id}/proposer_lookahead` |
| GET | `/eth/v1/beacon/states/{state_id}/ptc` (Gloas) |
| GET | `/eth/v1/beacon/headers` |
| GET | `/eth/v1/beacon/headers/{block_id}` |
| POST | `/eth/v1/beacon/blocks` |
| POST | `/eth/v2/beacon/blocks` |
| GET | `/eth/v2/beacon/blocks/{block_id}` |
| GET | `/eth/v1/beacon/blocks/{block_id}/root` |
| GET | `/eth/v1/beacon/blocks/{block_id}/attestations` |
| GET | `/eth/v2/beacon/blocks/{block_id}/attestations` |
| GET | `/eth/v1/beacon/blinded_blocks/{block_id}` |
| POST | `/eth/v1/beacon/blinded_blocks` |
| POST | `/eth/v2/beacon/blinded_blocks` |
| GET | `/eth/v1/beacon/blob_sidecars/{block_id}` |
| GET | `/eth/v1/beacon/blobs/{block_id}` |
| GET | `/eth/v1/beacon/execution_payload_envelopes/{block_id}` (Gloas) |
| POST | `/eth/v1/beacon/execution_payload_envelopes` (Gloas) |
| POST | `/eth/v1/beacon/execution_payload_bids` (Gloas) |
| GET, POST | `/eth/v1/beacon/pool/attestations` |
| GET, POST | `/eth/v2/beacon/pool/attestations` |
| GET, POST | `/eth/v1/beacon/pool/attester_slashings` |
| GET, POST | `/eth/v2/beacon/pool/attester_slashings` |
| GET, POST | `/eth/v1/beacon/pool/proposer_slashings` |
| GET, POST | `/eth/v1/beacon/pool/voluntary_exits` |
| GET, POST | `/eth/v1/beacon/pool/bls_to_execution_changes` |
| POST | `/eth/v1/beacon/pool/sync_committees` |
| GET, POST | `/eth/v1/beacon/pool/payload_attestations` (Gloas) |

### Rewards

| Method | Path |
| --- | --- |
| GET | `/eth/v1/beacon/rewards/blocks/{block_id}` |
| POST | `/eth/v1/beacon/rewards/sync_committee/{block_id}` |

The attestation rewards endpoint (`POST /eth/v1/beacon/rewards/attestations/{epoch}`) is not
implemented. For per-validator reward and penalty breakdowns, see the Grandine-specific
`/validator/statistics` endpoint in [Grandine-specific endpoints](./grandine_api.md).

### Builder

| Method | Path |
| --- | --- |
| GET | `/eth/v1/builder/states/{state_id}/expected_withdrawals` |

### Config

| Method | Path |
| --- | --- |
| GET | `/eth/v1/config/spec` |
| GET | `/eth/v1/config/fork_schedule` |
| GET | `/eth/v1/config/deposit_contract` |

### Debug

| Method | Path |
| --- | --- |
| GET | `/eth/v2/debug/beacon/states/{state_id}` |
| GET | `/eth/v2/debug/beacon/heads` |
| GET | `/eth/v1/debug/fork_choice` |
| GET | `/eth/v1/debug/beacon/data_column_sidecars/{block_id}` |

Full states are large. On mainnet a JSON state is hundreds of megabytes. Prefer SSZ, and do not
poll this endpoint.

Grandine also serves two non-standard endpoints under `/eth/v2/debug/tracing/` for changing the log
and trace levels at runtime. They are described in
[Grandine-specific endpoints](./grandine_api.md#log-and-trace-levels).

### Events

| Method | Path |
| --- | --- |
| GET | `/eth/v1/events` |

See [Event stream](./event_stream.md).

### Node

| Method | Path |
| --- | --- |
| GET | `/eth/v1/node/identity` |
| GET | `/eth/v1/node/peers` |
| GET | `/eth/v1/node/peers/{peer_id}` |
| GET | `/eth/v1/node/peer_count` |
| GET | `/eth/v1/node/version` |
| GET | `/eth/v2/node/version` |
| GET | `/eth/v1/node/syncing` |
| GET | `/eth/v1/node/health` |

### Validator

| Method | Path | Sync check |
| --- | --- | --- |
| GET | `/eth/v1/validator/duties/proposer/{epoch}` | no |
| GET | `/eth/v2/validator/duties/proposer/{epoch}` | yes |
| POST | `/eth/v1/validator/duties/attester/{epoch}` | yes |
| POST | `/eth/v1/validator/duties/sync/{epoch}` | yes |
| POST | `/eth/v1/validator/duties/ptc/{epoch}` (Gloas) | yes |
| GET | `/eth/v2/validator/blocks/{slot}` | yes |
| GET | `/eth/v3/validator/blocks/{slot}` | no |
| POST | `/eth/v4/validator/blocks/{slot}` (Gloas) | no |
| GET | `/eth/v1/validator/blinded_blocks/{slot}` | yes |
| GET | `/eth/v1/validator/execution_payload_envelopes/{slot}/{beacon_block_root}` (Gloas) | no |
| GET | `/eth/v1/validator/attestation_data` | yes |
| GET | `/eth/v1/validator/aggregate_attestation` | yes |
| GET | `/eth/v2/validator/aggregate_attestation` | yes |
| POST | `/eth/v1/validator/aggregate_and_proofs` | yes |
| POST | `/eth/v2/validator/aggregate_and_proofs` | yes |
| POST | `/eth/v1/validator/beacon_committee_subscriptions` | yes |
| POST | `/eth/v1/validator/sync_committee_subscriptions` | yes |
| GET | `/eth/v1/validator/sync_committee_contribution` | yes |
| POST | `/eth/v1/validator/contribution_and_proofs` | yes |
| POST | `/eth/v1/validator/prepare_beacon_proposer` | no |
| POST | `/eth/v1/validator/register_validator` | yes |
| POST | `/eth/v1/validator/proposer_preferences` (Gloas) | yes |
| POST | `/eth/v1/validator/liveness/{epoch}` | yes |
| GET | `/eth/v1/validator/payload_attestation_data` (Gloas) | yes |

"Sync check: yes" means the endpoint returns `503` while the node is syncing.

`POST /eth/v1/validator/liveness/{epoch}` needs liveness tracking, which is off by default. Start
the node with `--track-liveness` to enable it. Validator clients use this endpoint for
[doppelganger protection](./doppelganger_protection.md).

### Not supported

- **Light client endpoints** (`/eth/v1/beacon/light_client/...`) are not served. Grandine does not
  act as a light client server.
- **Keymanager API** endpoints (`/eth/v1/keystores`, `/eth/v1/remotekeys` and the per-validator fee
  recipient, gas limit and graffiti endpoints) are not part of this server. They are served by the
  validator API on a separate port with token authentication. See
  [Keymanager API](./keymanager_api.md).
- **Selection endpoints for distributed validators**
  (`POST /eth/v1/validator/beacon_committee_selections` and
  `POST /eth/v1/validator/sync_committee_selections`) are routed but return `501 Not Implemented`.
- **Prometheus metrics** are served by a separate server, not on port 5052. See
  [Metrics](./metrics.md).

## Runtime features that affect the API

Some behavior is controlled by runtime features, which you turn on with `--features`. See
[Runtime features](./runtime_features.md) for the full list.

| Feature | Effect |
| --- | --- |
| `ServeCostlyEndpoints` | Enables the expensive Grandine-specific endpoints `/validator/statistics`, `/validator/registered` and `/validator/owned`. Without it they return `403 Forbidden`. |
| `ServeLeakyEndpoints` | Enables `/system/stats`, which reveals host resource usage. Without it the endpoint returns `403 Forbidden`. |
| `LogHttpRequests` | Logs every request and response line, including the client address and latency. |
| `LogHttpHeaders` | Logs request headers. |
| `LogHttpBodies` | Logs request and response bodies, except for full states and event streams. |
| `PatchHttpContentType` | Treats requests without `Content-Type` as JSON. |

All standard endpoints are always served. The features above only gate the non-standard
endpoints and add logging.

```bash
grandine --network mainnet --features LogHttpRequests,ServeCostlyEndpoints
```

> **Note:** `LogHttpBodies` and `PatchHttpContentType` take effect only if they are enabled when the
> HTTP server starts, because Grandine adds their middleware while building the server. Turning them
> on later through `PATCH /features` has no effect on the API. The other features in this table are
> checked on every request and can be toggled at runtime.

## Examples

The examples assume the API is on `127.0.0.1:5052`. Pipe the output through `jq` for readable
JSON.

### Sync status

```bash
curl -s http://127.0.0.1:5052/eth/v1/node/syncing | jq
```

```json
{
  "data": {
    "head_slot": "12345678",
    "sync_distance": "0",
    "is_syncing": false,
    "is_optimistic": false,
    "el_offline": false
  }
}
```

`is_syncing: false` with a small `sync_distance` means the node follows the chain head.
`is_optimistic: true` means the execution client has not verified the head yet. `el_offline: true`
means the beacon node cannot reach the execution client. See
[Connecting an execution client](./execution_client.md).

### Health check

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:5052/eth/v1/node/health
```

`200` means synced, `206` means syncing. Load balancers and container health checks can use this
endpoint directly.

### Head block

```bash
curl -s http://127.0.0.1:5052/eth/v1/beacon/headers/head | jq '.data.header.message'
```

The `slot` field should increase by one every 12 seconds on mainnet.

### Finality checkpoints

```bash
curl -s http://127.0.0.1:5052/eth/v1/beacon/states/head/finality_checkpoints | jq
```

On a healthy network the finalized epoch is two epochs behind the current epoch. If it falls further
behind, the network is not finalizing.

You can also use this endpoint to cross-check a [checkpoint sync](./checkpoint_sync.md): compare the
finalized root with that of another trusted node or a block explorer.

### Validator status

By index or by public key:

```bash
curl -s http://127.0.0.1:5052/eth/v1/beacon/states/head/validators/VALIDATOR-INDEX-OR-PUBKEY | jq
```

The `status` field shows where the validator is in its lifecycle, for example `pending_queued`,
`active_ongoing`, `active_exiting`, `exited_unslashed` or `withdrawal_done`.

For several validators at once:

```bash
curl -s -X POST http://127.0.0.1:5052/eth/v1/beacon/states/head/validators \
  -H 'Content-Type: application/json' \
  -d '{"ids": ["VALIDATOR-INDEX-1", "VALIDATOR-INDEX-2"]}' | jq
```

### Peers

```bash
curl -s http://127.0.0.1:5052/eth/v1/node/peer_count | jq
curl -s http://127.0.0.1:5052/eth/v1/node/peers | jq '.meta.count'
```

A low peer count usually points to a port forwarding problem. See
[Networking and peers](./networking.md).

### Node identity

```bash
curl -s http://127.0.0.1:5052/eth/v1/node/identity | jq '.data | {peer_id, enr}'
```

Use the ENR to add this node as a static or trusted peer elsewhere.

### Proposer duties for the current epoch

```bash
EPOCH=$(( $(curl -s http://127.0.0.1:5052/eth/v1/beacon/headers/head \
  | jq -r '.data.header.message.slot') / 32 ))
curl -s http://127.0.0.1:5052/eth/v1/validator/duties/proposer/$EPOCH | jq
```

### Download the finalized state in SSZ

```bash
curl -s -H 'Accept: application/octet-stream' \
  -o finalized_state.ssz \
  http://127.0.0.1:5052/eth/v2/debug/beacon/states/finalized
```

## Command line options

These options apply to the beacon node (`grandine` and `grandine bn`):

- `--http-address` (default: `127.0.0.1`): address the API listens on.
- `--http-port` (default: `5052`): port the API listens on.
- `--http-allowed-origins` (default: the API's own listening URL): comma-separated list of allowed
  CORS origins; `*` allows any origin.
- `--timeout` (default: `1000000`): request timeout in milliseconds.
- `--disable-http-api` (default: off): run the beacon node without the HTTP API.
- `--max-events` (default: `100`): number of events buffered per topic for `/eth/v1/events`.
- `--track-liveness` (default: off): enable liveness tracking for
  `/eth/v1/validator/liveness/{epoch}`.
- `--features` (default: none): comma-separated runtime features, such as `ServeCostlyEndpoints`.

See [Command line reference](./cli_options.md) for all options.
