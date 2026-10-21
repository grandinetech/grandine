# Connecting an execution client

Since the Merge, every Ethereum node is a pair: a consensus client such as Grandine and an
execution client such as Geth, Nethermind, Besu, Erigon or Reth. The execution client holds the
account state and executes transactions. Grandine drives it through the authenticated Engine API:
it sends every new execution payload for validation, tells the execution client which block is the
head, and asks it to build payloads when a local validator proposes a block.

A beacon node without an execution client cannot verify execution payloads, so it cannot follow
the chain safely or serve validators. Run both clients on the same network, and keep both up to
date.

> **Tip:** For the fastest communication between the two layers, Grandine can also run embedded in
> Nethermind. It then calls Nethermind's Engine API directly, with no HTTP, JWT or JSON in between.
> See [Grandine embedded in Nethermind](./nethermind_integration.md).

## Step 1: Create a JWT secret

The Engine API is protected by a shared secret. Both clients read the same file and use it to sign
and check JSON Web Tokens (JWT). Create a random 32-byte secret in hex:

```bash
sudo mkdir -p /var/lib/ethereum
openssl rand -hex 32 | tr -d '\n' | sudo tee /var/lib/ethereum/jwt.hex > /dev/null
sudo chmod 640 /var/lib/ethereum/jwt.hex
```

Grandine accepts the hex string with or without a `0x` prefix and with or without a trailing
newline. The secret must be at least 32 bytes long, otherwise Grandine fails with `JWT secret must
be at least 32 bytes`.

> **Tip:** Some execution clients create the file themselves on first start if it does not exist.
> Creating it yourself makes the setup explicit and lets you choose the path and permissions.

## Step 2: Start the execution client

Enable the Engine API (port 8551 by convention) and point it at the secret. For Geth:

```bash
geth --mainnet \
  --datadir /var/lib/geth \
  --authrpc.addr 127.0.0.1 \
  --authrpc.port 8551 \
  --authrpc.jwtsecret /var/lib/ethereum/jwt.hex
```

Other execution clients have equivalent options, for example `--JsonRpc.JwtSecretFile` in
Nethermind, `--engine-jwt-secret` in Besu and `--authrpc.jwtsecret` in Reth and Erigon. Check your
execution client's documentation for the exact names.

## Step 3: Point Grandine at the execution client

```bash
grandine bn \
  --network mainnet \
  --eth1-rpc-urls http://127.0.0.1:8551 \
  --jwt-secret /var/lib/ethereum/jwt.hex \
  --checkpoint-sync-url CHECKPOINT-SYNC-URL
```

When the connection works, Grandine logs:

```text
updated capabilities for eth1 endpoint: http://127.0.0.1:8551/
updated client version for eth1 endpoint: http://127.0.0.1:8551/
```

The first line means the execution client accepted the JWT and answered
`engine_exchangeCapabilities`. Grandine repeats this exchange at the start of every epoch.

You can also see which execution client Grandine is talking to through the API:

```bash
curl -s http://127.0.0.1:5052/eth/v2/node/version
```

### Docker

When both clients run in Docker, put them on the same Docker network and use the container name as
the host:

```bash
docker network create eth

docker run -d --name grandine --network eth \
  -p 9000:9000/tcp -p 9000:9000/udp -p 9001:9001/udp \
  -v /path/to/grandine-data:/root/.grandine \
  -v /var/lib/ethereum/jwt.hex:/jwt.hex:ro \
  sifrai/grandine:stable \
  bn \
  --network mainnet \
  --eth1-rpc-urls http://EL-CONTAINER-NAME:8551 \
  --jwt-secret /jwt.hex \
  --checkpoint-sync-url CHECKPOINT-SYNC-URL
```

The execution client must then listen on an address the Grandine container can reach (for Geth,
`--authrpc.addr 0.0.0.0` with `--authrpc.vhosts EL-CONTAINER-NAME` or `*`). Do not publish port 8551
to the host or the internet. See [Running as a service](./running_as_a_service.md) for a complete
Docker Compose file.

## JWT claims

Grandine creates a fresh token for each Engine API request. The token carries the issue time and
expires after 60 seconds, so the clocks of both machines must be in sync. Run NTP or
`systemd-timesyncd`.

Two optional claims help an execution client tell several consensus clients apart:

- `--jwt-id`: the `id` claim, a unique identifier for this consensus client.
- `--jwt-version`: the `clv` claim, the client type and version.

Most setups do not need them.

## Multiple execution clients and fallback

`--eth1-rpc-urls` accepts several URLs, separated by spaces:

```bash
grandine bn \
  --eth1-rpc-urls http://127.0.0.1:8551 http://EL-HOST-2:8551 \
  --jwt-secret /var/lib/ethereum/jwt.hex \
  ...
```

The first URL is the primary endpoint and the others are fallbacks, in order. The same JWT secret is
used for all of them. Grandine handles them like this:

- Every request goes to the first endpoint that is marked online. If it fails, Grandine marks it
  offline, logs `Eth1 RPC endpoint ... returned an error: ...; switching to ...` and tries the next
  one.
- If every endpoint fails, it logs `last available Eth1 RPC endpoint ... returned an error` and the
  request fails (`all Eth1 RPC endpoints exhausted`).
- At the start of every epoch, Grandine checks all endpoints with `engine_exchangeCapabilities`. An
  endpoint that answers is marked online again, so traffic returns to the primary once it recovers.
- Some calls, such as `engine_getBlobsV2`, go only to endpoints that advertised support for them.

> **Warning:** Grandine sends Engine API calls only to the endpoint it is currently using. It does
> not keep the fallback execution clients up to date. A fallback that has no consensus client of its
> own falls behind and is still syncing when Grandine switches to it. Make sure each fallback
> execution client is kept synced by another beacon node.

If you need full redundancy, run complete pairs of beacon node and execution client. See
[Redundancy and fallback beacon nodes](./redundancy.md).

## Optimistic sync

The execution client usually needs longer to sync than Grandine, especially after a checkpoint
sync. While the execution client is syncing, it answers `engine_newPayload` and
`engine_forkchoiceUpdated` with `SYNCING` or `ACCEPTED` instead of `VALID`. Grandine then imports
the blocks *optimistically*: it follows the chain without confirmation that the payloads are
valid. You will see warnings like:

```text
engine_newPayload returned SYNCING status (beacon_block_root: 0x…, block_number: …, block_hash: 0x…, response: …)
engine_forkchoiceUpdated returned SYNCING status (…)
```

These warnings are expected while the execution client syncs. They stop once it catches up.

While the head is optimistic:

- `GET /eth/v1/node/syncing` reports `"is_optimistic": true`, and API responses carry
  `execution_optimistic: true`.
- Validators do not sign attestations, blocks or sync committee messages based on an optimistic
  head. The built-in validator client waits briefly for the head to be fully validated and
  otherwise skips the duty with `validator cannot perform its duties because chain head has not
  been fully verified by an execution engine`. A separate validator client ignores heads that a
  beacon node reports as optimistic.
- Shortly before each interval of a slot, Grandine sends the head payload to the execution client
  again, so the head becomes fully validated as soon as the execution client can verify it.

If the execution client later reports a payload as `INVALID`, Grandine logs `engine_newPayload
returned INVALID status`, marks the payload and all its descendants as invalid, and fork choice
moves the head to a valid branch.

## Running without an execution client

Grandine refuses to start with validator keys and no `--eth1-rpc-urls`
(`--eth1-rpc-urls must be specified when validators are present`). Without validators, a beacon
node can start without an execution client on a built-in network, or on a custom network when it is
given a genesis state with `--genesis-state-file`. A custom network without either stops with
`--eth1-rpc-urls must be specified when connecting to custom network without --genesis-state-file`.

Such a node still imports blocks and follows the head, but it cannot verify any execution payload,
so every block it imports stays optimistic. Engine API calls fail and are logged, for example
`engine_newPayload call failed: attempted to call Eth1 RPC endpoint but none were provided`. Use
this only for testing.

Clients differ here. Nimbus also has an optimistic mode without an execution client, while
Lighthouse does not start without `--execution-endpoint`. If you move from Lighthouse, a missing
`--eth1-rpc-urls` is therefore not reported at startup unless validators are loaded.

## What Grandine uses the Engine API for

| Method | Purpose | Timeout |
|---|---|---|
| `engine_newPayloadV1`–`V5` | Validate the execution payload of each new block. | 8 s |
| `engine_forkchoiceUpdatedV1`–`V4` | Set the head, safe and finalized blocks; start building a payload. | 8 s |
| `engine_getPayloadV1`–`V6` | Fetch a payload the execution client built for a local proposal. | 1 s |
| `engine_getBlobsV1`, `engine_getBlobsV2` | Fetch blobs from the execution client's mempool so they do not have to come from the network. | 2 s |
| `engine_getPayloadBodiesByHashV1`, `V2` | Fetch payloads of older blocks to serve full blocks from the database. | 10 s |
| `engine_exchangeCapabilities`, `engine_getClientVersionV1` | Discover supported methods and the client version, at startup and every epoch. | 1 s |

Grandine picks the method version that matches the fork of the block.

By default, Grandine stores finalized blocks without their execution payloads and fetches the
payloads from the execution client when it serves full blocks through the API or to peers. The
execution client therefore has to stay available for that, and must not prune the bodies of blocks
the beacon node serves. To keep payloads in Grandine's own database instead, use
`--store-payloads`. See [Storage and database](./storage.md).

## Deposit contract and custom genesis

Grandine reads the deposit contract through the execution client only when it has to build the
genesis state of a custom network from deposits, that is, on a `custom` network started without
`--genesis-state-file`. The related options are `--deposit-contract-starting-block` and
`--eth1-database-size`. Built-in networks do not need them. See
[Configuration files and custom networks](./configuration_files.md).

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `unable to update capabilities for eth1 endpoint: ...` with `401` or `Unauthorized` | The two clients use different JWT secrets, or the clocks differ by more than a minute. |
| `unable to update capabilities for eth1 endpoint: ...` with `connection refused` | The execution client is not running, listens on another address or port, or a firewall blocks it. |
| `failed to parse JWT secret` | The secret file is not plain hex. |
| `engine_newPayload returned SYNCING status` for hours | The execution client is still syncing, or it has no peers. Check its logs. |
| `el_offline: true` in `/eth/v1/node/syncing` | No endpoint has answered recently. |

See [Troubleshooting](./troubleshooting.md) for more.

## Command line options

See [Command line reference](./cli_options.md) for the full list.

- `--eth1-rpc-urls` (default: none): one or more Engine API URLs, separated by spaces. The first is
  the primary, the rest are fallbacks.
- `--jwt-secret` (default: none): path to the hex-encoded JWT secret.
- `--jwt-id` (default: none): `id` claim sent in the JWT.
- `--jwt-version` (default: none): `clv` claim sent in the JWT.
- `--store-payloads` (default: off): keep execution payloads of finalized blocks in Grandine's
  database.
- `--request-timeout` (default: `30000`): default timeout in milliseconds for outgoing HTTP
  requests. The Engine API calls above use their own timeouts.
- `--deposit-contract-starting-block` (default: from the network configuration): block to start
  reading the deposit contract from when building a custom genesis.
- `--eth1-database-size` (default: 16 GiB): size limit of the deposit cache database.
- `--terminal-total-difficulty-override`, `--terminal-block-hash-override`,
  `--terminal-block-hash-activation-epoch-override` (default: none): override the Merge transition
  parameters. Only relevant for networks that have not gone through the Merge.
