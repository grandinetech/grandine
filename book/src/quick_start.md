# Quick start

This tutorial runs a full Ethereum node on the Hoodi testnet: an execution client and Grandine,
connected with a JWT secret and synced with checkpoint sync. It takes about 15 minutes of work, plus
the time the execution client needs to sync.

The same steps work on Mainnet. Where a command differs, the Mainnet form is given as well.

> **Tip:** Practice on Hoodi before you run validators on Mainnet. Testnet ether has no value, so
> mistakes cost nothing.

## Before you start

- A machine that meets the [System requirements](./hardware_requirements.md).
- Grandine installed. See the [Installation overview](./installation.md). Check it with
  `grandine --version`.
- An execution client installed: Geth, Nethermind, Besu, Reth or Erigon. Follow its own installation
  guide.
- Ports 9000 TCP and UDP and 9001 UDP open for Grandine, and the execution client's peer-to-peer
  port (usually 30303 TCP and UDP) open for the execution client.

## Step 1: Create a JWT secret

The execution client and Grandine authenticate each other with a shared secret: 32 random bytes,
written as hex. Create it once and give both programs the same file:

```bash
sudo mkdir -p /var/lib/ethereum
openssl rand -hex 32 | tr -d "\n" | sudo tee /var/lib/ethereum/jwt.hex > /dev/null
sudo chmod 644 /var/lib/ethereum/jwt.hex
```

This tutorial uses `/var/lib/ethereum/jwt.hex`. Grandine accepts the secret with or without a `0x`
prefix and a trailing newline.

> **Note:** Some execution clients create a JWT secret on first start if the file does not exist. That
> also works, as long as Grandine reads the same file.

## Step 2: Start the execution client

Start your execution client with its Engine API on `127.0.0.1:8551` and the JWT secret from step 1.
Pick one of the examples. The flags belong to the execution clients, not to Grandine, and can change
between their releases; check the documentation of your client.

### Geth

```bash
geth \
  --hoodi \
  --datadir /var/lib/geth \
  --authrpc.addr 127.0.0.1 \
  --authrpc.port 8551 \
  --authrpc.jwtsecret /var/lib/ethereum/jwt.hex
```

For Mainnet, remove `--hoodi`.

### Nethermind

```bash
nethermind \
  --config hoodi \
  --data-dir /var/lib/nethermind \
  --JsonRpc.EngineHost 127.0.0.1 \
  --JsonRpc.EnginePort 8551 \
  --JsonRpc.JwtSecretFile /var/lib/ethereum/jwt.hex
```

For Mainnet, use `--config mainnet`.

### Besu

```bash
besu \
  --network=hoodi \
  --data-path=/var/lib/besu \
  --engine-rpc-port=8551 \
  --engine-host-allowlist=localhost,127.0.0.1 \
  --engine-jwt-secret=/var/lib/ethereum/jwt.hex
```

For Mainnet, use `--network=mainnet`.

### Reth

```bash
reth node \
  --chain hoodi \
  --datadir /var/lib/reth \
  --authrpc.addr 127.0.0.1 \
  --authrpc.port 8551 \
  --authrpc.jwtsecret /var/lib/ethereum/jwt.hex
```

For Mainnet, use `--chain mainnet`.

### Erigon

Erigon has its own built-in consensus client. Disable it with `--externalcl` so Erigon follows
Grandine:

```bash
erigon \
  --chain=hoodi \
  --datadir=/var/lib/erigon \
  --externalcl \
  --authrpc.addr=127.0.0.1 \
  --authrpc.port=8551 \
  --authrpc.jwtsecret=/var/lib/ethereum/jwt.hex
```

For Mainnet, use `--chain=mainnet`.

Leave the execution client running. Until a consensus client connects, it logs warnings that it has
not received any forkchoice updates. That is expected.

## Step 3: Start Grandine with checkpoint sync

Checkpoint sync starts Grandine from a recent finalized state downloaded from a trusted beacon node,
instead of from genesis. Grandine is then ready in minutes. Pick a checkpoint sync endpoint for your
network from the community-maintained
[list of checkpoint sync endpoints](https://eth-clients.github.io/checkpoint-sync-endpoints/), or use a
beacon node you run yourself.

Start Grandine:

```bash
grandine \
  --network hoodi \
  --eth1-rpc-urls http://127.0.0.1:8551 \
  --jwt-secret /var/lib/ethereum/jwt.hex \
  --checkpoint-sync-url CHECKPOINT-URL
```

For Mainnet, use `--network mainnet` and a Mainnet checkpoint endpoint.

With Docker on Linux, host networking lets the container reach the execution client on `127.0.0.1`:

```bash
docker run -d --name grandine \
  --network host \
  -v $HOME/.grandine:/root/.grandine \
  -v /var/lib/ethereum/jwt.hex:/jwt.hex:ro \
  sifrai/grandine:stable \
  --network hoodi \
  --eth1-rpc-urls http://127.0.0.1:8551 \
  --jwt-secret /jwt.hex \
  --checkpoint-sync-url CHECKPOINT-URL
```

What the options do:

- `--network hoodi` selects the network. The default is `mainnet`.
- `--eth1-rpc-urls` is the Engine API URL of the execution client. Note the port: 8551, not the
  regular JSON-RPC port 8545.
- `--jwt-secret` is the file from step 1.
- `--checkpoint-sync-url` is the beacon node to download the finalized state from.

Grandine stores its data in `~/.grandine/hoodi` (`~/.grandine/mainnet` on Mainnet). On Hoodi, the
first start also downloads the genesis state and stores it there.

> **Note:** Checkpoint sync only happens when the database is empty. If Grandine finds an existing
> database, it logs `skipping checkpoint sync: existing database found` and continues from its own
> data. If checkpoint sync fails, Grandine logs the error and starts from genesis, which takes much
> longer; stop it, fix the URL and start again.

## Step 4: Check that Grandine is syncing

### Read the logs

Shortly after start, you should see lines like these (shortened). Plain `grandine` always starts the
integrated validator client, even without keys, so the first line says `with validator client`:

```text
INFO runtime::runtime: starting beacon node with validator client peers=[0/0]
INFO fork_choice_control::checkpoint_sync: performing checkpoint sync from https://CHECKPOINT-URL/… peers=[0/200]
INFO fork_choice_control::checkpoint_sync: loaded state at slot 1234560 from https://CHECKPOINT-URL/ peers=[0/200]
...
INFO fork_choice_control::mutator: new finalized checkpoint (epoch: 38581, root: 0x…, head slot: 1234620, head root: 0x…) peers=[48/200]
```

- `peers=[48/200]` at the end of each line is the number of connected peers and the target. It should
  climb into the dozens within a few minutes. If it stays at 0, check your ports and firewall; see
  [Networking and peers](./networking.md).
- `new finalized checkpoint` lines appear about every epoch (6.4 minutes) once Grandine follows the
  chain. The `head slot` should match the current slot on a block explorer.
- Warnings about the execution client being offline or syncing are normal while the execution client
  catches up. Until it has synced, Grandine imports blocks *optimistically*.

### Ask the API

Grandine serves the Beacon Node API on `http://127.0.0.1:5052`. Check the sync status:

```bash
curl -s http://127.0.0.1:5052/eth/v1/node/syncing
```

```json
{"data":{"head_slot":"1234620","sync_distance":"0","is_syncing":false,"is_optimistic":false,"el_offline":false}}
```

- `is_syncing: false` and `sync_distance: 0`: Grandine has caught up with the chain.
- `is_optimistic: true`: Grandine has the head, but the execution client has not validated it yet.
  Wait until the execution client finishes syncing.
- `el_offline: true`: Grandine cannot reach the execution client. Check the URL, the port and the JWT
  secret. See [Connecting an execution client](./execution_client.md).

Other quick checks:

```bash
# 200 when synced, 206 while syncing
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:5052/eth/v1/node/health

# Number of connected peers
curl -s http://127.0.0.1:5052/eth/v1/node/peer_count

# Version of Grandine
curl -s http://127.0.0.1:5052/eth/v1/node/version
```

The node is ready for validators when `is_syncing` and `is_optimistic` are both `false` and
`el_offline` is `false`.

## Step 5 (optional): Add validators

Once the node is synced, you can run validators in the same process. Stop Grandine and start it again
with your keystores and a fee recipient:

```bash
grandine \
  --network hoodi \
  --eth1-rpc-urls http://127.0.0.1:8551 \
  --jwt-secret /var/lib/ethereum/jwt.hex \
  --checkpoint-sync-url CHECKPOINT-URL \
  --keystore-dir /path/to/validator_keys \
  --keystore-password-file /path/to/password.txt \
  --suggested-fee-recipient FEE-RECIPIENT-ADDRESS
```

Grandine logs `loaded N validator key(s)` on startup.

> **Warning:** Never run the same validator keys in two places. If these keys are, or were recently,
> active in another client, read [Migrating from another client](./migration.md) first and consider
> [doppelganger protection](./doppelganger_protection.md).

[Becoming a validator](./validator_overview.md) walks through generating keys, making the deposit and
checking that everything works.

## What next?

- [Running as a service](./running_as_a_service.md): run the node under systemd or Docker Compose so it
  starts on boot and restarts on failure.
- [Becoming a validator](./validator_overview.md): generate keys, deposit and start validating.
- [Metrics](./metrics.md) and [Monitoring validator performance](./validator_monitoring.md): watch your
  node.
- [Networking and peers](./networking.md): port forwarding and peer tuning.
- [Updating Grandine](./updating.md): stay on a current release.
- [Troubleshooting](./troubleshooting.md): what to do when something goes wrong.

## Command line options

- `--network`: default `mainnet`. Network to connect to: `mainnet`, `sepolia`, `holesky`, `hoodi` or `custom`.
- `--eth1-rpc-urls`: no default. Engine API URLs of the execution clients.
- `--jwt-secret`: no default. File with the hex-encoded JWT secret.
- `--checkpoint-sync-url`: no default. Beacon Node API URL to load a recent finalized checkpoint from.
- `--data-dir`: default `$HOME/.grandine`. Parent directory for data; the network name is appended.
- `--http-port`: default `5052`. Port of the Beacon Node API.
- `--keystore-dir`: no default. Directory with EIP-2335 validator keystores.
- `--keystore-password-file`: no default. File with the password for all keystores.
- `--suggested-fee-recipient`: no default. Execution address that receives priority fees.

See the [Command line reference](./cli_options.md) for the full list.
